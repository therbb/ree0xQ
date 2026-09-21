//! In-process HTTP smoke test for `ree0xq-server`.
//!
//! Boots the router on an ephemeral port, posts a mix of events
//! (modern, locked-with-BLOCKED, QKD-link), then reads back the
//! inventory, posture, blocked, and QKD endpoints to make sure
//! the routing + rollup pipeline survives end-to-end.

use std::net::SocketAddr;
use std::time::Duration;

use ree0xq_core::{
    AgilityBlock, AgilityLevel, Asset, AssetKind, ChannelProtection, ChannelState,
    CryptoInventoryEvent, LinkHealth, Posture, Primitive, PrimitiveRole, SCHEMA_MINOR,
    SCHEMA_VERSION,
};
use ree0xq_server::{router, AppState};

async fn spawn_server() -> SocketAddr {
    // Each test gets its own CA dir under a unique tempdir so
    // parallel tests do not race on ca.crt / ca.key.
    let tmp = tempfile::tempdir().expect("tempdir");
    let state = AppState::new_in_memory(tmp.path(), None).expect("AppState init");
    // Keep the tempdir alive for the lifetime of the spawned
    // server task by leaking it — the test process is short.
    std::mem::forget(tmp);
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

fn prim(role: PrimitiveRole, algo: &str, pq: Option<bool>) -> Primitive {
    Primitive {
        role,
        algorithm: algo.into(),
        parameters: Default::default(),
        pq_resistant: pq,
        nist_classification: None,
    }
}

fn modern_classical_tls() -> Vec<Primitive> {
    vec![
        prim(PrimitiveRole::Kex, "X25519", Some(false)),
        prim(PrimitiveRole::Sig, "ECDSA-P256", Some(false)),
        prim(PrimitiveRole::Encrypt, "AES-256-GCM", Some(true)),
        prim(PrimitiveRole::Hash, "SHA-384", Some(true)),
    ]
}

fn event(
    kind: AssetKind,
    identity: &str,
    source: &str,
    prims: Vec<Primitive>,
    cp: Option<ChannelProtection>,
    ag: Option<AgilityBlock>,
) -> CryptoInventoryEvent {
    CryptoInventoryEvent {
        schema_version: SCHEMA_VERSION,
        schema_minor: SCHEMA_MINOR,
        source_module: source.into(),
        observed_at: chrono::Utc::now(),
        asset: Asset {
            kind,
            identity: identity.into(),
            host: Some("test.example.com".into()),
        },
        primitives: prims,
        channel_protection: cp,
        agility: ag,
        posture: Posture {
            score: 0,
            rationale: "fixture".into(),
            recommended_replacement: None,
        },
    }
}

#[tokio::test]
async fn full_ingest_query_loop() {
    let addr = spawn_server().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // /healthz
    let r = client.get(format!("{base}/healthz")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "ok");

    // Three events:
    // 1) modern agile (no agility block → fallback Pinned)
    // 2) modern locked → BLOCKED flag
    // 3) QKD-KME link
    let agile = AgilityBlock {
        level: AgilityLevel::Configurable,
        level_score: AgilityLevel::Configurable.score(),
        evidence: vec![],
        scanner_version: "test".into(),
        rubric_version: "test".into(),
    };
    let locked = AgilityBlock {
        level: AgilityLevel::Locked,
        level_score: AgilityLevel::Locked.score(),
        evidence: vec![],
        scanner_version: "test".into(),
        rubric_version: "test".into(),
    };
    let cp_qkd = ChannelProtection {
        state: ChannelState::QkdHybridPsk,
        kme_endpoint: Some("http://kme-1.example/api/v1".into()),
        key_id_observed: None,
        psk_age_seconds: None,
        link_qber: Some(0.018),
        link_key_rate_bps: Some(12_480),
        link_health: LinkHealth::Ok,
        degraded_reason: None,
    };

    let events = vec![
        event(
            AssetKind::TlsSession,
            "tls-modern-1",
            "ree0xq-net",
            modern_classical_tls(),
            None,
            Some(agile.clone()),
        ),
        event(
            AssetKind::TlsSession,
            "tls-locked-1",
            "ree0xq-net",
            modern_classical_tls(),
            None,
            Some(locked.clone()),
        ),
        event(
            AssetKind::QkdKme,
            "KME-A",
            "ree0xq-qkd",
            vec![],
            Some(cp_qkd.clone()),
            None,
        ),
    ];

    let r = client
        .post(format!("{base}/v1/events/batch"))
        .json(&events)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["ingested"], 3);

    // /v1/events?limit=10
    let r = client
        .get(format!("{base}/v1/events?limit=10"))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["count"], 3);

    // /v1/inventory
    let r = client
        .get(format!("{base}/v1/inventory"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["count"], 3);
    let items = body["items"].as_array().unwrap();
    // Sorted by q descending; the locked asset should be ahead of the agile one.
    let q_locked: f64 = items
        .iter()
        .find(|i| i["identity"] == "tls-locked-1")
        .unwrap()["q"]
        .as_f64()
        .unwrap();
    let q_modern: f64 = items
        .iter()
        .find(|i| i["identity"] == "tls-modern-1")
        .unwrap()["q"]
        .as_f64()
        .unwrap();
    assert!(
        q_locked > q_modern,
        "locked must rank above modern; got {q_locked} vs {q_modern}"
    );

    // /v1/posture
    let r = client
        .get(format!("{base}/v1/posture"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["assets"], 3);
    assert_eq!(body["blocked_count"], 1);
    assert!(body["org_q"].as_f64().unwrap() > 0.0);

    // /v1/blocked
    let r = client
        .get(format!("{base}/v1/blocked"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["count"], 1);
    assert_eq!(body["items"][0]["identity"], "tls-locked-1");

    // /v1/qkd/links
    let r = client
        .get(format!("{base}/v1/qkd/links"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["count"], 1);
    assert_eq!(body["links"][0]["identity"], "KME-A");
    assert_eq!(body["links"][0]["link_health"], "ok");
}

#[tokio::test]
async fn schema_version_mismatch_is_rejected() {
    let addr = spawn_server().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Hand-craft an event with the wrong schema_version.
    let bad = serde_json::json!({
        "schema_version": 99,
        "source_module": "test",
        "observed_at": "2026-01-01T00:00:00Z",
        "asset": {"kind": "tls_session", "identity": "a"},
        "primitives": [],
        "posture": {"score": 0, "rationale": "x"}
    });
    let r = client
        .post(format!("{base}/v1/events"))
        .json(&bad)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 422);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["code"], "schema_version_mismatch");
}
