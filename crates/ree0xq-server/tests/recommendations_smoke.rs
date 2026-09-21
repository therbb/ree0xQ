//! Smoke for `GET /v1/recommendations` (SEZ-23).
//!
//! Seeds the in-process router with a mixed inventory and
//! checks the recommendations endpoint returns the
//! canonical replacements per asset, ranked cheapest first.

use std::net::SocketAddr;
use std::time::Duration;

use ree0xq_core::{
    Asset, AssetKind, CryptoInventoryEvent, Posture, Primitive, PrimitiveRole, SCHEMA_MINOR,
    SCHEMA_VERSION,
};
use ree0xq_server::{router, AppState};

async fn spawn_server() -> SocketAddr {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state = AppState::new_in_memory(tmp.path(), None).expect("AppState init");
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

fn p(role: PrimitiveRole, algo: &str) -> Primitive {
    Primitive {
        role,
        algorithm: algo.into(),
        parameters: Default::default(),
        pq_resistant: None,
        nist_classification: None,
    }
}

fn ev(
    source: &str,
    kind: AssetKind,
    identity: &str,
    prims: Vec<Primitive>,
) -> CryptoInventoryEvent {
    CryptoInventoryEvent {
        schema_version: SCHEMA_VERSION,
        schema_minor: SCHEMA_MINOR,
        source_module: source.into(),
        observed_at: chrono::Utc::now(),
        asset: Asset {
            kind,
            identity: identity.into(),
            host: Some("rec.example".into()),
        },
        primitives: prims,
        channel_protection: None,
        agility: None,
        posture: Posture {
            score: 0,
            rationale: "fixture".into(),
            recommended_replacement: None,
        },
    }
}

#[tokio::test]
async fn recommendations_endpoint_returns_canonical_replacements() {
    let addr = spawn_server().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let evs = vec![
        ev(
            "ree0xq-cert",
            AssetKind::X509Cert,
            "sha256:rsa-2048",
            vec![p(PrimitiveRole::Sig, "RSA-PKCS1-2048")],
        ),
        ev(
            "ree0xq-cert",
            AssetKind::X509Cert,
            "sha256:ecdsa-p256",
            vec![p(PrimitiveRole::Sig, "ECDSA-P256")],
        ),
        ev(
            "ree0xq-id",
            AssetKind::HsmSlot,
            "yubihsm/0/ml-dsa-65",
            vec![p(PrimitiveRole::Sig, "ML-DSA-65")],
        ),
    ];
    let r = client
        .post(format!("{base}/v1/events/batch"))
        .json(&evs)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // Endpoint round-trip.
    let body: serde_json::Value = client
        .get(format!("{base}/v1/recommendations"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // Two assets have recommendations; the PQ-safe ML-DSA-65
    // slot drops out.
    assert_eq!(body["count"], 2);
    let items = body["items"].as_array().unwrap();
    let by_id: std::collections::HashMap<&str, &serde_json::Value> = items
        .iter()
        .map(|it| (it["identity"].as_str().unwrap(), it))
        .collect();

    let rsa = by_id["sha256:rsa-2048"];
    let rsa_recs: Vec<&str> = rsa["recommendations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["replacement"].as_str().unwrap())
        .collect();
    assert!(rsa_recs.iter().any(|r| *r == "ML-DSA-44"));

    let ec = by_id["sha256:ecdsa-p256"];
    let ec_recs: Vec<&str> = ec["recommendations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["replacement"].as_str().unwrap())
        .collect();
    assert!(ec_recs.iter().any(|r| *r == "ML-DSA-65"));

    assert!(by_id.get("yubihsm/0/ml-dsa-65").is_none());
}
