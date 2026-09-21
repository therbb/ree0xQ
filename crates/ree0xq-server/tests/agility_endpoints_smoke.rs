//! Smoke for the V5 agility endpoints (SEZ-26):
//!
//! - `GET  /v1/agility/deadlines` — regulator deadline table.
//! - `GET  /v1/agility/compat`    — stack ↔ algorithm matrix.
//! - `POST /v1/agility/roadmap`   — project a plan against
//!   the current inventory.

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

fn ev(kind: AssetKind, id: &str, algo: &str) -> CryptoInventoryEvent {
    CryptoInventoryEvent {
        schema_version: SCHEMA_VERSION,
        schema_minor: SCHEMA_MINOR,
        source_module: "test".into(),
        observed_at: chrono::Utc::now(),
        asset: Asset {
            kind,
            identity: id.into(),
            host: Some("rec.example".into()),
        },
        primitives: vec![Primitive {
            role: PrimitiveRole::Sig,
            algorithm: algo.into(),
            parameters: Default::default(),
            pq_resistant: None,
            nist_classification: None,
        }],
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
async fn deadlines_endpoint_returns_table_and_filters() {
    let addr = spawn_server().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let full: serde_json::Value = client
        .get(format!("{base}/v1/agility/deadlines"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let full_count = full["count"].as_u64().unwrap();
    assert!(
        full_count >= 5,
        "expected ≥5 deadline rows; got {full_count}"
    );

    // Jurisdiction filter — US-* prefix.
    let us: serde_json::Value = client
        .get(format!("{base}/v1/agility/deadlines?jurisdiction=US"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let us_count = us["count"].as_u64().unwrap();
    assert!(
        us_count >= 2,
        "US-* should yield ≥2 entries; got {us_count}"
    );
    assert!(us_count < full_count, "US filter must shrink the table");
    for row in us["items"].as_array().unwrap() {
        let j = row["jurisdiction"].as_str().unwrap();
        assert!(j.starts_with("US"), "leaked non-US row: {j}");
    }
}

#[tokio::test]
async fn compat_endpoint_supports_full_stack_and_pair_lookup() {
    let addr = spawn_server().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Per-stack list.
    let openssl: serde_json::Value = client
        .get(format!("{base}/v1/agility/compat?stack=openssl-3.x"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ossl_count = openssl["count"].as_u64().unwrap();
    assert!(ossl_count >= 1, "openssl-3.x should appear in the matrix");

    // Pair-not-found → 404.
    let nf = client
        .get(format!(
            "{base}/v1/agility/compat?stack=openssl-3.x&algorithm=NOT-A-REAL-ALGO"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(nf.status(), 404);

    // Full dump (no filter).
    let dump: serde_json::Value = client
        .get(format!("{base}/v1/agility/compat"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(dump["count"].as_u64().unwrap() >= ossl_count);
}

#[tokio::test]
async fn roadmap_endpoint_projects_a_plan_against_live_inventory() {
    let addr = spawn_server().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Seed inventory with a couple of classical assets so the
    // projection has something to migrate.
    let evs = vec![
        ev(AssetKind::X509Cert, "sha256:rsa-2048", "RSA-2048"),
        ev(AssetKind::X509Cert, "sha256:ecdsa-p256", "ECDSA-P256"),
    ];
    let r = client
        .post(format!("{base}/v1/events/batch"))
        .json(&evs)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // POST a minimal plan that migrates both assets at one
    // milestone.
    let plan = serde_json::json!({
        "milestones": [
            {
                "label": "Q1-2027-fleet-cut",
                "date": "2027-01-01T00:00:00Z",
                "asset_ids": ["sha256:rsa-2048", "sha256:ecdsa-p256"],
                "target_primitives": ["ML-DSA-65"],
            }
        ]
    });
    let body: serde_json::Value = client
        .post(format!("{base}/v1/agility/roadmap"))
        .json(&plan)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(body["total_assets"], 2);
    let projections = body["projections"].as_array().unwrap();
    assert_eq!(projections.len(), 1);
    let p0 = &projections[0];
    assert_eq!(p0["milestone"], "Q1-2027-fleet-cut");
    assert_eq!(p0["assets_migrated"], 2);
    // org_q must drop (or stay flat) after migration.
    let before = p0["org_q_before"].as_f64().unwrap();
    let after = p0["org_q_after"].as_f64().unwrap();
    assert!(
        after <= before + 1e-6,
        "org_q should not increase after migrating to PQ; before={before} after={after}"
    );
}
