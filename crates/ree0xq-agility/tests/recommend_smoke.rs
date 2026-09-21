//! End-to-end smoke for the V5.0 recommendation engine
//! against a live in-process collector. Mirrors the
//! ree0xq-chain / ree0xq-cert / ree0xq-id smoke pattern.
//!
//! Flow:
//! 1. Seed a ree0xq-server with a mixed inventory (one
//!    RSA-2048 cert, one ECDSA-P256 cert, one AES-128
//!    blockchain-key, one ML-DSA-65 hsm_slot).
//! 2. Fetch `/v1/inventory` as JSON.
//! 3. Feed it into `recommend_for` per asset.
//! 4. Assert each asset gets the canonical replacement —
//!    and the PQ-already-safe key gets none.

use std::net::SocketAddr;
use std::time::Duration;

use ree0xq_core::{
    Asset, AssetKind, CryptoInventoryEvent, Posture, Primitive, PrimitiveRole, SCHEMA_MINOR,
    SCHEMA_VERSION,
};
use ree0xq_server::{router, AppState};

async fn spawn_server() -> SocketAddr {
    let tmp = tempfile::tempdir().expect("tempdir for CA");
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
            host: Some("smoke.example".into()),
        },
        primitives: prims,
        channel_protection: None,
        agility: None,
        posture: Posture {
            score: 0,
            rationale: "smoke fixture".into(),
            recommended_replacement: None,
        },
    }
}

fn prim(role: PrimitiveRole, name: &str) -> Primitive {
    Primitive {
        role,
        algorithm: name.into(),
        parameters: Default::default(),
        pq_resistant: None,
        nist_classification: None,
    }
}

#[tokio::test]
async fn recommend_canonical_replacements_per_asset_kind() {
    let addr = spawn_server().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Mixed inventory.
    let evs = vec![
        ev(
            "ree0xq-cert",
            AssetKind::X509Cert,
            "sha256:rsa-2048",
            vec![prim(PrimitiveRole::Sig, "RSA-PKCS1-2048")],
        ),
        ev(
            "ree0xq-cert",
            AssetKind::X509Cert,
            "sha256:ecdsa-p256",
            vec![prim(PrimitiveRole::Sig, "ECDSA-P256")],
        ),
        ev(
            "ree0xq-chain",
            AssetKind::BlockchainKey,
            "btc:legacy",
            vec![
                prim(PrimitiveRole::Sig, "ECDSA-secp256k1"),
                prim(PrimitiveRole::Hash, "SHA-256"),
            ],
        ),
        ev(
            "ree0xq-id",
            AssetKind::HsmSlot,
            "yubihsm/0/ml-dsa-65",
            vec![prim(PrimitiveRole::Sig, "ML-DSA-65")],
        ),
    ];
    let r = client
        .post(format!("{base}/v1/events/batch"))
        .json(&evs)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // Pull /v1/inventory and feed it into the recommender.
    use ree0xq_agility::recommend;
    let inv: serde_json::Value = client
        .get(format!("{base}/v1/inventory"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = inv["items"].as_array().unwrap();
    assert_eq!(items.len(), 4);

    let mut got: std::collections::HashMap<String, Vec<String>> = Default::default();
    for it in items {
        let identity = it["identity"].as_str().unwrap().to_string();
        let prim_names: Vec<String> = it["primitives"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap().to_string())
            .collect();
        let prims: Vec<Primitive> = prim_names
            .iter()
            .map(|name| prim(classify_role(name), name))
            .collect();
        let recs = recommend::recommend_for(&prims);
        got.insert(identity, recs.into_iter().map(|r| r.replacement).collect());
    }

    // RSA-2048 → ML-DSA-44 (and SLH-DSA fallback).
    let rsa = &got["sha256:rsa-2048"];
    assert!(
        rsa.iter().any(|r| r == "ML-DSA-44"),
        "RSA-2048 missing ML-DSA-44: {rsa:?}"
    );
    // ECDSA-P256 → ML-DSA-65.
    let ec = &got["sha256:ecdsa-p256"];
    assert!(
        ec.iter().any(|r| r == "ML-DSA-65"),
        "ECDSA-P256 missing ML-DSA-65: {ec:?}"
    );
    // BTC legacy (secp256k1 ECDSA) — same family-handling
    // as ECDSA-P256, returns ML-DSA-65 too.
    let btc = &got["btc:legacy"];
    assert!(btc.iter().any(|r| r == "ML-DSA-65"));
    // ML-DSA-65 already PQ-safe — no recommendations.
    assert_eq!(
        got["yubihsm/0/ml-dsa-65"].len(),
        0,
        "PQ-safe asset should get no recommendations"
    );
}

// Same helper as the binary's, duplicated here so the test
// doesn't have to depend on a binary module.
fn classify_role(algorithm: &str) -> PrimitiveRole {
    let upper = algorithm.to_ascii_uppercase();
    if upper.contains("AES")
        || upper.contains("CHACHA")
        || upper.contains("DES")
        || upper.contains("RC4")
    {
        return PrimitiveRole::Encrypt;
    }
    if upper.starts_with("SHA")
        || upper.starts_with("KECCAK")
        || upper.starts_with("MD5")
        || upper.starts_with("HMAC")
    {
        return PrimitiveRole::Hash;
    }
    if upper.contains("X25519")
        || upper.contains("ML-KEM")
        || upper.contains("MLKEM")
        || upper.contains("ECDH")
    {
        return PrimitiveRole::Kex;
    }
    PrimitiveRole::Sig
}
