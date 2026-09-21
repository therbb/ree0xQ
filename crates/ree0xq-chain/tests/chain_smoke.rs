//! End-to-end smoke for the three V3 ree0xq-chain backends.
//!
//! Spawns `ree0xq-server` on an ephemeral port, runs all
//! three scanners (Bitcoin / Ethereum / QRL) with a
//! `reqwest::blocking` sink, then reads back through the
//! collector and asserts every event landed with the right
//! shape — `asset.kind = blockchain_key`, the chain in
//! `asset.host`, and a primitive list matching the
//! address-type classifier's contract.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use ree0xq_chain::{bitcoin as bc, ethereum as eth, qrl};
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

#[tokio::test]
async fn all_three_chains_round_trip_through_collector() {
    let addr = spawn_server().await;
    let url = format!("http://{addr}/v1/events");

    let btc_addrs = vec![
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(), // P2PKH
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr".to_string(), // P2TR
    ];
    let eth_addrs = vec!["0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".to_string()];
    let qrl_addrs = vec![format!("Q{}", "0".repeat(78))];

    let identities = Arc::new(Mutex::new(Vec::<String>::new()));
    let identities_clone = Arc::clone(&identities);
    let url_clone = url.clone();

    tokio::task::spawn_blocking(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let post = |ev: &ree0xq_core::CryptoInventoryEvent| {
            identities_clone
                .lock()
                .unwrap()
                .push(ev.asset.identity.clone());
            let r = client.post(&url_clone).json(ev).send().expect("POST");
            assert!(r.status().is_success(), "{}", r.status());
        };
        let s1 = bc::scan_addresses(&btc_addrs, |ev| post(&ev));
        let s2 = eth::scan_addresses(&eth_addrs, |ev| post(&ev));
        let s3 = qrl::scan_addresses(&qrl_addrs, |ev| post(&ev));
        assert_eq!(s1.events_emitted, 2);
        assert_eq!(s2.events_emitted, 1);
        assert_eq!(s3.events_emitted, 1);
    })
    .await
    .unwrap();

    // Read everything back and verify per-chain shape.
    let client = reqwest::Client::new();
    let inv: serde_json::Value = client
        .get(format!("http://{addr}/v1/inventory"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(inv["count"], 4, "all 4 events should land");

    let items = inv["items"].as_array().unwrap();
    let by_host: std::collections::HashMap<&str, Vec<&serde_json::Value>> = {
        let mut m: std::collections::HashMap<&str, Vec<&serde_json::Value>> =
            std::collections::HashMap::new();
        for it in items {
            let host = it["host"].as_str().unwrap();
            m.entry(host).or_default().push(it);
        }
        m
    };
    assert_eq!(by_host.get("bitcoin").map(|v| v.len()), Some(2));
    assert_eq!(by_host.get("ethereum").map(|v| v.len()), Some(1));
    assert_eq!(by_host.get("qrl").map(|v| v.len()), Some(1));

    for it in &by_host["bitcoin"] {
        assert_eq!(it["asset_kind"], "blockchain_key");
        let prims = it["primitives"].as_array().unwrap();
        let names: Vec<&str> = prims.iter().map(|p| p.as_str().unwrap()).collect();
        // Either ECDSA or Schnorr depending on script type;
        // both belong to secp256k1.
        assert!(
            names.iter().any(|n| n.contains("secp256k1")),
            "missing secp256k1 in {names:?}"
        );
        assert!(names.contains(&"SHA-256"));
    }
    for it in &by_host["ethereum"] {
        let prims = it["primitives"].as_array().unwrap();
        let names: Vec<&str> = prims.iter().map(|p| p.as_str().unwrap()).collect();
        assert!(names.contains(&"ECDSA-secp256k1"));
        assert!(names.contains(&"Keccak-256"));
    }
    for it in &by_host["qrl"] {
        let prims = it["primitives"].as_array().unwrap();
        let names: Vec<&str> = prims.iter().map(|p| p.as_str().unwrap()).collect();
        assert!(names.contains(&"XMSS"), "missing XMSS in {names:?}");
    }
}
