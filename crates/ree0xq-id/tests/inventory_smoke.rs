//! End-to-end smoke for the ree0xq-id offline inventory
//! classifier (SEZ-15) against a live in-process collector.
//! Mirrors the ree0xq-chain / ree0xq-cert smoke shape.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use ree0xq_id::inventory::{self, KeyInventory, SlotInventory};
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

fn fixture() -> Vec<SlotInventory> {
    vec![
        SlotInventory {
            hsm_vendor: "Thales nShield".into(),
            hsm_model: Some("Connect XC".into()),
            slot_id: "0".into(),
            label: Some("Production CA".into()),
            keys: vec![
                KeyInventory {
                    key_id: "ca-sign-2024".into(),
                    key_type: "RSA".into(),
                    key_size_bits: Some(4096),
                    usage: vec!["sign".into()],
                },
                KeyInventory {
                    key_id: "tls-server-2026".into(),
                    key_type: "ECDSA-P256".into(),
                    key_size_bits: None,
                    usage: vec!["sign".into()],
                },
            ],
        },
        SlotInventory {
            hsm_vendor: "AWS CloudHSM".into(),
            hsm_model: Some("v2".into()),
            slot_id: "1".into(),
            label: None,
            keys: vec![KeyInventory {
                key_id: "code-sign-pq".into(),
                key_type: "ML-DSA-65".into(),
                key_size_bits: None,
                usage: vec!["sign".into()],
            }],
        },
    ]
}

#[tokio::test]
async fn inventory_scan_round_trips_through_collector() {
    let addr = spawn_server().await;
    let url = format!("http://{addr}/v1/events");

    let identities = Arc::new(Mutex::new(Vec::<String>::new()));
    let identities_clone = Arc::clone(&identities);
    let url_clone = url.clone();
    let inv = fixture();

    tokio::task::spawn_blocking(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let stats = inventory::scan(&inv, |ev| {
            identities_clone
                .lock()
                .unwrap()
                .push(ev.asset.identity.clone());
            let r = client.post(&url_clone).json(&ev).send().expect("POST");
            assert!(r.status().is_success(), "{}", r.status());
        });
        assert_eq!(stats.slots_seen, 2);
        assert_eq!(stats.keys_seen, 3);
        assert_eq!(stats.events_emitted, 3);
    })
    .await
    .unwrap();

    // Read back + verify per-key shape.
    let client = reqwest::Client::new();
    let inv_resp: serde_json::Value = client
        .get(format!("http://{addr}/v1/inventory"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(inv_resp["count"], 3);
    let items = inv_resp["items"].as_array().unwrap();
    for it in items {
        assert_eq!(it["asset_kind"], "hsm_slot");
        assert_eq!(it["source_module"], "ree0xq-id");
    }

    // Find the PQ key by identity and assert it carries the
    // pq_resistant + ML-DSA-65 primitive.
    let pq = items
        .iter()
        .find(|it| it["identity"].as_str().unwrap().ends_with("/code-sign-pq"))
        .unwrap();
    let prims = pq["primitives"].as_array().unwrap();
    let names: Vec<&str> = prims.iter().map(|p| p.as_str().unwrap()).collect();
    assert!(
        names.iter().any(|n| *n == "ML-DSA-65"),
        "missing ML-DSA-65 in {names:?}"
    );
}
