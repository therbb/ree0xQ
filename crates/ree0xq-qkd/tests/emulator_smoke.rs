//! In-process smoke test for the KME emulator.
//!
//! Boots the emulator on an ephemeral port, exercises every ETSI 014
//! endpoint, drives one `/control` op, and confirms the response
//! shapes round-trip. Mirrors the kind of integration test the
//! paper's Study 2 will rely on at a much larger scale.

use std::sync::Arc;
use std::time::Duration;

use ree0xq_qkd::emulator::{router, ControlOp, EmulatorConfig, EmulatorState};
use ree0xq_qkd::etsi014::{DecKeyId, DecKeysRequest, KeyContainer, StatusResponse};
use tokio::sync::RwLock;

async fn spawn_emulator() -> String {
    let cfg = EmulatorConfig::default();
    let state = Arc::new(RwLock::new(EmulatorState::new(cfg)));
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    // Give the listener a moment to start accepting.
    tokio::time::sleep(Duration::from_millis(50)).await;
    format!("http://{addr}")
}

#[tokio::test]
async fn full_round_trip_through_emulator() {
    let base = spawn_emulator().await;
    let client = reqwest::Client::new();

    // /status
    let status: StatusResponse = client
        .get(format!("{base}/api/v1/keys/SAE-PEER/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status.source_kme_id, "KME-A");
    assert_eq!(status.target_kme_id, "KME-B");
    assert_eq!(status.key_size, 256);

    // /enc_keys?number=3
    let enc: KeyContainer = client
        .get(format!("{base}/api/v1/keys/SAE-PEER/enc_keys"))
        .query(&[("number", "3")])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(enc.keys.len(), 3);

    // /dec_keys for those same keys
    let dec_req = DecKeysRequest {
        key_IDs: enc
            .keys
            .iter()
            .map(|k| DecKeyId {
                key_id: k.key_id.clone(),
            })
            .collect(),
    };
    let dec: KeyContainer = client
        .post(format!("{base}/api/v1/keys/SAE-PEER/dec_keys"))
        .json(&dec_req)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(dec.keys.len(), 3);
    for (e, d) in enc.keys.iter().zip(dec.keys.iter()) {
        assert_eq!(e.key_id, d.key_id);
        assert_eq!(e.key, d.key, "dec_keys must return identical material");
    }

    // /control: force a failure and confirm /status returns 503
    let resp = client
        .post(format!("{base}/control"))
        .json(&ControlOp::ForceFailure {
            reason: "test-induced".into(),
        })
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let status_after = client
        .get(format!("{base}/api/v1/keys/SAE-PEER/status"))
        .send()
        .await
        .unwrap();
    assert_eq!(status_after.status().as_u16(), 503);
}
