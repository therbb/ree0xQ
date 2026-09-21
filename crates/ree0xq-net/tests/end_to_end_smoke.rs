//! End-to-end smoke: ree0xq-net pcap-file path → ree0xq-server `/v1/events`.
//!
//! Spins the collector router in-process on an ephemeral port, runs
//! `live::observe_pcap` against the synthetic ClientHello fixture
//! committed in `tests/fixtures/synth-clienthello.pcap`, POSTs every
//! emitted event to `/v1/events`, then reads them back and asserts
//! the round trip preserved the primitives the parser extracted.
//!
//! Exercises the full chain that lands an event in the collector
//! store without leaving the test process: parse → JSON →
//! `axum` route → `DashMap` → JSON → assertion.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use ree0xq_net::live;
use ree0xq_server::{router, AppState};

async fn spawn_server() -> SocketAddr {
    // Per-test CA dir keeps parallel runs from racing on the
    // on-disk ca.crt / ca.key.
    let tmp = tempfile::tempdir().expect("tempdir");
    let state = AppState::new_in_memory(tmp.path(), None).expect("AppState init");
    std::mem::forget(tmp);
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    // Give the runtime a tick to start accepting connections.
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

fn fixture_pcap() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/synth-clienthello.pcap");
    p
}

#[tokio::test]
async fn pcap_file_to_collector_roundtrip() {
    let addr = spawn_server().await;
    let events_url = format!("http://{addr}/v1/events");

    // observe_pcap is sync; drive it from a blocking task and POST
    // each event with the sync reqwest client. The closure captures
    // a fresh blocking client so the test does not leak runtimes.
    let posted_events = {
        let url = events_url.clone();
        tokio::task::spawn_blocking(move || {
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("reqwest client");
            let mut count = 0usize;
            live::observe_pcap(fixture_pcap(), |ev| {
                let r = client.post(&url).json(&ev).send().expect("POST /v1/events");
                assert!(
                    r.status().is_success(),
                    "collector rejected event: {}",
                    r.status()
                );
                count += 1;
            })
            .expect("observe_pcap");
            count
        })
        .await
        .unwrap()
    };

    assert_eq!(
        posted_events, 1,
        "synthetic fixture should yield exactly one ClientHello event"
    );

    // Read the event back through the collector and inspect the
    // primitives that survived JSON round-tripping.
    let client = reqwest::Client::new();
    let body: serde_json::Value = client
        .get(&events_url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(body["count"], 1, "store should hold one event");
    let ev = &body["events"][0];
    assert_eq!(ev["source_module"], "ree0xq-net");
    assert_eq!(ev["asset"]["kind"], "tls_session");

    let algos: Vec<&str> = ev["primitives"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["algorithm"].as_str().unwrap())
        .collect();
    for expected in ["X25519+ML-KEM-768", "X25519", "ML-DSA-65", "AES-256-GCM"] {
        assert!(
            algos.contains(&expected),
            "missing primitive {expected:?}; got {algos:?}"
        );
    }

    // Confirm the rollup endpoints see the event too.
    let inv: serde_json::Value = client
        .get(format!("http://{addr}/v1/inventory"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(inv["count"], 1, "inventory should mirror the event");
    let posture: serde_json::Value = client
        .get(format!("http://{addr}/v1/posture"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(posture["assets"], 1);
    assert!(
        posture["org_q"].as_f64().unwrap() > 0.0,
        "org_q should be a positive rollup, got {}",
        posture["org_q"]
    );
}
