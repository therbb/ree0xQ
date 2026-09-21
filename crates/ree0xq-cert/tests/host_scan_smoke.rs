//! End-to-end smoke for the SEZ-9 host-scan path.
//!
//! Spins `ree0xq-server`'s in-memory router in-process on an
//! ephemeral port, writes a small fixture cert bundle to a
//! temp directory, runs the host scanner against it with a
//! blocking reqwest POSTing each event to `/v1/events`, then
//! reads back via `/v1/inventory` and asserts the certs
//! landed.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use ree0xq_cert::scan;
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

fn write_fixture(dir: &std::path::Path, names: &[&str]) {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    use std::io::Write;
    for name in names {
        let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec![format!("{name}.example.com")]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("{name}.example.com"));
        params.distinguished_name = dn;
        let cert = params.self_signed(&kp).unwrap();
        let mut f = std::fs::File::create(dir.join(format!("{name}.pem"))).unwrap();
        f.write_all(cert.pem().as_bytes()).unwrap();
    }
}

#[tokio::test]
async fn host_scan_to_collector_roundtrip() {
    let addr = spawn_server().await;
    let url = format!("http://{addr}/v1/events");

    // Write three fixture certs under a temp root.
    let root_tmp = tempfile::tempdir().expect("root tempdir");
    write_fixture(root_tmp.path(), &["alpha", "beta", "gamma"]);
    let root: PathBuf = root_tmp.path().to_path_buf();

    // host_scan + POST happens on a blocking task; collect
    // identities for a post-check.
    let identities = Arc::new(Mutex::new(Vec::<String>::new()));
    let identities_clone = Arc::clone(&identities);
    let stats = tokio::task::spawn_blocking(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        scan::host_scan(&[root], |ev| {
            identities_clone
                .lock()
                .unwrap()
                .push(ev.asset.identity.clone());
            let r = client.post(&url).json(&ev).send().expect("POST");
            assert!(
                r.status().is_success(),
                "collector rejected: {}",
                r.status()
            );
        })
        .expect("host_scan")
    })
    .await
    .unwrap();

    assert_eq!(stats.certs_parsed, 3);
    assert_eq!(stats.events_emitted, 3);
    assert_eq!(identities.lock().unwrap().len(), 3);

    // Read back via /v1/inventory.
    let client = reqwest::Client::new();
    let inv: serde_json::Value = client
        .get(format!("http://{addr}/v1/inventory"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(inv["count"], 3, "all 3 certs should land in inventory");
    let items = inv["items"].as_array().unwrap();
    for item in items {
        assert_eq!(item["asset_kind"], "x509_cert");
        assert_eq!(item["source_module"], "ree0xq-cert");
        let prims = item["primitives"].as_array().unwrap();
        // Every fixture cert is ECDSA-P256 + SHA-256 — sig +
        // hash primitive should be present.
        let names: Vec<&str> = prims.iter().map(|p| p.as_str().unwrap()).collect();
        assert!(
            names.iter().any(|n| *n == "ECDSA"),
            "missing ECDSA in {names:?}"
        );
        assert!(
            names.iter().any(|n| *n == "SHA-256"),
            "missing SHA-256 in {names:?}"
        );
    }

    // /v1/posture should now report 3 assets.
    let posture: serde_json::Value = client
        .get(format!("http://{addr}/v1/posture"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(posture["assets"], 3);
    assert!(posture["org_q"].as_f64().unwrap() > 0.0);
}
