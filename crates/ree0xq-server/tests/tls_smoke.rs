//! End-to-end smoke for the SEZ-6 TLS termination + mTLS path.
//!
//! Boots both listeners in-process on ephemeral ports:
//!
//! - bootstrap port: TLS with server cert only (no client
//!   cert required) — agents reach `/v1/admin/bootstrap-tokens`
//!   and `/v1/enrol` here;
//! - main port: mTLS — TLS handshake requires a client cert
//!   signed by the internal CA; hosts `/v1/events` and the
//!   other inventory routes.
//!
//! Exercises:
//!
//! - reaching the bootstrap port with the CA cert pinned and
//!   no client cert,
//! - reaching the mTLS port *without* a client cert fails the
//!   TLS handshake (proves the verifier is wired),
//! - issuing a bootstrap token over the bootstrap port,
//!   redeeming it for an agent cert, then using that cert to
//!   POST an event over the mTLS port,
//! - reading the posted event back through `/v1/events` over
//!   the same mTLS connection — proves the full bootstrap →
//!   enrol → authenticated-POST chain works end-to-end.

use std::net::SocketAddr;
use std::time::Duration;

use ree0xq_server::{ca::Ca, router_bootstrap, router_main, tls, AppState};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

const ADMIN_SECRET: &str = "test-admin-secret-tls";

struct TestServer {
    mtls_addr: SocketAddr,
    bootstrap_addr: SocketAddr,
    ca_cert_pem: String,
}

async fn spawn_tls_server() -> TestServer {
    // One default crypto provider per process. Idempotent.
    tls::install_default_crypto_provider();

    let tmp = tempfile::tempdir().expect("tempdir");
    let ca = Ca::load_or_init(tmp.path()).expect("ca init");
    let ca_cert_pem = ca.cert_pem();

    let state =
        AppState::new_in_memory(tmp.path(), Some(ADMIN_SECRET.into())).expect("AppState init");
    std::mem::forget(tmp);

    let server_cert = state
        .ca
        .sign_server_cert("localhost", &["127.0.0.1".into(), "localhost".into()], 30)
        .expect("server cert");

    let mtls_cfg = tls::build_mtls_config(
        &server_cert.cert_pem,
        &server_cert.key_pem,
        &server_cert.ca_cert_pem,
    )
    .expect("mtls config");
    let boot_cfg = tls::build_bootstrap_config(&server_cert.cert_pem, &server_cert.key_pem)
        .expect("bootstrap config");

    let mtls_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let bootstrap_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // axum_server::bind_rustls binds + announces the addr via
    // a Handle; we use that to discover the ephemeral port.
    let mtls_handle = axum_server::Handle::new();
    let bootstrap_handle = axum_server::Handle::new();

    let mtls_handle_clone = mtls_handle.clone();
    let main_app = router_main(state.clone());
    tokio::spawn(async move {
        axum_server::bind_rustls(
            mtls_addr,
            axum_server::tls_rustls::RustlsConfig::from_config(mtls_cfg),
        )
        .handle(mtls_handle_clone)
        .serve(main_app.into_make_service())
        .await
        .unwrap();
    });

    let bootstrap_handle_clone = bootstrap_handle.clone();
    let boot_app = router_bootstrap(state);
    tokio::spawn(async move {
        axum_server::bind_rustls(
            bootstrap_addr,
            axum_server::tls_rustls::RustlsConfig::from_config(boot_cfg),
        )
        .handle(bootstrap_handle_clone)
        .serve(boot_app.into_make_service())
        .await
        .unwrap();
    });

    // Wait until both listeners have published their actual
    // bound addresses (axum-server reports after bind).
    let mtls_addr = await_listening(&mtls_handle).await;
    let bootstrap_addr = await_listening(&bootstrap_handle).await;

    TestServer {
        mtls_addr,
        bootstrap_addr,
        ca_cert_pem,
    }
}

async fn await_listening(handle: &axum_server::Handle) -> SocketAddr {
    // axum-server's Handle::listening returns a future that
    // resolves once the bind is live. We bound to :0 so we have
    // to ask for the actual address back.
    for _ in 0..50 {
        if let Some(addr) = handle.listening().await {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server failed to start within 1s");
}

fn ca_only_client(ca_pem: &str) -> reqwest::Client {
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap()
    {
        root_store.add(cert).unwrap();
    }
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(cfg)
        .build()
        .unwrap()
}

fn mtls_client(ca_pem: &str, agent_cert_pem: &str, agent_key_pem: &str) -> reqwest::Client {
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap()
    {
        root_store.add(cert).unwrap();
    }
    let agent_chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut agent_cert_pem.as_bytes())
            .collect::<std::result::Result<_, _>>()
            .unwrap();
    let agent_key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut agent_key_pem.as_bytes())
            .unwrap()
            .expect("agent key");
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(agent_chain, agent_key)
        .unwrap();
    reqwest::Client::builder()
        .use_preconfigured_tls(cfg)
        .build()
        .unwrap()
}

#[tokio::test]
async fn full_mtls_bootstrap_to_event() {
    let s = spawn_tls_server().await;
    let bootstrap_base = format!("https://{}", s.bootstrap_addr);
    let mtls_base = format!("https://{}", s.mtls_addr);

    // /healthz over the bootstrap port works with CA-only trust.
    let client = ca_only_client(&s.ca_cert_pem);
    let r = client
        .get(format!("{bootstrap_base}/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "ok");

    // Issue a bootstrap token (admin path on the bootstrap port).
    let r = client
        .post(format!("{bootstrap_base}/v1/admin/bootstrap-tokens"))
        .header(ree0xq_server::enrol::ADMIN_HEADER, ADMIN_SECRET)
        .json(&serde_json::json!({ "agent_id": "tls-agent-01" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "issue should succeed over TLS");
    let issued: serde_json::Value = r.json().await.unwrap();
    let token = issued["token"].as_str().unwrap().to_string();

    // Enrol over the bootstrap port (no client cert presented).
    let r = client
        .post(format!("{bootstrap_base}/v1/enrol"))
        .header(ree0xq_server::enrol::BOOTSTRAP_HEADER, &token)
        .json(&serde_json::json!({ "agent_id": "tls-agent-01" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "enrol over bootstrap TLS should succeed");
    let cert: serde_json::Value = r.json().await.unwrap();
    let agent_cert_pem = cert["cert_pem"].as_str().unwrap().to_string();
    let agent_key_pem = cert["key_pem"].as_str().unwrap().to_string();

    // mTLS port without a client cert: handshake fails. We use
    // the CA-only client (no cert) and expect a connection error,
    // not a 401 — the rejection happens at the TLS layer.
    let r = client
        .post(format!("{mtls_base}/v1/events"))
        .json(&serde_json::json!({
            "schema_version": 1, "schema_minor": 1,
            "source_module": "tls-smoke",
            "observed_at": "2026-05-20T12:00:00Z",
            "asset": {"kind": "tls_session", "identity": "smoke-1"},
            "primitives": [{"role":"kex","algorithm":"X25519MLKEM768","pq_resistant":true}],
            "posture": {"score": 0, "rationale":"smoke"}
        }))
        .send()
        .await;
    assert!(
        r.is_err(),
        "mTLS port should refuse a client without a cert at the TLS layer, got {:?}",
        r.map(|r| r.status())
    );

    // mTLS port with the enrolled cert: POST + GET work end-to-end.
    let agent = mtls_client(&s.ca_cert_pem, &agent_cert_pem, &agent_key_pem);
    let r = agent
        .post(format!("{mtls_base}/v1/events"))
        .json(&serde_json::json!({
            "schema_version": 1, "schema_minor": 1,
            "source_module": "tls-smoke",
            "observed_at": "2026-05-20T12:00:00Z",
            "asset": {"kind": "tls_session", "identity": "smoke-1", "host": "client.example"},
            "primitives": [{"role":"kex","algorithm":"X25519MLKEM768","pq_resistant":true}],
            "posture": {"score": 0, "rationale":"smoke"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 202, "mTLS POST should succeed");

    let body: serde_json::Value = agent
        .get(format!("{mtls_base}/v1/events"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["count"], 1, "the event should be readable back");
    assert_eq!(body["events"][0]["asset"]["identity"], "smoke-1");
}
