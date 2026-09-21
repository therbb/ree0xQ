//! Rustls server configurations for the V1 TLS path (SEZ-6).
//!
//! Two listener modes share the same on-disk CA:
//!
//! - **Bootstrap listener.** TLS with the server's own cert,
//!   no client-cert verifier. Hosts `/healthz`, `/v1/enrol`,
//!   and `/v1/admin/bootstrap-tokens` so un-enrolled agents can
//!   still reach enrolment over an encrypted channel.
//!
//! - **mTLS main listener.** TLS with a client-cert verifier
//!   that trusts only certs signed by the internal CA. Hosts
//!   `/v1/events`, `/v1/inventory`, `/v1/posture`, `/v1/blocked`,
//!   `/v1/qkd/links`. A successful TLS handshake is the
//!   authentication check — by the time a request reaches the
//!   handler, the peer has already proved possession of a
//!   CA-signed client cert.
//!
//! Splitting the routes across two listeners means we never
//! need to thread peer-cert info through `axum` request
//! extensions: routing layer does the job.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

/// Build a rustls server config for the bootstrap listener: TLS
/// with a CA-signed server cert and **no** client-cert
/// verification. Reachable by any TLS client that trusts the CA.
pub fn build_bootstrap_config(
    server_cert_pem: &str,
    server_key_pem: &str,
) -> Result<Arc<ServerConfig>> {
    let (chain, key) = load_pem(server_cert_pem, server_key_pem)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("rustls bootstrap with_single_cert")?;
    Ok(Arc::new(config))
}

/// Build a rustls server config for the mTLS main listener:
/// TLS with a CA-signed server cert *and* a client-cert
/// verifier that requires the client to present a cert chain
/// rooted at the internal CA. Handshakes without a valid
/// client cert are rejected at the TLS layer — the handler
/// never sees the request.
pub fn build_mtls_config(
    server_cert_pem: &str,
    server_key_pem: &str,
    ca_cert_pem: &str,
) -> Result<Arc<ServerConfig>> {
    let (chain, key) = load_pem(server_cert_pem, server_key_pem)?;

    let mut roots = RootCertStore::empty();
    let mut ca_reader = ca_cert_pem.as_bytes();
    let mut added = 0usize;
    for cert in rustls_pemfile::certs(&mut ca_reader) {
        let cert = cert.context("parse CA PEM")?;
        roots.add(cert).context("add CA to root store")?;
        added += 1;
    }
    if added == 0 {
        return Err(anyhow!("no CA certs found in ca_cert_pem"));
    }

    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("WebPkiClientVerifier build")?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .context("rustls mtls with_single_cert")?;
    Ok(Arc::new(config))
}

fn load_pem(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut chain_reader = cert_pem.as_bytes();
    let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut chain_reader)
        .collect::<std::result::Result<_, _>>()
        .context("parse server cert PEM")?;
    if chain.is_empty() {
        return Err(anyhow!("server cert PEM contained no certificates"));
    }

    let mut key_reader = key_pem.as_bytes();
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("parse server key PEM")?
        .ok_or_else(|| anyhow!("server key PEM contained no private key"))?;
    Ok((chain, key))
}

/// Install the `ring` crypto provider as the process default.
/// Must be called once before any rustls config is built.
pub fn install_default_crypto_provider() {
    // Idempotent: ignore the Err returned when a provider is
    // already installed (e.g. from a previous test in the same
    // process).
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::Ca;
    use tempfile::tempdir;

    #[test]
    fn bootstrap_config_round_trips() {
        install_default_crypto_provider();
        let d = tempdir().unwrap();
        let ca = Ca::load_or_init(d.path()).unwrap();
        let s = ca
            .sign_server_cert(
                "ree0xq.local",
                &["127.0.0.1".into(), "localhost".into()],
                30,
            )
            .unwrap();
        let _cfg = build_bootstrap_config(&s.cert_pem, &s.key_pem).unwrap();
    }

    #[test]
    fn mtls_config_requires_ca() {
        install_default_crypto_provider();
        let d = tempdir().unwrap();
        let ca = Ca::load_or_init(d.path()).unwrap();
        let s = ca
            .sign_server_cert("ree0xq.local", &["127.0.0.1".into()], 30)
            .unwrap();
        // Building succeeds when the CA cert is valid PEM.
        let _cfg = build_mtls_config(&s.cert_pem, &s.key_pem, &s.ca_cert_pem).unwrap();
        // And fails when the CA PEM is empty / not a cert.
        assert!(build_mtls_config(&s.cert_pem, &s.key_pem, "not a cert").is_err());
    }
}
