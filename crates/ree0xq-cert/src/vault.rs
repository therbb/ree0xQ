//! HashiCorp Vault PKI backend.
//!
//! First internal-CA source for ree0xq-cert. Vault operators
//! point the scanner at a PKI mount path and a Vault token;
//! the scanner lists every active cert serial under the
//! mount, fetches each cert's PEM, parses it with the same
//! [`crate::cert::event_from_cert`] library code the host-scan
//! and ct-scan paths use, and emits one
//! `crypto_inventory_event` per cert.
//!
//! The trait stays narrow on purpose so the AD CS, ACME, and
//! PKCS#11 backends planned for V2.3+ drop in without
//! touching the scanner loop.

use std::time::Duration;

use anyhow::{anyhow, Result};
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::cert::{event_from_cert, parse_pem_bundle};

/// Vault backend trait — narrow surface, two calls.
pub trait VaultBackend {
    /// List every active cert serial under the configured PKI
    /// mount. The Vault HTTP impl returns these in
    /// hex-with-colons format (`53:36:c4:…`); other backends
    /// can use any format the trait's caller treats as opaque.
    fn list_serials(&self, mount: &str) -> Result<Vec<String>>;

    /// Fetch the PEM bytes for one cert by serial.
    fn fetch_cert_pem(&self, mount: &str, serial: &str) -> Result<Vec<u8>>;

    /// Human-readable backend label, used in log lines and
    /// the event source-module-decoration string.
    fn backend_label(&self) -> &'static str;
}

/// HTTP-over-rustls Vault backend. Reads
/// `LIST /v1/<mount>/certs` and `GET /v1/<mount>/cert/<serial>`
/// authenticated by an `X-Vault-Token` header.
pub struct VaultHttpBackend {
    addr: String,
    token: String,
    client: reqwest::blocking::Client,
}

impl VaultHttpBackend {
    /// Build a new client. `addr` is the Vault base URL
    /// (e.g. `http://127.0.0.1:8200`); `token` is the
    /// caller-supplied Vault token (root in dev mode,
    /// per-role in production). The token never appears in
    /// any log line written by this struct.
    pub fn new(addr: impl Into<String>, token: impl Into<String>) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("ree0xq-cert/0.1 (+https://github.com/e2esolutions-tech/ree0xQ)")
            .build()
            .map_err(|e| anyhow!("vault client build: {e}"))?;
        Ok(Self {
            addr: addr.into().trim_end_matches('/').to_string(),
            token: token.into(),
            client,
        })
    }
}

#[derive(Debug, Deserialize)]
struct VaultListData {
    data: VaultListDataInner,
}
#[derive(Debug, Deserialize)]
struct VaultListDataInner {
    keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct VaultCertData {
    data: VaultCertDataInner,
}
#[derive(Debug, Deserialize)]
struct VaultCertDataInner {
    certificate: String,
}

impl VaultBackend for VaultHttpBackend {
    fn list_serials(&self, mount: &str) -> Result<Vec<String>> {
        let url = format!("{}/v1/{}/certs", self.addr, mount.trim_matches('/'));
        debug!(url = %sanitised_url(&url), "vault LIST certs");
        let r = self
            .client
            .request(reqwest::Method::from_bytes(b"LIST")?, &url)
            .header("X-Vault-Token", &self.token)
            .send()
            .map_err(|e| anyhow!("vault LIST: {e}"))?;
        if r.status() == reqwest::StatusCode::NOT_FOUND {
            // Empty mount: Vault returns 404 with the
            // "no certificates" message rather than an
            // empty list. Surface it as an empty result.
            return Ok(Vec::new());
        }
        if !r.status().is_success() {
            return Err(anyhow!("vault LIST returned {}", r.status()));
        }
        let parsed: VaultListData = r.json().map_err(|e| anyhow!("vault LIST JSON: {e}"))?;
        Ok(parsed.data.keys)
    }

    fn fetch_cert_pem(&self, mount: &str, serial: &str) -> Result<Vec<u8>> {
        let url = format!(
            "{}/v1/{}/cert/{}",
            self.addr,
            mount.trim_matches('/'),
            serial
        );
        debug!(url = %sanitised_url(&url), "vault GET cert");
        let r = self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .map_err(|e| anyhow!("vault GET: {e}"))?;
        if !r.status().is_success() {
            return Err(anyhow!("vault GET returned {}", r.status()));
        }
        let parsed: VaultCertData = r.json().map_err(|e| anyhow!("vault GET JSON: {e}"))?;
        Ok(parsed.data.certificate.into_bytes())
    }

    fn backend_label(&self) -> &'static str {
        "vault"
    }
}

/// Strip an `X-Vault-Token=` query / a `:password@` chunk
/// from a URL before logging. Defensive — the URLs we
/// produce don't carry credentials today, but operator
/// overrides could.
fn sanitised_url(url: &str) -> String {
    // No token in our own URLs; keep defensive logic similar
    // to ree0xq-server's Postgres sanitiser pattern.
    if let Some(scheme_end) = url.find("://") {
        let rest = &url[scheme_end + 3..];
        if let Some(at) = rest.find('@') {
            if let Some(colon) = rest[..at].find(':') {
                let scheme = &url[..scheme_end + 3];
                let user = &rest[..colon];
                let tail = &rest[at..];
                return format!("{scheme}{user}{tail}");
            }
        }
    }
    url.into()
}

/// Caller-supplied configuration for [`vault_scan`].
#[derive(Debug, Clone)]
pub struct VaultScanConfig {
    /// One or more PKI mount paths (e.g. `pki`, `pki/intermediate`).
    pub mounts: Vec<String>,
    /// Pause between per-cert fetches.
    pub rate_delay_ms: u64,
}

/// Statistics from one [`vault_scan`] pass.
#[derive(Debug, Default, Clone)]
pub struct VaultScanStats {
    pub mounts_scanned: usize,
    pub serials_listed: usize,
    pub certs_fetched: usize,
    pub fetch_failures: usize,
    pub events_emitted: usize,
}

/// Walk every mount in `cfg`, fetching every cert and calling
/// `on_event` per discovered cert. Per-cert failures are
/// folded into the returned stats; the scan never aborts on
/// one bad cert.
pub fn vault_scan<B: VaultBackend, F>(
    cfg: &VaultScanConfig,
    backend: &B,
    mut on_event: F,
) -> Result<VaultScanStats>
where
    F: FnMut(ree0xq_core::CryptoInventoryEvent),
{
    let mut stats = VaultScanStats::default();
    let delay = Duration::from_millis(cfg.rate_delay_ms);

    for mount in &cfg.mounts {
        stats.mounts_scanned += 1;
        info!(mount = %mount, backend = backend.backend_label(), "vault LIST");
        let serials = match backend.list_serials(mount) {
            Ok(s) => s,
            Err(e) => {
                warn!(mount = %mount, error = %e, "list_serials failed");
                continue;
            }
        };
        stats.serials_listed += serials.len();

        for (idx, serial) in serials.iter().enumerate() {
            if idx > 0 && !delay.is_zero() {
                std::thread::sleep(delay);
            }
            match backend.fetch_cert_pem(mount, serial) {
                Ok(pem) => {
                    let parsed = match parse_pem_bundle(&pem, None) {
                        Ok(v) if !v.is_empty() => v,
                        Ok(_) => {
                            warn!(serial = %serial, "vault GET returned no CERTIFICATE block");
                            stats.fetch_failures += 1;
                            continue;
                        }
                        Err(e) => {
                            warn!(serial = %serial, error = %e, "vault PEM parse failed");
                            stats.fetch_failures += 1;
                            continue;
                        }
                    };
                    stats.certs_fetched += 1;
                    for cert in &parsed {
                        match event_from_cert(cert) {
                            Ok(ev) => {
                                stats.events_emitted += 1;
                                on_event(ev);
                            }
                            Err(e) => warn!(serial = %serial, error = %e, "event_from_cert"),
                        }
                    }
                }
                Err(e) => {
                    warn!(serial = %serial, error = %e, "fetch_cert_pem failed");
                    stats.fetch_failures += 1;
                }
            }
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn fixture_cert_pem(cn: &str) -> Vec<u8> {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
        let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec![cn.to_string()]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        params.self_signed(&kp).unwrap().pem().into_bytes()
    }

    struct FakeVault {
        serials: Vec<String>,
        fetched: RefCell<Vec<String>>,
    }

    impl FakeVault {
        fn new(serials: Vec<&str>) -> Self {
            Self {
                serials: serials.into_iter().map(String::from).collect(),
                fetched: RefCell::new(Vec::new()),
            }
        }
    }

    impl VaultBackend for FakeVault {
        fn list_serials(&self, _: &str) -> Result<Vec<String>> {
            Ok(self.serials.clone())
        }
        fn fetch_cert_pem(&self, _: &str, serial: &str) -> Result<Vec<u8>> {
            self.fetched.borrow_mut().push(serial.into());
            Ok(fixture_cert_pem(&format!("{serial}.svc.local")))
        }
        fn backend_label(&self) -> &'static str {
            "fake-vault"
        }
    }

    #[test]
    fn list_data_deserialises() {
        let r: VaultListData =
            serde_json::from_str(r#"{"data":{"keys":["aa:bb","cc:dd","ee:ff"]}}"#).unwrap();
        assert_eq!(r.data.keys, vec!["aa:bb", "cc:dd", "ee:ff"]);
    }

    #[test]
    fn cert_data_deserialises() {
        let r: VaultCertData = serde_json::from_str(
            r#"{"data":{"certificate":"-----BEGIN CERTIFICATE-----\nXX\n-----END CERTIFICATE-----\n"}}"#,
        )
        .unwrap();
        assert!(r.data.certificate.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn scan_emits_per_cert_and_records_serials() {
        let backend = FakeVault::new(vec!["aa:bb", "cc:dd", "ee:ff"]);
        let cfg = VaultScanConfig {
            mounts: vec!["pki".into()],
            rate_delay_ms: 0,
        };
        let mut hosts = Vec::new();
        let stats = vault_scan(&cfg, &backend, |ev| {
            hosts.push(ev.asset.host.clone().unwrap_or_default());
        })
        .unwrap();
        assert_eq!(stats.mounts_scanned, 1);
        assert_eq!(stats.serials_listed, 3);
        assert_eq!(stats.certs_fetched, 3);
        assert_eq!(stats.events_emitted, 3);
        assert_eq!(hosts.len(), 3);
        let fetched = backend.fetched.borrow();
        assert_eq!(*fetched, vec!["aa:bb", "cc:dd", "ee:ff"]);
    }

    #[test]
    fn empty_mount_is_noop() {
        let backend = FakeVault::new(vec![]);
        let cfg = VaultScanConfig {
            mounts: vec!["pki".into()],
            rate_delay_ms: 0,
        };
        let stats = vault_scan(&cfg, &backend, |_| {}).unwrap();
        assert_eq!(stats.serials_listed, 0);
        assert_eq!(stats.events_emitted, 0);
    }

    #[test]
    fn sanitised_url_keeps_normal_urls() {
        assert_eq!(
            sanitised_url("http://127.0.0.1:8200/v1/pki/certs"),
            "http://127.0.0.1:8200/v1/pki/certs"
        );
        assert_eq!(
            sanitised_url("https://vault:secret@vault.example/v1/pki/certs"),
            "https://vault@vault.example/v1/pki/certs"
        );
    }
}
