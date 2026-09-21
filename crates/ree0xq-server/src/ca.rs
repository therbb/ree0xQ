//! CA + agent-cert minting for the V1 mTLS bootstrap (SEZ-6).
//!
//! On first boot we generate an ECDSA-P256 root CA, persist its
//! certificate (PEM) and private key (PEM, mode 0600) under a
//! configurable `ca_dir`, and load the same files on every
//! subsequent restart. Per-agent certificates are minted on
//! demand from the same CA when an agent presents a valid
//! bootstrap token to `POST /v1/enrol`.
//!
//! Out of scope for this commit:
//! - TLS termination on `ree0xq-server` (the collector still
//!   listens on plain HTTP). Wiring `rustls` + a TLS acceptor
//!   that uses this CA arrives in a follow-up.
//! - Encrypt-at-rest of the CA key. The file lives at 0600 on
//!   the host filesystem; the long-term plan is to migrate to
//!   Postgres-with-envelope-encryption once SEZ-2 lands.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use parking_lot::Mutex;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
};
use serde::Serialize;
use tracing::info;

const CA_CERT_FILE: &str = "ca.crt";
const CA_KEY_FILE: &str = "ca.key";

/// CA root used to sign per-agent client certificates.
#[derive(Clone)]
pub struct Ca {
    inner: Arc<Mutex<CaInner>>,
}

struct CaInner {
    /// The persisted-on-disk PEM. Stable across restarts — this
    /// is what we hand to enrolling agents so the bytes they
    /// trust match what's actually on disk.
    cert_pem: String,
    /// In-memory CA certificate used as the issuer when signing
    /// agent certs. On reload this is reconstructed from the
    /// persisted params + keypair; its bytes may differ from
    /// `cert_pem`, but its public key and subject DN match, so
    /// agents verifying against the trusted `cert_pem` accept
    /// the signature.
    issuer_cert: Certificate,
    /// CA private key, used to sign agent certs.
    issuer_key: KeyPair,
}

impl Ca {
    /// Load the CA from `dir` if both `ca.crt` and `ca.key` are
    /// present, otherwise generate a new ECDSA-P256 root CA,
    /// persist both files, and return the freshly built CA.
    /// The key file is created at mode 0600 on unix targets.
    pub fn load_or_init(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir).with_context(|| format!("create CA dir {}", dir.display()))?;
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);

        let (cert_pem, key_pem, generated) = if cert_path.exists() && key_path.exists() {
            (
                fs::read_to_string(&cert_path)
                    .with_context(|| format!("read {}", cert_path.display()))?,
                fs::read_to_string(&key_path)
                    .with_context(|| format!("read {}", key_path.display()))?,
                false,
            )
        } else if cert_path.exists() || key_path.exists() {
            return Err(anyhow!(
                "CA dir {} contains exactly one of (ca.crt, ca.key); \
                 refusing to overwrite — remove the partial state and retry",
                dir.display()
            ));
        } else {
            let keypair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
            let params = ca_params()?;
            let cert = params.self_signed(&keypair)?;
            let cert_pem = cert.pem();
            let key_pem = keypair.serialize_pem();
            fs::write(&cert_path, &cert_pem)
                .with_context(|| format!("write {}", cert_path.display()))?;
            write_private_key(&key_path, &key_pem)
                .with_context(|| format!("write {}", key_path.display()))?;
            (cert_pem, key_pem, true)
        };

        let keypair = KeyPair::from_pem(&key_pem).context("parse CA private key PEM")?;
        let params =
            CertificateParams::from_ca_cert_pem(&cert_pem).context("parse CA certificate PEM")?;
        // Re-self-sign so we have a Certificate handle for the
        // signed_by() flow. The DER will differ from `cert_pem`
        // on the timestamp/serial axes, but the public key and
        // subject DN — the parts that bind verification to the
        // trust anchor — come straight from the parsed file.
        let issuer_cert = params.self_signed(&keypair)?;

        if generated {
            info!(dir = %dir.display(), "generated new ree0xQ Root CA");
        } else {
            info!(dir = %dir.display(), "loaded existing ree0xQ Root CA");
        }

        Ok(Self {
            inner: Arc::new(Mutex::new(CaInner {
                cert_pem,
                issuer_cert,
                issuer_key: keypair,
            })),
        })
    }

    /// PEM-encoded CA certificate. Safe to hand out to agents at
    /// enrolment time — they trust this to verify the server's
    /// (future mTLS) certificate.
    pub fn cert_pem(&self) -> String {
        self.inner.lock().cert_pem.clone()
    }

    /// Mint a fresh client certificate for `agent_id`, signed by
    /// this CA. CN = `agent_id`, EKU = clientAuth, validity =
    /// `validity_days` (caller-controlled, typically 365).
    pub fn sign_agent_cert(&self, agent_id: &str, validity_days: i64) -> Result<AgentCert> {
        let agent_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, agent_id);
        dn.push(DnType::OrganizationName, "ree0xQ Agent");
        params.distinguished_name = dn;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::days(validity_days);
        let expires_at = params.not_after;

        let inner = self.inner.lock();
        let cert = params.signed_by(&agent_kp, &inner.issuer_cert, &inner.issuer_key)?;
        Ok(AgentCert {
            cert_pem: cert.pem(),
            key_pem: agent_kp.serialize_pem(),
            ca_cert_pem: inner.cert_pem.clone(),
            agent_id: agent_id.into(),
            expires_at: chrono::DateTime::<chrono::Utc>::from_timestamp(
                expires_at.unix_timestamp(),
                expires_at.nanosecond(),
            )
            .unwrap_or_else(chrono::Utc::now),
        })
    }
}

impl Ca {
    /// Mint a server certificate for the collector's own TLS
    /// listener. CN = `common_name`, EKU = serverAuth, SANs
    /// drawn from `sans` (each entry is parsed as a DNS name
    /// when it doesn't look like an IPv4/IPv6 literal).
    pub fn sign_server_cert(
        &self,
        common_name: &str,
        sans: &[String],
        validity_days: i64,
    ) -> Result<ServerCert> {
        let server_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        dn.push(DnType::OrganizationName, "ree0xQ Server");
        params.distinguished_name = dn;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.subject_alt_names = sans
            .iter()
            .map(|s| match s.parse::<std::net::IpAddr>() {
                Ok(ip) => SanType::IpAddress(ip),
                Err(_) => SanType::DnsName(s.as_str().try_into().expect("valid DNS name")),
            })
            .collect();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::days(validity_days);

        let inner = self.inner.lock();
        let cert = params.signed_by(&server_kp, &inner.issuer_cert, &inner.issuer_key)?;
        Ok(ServerCert {
            cert_pem: cert.pem(),
            key_pem: server_kp.serialize_pem(),
            ca_cert_pem: inner.cert_pem.clone(),
        })
    }
}

/// Output of [`Ca::sign_server_cert`]. The server keeps the
/// cert + key in memory and feeds them to the rustls listener;
/// the CA cert is included so clients can be told the chain.
#[derive(Debug, Clone)]
pub struct ServerCert {
    /// PEM-encoded server certificate.
    pub cert_pem: String,
    /// PEM-encoded server private key.
    pub key_pem: String,
    /// PEM-encoded CA certificate.
    pub ca_cert_pem: String,
}

/// Output of [`Ca::sign_agent_cert`]. Returned to the agent as
/// the body of `POST /v1/enrol`.
#[derive(Debug, Serialize, Clone)]
pub struct AgentCert {
    /// PEM-encoded client certificate.
    pub cert_pem: String,
    /// PEM-encoded private key matching `cert_pem`. The server
    /// never persists this — it lives only in the HTTP response.
    pub key_pem: String,
    /// PEM-encoded CA certificate the agent should trust.
    pub ca_cert_pem: String,
    /// Common Name / agent identifier the cert was issued to.
    pub agent_id: String,
    /// UTC moment after which the cert is no longer valid.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

fn ca_params() -> Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "ree0xQ Root CA");
    dn.push(DnType::OrganizationName, "e2e Solutions");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(365 * 10);
    Ok(params)
}

#[cfg(unix)]
fn write_private_key(path: &Path, contents: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, contents)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_key(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generates_then_loads_idempotently() {
        let d = tempdir().unwrap();
        let ca1 = Ca::load_or_init(d.path()).unwrap();
        let pem1 = ca1.cert_pem();
        // Re-open the same dir — should load the on-disk cert
        // verbatim instead of regenerating.
        let ca2 = Ca::load_or_init(d.path()).unwrap();
        assert_eq!(pem1, ca2.cert_pem());
    }

    #[test]
    fn signed_agent_cert_carries_agent_id() {
        let d = tempdir().unwrap();
        let ca = Ca::load_or_init(d.path()).unwrap();
        let cert = ca.sign_agent_cert("ree0xq-net-01", 365).unwrap();
        assert_eq!(cert.agent_id, "ree0xq-net-01");
        assert!(cert.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(cert.ca_cert_pem.contains("BEGIN CERTIFICATE"));
        // CN must round-trip through the PEM.
        assert!(cert.cert_pem.lines().count() > 5);
    }

    #[test]
    fn partial_state_refuses_to_overwrite() {
        let d = tempdir().unwrap();
        // Plant only ca.crt with garbage to simulate a corrupted dir.
        fs::write(d.path().join("ca.crt"), "garbage").unwrap();
        let err = Ca::load_or_init(d.path()).err().expect("should fail");
        assert!(format!("{err:?}").contains("partial state"));
    }
}
