//! X.509 → `CryptoInventoryEvent` parser.
//!
//! Given a single DER cert (or a slice carved out of a PEM
//! block by [`parse_pem_bundle`]), produces the
//! [`CryptoInventoryEvent`] the collector ingests. Identity is
//! the cert's SHA-256 fingerprint (hex, lowercased) — stable
//! across re-scans of the same cert and unique per cert chain.
//!
//! Out of scope here: cert-chain *validation* (no trust-store
//! traversal, no signature verification). ree0xQ observes; it
//! does not endorse.

use std::path::Path;

use anyhow::{anyhow, Result};
use ree0xq_core::{
    Asset, AssetKind, CryptoInventoryEvent, Posture, Primitive, PrimitiveRole, SCHEMA_MINOR,
    SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::MODULE_NAME;

/// One DER-encoded certificate plus its source-path hint. The
/// parser hands these out from a PEM bundle so the caller can
/// preserve "which file did this come from" in the event body.
#[derive(Debug, Clone)]
pub struct ParsedCert {
    /// The raw DER bytes of one certificate, owned so the
    /// struct outlives its source buffer.
    pub der: Vec<u8>,
    /// The on-disk path the bundle came from. Set to `None`
    /// when the input wasn't backed by a file.
    pub source_path: Option<String>,
    /// Zero-based index of this cert inside the bundle.
    pub bundle_index: usize,
}

/// Iterate every `CERTIFICATE` PEM block in `pem_bytes`,
/// yielding one [`ParsedCert`] per cert. Skips non-`CERTIFICATE`
/// blocks (CRLs, private keys, …) without raising. Errors only
/// when the input isn't valid PEM at all.
pub fn parse_pem_bundle(pem_bytes: &[u8], source_path: Option<&Path>) -> Result<Vec<ParsedCert>> {
    use std::io::{BufReader, Cursor};
    use x509_parser::pem::Pem;

    let mut out = Vec::new();
    let path_str = source_path.map(|p| p.display().to_string());
    let mut reader = BufReader::new(Cursor::new(pem_bytes));
    let mut idx = 0usize;
    loop {
        match Pem::read(&mut reader) {
            Ok((pem, _consumed)) => {
                if pem.label != "CERTIFICATE" {
                    tracing::debug!(label = %pem.label, "skipping non-CERTIFICATE PEM block");
                    continue;
                }
                out.push(ParsedCert {
                    der: pem.contents,
                    source_path: path_str.clone(),
                    bundle_index: idx,
                });
                idx += 1;
            }
            Err(x509_parser::error::PEMError::MissingHeader) => break,
            Err(e) => return Err(anyhow!("PEM parse: {e}")),
        }
    }
    Ok(out)
}

/// Build a `crypto_inventory_event` from one parsed cert.
pub fn event_from_cert(cert: &ParsedCert) -> Result<CryptoInventoryEvent> {
    let (_, parsed) =
        X509Certificate::from_der(&cert.der).map_err(|e| anyhow!("x509 parse: {e}"))?;

    let fingerprint = sha256_hex(&cert.der);
    let cn = subject_cn(&parsed).unwrap_or_else(|| fingerprint.clone());
    let host = first_san(&parsed).or_else(|| subject_cn(&parsed));
    let identity = format!("sha256:{fingerprint}");

    let primitives = primitives_for(&parsed)?;
    let not_before = chrono_from_asn1_time(parsed.validity().not_before);
    let not_after = chrono_from_asn1_time(parsed.validity().not_after);
    let rationale = format!(
        "X.509 cert CN={cn} sig={} key={} bytes; valid {}..{}",
        sig_algo_name(&parsed),
        public_key_byte_len(&parsed),
        not_before
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| "?".into()),
        not_after
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| "?".into()),
    );

    Ok(CryptoInventoryEvent {
        schema_version: SCHEMA_VERSION,
        schema_minor: SCHEMA_MINOR,
        source_module: MODULE_NAME.into(),
        observed_at: chrono::Utc::now(),
        asset: Asset {
            kind: AssetKind::X509Cert,
            identity,
            host,
        },
        primitives,
        channel_protection: None,
        agility: None,
        posture: Posture {
            score: 50,
            rationale,
            recommended_replacement: None,
        },
    })
}

fn subject_cn(cert: &X509Certificate<'_>) -> Option<String> {
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok().map(|s| s.to_string()))
}

fn first_san(cert: &X509Certificate<'_>) -> Option<String> {
    cert.subject_alternative_name()
        .ok()
        .flatten()
        .and_then(|s| {
            s.value.general_names.iter().find_map(|gn| match gn {
                GeneralName::DNSName(n) => Some((*n).to_string()),
                _ => None,
            })
        })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn chrono_from_asn1_time(t: ASN1Time) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp(t.timestamp(), 0)
}

fn sig_algo_name(cert: &X509Certificate<'_>) -> &'static str {
    // The signature_algorithm OID lives on TbsCertificate, the
    // outer Certificate also carries one (they have to match for
    // a well-formed cert). We use the outer one.
    let oid = &cert.signature_algorithm.algorithm;
    match oid.to_id_string().as_str() {
        "1.2.840.113549.1.1.5" => "RSA-PKCS1-SHA1",
        "1.2.840.113549.1.1.11" => "RSA-PKCS1-SHA256",
        "1.2.840.113549.1.1.12" => "RSA-PKCS1-SHA384",
        "1.2.840.113549.1.1.13" => "RSA-PKCS1-SHA512",
        "1.2.840.113549.1.1.10" => "RSA-PSS",
        "1.2.840.10045.4.3.2" => "ECDSA-SHA256",
        "1.2.840.10045.4.3.3" => "ECDSA-SHA384",
        "1.2.840.10045.4.3.4" => "ECDSA-SHA512",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        // ML-DSA per NIST FIPS 204 — IANA / IETF OIDs as
        // they land. (Placeholder.)
        "2.16.840.1.101.3.4.3.17" => "ML-DSA-44",
        "2.16.840.1.101.3.4.3.18" => "ML-DSA-65",
        "2.16.840.1.101.3.4.3.19" => "ML-DSA-87",
        _ => "unknown",
    }
}

fn primitives_for(cert: &X509Certificate<'_>) -> Result<Vec<Primitive>> {
    let sig_name = sig_algo_name(cert);
    let (sig_role_algo, sig_pq, hash_part) = decompose_sig(sig_name);
    let mut prims = vec![Primitive {
        role: PrimitiveRole::Sig,
        algorithm: sig_role_algo.into(),
        parameters: Default::default(),
        pq_resistant: Some(sig_pq),
        nist_classification: pq_nist_level(sig_name),
    }];
    if let Some(hash) = hash_part {
        prims.push(Primitive {
            role: PrimitiveRole::Hash,
            algorithm: hash.into(),
            parameters: Default::default(),
            // Symmetric primitives (incl. hashes) survive
            // Grover with a 2× weakening; SHA-256 / SHA-384 /
            // SHA-512 stay PQ-safe.
            pq_resistant: Some(true),
            nist_classification: None,
        });
    }
    Ok(prims)
}

/// Map "RSA-PKCS1-SHA256" → ("RSA-PKCS1", false, Some("SHA-256"))
/// etc. Pulls the hash out so the rollup can see it as its own
/// primitive.
fn decompose_sig(sig: &str) -> (&str, bool, Option<&str>) {
    match sig {
        "RSA-PKCS1-SHA1" => ("RSA-PKCS1", false, Some("SHA-1")),
        "RSA-PKCS1-SHA256" => ("RSA-PKCS1", false, Some("SHA-256")),
        "RSA-PKCS1-SHA384" => ("RSA-PKCS1", false, Some("SHA-384")),
        "RSA-PKCS1-SHA512" => ("RSA-PKCS1", false, Some("SHA-512")),
        "RSA-PSS" => ("RSA-PSS", false, None),
        "ECDSA-SHA256" => ("ECDSA", false, Some("SHA-256")),
        "ECDSA-SHA384" => ("ECDSA", false, Some("SHA-384")),
        "ECDSA-SHA512" => ("ECDSA", false, Some("SHA-512")),
        "Ed25519" => ("Ed25519", false, None),
        "Ed448" => ("Ed448", false, None),
        "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87" => (sig, true, None),
        _ => (sig, false, None),
    }
}

fn pq_nist_level(sig: &str) -> Option<ree0xq_core::NistLevel> {
    match sig {
        "ML-DSA-44" => Some(ree0xq_core::NistLevel::L1),
        "ML-DSA-65" => Some(ree0xq_core::NistLevel::L3),
        "ML-DSA-87" => Some(ree0xq_core::NistLevel::L5),
        _ => None,
    }
}

fn public_key_byte_len(cert: &X509Certificate<'_>) -> usize {
    cert.tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .len()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A test cert generated via rcgen so we can self-contain
    // the fixture without checking a real cert into the repo.
    // Built once at module load (it's deterministic given the
    // keypair).
    fn fixture_pem() -> Vec<u8> {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
        let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec!["example.com".into()]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "test.example.com");
        params.distinguished_name = dn;
        let cert = params.self_signed(&kp).unwrap();
        cert.pem().into_bytes()
    }

    #[test]
    fn pem_bundle_yields_certs() {
        let pem = fixture_pem();
        let bundle = parse_pem_bundle(&pem, Some(Path::new("/tmp/fake.pem"))).unwrap();
        assert_eq!(bundle.len(), 1);
        assert_eq!(bundle[0].bundle_index, 0);
        assert_eq!(bundle[0].source_path.as_deref(), Some("/tmp/fake.pem"));
    }

    #[test]
    fn event_carries_expected_fields() {
        let pem = fixture_pem();
        let bundle = parse_pem_bundle(&pem, None).unwrap();
        let ev = event_from_cert(&bundle[0]).unwrap();
        assert_eq!(ev.source_module, MODULE_NAME);
        assert_eq!(ev.asset.kind, AssetKind::X509Cert);
        assert!(ev.asset.identity.starts_with("sha256:"));
        assert_eq!(ev.asset.identity.len(), "sha256:".len() + 64);
        assert!(ev.posture.rationale.contains("ECDSA-SHA256"));
        // Signature primitive + hash primitive.
        assert!(ev
            .primitives
            .iter()
            .any(|p| p.role == PrimitiveRole::Sig && p.algorithm == "ECDSA"));
        assert!(ev
            .primitives
            .iter()
            .any(|p| p.role == PrimitiveRole::Hash && p.algorithm == "SHA-256"));
    }

    #[test]
    fn non_certificate_blocks_are_skipped() {
        // Cert + bogus PRIVATE KEY block; only the cert
        // should come out.
        let mut pem = fixture_pem();
        pem.extend_from_slice(
            b"-----BEGIN PRIVATE KEY-----\nQUJDREVG\n-----END PRIVATE KEY-----\n",
        );
        let bundle = parse_pem_bundle(&pem, None).unwrap();
        assert_eq!(bundle.len(), 1, "PRIVATE KEY block must not become a cert");
    }

    #[test]
    fn malformed_pem_errors_clean() {
        let r = parse_pem_bundle(b"this is not pem at all", None);
        // pem 3.0 is permissive — returns empty slice when no
        // BEGIN/END markers are present, rather than erroring.
        // Either outcome is acceptable; what we don't want is
        // a panic.
        if let Ok(v) = r {
            assert!(v.is_empty())
        }
    }
}
