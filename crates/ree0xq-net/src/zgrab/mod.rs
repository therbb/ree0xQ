//! Adapter from ZMap `zgrab2 tls` JSON output to
//! [`CryptoInventoryEvent`].
//!
//! `zgrab2` emits one JSON object per host with a fairly stable
//! schema even across versions. We accept the minimal shape needed
//! for posture classification and ignore everything else, so the
//! adapter survives version drift.
//!
//! Reference: <https://github.com/zmap/zgrab2>
//!
//! Wire example (trimmed):
//!
//! ```json
//! {
//!   "domain": "api.example.com",
//!   "ip": "203.0.113.42",
//!   "data": {
//!     "tls": {
//!       "result": {
//!         "handshake_log": {
//!           "server_hello": {
//!             "version": { "name": "TLSv1.3", "value": 772 },
//!             "cipher_suite": { "hex": "0x1302", "name": "TLS_AES_256_GCM_SHA384" },
//!             "selected_group": "x25519mlkem768"
//!           },
//!           "server_certificates": {
//!             "certificate": {
//!               "parsed": {
//!                 "signature_algorithm": { "name": "SHA256-RSA" }
//!               }
//!             }
//!           }
//!         }
//!       }
//!     }
//!   }
//! }
//! ```
//!
//! The adapter is tolerant: missing fields produce empty primitive
//! lists; the posture engine downstream treats absence as `unknown`.

use ree0xq_core::{CryptoInventoryEvent, Primitive, PrimitiveRole};
use serde::{Deserialize, Serialize};

use crate::algos;

/// Top-level zgrab2 record shape.
#[derive(Debug, Deserialize)]
pub struct ZgrabRecord {
    /// Hostname the scanner targeted (often equals the SNI name).
    #[serde(default)]
    pub domain: Option<String>,
    /// Resolved IP address.
    #[serde(default)]
    pub ip: Option<String>,
    /// Per-protocol scan data; we only consume `tls` here.
    #[serde(default)]
    pub data: ZgrabData,
}

/// `data` block; only `tls` populated in this MVP.
#[derive(Debug, Default, Deserialize)]
pub struct ZgrabData {
    /// TLS scanner output.
    #[serde(default)]
    pub tls: Option<TlsSection>,
}

/// `data.tls` block.
#[derive(Debug, Default, Deserialize)]
pub struct TlsSection {
    /// `result` block; absent on scan failure.
    #[serde(default)]
    pub result: Option<TlsResult>,
}

/// `data.tls.result` block.
#[derive(Debug, Default, Deserialize)]
pub struct TlsResult {
    /// Handshake log; the field we care about.
    #[serde(default)]
    pub handshake_log: Option<HandshakeLog>,
}

/// `data.tls.result.handshake_log` block.
#[derive(Debug, Default, Deserialize)]
pub struct HandshakeLog {
    /// ServerHello observation.
    #[serde(default)]
    pub server_hello: Option<ServerHello>,
    /// Server-presented certificate chain (we read the leaf's
    /// signature_algorithm).
    #[serde(default)]
    pub server_certificates: Option<ServerCertificates>,
}

/// ServerHello fields we extract.
#[derive(Debug, Default, Deserialize)]
pub struct ServerHello {
    /// Negotiated TLS version.
    #[serde(default)]
    pub version: Option<NamedValue>,
    /// Negotiated cipher suite (TLS 1.3 → name field is enough).
    #[serde(default)]
    pub cipher_suite: Option<NamedValue>,
    /// Selected named group (TLS 1.3). `selected_group` is the
    /// zgrab2 v0.1 spelling; some forks use `key_share_group`.
    #[serde(default, alias = "key_share_group")]
    pub selected_group: Option<serde_json::Value>,
}

/// Common `{ name, value, hex }` shape used by zgrab2 for ciphers,
/// versions, named groups.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct NamedValue {
    /// Spelled-out name (e.g. `TLS_AES_256_GCM_SHA384`).
    #[serde(default)]
    pub name: Option<String>,
    /// Numeric IANA code (e.g. 0x1302 → 4866).
    #[serde(default)]
    pub value: Option<u32>,
    /// Hex form sometimes emitted alongside `value`.
    #[serde(default)]
    pub hex: Option<String>,
}

/// Server certificate block.
#[derive(Debug, Default, Deserialize)]
pub struct ServerCertificates {
    /// Leaf certificate.
    #[serde(default)]
    pub certificate: Option<Certificate>,
}

/// Leaf certificate; we only need the `parsed.signature_algorithm`.
#[derive(Debug, Default, Deserialize)]
pub struct Certificate {
    /// Parsed cert.
    #[serde(default)]
    pub parsed: Option<CertParsed>,
}

/// `parsed.signature_algorithm` carries the cert's sig algo name.
#[derive(Debug, Default, Deserialize)]
pub struct CertParsed {
    /// E.g. `"SHA256-RSA"`, `"ECDSA-SHA256"`.
    #[serde(default)]
    pub signature_algorithm: Option<NamedValue>,
}

/// Convert one zgrab2 record into a `CryptoInventoryEvent`.
///
/// The asset identity is `sha256-flavoured` (we hash domain+IP into
/// a short hex string so reruns deduplicate cleanly upstream).
pub fn event_from_zgrab(record: &ZgrabRecord) -> CryptoInventoryEvent {
    let host = record
        .domain
        .clone()
        .or_else(|| record.ip.clone())
        .unwrap_or_else(|| "unknown".into());
    let identity = synthetic_identity(record);
    let primitives = primitives_from_zgrab(record);
    crate::build_tls_event(host, identity, primitives)
}

/// Build a stable identity from `domain` + `ip` without bringing in
/// an explicit hash crate — a salted FNV-1a is sufficient for the
/// dedup window operators actually need (minutes to hours).
fn synthetic_identity(record: &ZgrabRecord) -> String {
    const SALT: u64 = 0xcbf29ce484222325; // FNV offset basis
    let mut h: u64 = SALT;
    let push = |h: &mut u64, s: &str| {
        for b in s.bytes() {
            *h ^= u64::from(b);
            *h = h.wrapping_mul(0x100000001b3);
        }
    };
    if let Some(d) = &record.domain {
        push(&mut h, d);
    }
    push(&mut h, "|");
    if let Some(ip) = &record.ip {
        push(&mut h, ip);
    }
    format!("zgrab-{:016x}", h)
}

/// Translate a zgrab record into a `Vec<Primitive>` using the algos
/// table.
pub fn primitives_from_zgrab(record: &ZgrabRecord) -> Vec<Primitive> {
    let mut out = Vec::new();
    let Some(tls) = &record.data.tls else {
        return out;
    };
    let Some(result) = &tls.result else {
        return out;
    };
    let Some(hs) = &result.handshake_log else {
        return out;
    };

    if let Some(sh) = &hs.server_hello {
        if let Some(cs) = &sh.cipher_suite {
            if let Some(name) = &cs.name {
                let p = if name.starts_with("TLS_AES_") || name.starts_with("TLS_CHACHA20_") {
                    algos::primitives_from_tls13_ciphersuite(name)
                } else {
                    algos::primitives_from_tls12_ciphersuite(name)
                };
                out.extend(p);
            }
        }
        if let Some(group) = &sh.selected_group {
            let name = group.as_str().map(|s| s.to_string()).unwrap_or_else(|| {
                group
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default()
            });
            if !name.is_empty() {
                if let Some(p) = algos::primitive_from_supported_group(&name) {
                    out.push(p);
                }
            }
        }
    }

    if let Some(cert_block) = &hs.server_certificates {
        if let Some(cert) = &cert_block.certificate {
            if let Some(parsed) = &cert.parsed {
                if let Some(sig) = &parsed.signature_algorithm {
                    if let Some(name) = &sig.name {
                        if let Some(p) = parse_cert_sig_algorithm(name) {
                            out.push(p);
                        }
                    }
                }
            }
        }
    }
    out
}

/// X.509 certificate signature-algorithm names use a different
/// spelling than TLS signature_schemes. Examples:
/// `"SHA256-RSA"`, `"ECDSA-SHA256"`, `"SHA384-RSA-PSS"`.
fn parse_cert_sig_algorithm(name: &str) -> Option<Primitive> {
    let n = name.replace('_', "-").to_uppercase();
    let (algo, pq) = match n.as_str() {
        "SHA256-RSA" | "SHA-256-RSA" => ("RSA-PKCS1-SHA256", Some(false)),
        "SHA384-RSA" => ("RSA-PKCS1-SHA384", Some(false)),
        "SHA512-RSA" => ("RSA-PKCS1-SHA512", Some(false)),
        "SHA256-RSA-PSS" => ("RSA-PSS-SHA256", Some(false)),
        "SHA384-RSA-PSS" => ("RSA-PSS-SHA384", Some(false)),
        "SHA512-RSA-PSS" => ("RSA-PSS-SHA512", Some(false)),
        "ECDSA-SHA256" => ("ECDSA-P256", Some(false)),
        "ECDSA-SHA384" => ("ECDSA-P384", Some(false)),
        "ECDSA-SHA512" => ("ECDSA-P521", Some(false)),
        "SHA1-RSA" | "SHA-1-RSA" => ("RSA-PKCS1-SHA1", Some(false)),
        "MD5-RSA" => ("RSA-MD5", Some(false)),
        "ED25519" => ("Ed25519", Some(false)),
        "ML-DSA-44" | "MLDSA44" | "DILITHIUM2" => ("ML-DSA-44", Some(true)),
        "ML-DSA-65" | "MLDSA65" | "DILITHIUM3" => ("ML-DSA-65", Some(true)),
        "ML-DSA-87" | "MLDSA87" | "DILITHIUM5" => ("ML-DSA-87", Some(true)),
        _ => return None,
    };
    Some(Primitive {
        role: PrimitiveRole::Sig,
        algorithm: algo.into(),
        parameters: Default::default(),
        pq_resistant: pq,
        nist_classification: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_tls13_x25519mlkem768() -> ZgrabRecord {
        let json = r#"{
          "domain": "api.example.com",
          "ip": "203.0.113.42",
          "data": {
            "tls": {
              "result": {
                "handshake_log": {
                  "server_hello": {
                    "version": { "name": "TLSv1.3", "value": 772 },
                    "cipher_suite": { "name": "TLS_AES_256_GCM_SHA384", "value": 4866 },
                    "selected_group": "X25519MLKEM768"
                  },
                  "server_certificates": {
                    "certificate": {
                      "parsed": {
                        "signature_algorithm": { "name": "ECDSA-SHA256" }
                      }
                    }
                  }
                }
              }
            }
          }
        }"#;
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn modern_tls13_record_yields_full_primitive_set() {
        let rec = fixture_tls13_x25519mlkem768();
        let prims = primitives_from_zgrab(&rec);
        let names: Vec<&str> = prims.iter().map(|p| p.algorithm.as_str()).collect();
        assert!(names.contains(&"AES-256-GCM"));
        assert!(names.contains(&"SHA-384"));
        assert!(names.contains(&"X25519+ML-KEM-768"));
        assert!(names.contains(&"ECDSA-P256"));
    }

    #[test]
    fn classical_tls12_record_yields_classical_primitives() {
        let json = r#"{
          "domain": "legacy.example.com",
          "ip": "192.0.2.10",
          "data": {
            "tls": {
              "result": {
                "handshake_log": {
                  "server_hello": {
                    "cipher_suite": { "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" }
                  },
                  "server_certificates": {
                    "certificate": {
                      "parsed": { "signature_algorithm": { "name": "SHA256-RSA" } }
                    }
                  }
                }
              }
            }
          }
        }"#;
        let rec: ZgrabRecord = serde_json::from_str(json).unwrap();
        let prims = primitives_from_zgrab(&rec);
        let names: Vec<&str> = prims.iter().map(|p| p.algorithm.as_str()).collect();
        assert!(names.contains(&"ECDHE"));
        assert!(names.contains(&"RSA"));
        assert!(names.contains(&"AES-256-GCM"));
        assert!(names.contains(&"SHA-384"));
        assert!(names.contains(&"RSA-PKCS1-SHA256"));
    }

    #[test]
    fn event_from_zgrab_carries_domain_as_host() {
        let rec = fixture_tls13_x25519mlkem768();
        let ev = event_from_zgrab(&rec);
        assert_eq!(ev.asset.host.as_deref(), Some("api.example.com"));
        assert!(ev.asset.identity.starts_with("zgrab-"));
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.contains("X25519+ML-KEM-768"));
    }

    #[test]
    fn missing_data_does_not_panic() {
        let rec: ZgrabRecord = serde_json::from_str(r#"{"domain":"x"}"#).unwrap();
        let prims = primitives_from_zgrab(&rec);
        assert!(prims.is_empty());
        let ev = event_from_zgrab(&rec);
        assert_eq!(ev.asset.host.as_deref(), Some("x"));
    }

    #[test]
    fn synthetic_identity_is_deterministic() {
        let r1 = fixture_tls13_x25519mlkem768();
        let r2 = fixture_tls13_x25519mlkem768();
        assert_eq!(synthetic_identity(&r1), synthetic_identity(&r2));
    }
}
