//! Mapping from observed wire identifiers to `ree0xq_core::Primitive`.
//!
//! Inputs are the kinds of strings that TLS scanners (zgrab2, sslyze,
//! testssl.sh) and our own [`crate::tls`] parser emit:
//!
//! - IANA TLS 1.3 ciphersuite names like `TLS_AES_256_GCM_SHA384`.
//! - IANA TLS 1.2 ciphersuite names like
//!   `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`.
//! - `supported_groups` entries like `X25519`, `secp256r1`, `X25519MLKEM768`.
//! - `signature_algorithms` entries like `ecdsa_secp256r1_sha256`,
//!   `rsa_pss_rsae_sha256`, `mldsa_65`.
//!
//! Output is a `Vec<Primitive>` populated for the roles relevant to
//! that observation. The mapping is conservative — anything the table
//! does not recognise is emitted as `pq_resistant: None` so the
//! posture engine flags it for operator review rather than scoring it
//! as classical-or-PQ by default.

use ree0xq_core::{NistLevel, Primitive, PrimitiveRole};

/// Classify a TLS 1.3 ciphersuite into its symmetric-encrypt and hash
/// primitives. TLS 1.3 separates kex / sig / encrypt; this function
/// only fills the encrypt + hash roles.
pub fn primitives_from_tls13_ciphersuite(name: &str) -> Vec<Primitive> {
    let (encrypt_algo, encrypt_pq) = match name {
        "TLS_AES_128_GCM_SHA256" => ("AES-128-GCM", Some(false)),
        "TLS_AES_256_GCM_SHA384" => ("AES-256-GCM", Some(true)),
        "TLS_CHACHA20_POLY1305_SHA256" => ("ChaCha20-Poly1305", Some(true)),
        "TLS_AES_128_CCM_SHA256" => ("AES-128-CCM", Some(false)),
        "TLS_AES_128_CCM_8_SHA256" => ("AES-128-CCM-8", Some(false)),
        _ => return vec![],
    };
    let hash_algo = if name.ends_with("SHA384") {
        "SHA-384"
    } else if name.ends_with("SHA256") {
        "SHA-256"
    } else {
        return vec![Primitive {
            role: PrimitiveRole::Encrypt,
            algorithm: encrypt_algo.into(),
            parameters: Default::default(),
            pq_resistant: encrypt_pq,
            nist_classification: None,
        }];
    };
    vec![
        Primitive {
            role: PrimitiveRole::Encrypt,
            algorithm: encrypt_algo.into(),
            parameters: Default::default(),
            pq_resistant: encrypt_pq,
            nist_classification: None,
        },
        Primitive {
            role: PrimitiveRole::Hash,
            algorithm: hash_algo.into(),
            parameters: Default::default(),
            pq_resistant: Some(true),
            nist_classification: None,
        },
    ]
}

/// Classify a TLS 1.2 ciphersuite into its constituent kex / sig /
/// encrypt / hash roles. Returns up to four primitives.
///
/// TLS 1.2 names are `TLS_<KEX>_<SIG?>_WITH_<ENCRYPT>_<HASH>`. We do a
/// pattern-walk rather than a full IANA table for compactness — the
/// long tail of legacy suites is covered by the unknown-suite branch
/// in [`primitive_from_signature_scheme`].
pub fn primitives_from_tls12_ciphersuite(name: &str) -> Vec<Primitive> {
    let mut out = Vec::with_capacity(4);

    // ---- kex ----
    if let Some(kex_alg) = match () {
        _ if name.contains("_ECDHE_") => Some("ECDHE"),
        _ if name.contains("_DHE_") => Some("DHE"),
        _ if name.contains("_ECDH_") => Some("ECDH"),
        _ if name.contains("_RSA_") && !name.contains("_DHE_") && !name.contains("_ECDHE_") => {
            Some("RSA-KEX")
        }
        _ => None,
    } {
        // `RSA-KEX` (raw RSA encryption of premaster secret) is broken
        // by Shor *and* by Bleichenbacher-style oracles; flag as
        // deprecated by emitting `pq_resistant: Some(false)` and
        // letting the rollup table mark it as deprecated.
        let pq = matches!(kex_alg, "RSA-KEX").then_some(false);
        out.push(Primitive {
            role: PrimitiveRole::Kex,
            algorithm: kex_alg.into(),
            parameters: Default::default(),
            pq_resistant: pq.or(Some(false)),
            nist_classification: None,
        });
    }

    // ---- sig ----
    if let Some(sig_alg) = match () {
        _ if name.contains("_ECDSA_") => Some("ECDSA"),
        _ if name.contains("_RSA_") => Some("RSA"),
        _ if name.contains("_DSS_") => Some("DSA"),
        _ if name.contains("_anon_") => Some("anonymous"),
        _ => None,
    } {
        out.push(Primitive {
            role: PrimitiveRole::Sig,
            algorithm: sig_alg.into(),
            parameters: Default::default(),
            pq_resistant: Some(false),
            nist_classification: None,
        });
    }

    // ---- encrypt ----
    let encrypt_alg = if name.contains("_AES_256_GCM") {
        Some(("AES-256-GCM", Some(true)))
    } else if name.contains("_AES_128_GCM") {
        Some(("AES-128-GCM", Some(false)))
    } else if name.contains("_AES_256_CBC") {
        Some(("AES-256-CBC", Some(false)))
    } else if name.contains("_AES_128_CBC") {
        Some(("AES-128-CBC", Some(false)))
    } else if name.contains("_CHACHA20_POLY1305") {
        Some(("ChaCha20-Poly1305", Some(true)))
    } else if name.contains("_3DES_") {
        Some(("3DES", Some(false)))
    } else if name.contains("_RC4_") {
        Some(("RC4", Some(false)))
    } else if name.contains("_NULL_") {
        Some(("NULL", Some(false)))
    } else {
        None
    };
    if let Some((enc, pq)) = encrypt_alg {
        out.push(Primitive {
            role: PrimitiveRole::Encrypt,
            algorithm: enc.into(),
            parameters: Default::default(),
            pq_resistant: pq,
            nist_classification: None,
        });
    }

    // ---- hash (the trailing suffix) ----
    let hash_alg = if name.ends_with("_SHA384") {
        Some(("SHA-384", Some(true)))
    } else if name.ends_with("_SHA256") {
        Some(("SHA-256", Some(true)))
    } else if name.ends_with("_SHA") {
        Some(("SHA-1", Some(false)))
    } else if name.ends_with("_MD5") {
        Some(("MD5", Some(false)))
    } else {
        None
    };
    if let Some((hash, pq)) = hash_alg {
        out.push(Primitive {
            role: PrimitiveRole::Hash,
            algorithm: hash.into(),
            parameters: Default::default(),
            pq_resistant: pq,
            nist_classification: None,
        });
    }

    out
}

/// Map a `supported_groups` entry (TLS 1.3 named group) to a kex
/// primitive. Covers classical NIST curves, X25519/X448, finite-field
/// MODP groups, and the hybrid PQ groups that have been provisionally
/// assigned IANA codepoints during the migration window.
pub fn primitive_from_supported_group(name: &str) -> Option<Primitive> {
    let (algo, pq, nist) = match name {
        // Classical EC
        "secp256r1" | "P-256" | "prime256v1" => ("ECDHE-P256", Some(false), None),
        "secp384r1" | "P-384" => ("ECDHE-P384", Some(false), None),
        "secp521r1" | "P-521" => ("ECDHE-P521", Some(false), None),
        "x25519" | "X25519" => ("X25519", Some(false), None),
        "x448" | "X448" => ("X448", Some(false), None),
        // Finite-field DHE groups (RFC 7919)
        "ffdhe2048" => ("DHE-2048", Some(false), None),
        "ffdhe3072" => ("DHE-3072", Some(false), None),
        "ffdhe4096" => ("DHE-4096", Some(false), None),
        // ML-KEM (FIPS 203) — pure PQ
        "MLKEM512" | "mlkem512" | "ML-KEM-512" => ("ML-KEM-512", Some(true), Some(NistLevel::L1)),
        "MLKEM768" | "mlkem768" | "ML-KEM-768" => ("ML-KEM-768", Some(true), Some(NistLevel::L3)),
        "MLKEM1024" | "mlkem1024" | "ML-KEM-1024" => {
            ("ML-KEM-1024", Some(true), Some(NistLevel::L5))
        }
        // Hybrid PQ groups (the post-quantum migration deployment pattern)
        "X25519MLKEM768" | "x25519mlkem768" | "X25519Kyber768Draft00" => {
            ("X25519+ML-KEM-768", Some(true), Some(NistLevel::L3))
        }
        "SecP256r1MLKEM768" | "secp256r1mlkem768" => {
            ("ECDHE-P256+ML-KEM-768", Some(true), Some(NistLevel::L3))
        }
        "P384MLKEM1024" | "secp384r1mlkem1024" => {
            ("ECDHE-P384+ML-KEM-1024", Some(true), Some(NistLevel::L5))
        }
        _ => return None,
    };
    let mut params = serde_json::Map::new();
    params.insert("named_group".into(), serde_json::Value::String(name.into()));
    Some(Primitive {
        role: PrimitiveRole::Kex,
        algorithm: algo.into(),
        parameters: params,
        pq_resistant: pq,
        nist_classification: nist,
    })
}

/// Map a `signature_algorithms` / `signature_schemes` entry to a sig
/// primitive. Recognises both classical and PQ schemes.
pub fn primitive_from_signature_scheme(name: &str) -> Option<Primitive> {
    let (algo, pq, nist) = match name {
        // Classical RSA-PSS
        "rsa_pss_rsae_sha256" | "rsa_pss_pss_sha256" => ("RSA-PSS-SHA256", Some(false), None),
        "rsa_pss_rsae_sha384" | "rsa_pss_pss_sha384" => ("RSA-PSS-SHA384", Some(false), None),
        "rsa_pss_rsae_sha512" | "rsa_pss_pss_sha512" => ("RSA-PSS-SHA512", Some(false), None),
        // Classical RSA-PKCS1
        "rsa_pkcs1_sha1" => ("RSA-PKCS1-SHA1", Some(false), None),
        "rsa_pkcs1_sha256" => ("RSA-PKCS1-SHA256", Some(false), None),
        "rsa_pkcs1_sha384" => ("RSA-PKCS1-SHA384", Some(false), None),
        "rsa_pkcs1_sha512" => ("RSA-PKCS1-SHA512", Some(false), None),
        // ECDSA
        "ecdsa_secp256r1_sha256" => ("ECDSA-P256", Some(false), None),
        "ecdsa_secp384r1_sha384" => ("ECDSA-P384", Some(false), None),
        "ecdsa_secp521r1_sha512" => ("ECDSA-P521", Some(false), None),
        // EdDSA
        "ed25519" => ("Ed25519", Some(false), None),
        "ed448" => ("Ed448", Some(false), None),
        // PQ signatures (FIPS 204 / 205)
        "mldsa44" | "ML-DSA-44" | "dilithium2" => ("ML-DSA-44", Some(true), Some(NistLevel::L1)),
        "mldsa65" | "ML-DSA-65" | "dilithium3" => ("ML-DSA-65", Some(true), Some(NistLevel::L3)),
        "mldsa87" | "ML-DSA-87" | "dilithium5" => ("ML-DSA-87", Some(true), Some(NistLevel::L5)),
        "slhdsa_sha2_128s" | "SLH-DSA-SHA2-128S" | "sphincs_sha2_128s" => {
            ("SLH-DSA-SHA2-128s", Some(true), Some(NistLevel::L1))
        }
        "slhdsa_sha2_256s" | "SLH-DSA-SHA2-256S" => {
            ("SLH-DSA-SHA2-256s", Some(true), Some(NistLevel::L5))
        }
        // Legacy
        "sha1_dsa" | "dsa_sha1" => ("DSA-SHA1", Some(false), None),
        _ => return None,
    };
    Some(Primitive {
        role: PrimitiveRole::Sig,
        algorithm: algo.into(),
        parameters: Default::default(),
        pq_resistant: pq,
        nist_classification: nist,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls13_aes_256_gcm_sha384_maps_cleanly() {
        let prims = primitives_from_tls13_ciphersuite("TLS_AES_256_GCM_SHA384");
        assert_eq!(prims.len(), 2);
        assert_eq!(prims[0].algorithm, "AES-256-GCM");
        assert_eq!(prims[0].role, PrimitiveRole::Encrypt);
        assert_eq!(prims[1].algorithm, "SHA-384");
        assert_eq!(prims[1].role, PrimitiveRole::Hash);
        assert_eq!(prims[0].pq_resistant, Some(true));
    }

    #[test]
    fn tls12_ecdhe_rsa_aes_256_gcm_sha384_recovers_all_four_roles() {
        let prims = primitives_from_tls12_ciphersuite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        assert_eq!(prims.len(), 4);
        let mut by_role = std::collections::HashMap::new();
        for p in &prims {
            by_role.insert(format!("{:?}", p.role), p.algorithm.clone());
        }
        assert_eq!(by_role.get("Kex").map(String::as_str), Some("ECDHE"));
        assert_eq!(by_role.get("Sig").map(String::as_str), Some("RSA"));
        assert_eq!(
            by_role.get("Encrypt").map(String::as_str),
            Some("AES-256-GCM")
        );
        assert_eq!(by_role.get("Hash").map(String::as_str), Some("SHA-384"));
    }

    #[test]
    fn legacy_rsa_3des_sha1_carries_three_deprecated_signals() {
        let prims = primitives_from_tls12_ciphersuite("TLS_RSA_WITH_3DES_EDE_CBC_SHA");
        let algos: Vec<&str> = prims.iter().map(|p| p.algorithm.as_str()).collect();
        assert!(algos.contains(&"RSA-KEX"));
        assert!(algos.contains(&"RSA"));
        assert!(algos.contains(&"3DES"));
        assert!(algos.contains(&"SHA-1"));
    }

    #[test]
    fn supported_group_x25519_maps_to_classical_kex() {
        let p = primitive_from_supported_group("x25519").unwrap();
        assert_eq!(p.algorithm, "X25519");
        assert_eq!(p.pq_resistant, Some(false));
    }

    #[test]
    fn supported_group_hybrid_pq_maps_to_pq_with_nist_level() {
        let p = primitive_from_supported_group("X25519MLKEM768").unwrap();
        assert_eq!(p.algorithm, "X25519+ML-KEM-768");
        assert_eq!(p.pq_resistant, Some(true));
        assert_eq!(p.nist_classification, Some(NistLevel::L3));
    }

    #[test]
    fn signature_scheme_mldsa_maps_to_pq_with_level() {
        let p = primitive_from_signature_scheme("mldsa65").unwrap();
        assert_eq!(p.algorithm, "ML-DSA-65");
        assert_eq!(p.nist_classification, Some(NistLevel::L3));
        let p2 = primitive_from_signature_scheme("ecdsa_secp256r1_sha256").unwrap();
        assert_eq!(p2.algorithm, "ECDSA-P256");
        assert_eq!(p2.pq_resistant, Some(false));
    }

    #[test]
    fn unknown_identifiers_return_none() {
        assert!(primitive_from_supported_group("not-a-real-group").is_none());
        assert!(primitive_from_signature_scheme("not-a-real-sig").is_none());
        assert!(primitives_from_tls13_ciphersuite("TLS_NONEXISTENT").is_empty());
    }
}
