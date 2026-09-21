//! Key-type → `Primitive` mapping, shared across the
//! offline, PKCS#11, and KMS backends.
//!
//! The input is a backend-supplied
//! `(key_type, key_size_bits)` pair; the output is the
//! `Vec<Primitive>` the rollup looks at. Symmetric keys
//! (AES, HMAC) and asymmetric keys both flow through here.
//! The mapping is intentionally permissive — unrecognised
//! key types come out as `unknown:<name>` rather than an
//! error, so a future HSM that adds a new spec can still
//! be inventoried.

use ree0xq_core::{NistLevel, Primitive, PrimitiveRole};

/// Map a (key_type, optional_key_size_bits) pair onto the
/// list of primitives an event for that key should carry.
///
/// `key_type` is the backend's native spec name (e.g.
/// `RSA`, `ECDSA-P256`, `Ed25519`, `ML-DSA-65`, `AES`,
/// `HMAC-SHA256`). For RSA keys the caller passes the bit
/// length in `key_size_bits`; for the curve-named specs
/// the size is implicit and the argument is ignored.
pub fn primitives_for(key_type: &str, key_size_bits: Option<u32>) -> Vec<Primitive> {
    let upper = key_type.to_ascii_uppercase();
    let upper = upper.as_str();
    match upper {
        // Asymmetric — classical.
        "RSA" => vec![sig("RSA-PKCS1", false, None, key_size_bits)],
        "ECDSA-P256" | "ECC-NIST-P256" | "EC-P256" => {
            vec![sig("ECDSA-P256", false, None, None), hash_sha("SHA-256")]
        }
        "ECDSA-P384" | "ECC-NIST-P384" | "EC-P384" => {
            vec![sig("ECDSA-P384", false, None, None), hash_sha("SHA-384")]
        }
        "ECDSA-P521" | "ECC-NIST-P521" | "EC-P521" => {
            vec![sig("ECDSA-P521", false, None, None), hash_sha("SHA-512")]
        }
        "ECDSA-SECP256K1" | "ECC-SECG-P256K1" => {
            vec![
                sig("ECDSA-secp256k1", false, None, None),
                hash_sha("SHA-256"),
            ]
        }
        "ED25519" => vec![sig("Ed25519", false, None, None)],
        "ED448" => vec![sig("Ed448", false, None, None)],
        // Asymmetric — PQC (NIST FIPS 204 ML-DSA).
        "ML-DSA-44" => vec![sig("ML-DSA-44", true, Some(NistLevel::L1), None)],
        "ML-DSA-65" => vec![sig("ML-DSA-65", true, Some(NistLevel::L3), None)],
        "ML-DSA-87" => vec![sig("ML-DSA-87", true, Some(NistLevel::L5), None)],
        // Asymmetric — PQC (NIST FIPS 205 SLH-DSA).
        "SLH-DSA-SHA2-128S" | "SLH-DSA-128S" => {
            vec![sig("SLH-DSA-SHA2-128s", true, Some(NistLevel::L1), None)]
        }
        "SLH-DSA-SHA2-192S" | "SLH-DSA-192S" => {
            vec![sig("SLH-DSA-SHA2-192s", true, Some(NistLevel::L3), None)]
        }
        // Symmetric — AES variants. We surface the size as
        // a parameter on the primitive so consumers can
        // tell AES-128 (Grover-weakened) from AES-256.
        "AES" => {
            let size = key_size_bits.unwrap_or(256);
            vec![encrypt(format!("AES-{size}"), size >= 256)]
        }
        // HMAC family.
        "HMAC-SHA256" | "HMAC_SHA_256" => vec![hash_sha("SHA-256")],
        "HMAC-SHA384" | "HMAC_SHA_384" => vec![hash_sha("SHA-384")],
        "HMAC-SHA512" | "HMAC_SHA_512" => vec![hash_sha("SHA-512")],
        // Fallback: emit the raw name as a Sig primitive so
        // the operator can see it in /v1/inventory; the
        // `pq_resistant` flag is unknown.
        _ => vec![Primitive {
            role: PrimitiveRole::Sig,
            algorithm: format!("unknown:{key_type}"),
            parameters: Default::default(),
            pq_resistant: None,
            nist_classification: None,
        }],
    }
}

fn sig(name: &str, pq: bool, level: Option<NistLevel>, bits: Option<u32>) -> Primitive {
    let algorithm = match bits {
        Some(b) => format!("{name}-{b}"),
        None => name.to_string(),
    };
    Primitive {
        role: PrimitiveRole::Sig,
        algorithm,
        parameters: Default::default(),
        pq_resistant: Some(pq),
        nist_classification: level,
    }
}

fn hash_sha(name: &str) -> Primitive {
    Primitive {
        role: PrimitiveRole::Hash,
        algorithm: name.into(),
        parameters: Default::default(),
        pq_resistant: Some(true),
        nist_classification: None,
    }
}

fn encrypt(algorithm: String, pq_safe: bool) -> Primitive {
    Primitive {
        role: PrimitiveRole::Encrypt,
        algorithm,
        parameters: Default::default(),
        pq_resistant: Some(pq_safe),
        nist_classification: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_carries_bit_length() {
        let prims = primitives_for("RSA", Some(4096));
        assert_eq!(prims.len(), 1);
        assert_eq!(prims[0].algorithm, "RSA-PKCS1-4096");
        assert_eq!(prims[0].pq_resistant, Some(false));
    }

    #[test]
    fn ecdsa_p256_carries_hash_pair() {
        let prims = primitives_for("ECDSA-P256", None);
        assert!(prims
            .iter()
            .any(|p| p.role == PrimitiveRole::Sig && p.algorithm == "ECDSA-P256"));
        assert!(prims
            .iter()
            .any(|p| p.role == PrimitiveRole::Hash && p.algorithm == "SHA-256"));
    }

    #[test]
    fn ml_dsa_65_is_pq_with_l3() {
        let prims = primitives_for("ML-DSA-65", None);
        assert_eq!(prims[0].pq_resistant, Some(true));
        assert_eq!(prims[0].nist_classification, Some(NistLevel::L3));
    }

    #[test]
    fn aes_256_marks_pq_safe_aes_128_does_not() {
        let aes256 = primitives_for("AES", Some(256));
        assert_eq!(aes256[0].algorithm, "AES-256");
        assert_eq!(aes256[0].pq_resistant, Some(true));
        let aes128 = primitives_for("AES", Some(128));
        assert_eq!(aes128[0].algorithm, "AES-128");
        assert_eq!(aes128[0].pq_resistant, Some(false));
    }

    #[test]
    fn unknown_key_type_surfaces_as_unknown_prefix() {
        let prims = primitives_for("WeirdNewAlgo", None);
        assert!(prims[0].algorithm.starts_with("unknown:"));
        assert_eq!(prims[0].pq_resistant, None);
    }

    #[test]
    fn case_insensitive_match() {
        let lower = primitives_for("ecdsa-p256", None);
        let upper = primitives_for("ECDSA-P256", None);
        assert_eq!(lower.len(), upper.len());
        assert_eq!(lower[0].algorithm, upper[0].algorithm);
    }
}
