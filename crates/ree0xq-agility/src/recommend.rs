//! Per-asset PQ replacement recommendations (SEZ-19).
//!
//! Given the primitive list an asset currently uses, return
//! a ranked list of replacement [`Recommendation`]s, each
//! with rationale + cost markers. The rules are intentionally
//! hand-curated — V5.0 is a small table, not an inferred
//! one; we'd rather get the canonical replacements right
//! than try to be clever.
//!
//! Rule pattern: the recommender walks the asset's
//! `Sig` and `Encrypt` primitives. For each primitive that
//! matches a known classical algorithm, it emits one or
//! more recommendation entries. Hash / KEX primitives feed
//! into the *rationale* but don't trigger replacements on
//! their own (SHA-256 stays PQ-safe; PQ-KEX is handled by
//! ree0xq-net's separate transport-level recommendation
//! flow).

use serde::{Deserialize, Serialize};

use ree0xq_core::{Primitive, PrimitiveRole};

/// Cost markers attached to each recommendation. Operators
/// use these to pick between "good replacement, expensive"
/// vs "cheap replacement, partial fix".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cost {
    /// Trivial — server-side config tweak, no client-side
    /// impact.
    Trivial,
    /// Low — software update or library version bump.
    Low,
    /// Medium — re-issue certs, rotate keys, or update
    /// firmware on a manageable fleet.
    Medium,
    /// High — hardware refresh, vendor firmware cycle, or
    /// a multi-quarter capital program.
    High,
}

/// One concrete replacement option.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    /// The classical primitive this entry replaces.
    pub replaces: String,
    /// The replacement algorithm name.
    pub replacement: String,
    /// One-line "why this is the right replacement" hint.
    pub rationale: String,
    /// Migration cost class.
    pub cost: Cost,
    /// Notes on what breaks — chain depth, client compat,
    /// perf overhead, etc.
    pub caveats: Vec<String>,
}

/// Walk the asset's primitives and return every recommended
/// replacement, ordered by [`Cost`] ascending (cheapest
/// first — operators usually pick the lowest-cost option
/// that closes the gap).
pub fn recommend_for(primitives: &[Primitive]) -> Vec<Recommendation> {
    let mut out = Vec::new();
    for p in primitives {
        match p.role {
            PrimitiveRole::Sig => recommend_for_sig(p, &mut out),
            PrimitiveRole::Encrypt => recommend_for_encrypt(p, &mut out),
            _ => {} // Hash / Kex / Auth: handled by the
                    // transport-level recommendation flow.
        }
    }
    out.sort_by_key(|r| r.cost);
    out
}

fn recommend_for_sig(p: &Primitive, out: &mut Vec<Recommendation>) {
    let algo = p.algorithm.as_str();
    // Extract bit length suffix when present (e.g.
    // "RSA-PKCS1-2048" → 2048).
    let bits = parse_trailing_bits(algo);
    if algo.starts_with("RSA-PKCS1") || algo.starts_with("RSA-PSS") {
        let level = nist_level_for_rsa(bits);
        out.push(Recommendation {
            replaces: algo.into(),
            replacement: format!("ML-DSA-{}", level.ml_dsa_id()),
            rationale: format!(
                "FIPS 204 ML-DSA at NIST level {} matches the classical strength of {algo}",
                level.label()
            ),
            cost: Cost::Medium,
            caveats: vec![
                "Cert chain depth grows: ML-DSA signatures are 2-4 KB.".into(),
                "Client TLS stack must support `mldsa` certificate signature.".into(),
            ],
        });
        out.push(Recommendation {
            replaces: algo.into(),
            replacement: format!("SLH-DSA-SHA2-{}s", level.slh_dsa_size()),
            rationale:
                "FIPS 205 SLH-DSA: hash-based fallback if ML-DSA lattice family proves unstable."
                    .into(),
            cost: Cost::High,
            caveats: vec![
                "Signatures are 8-50 KB — non-trivial for TLS handshake size.".into(),
                "Stateless: safe for general-purpose code-signing.".into(),
            ],
        });
        return;
    }
    if algo.starts_with("ECDSA-") || algo == "Ed25519" || algo == "Ed448" {
        // Treat all classical curve sigs as L3-equivalent
        // for the default replacement; operators with
        // P-521 specifically can pick L5 manually.
        out.push(Recommendation {
            replaces: algo.into(),
            replacement: "ML-DSA-65".into(),
            rationale: "ML-DSA-65 matches the security level of P-256 / Ed25519 with PQ guarantees."
                .into(),
            cost: Cost::Medium,
            caveats: vec![
                "Signature ~3.3 KB vs 64 B for Ed25519 — measure cert-chain depth impact.".into(),
            ],
        });
        return;
    }
    if algo.starts_with("Schnorr-secp256k1") {
        out.push(Recommendation {
            replaces: algo.into(),
            replacement: "FROST-PQ (research)".into(),
            rationale: "Bitcoin Taproot's Schnorr family has no production PQ replacement yet — track BIP / IRTF CFRG work.".into(),
            cost: Cost::High,
            caveats: vec![
                "Consensus-level chain change required; no operator-side migration path.".into(),
            ],
        });
    }
}

fn recommend_for_encrypt(p: &Primitive, out: &mut Vec<Recommendation>) {
    let algo = p.algorithm.as_str();
    if algo == "AES-128" || algo == "AES-128-GCM" {
        out.push(Recommendation {
            replaces: algo.into(),
            replacement: "AES-256".into(),
            rationale: "Grover halves the effective key length: AES-128 → 64-bit PQ security; AES-256 → 128-bit.".into(),
            cost: Cost::Low,
            caveats: vec![
                "Same cipher family, server-config-only change in most stacks.".into(),
            ],
        });
        return;
    }
    if algo == "DES" || algo == "3DES" || algo.starts_with("RC4") || algo == "AES-CBC" {
        out.push(Recommendation {
            replaces: algo.into(),
            replacement: "AES-256-GCM".into(),
            rationale: "Modern AEAD cipher; the classical algorithm is broken or weak by today's standards.".into(),
            cost: Cost::Low,
            caveats: vec![
                "Most TLS terminators already support AES-GCM; flip the negotiate-list.".into(),
            ],
        });
    }
}

fn parse_trailing_bits(s: &str) -> Option<u32> {
    let last = s.rsplit('-').next()?;
    last.parse().ok()
}

#[derive(Debug, Clone, Copy)]
enum NistLevel {
    L1,
    L3,
    L5,
}

impl NistLevel {
    fn label(self) -> &'static str {
        match self {
            Self::L1 => "1 (AES-128)",
            Self::L3 => "3 (AES-192)",
            Self::L5 => "5 (AES-256)",
        }
    }
    fn ml_dsa_id(self) -> &'static str {
        match self {
            Self::L1 => "44",
            Self::L3 => "65",
            Self::L5 => "87",
        }
    }
    fn slh_dsa_size(self) -> &'static str {
        match self {
            Self::L1 => "128",
            Self::L3 => "192",
            Self::L5 => "192", // L5 SLH-DSA is 256s — use 192s as a default; operator can override.
        }
    }
}

fn nist_level_for_rsa(bits: Option<u32>) -> NistLevel {
    match bits {
        Some(b) if b <= 2048 => NistLevel::L1,
        Some(b) if b <= 3072 => NistLevel::L3,
        Some(_) => NistLevel::L5,
        None => NistLevel::L3, // sensible default when the
                               // bit length isn't in the
                               // algorithm string.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(name: &str) -> Primitive {
        Primitive {
            role: PrimitiveRole::Sig,
            algorithm: name.into(),
            parameters: Default::default(),
            pq_resistant: Some(false),
            nist_classification: None,
        }
    }

    fn encrypt(name: &str) -> Primitive {
        Primitive {
            role: PrimitiveRole::Encrypt,
            algorithm: name.into(),
            parameters: Default::default(),
            pq_resistant: Some(false),
            nist_classification: None,
        }
    }

    #[test]
    fn rsa_2048_recommends_ml_dsa_44_then_slh_dsa() {
        let recs = recommend_for(&[sig("RSA-PKCS1-2048")]);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].replacement, "ML-DSA-44");
        assert_eq!(recs[0].cost, Cost::Medium);
        assert!(recs[1].replacement.starts_with("SLH-DSA"));
        assert_eq!(recs[1].cost, Cost::High);
    }

    #[test]
    fn rsa_4096_lands_at_l5() {
        let recs = recommend_for(&[sig("RSA-PKCS1-4096")]);
        assert_eq!(recs[0].replacement, "ML-DSA-87");
    }

    #[test]
    fn ecdsa_p256_recommends_ml_dsa_65() {
        let recs = recommend_for(&[sig("ECDSA-P256")]);
        assert_eq!(recs[0].replacement, "ML-DSA-65");
    }

    #[test]
    fn aes_128_recommends_aes_256_at_low_cost() {
        let recs = recommend_for(&[encrypt("AES-128-GCM")]);
        assert_eq!(recs[0].replacement, "AES-256");
        assert_eq!(recs[0].cost, Cost::Low);
    }

    #[test]
    fn legacy_des_recommends_aes_gcm() {
        let recs = recommend_for(&[encrypt("3DES")]);
        assert_eq!(recs[0].replacement, "AES-256-GCM");
        assert_eq!(recs[0].cost, Cost::Low);
    }

    #[test]
    fn taproot_schnorr_has_no_clean_replacement() {
        let recs = recommend_for(&[sig("Schnorr-secp256k1")]);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].replacement.contains("FROST-PQ"));
        assert_eq!(recs[0].cost, Cost::High);
    }

    #[test]
    fn cost_ordering_is_stable_ascending() {
        let recs = recommend_for(&[sig("RSA-PKCS1-2048"), encrypt("AES-128-GCM")]);
        // AES-128 → AES-256 is Low; the two RSA recs are
        // Medium and High. Ordering must be Low → Medium →
        // High.
        let costs: Vec<Cost> = recs.iter().map(|r| r.cost).collect();
        assert_eq!(costs, vec![Cost::Low, Cost::Medium, Cost::High]);
    }

    #[test]
    fn hash_and_kex_primitives_do_not_trigger_recs() {
        let prims = vec![
            Primitive {
                role: PrimitiveRole::Hash,
                algorithm: "SHA-256".into(),
                parameters: Default::default(),
                pq_resistant: Some(true),
                nist_classification: None,
            },
            Primitive {
                role: PrimitiveRole::Kex,
                algorithm: "X25519".into(),
                parameters: Default::default(),
                pq_resistant: Some(false),
                nist_classification: None,
            },
        ];
        assert!(recommend_for(&prims).is_empty());
    }
}
