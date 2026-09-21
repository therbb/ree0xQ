//! Bitcoin address-type classifier (SEZ-12).
//!
//! Five canonical script types in the wild today:
//!
//! - **P2PKH** (Pay-to-PubKey-Hash). Legacy. Mainnet
//!   addresses start with `1`, testnet with `m` or `n`.
//!   Spends with **ECDSA** over secp256k1; the address
//!   itself is a RIPEMD-160(SHA-256(pubkey)).
//! - **P2SH** (Pay-to-Script-Hash). Mainnet starts with
//!   `3`, testnet with `2`. The redeem script can be
//!   anything; in practice most P2SH wrap a P2WPKH (P2SH-
//!   P2WPKH), so spending still uses ECDSA-secp256k1.
//! - **P2WPKH** (native SegWit v0, pubkey hash). Mainnet
//!   `bc1q…` 42 chars total, testnet `tb1q…`. ECDSA.
//! - **P2WSH** (native SegWit v0, script hash). Same
//!   prefix as P2WPKH, length 62 chars. The witness
//!   script can be anything; ECDSA is the overwhelmingly
//!   common case.
//! - **P2TR** (Taproot, SegWit v1). Mainnet `bc1p…` 62
//!   chars, testnet `tb1p…`. Spends with **Schnorr** over
//!   secp256k1.
//!
//! Classification is prefix + length based. We don't
//! actually base58- or bech32-decode the addresses — the
//! prefix and length are sufficient to map onto the
//! primitive set, and a malformed-but-prefix-matching
//! address still classifies to the right primitives at the
//! cost of being a "ghost" entry in the operator's
//! inventory (handled by the address-list curation step
//! upstream of this binary).

use ree0xq_core::{Primitive, PrimitiveRole};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::event::build_event;

/// Bitcoin script type as inferred from the address prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptType {
    P2pkh,
    P2sh,
    P2wpkh,
    P2wsh,
    P2tr,
}

impl ScriptType {
    /// Human-readable label for the rationale string.
    pub fn label(&self) -> &'static str {
        match self {
            Self::P2pkh => "P2PKH",
            Self::P2sh => "P2SH",
            Self::P2wpkh => "P2WPKH",
            Self::P2wsh => "P2WSH",
            Self::P2tr => "P2TR (Taproot)",
        }
    }

    /// Primitive list this script type spends with.
    pub fn primitives(&self) -> Vec<Primitive> {
        match self {
            // Schnorr signatures for Taproot.
            Self::P2tr => vec![
                Primitive {
                    role: PrimitiveRole::Sig,
                    algorithm: "Schnorr-secp256k1".into(),
                    parameters: Default::default(),
                    pq_resistant: Some(false),
                    nist_classification: None,
                },
                Primitive {
                    role: PrimitiveRole::Hash,
                    algorithm: "SHA-256".into(),
                    parameters: Default::default(),
                    pq_resistant: Some(true),
                    nist_classification: None,
                },
            ],
            // Everything else: ECDSA + SHA-256 (the
            // RIPEMD-160 layer is a hash-only step, not
            // a signature primitive, so we surface SHA-256
            // as the visible hash).
            _ => vec![
                Primitive {
                    role: PrimitiveRole::Sig,
                    algorithm: "ECDSA-secp256k1".into(),
                    parameters: Default::default(),
                    pq_resistant: Some(false),
                    nist_classification: None,
                },
                Primitive {
                    role: PrimitiveRole::Hash,
                    algorithm: "SHA-256".into(),
                    parameters: Default::default(),
                    pq_resistant: Some(true),
                    nist_classification: None,
                },
            ],
        }
    }
}

/// Map an address string onto a [`ScriptType`]. Returns
/// `None` for anything that doesn't match a known prefix /
/// length pair. The function is deliberately strict — an
/// unrecognised prefix is more useful as a "skipped" log
/// line than as a misclassified event.
pub fn classify(address: &str) -> Option<ScriptType> {
    let trimmed = address.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    // bech32 (SegWit v0 / v1). bech32 is case-insensitive
    // by spec; we lowercase before checking.
    if let Some(suffix) = lower
        .strip_prefix("bc1q")
        .or_else(|| lower.strip_prefix("tb1q"))
    {
        // P2WPKH = 32-byte witness program → 38 chars of
        // bech32 data (suffix after the `bc1q` separator).
        // P2WSH  = 32 → 58 chars suffix. We use the total
        // address length as the cleaner discriminator.
        let total = lower.len();
        return Some(match total {
            42 => ScriptType::P2wpkh, // bc1q + 38 data
            62 => ScriptType::P2wsh,  // bc1q + 58 data
            _ => return None,
        });
        // P2WPKH on testnet is also 42 (`tb1q…`), matches above.
    }
    if let Some(_suffix) = lower
        .strip_prefix("bc1p")
        .or_else(|| lower.strip_prefix("tb1p"))
    {
        if lower.len() == 62 {
            return Some(ScriptType::P2tr);
        }
        return None;
    }
    // Base58 (legacy). Length 26..35 typical (canonical 33-34).
    let leading = trimmed.chars().next()?;
    let len = trimmed.len();
    if !(26..=35).contains(&len) {
        return None;
    }
    match leading {
        '1' | 'm' | 'n' => Some(ScriptType::P2pkh),
        '3' | '2' => Some(ScriptType::P2sh),
        _ => None,
    }
}

/// Per-run stats from [`scan_addresses`].
#[derive(Debug, Default, Clone, Copy)]
pub struct ScanStats {
    pub addresses_seen: usize,
    pub addresses_classified: usize,
    pub addresses_skipped_unknown: usize,
    pub events_emitted: usize,
}

/// Drive the classifier across an address list, calling
/// `on_event` once per recognised address.
pub fn scan_addresses<F>(addresses: &[String], mut on_event: F) -> ScanStats
where
    F: FnMut(ree0xq_core::CryptoInventoryEvent),
{
    let mut stats = ScanStats::default();
    for addr in addresses {
        stats.addresses_seen += 1;
        match classify(addr) {
            Some(st) => {
                stats.addresses_classified += 1;
                let prims = st.primitives();
                let rationale = format!(
                    "Bitcoin {} address; spends with {} + SHA-256",
                    st.label(),
                    prims
                        .iter()
                        .find(|p| p.role == PrimitiveRole::Sig)
                        .map(|p| p.algorithm.as_str())
                        .unwrap_or("?")
                );
                debug!(address = %addr, script_type = ?st, "classified");
                let ev = build_event("bitcoin", addr, prims, rationale);
                stats.events_emitted += 1;
                on_event(ev);
            }
            None => {
                warn!(address = %addr, "unrecognised Bitcoin address; skipping");
                stats.addresses_skipped_unknown += 1;
            }
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_canonical_mainnet_addresses() {
        // Famous addresses (Genesis coinbase, real-world examples).
        // P2PKH: Bitcoin genesis block coinbase.
        assert_eq!(
            classify("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            Some(ScriptType::P2pkh)
        );
        // P2SH: any '3' prefix, 34 chars.
        assert_eq!(
            classify("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"),
            Some(ScriptType::P2sh)
        );
        // P2WPKH: 42 chars total, 'bc1q' prefix.
        assert_eq!(
            classify("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
            Some(ScriptType::P2wpkh)
        );
        // P2WSH: 62 chars total.
        assert_eq!(
            classify("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"),
            Some(ScriptType::P2wsh)
        );
        // P2TR: 62 chars, 'bc1p'.
        assert_eq!(
            classify("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"),
            Some(ScriptType::P2tr)
        );
    }

    #[test]
    fn p2pkh_primitives_are_ecdsa_secp256k1() {
        let prims = ScriptType::P2pkh.primitives();
        assert_eq!(prims.len(), 2);
        assert!(prims
            .iter()
            .any(|p| p.role == PrimitiveRole::Sig && p.algorithm == "ECDSA-secp256k1"));
        assert!(prims
            .iter()
            .any(|p| p.role == PrimitiveRole::Hash && p.algorithm == "SHA-256"));
    }

    #[test]
    fn p2tr_primitives_are_schnorr() {
        let prims = ScriptType::P2tr.primitives();
        assert!(prims
            .iter()
            .any(|p| p.role == PrimitiveRole::Sig && p.algorithm == "Schnorr-secp256k1"));
    }

    #[test]
    fn unrecognised_addresses_are_rejected() {
        assert_eq!(classify(""), None);
        assert_eq!(classify("not-an-address"), None);
        assert_eq!(classify("4abc"), None); // wrong prefix
                                            // Wrong length for bech32 v0:
        assert_eq!(classify("bc1q123"), None);
    }

    #[test]
    fn scan_emits_per_address_with_correct_chain() {
        let addrs = vec![
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr".to_string(),
            "not-real".to_string(),
        ];
        let mut emitted = Vec::new();
        let stats = scan_addresses(&addrs, |ev| emitted.push(ev));
        assert_eq!(stats.addresses_seen, 3);
        assert_eq!(stats.addresses_classified, 2);
        assert_eq!(stats.addresses_skipped_unknown, 1);
        assert_eq!(stats.events_emitted, 2);
        assert!(emitted
            .iter()
            .all(|ev| ev.asset.host.as_deref() == Some("bitcoin")));
        assert!(emitted[0].asset.identity.starts_with("bitcoin:1"));
        assert!(emitted[1].asset.identity.starts_with("bitcoin:bc1p"));
    }
}
