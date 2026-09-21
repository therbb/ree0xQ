//! Ethereum address-type classifier (SEZ-13).
//!
//! Every Ethereum address is a 20-byte identifier
//! displayed as `0x` + 40 hex chars. Externally-owned
//! accounts (EOAs) spend with **secp256k1-ECDSA** + a
//! Keccak-256 hash; smart contracts have no associated
//! key and instead execute bytecode. Distinguishing EOA
//! from contract requires a live RPC call
//! (`eth_getCode`); V3.1 treats every address as
//! EOA-equivalent for the primitive classification and
//! defers contract detection to a future live-RPC backend.
//!
//! EIP-55 checksums (mixed-case addresses) are optional
//! per the spec; the classifier accepts lowercase,
//! uppercase, and mixed-case forms. We don't validate the
//! checksum here — that's a curation step the address-list
//! producer can run.

use ree0xq_core::{Primitive, PrimitiveRole};
use tracing::{debug, warn};

use crate::event::build_event;

const ETH_HEX_LEN: usize = 40;

/// Returns `true` when `s` is a syntactically valid
/// Ethereum address (0x + 40 hex chars).
pub fn is_valid(address: &str) -> bool {
    let s = address.trim();
    let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) else {
        return false;
    };
    rest.len() == ETH_HEX_LEN && rest.chars().all(|c| c.is_ascii_hexdigit())
}

/// Primitive set Ethereum addresses imply.
pub fn primitives() -> Vec<Primitive> {
    vec![
        Primitive {
            role: PrimitiveRole::Sig,
            algorithm: "ECDSA-secp256k1".into(),
            parameters: Default::default(),
            pq_resistant: Some(false),
            nist_classification: None,
        },
        Primitive {
            role: PrimitiveRole::Hash,
            algorithm: "Keccak-256".into(),
            parameters: Default::default(),
            pq_resistant: Some(true),
            nist_classification: None,
        },
    ]
}

/// Stats from one [`scan_addresses`] pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScanStats {
    pub addresses_seen: usize,
    pub addresses_classified: usize,
    pub addresses_skipped_invalid: usize,
    pub events_emitted: usize,
}

/// Drive the classifier across an address list.
pub fn scan_addresses<F>(addresses: &[String], mut on_event: F) -> ScanStats
where
    F: FnMut(ree0xq_core::CryptoInventoryEvent),
{
    let mut stats = ScanStats::default();
    for addr in addresses {
        stats.addresses_seen += 1;
        if !is_valid(addr) {
            warn!(address = %addr, "invalid Ethereum address; skipping");
            stats.addresses_skipped_invalid += 1;
            continue;
        }
        stats.addresses_classified += 1;
        let prims = primitives();
        let rationale = format!(
            "Ethereum address; EOA classification — spends with ECDSA-secp256k1 + Keccak-256. Contract-vs-EOA disambiguation requires a live RPC and is V3.x scope."
        );
        debug!(address = %addr, "ethereum classify");
        let ev = build_event("ethereum", addr.trim(), prims, rationale);
        stats.events_emitted += 1;
        on_event(ev);
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_eth_address_forms() {
        // Vitalik's address — public knowledge.
        assert!(is_valid("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"));
        // All-lowercase.
        assert!(is_valid("0xd8da6bf26964af9d7eed9e03e53415d37aa96045"));
        // All-uppercase.
        assert!(is_valid("0xD8DA6BF26964AF9D7EED9E03E53415D37AA96045"));
        // Capital-X prefix is acceptable per casual usage.
        assert!(is_valid("0Xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"));
    }

    #[test]
    fn rejects_malformed_addresses() {
        assert!(!is_valid(""));
        assert!(!is_valid("0x"));
        assert!(!is_valid("0xshort"));
        assert!(!is_valid("d8da6bf26964af9d7eed9e03e53415d37aa96045")); // no 0x
        assert!(!is_valid("0xd8da6bf26964af9d7eed9e03e53415d37aa96045ZZ")); // wrong length + non-hex
        assert!(!is_valid("0xd8da6bf26964af9d7eed9e03e53415d37aa9604z")); // non-hex
    }

    #[test]
    fn primitives_are_ecdsa_secp256k1_plus_keccak() {
        let prims = primitives();
        assert!(prims
            .iter()
            .any(|p| p.role == PrimitiveRole::Sig && p.algorithm == "ECDSA-secp256k1"));
        assert!(prims
            .iter()
            .any(|p| p.role == PrimitiveRole::Hash && p.algorithm == "Keccak-256"));
    }

    #[test]
    fn scan_emits_per_address_skipping_invalid() {
        let addrs = vec![
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".to_string(),
            "not-an-address".to_string(),
            "0x0000000000000000000000000000000000000000".to_string(),
        ];
        let mut emitted = Vec::new();
        let stats = scan_addresses(&addrs, |ev| emitted.push(ev));
        assert_eq!(stats.addresses_seen, 3);
        assert_eq!(stats.addresses_classified, 2);
        assert_eq!(stats.addresses_skipped_invalid, 1);
        assert_eq!(stats.events_emitted, 2);
        assert!(emitted
            .iter()
            .all(|ev| ev.asset.host.as_deref() == Some("ethereum")));
    }
}
