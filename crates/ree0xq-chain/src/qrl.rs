//! QRL (Quantum Resistant Ledger) address classifier
//! (SEZ-14).
//!
//! QRL is a PQ-native chain — every address spends with
//! **XMSS**, a hash-based, stateful signature scheme
//! (NIST SP 800-208). The point of including QRL in V3 is
//! to prove that the existing `crypto_inventory_event`
//! schema doesn't fall over on hash-based PQ signatures:
//! `pq_resistant: true`, no NIST classification level (XMSS
//! is its own family, not one of the FIPS 203-205
//! standards), and the primitive name surfaces as `XMSS`.
//!
//! ## Address format
//!
//! QRL addresses are 79 characters starting with the
//! single letter `Q` and followed by 78 hex digits — a
//! prefix byte plus a hash of the XMSS public key. The
//! classifier accepts that exact shape; other variants
//! (testnet, base32 alternatives) aren't in the production
//! corpus today.

use ree0xq_core::{Primitive, PrimitiveRole};
use tracing::{debug, warn};

use crate::event::build_event;

const QRL_HEX_LEN: usize = 78;

/// Returns `true` when `s` is a syntactically valid QRL
/// mainnet address (`Q` + 78 hex chars).
pub fn is_valid(address: &str) -> bool {
    let s = address.trim();
    let Some(rest) = s.strip_prefix('Q') else {
        return false;
    };
    rest.len() == QRL_HEX_LEN && rest.chars().all(|c| c.is_ascii_hexdigit())
}

/// Primitive list every QRL address spends with.
pub fn primitives() -> Vec<Primitive> {
    vec![
        Primitive {
            role: PrimitiveRole::Sig,
            algorithm: "XMSS".into(),
            parameters: Default::default(),
            // XMSS is hash-based and quantum-resistant — see
            // NIST SP 800-208. Stateful signatures: the
            // signer must track an internal counter or
            // signatures lose their security; that's the
            // operational caveat documented for QRL.
            pq_resistant: Some(true),
            // XMSS is standardised by NIST SP 800-208,
            // separate from the FIPS 203/204/205 family,
            // so we leave the level unset rather than
            // misrepresent it.
            nist_classification: None,
        },
        Primitive {
            role: PrimitiveRole::Hash,
            algorithm: "SHA-256".into(),
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
            warn!(address = %addr, "invalid QRL address; skipping");
            stats.addresses_skipped_invalid += 1;
            continue;
        }
        stats.addresses_classified += 1;
        let prims = primitives();
        let rationale =
            "QRL address; XMSS hash-based PQ signature (stateful) + SHA-256 hash. Quantum-resistant under standard hash-collision assumptions.".to_string();
        debug!(address = %addr, "qrl classify");
        let ev = build_event("qrl", addr.trim(), prims, rationale);
        stats.events_emitted += 1;
        on_event(ev);
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_addr() -> String {
        // Q + 78 hex chars. Not a real QRL address; the
        // shape is what matters for classification.
        format!("Q{}", "0".repeat(78))
    }

    #[test]
    fn accepts_canonical_qrl_address_shape() {
        assert!(is_valid(&fake_addr()));
        // 78 hex chars mix of digits + a-f also works. Build
        // exactly 78 hex chars: 64-char block + 14 more.
        let body: String = "0123456789abcdef".repeat(4) + "deadbeefdeadbe"; // 64 + 14 = 78
        assert_eq!(body.len(), 78);
        assert!(is_valid(&format!("Q{body}")));
    }

    #[test]
    fn rejects_malformed_qrl_addresses() {
        assert!(!is_valid(""));
        assert!(!is_valid("Q"));
        assert!(!is_valid("Qshort"));
        // No leading Q.
        assert!(!is_valid(&"a".repeat(79)));
        // Wrong length.
        assert!(!is_valid(&format!("Q{}", "0".repeat(77))));
        assert!(!is_valid(&format!("Q{}", "0".repeat(79))));
        // Non-hex char in the body.
        assert!(!is_valid(&format!("Q{}", "z".repeat(78))));
    }

    #[test]
    fn primitives_are_xmss_pq_safe() {
        let prims = primitives();
        let sig = prims.iter().find(|p| p.role == PrimitiveRole::Sig).unwrap();
        assert_eq!(sig.algorithm, "XMSS");
        assert_eq!(sig.pq_resistant, Some(true));
        assert!(prims
            .iter()
            .any(|p| p.role == PrimitiveRole::Hash && p.algorithm == "SHA-256"));
    }

    #[test]
    fn scan_emits_per_address_and_drops_invalid() {
        let valid = fake_addr();
        let addrs = vec![
            valid.clone(),
            "not-qrl".to_string(),
            format!("Q{}", "0".repeat(77)), // wrong length
        ];
        let mut emitted = Vec::new();
        let stats = scan_addresses(&addrs, |ev| emitted.push(ev));
        assert_eq!(stats.addresses_seen, 3);
        assert_eq!(stats.addresses_classified, 1);
        assert_eq!(stats.addresses_skipped_invalid, 2);
        assert_eq!(stats.events_emitted, 1);
        assert!(emitted[0].asset.host.as_deref() == Some("qrl"));
        // The event must carry the pq_resistant flag on the
        // XMSS primitive — that's the whole point of V3.2.
        let sig = emitted[0]
            .primitives
            .iter()
            .find(|p| p.role == PrimitiveRole::Sig)
            .unwrap();
        assert_eq!(sig.pq_resistant, Some(true));
        assert_eq!(sig.algorithm, "XMSS");
    }
}
