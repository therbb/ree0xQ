//! Offline HSM inventory classifier (SEZ-15).
//!
//! The operator runs an export script against each HSM in
//! their environment and produces a JSON file like:
//!
//! ```json
//! [
//!   {
//!     "hsm_vendor":  "Thales nShield",
//!     "hsm_model":   "Connect XC",
//!     "slot_id":     "0",
//!     "label":       "Production CA Signing",
//!     "keys": [
//!       {
//!         "key_id":         "ca-sign-2024",
//!         "key_type":       "RSA",
//!         "key_size_bits":  4096,
//!         "usage":          ["sign", "verify"]
//!       },
//!       {
//!         "key_id":   "tls-server-2026",
//!         "key_type": "ECDSA-P256",
//!         "usage":    ["sign"]
//!       }
//!     ]
//!   }
//! ]
//! ```
//!
//! `ree0xq-id inventory-scan --input <file>` walks the
//! JSON, maps each `(key_type, key_size_bits?)` through
//! [`crate::algos::primitives_for`], and emits one
//! `crypto_inventory_event` per key. The event's identity
//! is `<hsm_vendor>/<slot_id>/<key_id>`, the host is the
//! vendor/model pair so the dashboard can group keys per
//! HSM.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::algos::primitives_for;
use crate::event::build_event;

/// One HSM/slot snapshot. Matches the JSON input shape.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SlotInventory {
    pub hsm_vendor: String,
    pub hsm_model: Option<String>,
    pub slot_id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub keys: Vec<KeyInventory>,
}

/// One key on a slot.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyInventory {
    pub key_id: String,
    pub key_type: String,
    #[serde(default)]
    pub key_size_bits: Option<u32>,
    #[serde(default)]
    pub usage: Vec<String>,
}

/// Per-run stats from [`scan`].
#[derive(Debug, Default, Clone, Copy)]
pub struct ScanStats {
    pub slots_seen: usize,
    pub keys_seen: usize,
    pub events_emitted: usize,
}

/// Drive the offline classifier across a parsed inventory.
pub fn scan<F>(inventory: &[SlotInventory], mut on_event: F) -> ScanStats
where
    F: FnMut(ree0xq_core::CryptoInventoryEvent),
{
    let mut stats = ScanStats::default();
    for slot in inventory {
        stats.slots_seen += 1;
        let host = match &slot.hsm_model {
            Some(m) => Some(format!("{} {}", slot.hsm_vendor, m)),
            None => Some(slot.hsm_vendor.clone()),
        };
        for key in &slot.keys {
            stats.keys_seen += 1;
            let prims = primitives_for(&key.key_type, key.key_size_bits);
            let identity = format!("{}/{}/{}", slot.hsm_vendor, slot.slot_id, key.key_id);
            let rationale = format!(
                "HSM slot {} on {} {}: key {} ({}{}), usage={}",
                slot.slot_id,
                slot.hsm_vendor,
                slot.hsm_model.as_deref().unwrap_or("(unknown model)"),
                key.key_id,
                key.key_type,
                key.key_size_bits
                    .map(|b| format!(" {b}b"))
                    .unwrap_or_default(),
                if key.usage.is_empty() {
                    "?".into()
                } else {
                    key.usage.join(",")
                },
            );
            on_event(build_event(identity, host.clone(), prims, rationale));
            stats.events_emitted += 1;
        }
    }
    stats
}

/// Convenience: parse a JSON file then [`scan`] it.
pub fn scan_file<F>(path: &str, on_event: F) -> Result<ScanStats>
where
    F: FnMut(ree0xq_core::CryptoInventoryEvent),
{
    let raw = std::fs::read_to_string(path).with_context(|| format!("read inventory {path}"))?;
    let inv: Vec<SlotInventory> =
        serde_json::from_str(&raw).with_context(|| format!("parse inventory {path}"))?;
    Ok(scan(&inv, on_event))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ree0xq_core::{AssetKind, PrimitiveRole};

    fn fixture() -> Vec<SlotInventory> {
        vec![
            SlotInventory {
                hsm_vendor: "Thales nShield".into(),
                hsm_model: Some("Connect XC".into()),
                slot_id: "0".into(),
                label: Some("Production CA".into()),
                keys: vec![
                    KeyInventory {
                        key_id: "ca-sign-2024".into(),
                        key_type: "RSA".into(),
                        key_size_bits: Some(4096),
                        usage: vec!["sign".into(), "verify".into()],
                    },
                    KeyInventory {
                        key_id: "tls-server-2026".into(),
                        key_type: "ECDSA-P256".into(),
                        key_size_bits: None,
                        usage: vec!["sign".into()],
                    },
                ],
            },
            SlotInventory {
                hsm_vendor: "YubiHSM 2".into(),
                hsm_model: Some("2.4".into()),
                slot_id: "1".into(),
                label: None,
                keys: vec![KeyInventory {
                    key_id: "code-sign-pq".into(),
                    key_type: "ML-DSA-65".into(),
                    key_size_bits: None,
                    usage: vec!["sign".into()],
                }],
            },
        ]
    }

    #[test]
    fn scan_emits_one_event_per_key() {
        let inv = fixture();
        let mut events = Vec::new();
        let stats = scan(&inv, |ev| events.push(ev));
        assert_eq!(stats.slots_seen, 2);
        assert_eq!(stats.keys_seen, 3);
        assert_eq!(stats.events_emitted, 3);
        for ev in &events {
            assert_eq!(ev.asset.kind, AssetKind::HsmSlot);
        }
        // Identity convention: vendor/slot/key_id.
        let identities: Vec<&str> = events.iter().map(|e| e.asset.identity.as_str()).collect();
        assert!(identities.contains(&"Thales nShield/0/ca-sign-2024"));
        assert!(identities.contains(&"YubiHSM 2/1/code-sign-pq"));
    }

    #[test]
    fn pq_key_carries_pq_flag() {
        let inv = fixture();
        let mut events = Vec::new();
        scan(&inv, |ev| events.push(ev));
        let pq = events
            .iter()
            .find(|e| e.asset.identity.ends_with("/code-sign-pq"))
            .unwrap();
        let sig = pq
            .primitives
            .iter()
            .find(|p| p.role == PrimitiveRole::Sig)
            .unwrap();
        assert_eq!(sig.algorithm, "ML-DSA-65");
        assert_eq!(sig.pq_resistant, Some(true));
    }

    #[test]
    fn missing_key_size_for_rsa_falls_back_gracefully() {
        let inv = vec![SlotInventory {
            hsm_vendor: "v".into(),
            hsm_model: None,
            slot_id: "0".into(),
            label: None,
            keys: vec![KeyInventory {
                key_id: "k".into(),
                key_type: "RSA".into(),
                key_size_bits: None,
                usage: vec![],
            }],
        }];
        let mut events = Vec::new();
        scan(&inv, |ev| events.push(ev));
        // RSA without explicit size still emits an event;
        // the algorithm string just lacks a bit suffix.
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].primitives[0].algorithm, "RSA-PKCS1");
    }

    #[test]
    fn scan_file_round_trips() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), serde_json::to_string(&fixture()).unwrap()).unwrap();
        let mut events = Vec::new();
        let stats = scan_file(tmp.path().to_str().unwrap(), |ev| events.push(ev)).unwrap();
        assert_eq!(stats.events_emitted, 3);
        assert_eq!(events.len(), 3);
    }
}
