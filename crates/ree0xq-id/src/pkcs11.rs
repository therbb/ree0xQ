//! PKCS#11 backend (SEZ-16, feature `pkcs11`).
//!
//! The cryptoki crate wraps a vendor-supplied PKCS#11
//! library (`libsofthsm2.so`, `libnss3.so`, an HSM's
//! proprietary `.so`, …) and exposes `C_OpenSession`,
//! `C_FindObjectsInit`, etc. as Rust types. We list every
//! token slot, walk its objects, classify each public key
//! by `CKA_KEY_TYPE` + `CKA_MODULUS_BITS` /
//! `CKA_EC_PARAMS`, and emit one `crypto_inventory_event`
//! per key.
//!
//! End-to-end validation is operator-side because the dev /
//! CI environment doesn't have a vendor PKCS#11 library
//! installed by default. The companion runbook at
//! [`docs/ree0xq-id-pkcs11.md`](../../../docs/ree0xq-id-pkcs11.md)
//! walks the SoftHSM-based reproducer.

use anyhow::{Context, Result};
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use std::path::Path;

use crate::algos::primitives_for;
use crate::event::build_event;

/// Caller-supplied configuration for [`scan`].
pub struct Pkcs11Config<'a> {
    /// Path to the vendor PKCS#11 shared library
    /// (e.g. `/usr/lib/softhsm/libsofthsm2.so`).
    pub library: &'a Path,
    /// Optional user PIN; when set the scanner opens an
    /// authenticated session and can see private-only
    /// objects. Without a PIN we still see the public
    /// half — enough for inventory.
    pub user_pin: Option<&'a str>,
    /// Restrict to a specific slot id; `None` walks every
    /// slot the library reports.
    pub only_slot: Option<u64>,
}

/// Per-run stats from [`scan`].
#[derive(Debug, Default, Clone, Copy)]
pub struct ScanStats {
    pub slots_seen: usize,
    pub objects_seen: usize,
    pub events_emitted: usize,
    pub objects_skipped: usize,
}

/// Drive the PKCS#11 walker.
pub fn scan<F>(cfg: &Pkcs11Config<'_>, mut on_event: F) -> Result<ScanStats>
where
    F: FnMut(ree0xq_core::CryptoInventoryEvent),
{
    let pkcs11 = Pkcs11::new(cfg.library)
        .with_context(|| format!("load PKCS#11 lib {}", cfg.library.display()))?;
    pkcs11
        .initialize(CInitializeArgs::OsThreads)
        .context("C_Initialize")?;

    let mut stats = ScanStats::default();
    let slots = pkcs11.get_slots_with_token()?;
    for slot in slots {
        let raw_slot: u64 = slot.id();
        if let Some(want) = cfg.only_slot {
            if want != raw_slot {
                continue;
            }
        }
        stats.slots_seen += 1;
        let token_info = pkcs11.get_token_info(slot).context("get_token_info")?;
        let token_label = token_info.label().to_string();
        let session = pkcs11
            .open_ro_session(slot)
            .with_context(|| format!("open_ro_session(slot={raw_slot})"))?;
        if let Some(pin) = cfg.user_pin {
            session
                .login(UserType::User, Some(&AuthPin::new(pin.into())))
                .context("C_Login")?;
        }

        // Walk every public-key + secret-key object.
        for class in [ObjectClass::PUBLIC_KEY, ObjectClass::SECRET_KEY] {
            let handles = session
                .find_objects(&[Attribute::Class(class)])
                .context("C_FindObjects")?;
            for h in handles {
                stats.objects_seen += 1;
                let attrs = session.get_attributes(
                    h,
                    &[
                        AttributeType::Label,
                        AttributeType::KeyType,
                        AttributeType::ModulusBits,
                        AttributeType::EcParams,
                    ],
                )?;
                let mut label = String::new();
                let mut kt: Option<KeyType> = None;
                let mut bits: Option<u32> = None;
                for a in attrs {
                    match a {
                        Attribute::Label(b) => label = String::from_utf8_lossy(&b).to_string(),
                        Attribute::KeyType(v) => kt = Some(v),
                        Attribute::ModulusBits(v) => bits = Some(u64::from(v) as u32),
                        _ => {}
                    }
                }
                let Some(kt) = kt else {
                    stats.objects_skipped += 1;
                    continue;
                };
                let key_spec = key_type_label(kt);
                let prims = primitives_for(&key_spec, bits);
                let identity = format!("pkcs11:{token_label}/slot:{raw_slot}/{label}");
                let host = Some(format!("PKCS#11 {token_label}"));
                let rationale = format!(
                    "PKCS#11 {} {} on slot {}{}",
                    class_label(class),
                    key_spec,
                    raw_slot,
                    bits.map(|b| format!(" ({b}-bit)")).unwrap_or_default(),
                );
                on_event(build_event(identity, host, prims, rationale));
                stats.events_emitted += 1;
            }
        }
    }
    Ok(stats)
}

fn key_type_label(kt: KeyType) -> String {
    // cryptoki's KeyType is a struct with raw CKK_* constants;
    // Debug renders something useful but the readable
    // mapping is small and we want it stable.
    match kt {
        KeyType::RSA => "RSA".into(),
        KeyType::EC => "ECDSA-P256".into(), // refined by EcParams when we add OID parsing
        KeyType::AES => "AES".into(),
        KeyType::EC_EDWARDS => "Ed25519".into(),
        _ => format!("{kt:?}"),
    }
}

fn class_label(c: ObjectClass) -> &'static str {
    if c == ObjectClass::PUBLIC_KEY {
        "public-key"
    } else if c == ObjectClass::SECRET_KEY {
        "secret-key"
    } else {
        "object"
    }
}
