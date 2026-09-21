//! ETSI GS QKD 014 V1.1.1 (2019-02) wire types.
//!
//! Reference: ETSI GS QKD 014 V1.1.1, *Quantum Key Distribution (QKD);
//! Protocol and data format of REST-based key delivery API*, February
//! 2019.
//! <https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf>
//!
//! All structures here are JSON-on-the-wire; field naming follows the
//! spec exactly (snake_case) so that captures from real KMEs round-trip
//! without coercion. The emulator and the collector are both built on
//! these types — any change here must be agreed across both.

use serde::{Deserialize, Serialize};

/// Path components of the v1 API. We keep the version path literal in
/// one place so the collector and emulator don't drift.
pub mod paths {
    /// Base for every v1 endpoint.
    pub const BASE: &str = "/api/v1/keys";

    /// `GET /api/v1/keys/{slave_SAE_ID}/status`
    pub const STATUS: &str = "status";

    /// `GET /api/v1/keys/{slave_SAE_ID}/enc_keys`
    pub const ENC_KEYS: &str = "enc_keys";

    /// `POST /api/v1/keys/{master_SAE_ID}/dec_keys`
    pub const DEC_KEYS: &str = "dec_keys";
}

/// Response body of `GET /api/v1/keys/{slave_SAE_ID}/status`.
///
/// Fields per ETSI GS QKD 014 §5.1, Table 1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StatusResponse {
    /// KME ID of the KME that this status refers to.
    #[serde(rename = "source_KME_ID")]
    pub source_kme_id: String,
    /// KME ID of the target KME (the SAE's remote peer's KME).
    #[serde(rename = "target_KME_ID")]
    pub target_kme_id: String,
    /// SAE ID of the master SAE (the calling SAE).
    #[serde(rename = "master_SAE_ID")]
    pub master_sae_id: String,
    /// SAE ID of the slave SAE (the peer SAE).
    #[serde(rename = "slave_SAE_ID")]
    pub slave_sae_id: String,
    /// Default key size in bits.
    pub key_size: u32,
    /// Number of keys currently stored and ready for delivery.
    pub stored_key_count: u32,
    /// Maximum number of keys the KME can store.
    pub max_key_count: u32,
    /// Maximum number of keys per request.
    pub max_key_per_request: u32,
    /// Maximum key size in bits.
    pub max_key_size: u32,
    /// Minimum key size in bits.
    pub min_key_size: u32,
    /// Maximum number of additional slave SAE IDs per request.
    #[serde(rename = "max_SAE_ID_count")]
    pub max_sae_id_count: u32,

    // ----- Extension fields (vendor-specific allowed per spec §5.1) -----
    //
    // We surface telemetry that real-world KMEs commonly expose
    // and that ree0xQ relies on. These are tolerated by spec-compliant
    // clients that do not recognise them.
    /// Observed QBER on the underlying link, on [0.0, 1.0].
    /// ree0xQ/emulator extension; ignored by minimal clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_qber: Option<f32>,
    /// Average key-generation rate over the prior minute (bits/sec).
    /// ree0xQ/emulator extension.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_key_rate_bps: Option<u64>,
}

/// Container returned by `GET /enc_keys` or `POST /dec_keys` carrying
/// one or more keys.
///
/// Fields per ETSI GS QKD 014 §5.2 / §5.3.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyContainer {
    /// One or more keys.
    pub keys: Vec<Key>,
}

/// A single QKD-delivered key.
///
/// Fields per ETSI GS QKD 014 §5.2, Table 4.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Key {
    /// UUID v4 identifying the key.
    #[serde(rename = "key_ID")]
    pub key_id: String,
    /// Base64-encoded key material. The key length matches the
    /// `key_size` advertised in `StatusResponse` unless the request
    /// specified otherwise.
    pub key: String,
}

/// Query parameters for `GET /enc_keys` per ETSI GS QKD 014 §5.2.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EncKeysQuery {
    /// Requested key size in bits. If absent, the default
    /// (`StatusResponse::key_size`) is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
    /// Requested number of keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<u32>,
}

/// Request body for `POST /dec_keys` per ETSI GS QKD 014 §5.3.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[allow(non_snake_case)] // field name mandated by ETSI GS QKD 014 §5.3
pub struct DecKeysRequest {
    /// One or more key IDs whose material is requested.
    pub key_IDs: Vec<DecKeyId>,
}

/// One entry in [`DecKeysRequest`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecKeyId {
    /// UUID of the requested key, returned previously by the master
    /// KME's `/enc_keys` call.
    #[serde(rename = "key_ID")]
    pub key_id: String,
}

/// Error response shape used by ETSI 014 KMEs.
///
/// Fields per ETSI GS QKD 014 §5.4.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorResponse {
    /// Short message classifying the error (e.g. `"size_too_large"`,
    /// `"key_not_available"`, `"unauthorized"`).
    pub message: String,
    /// Free-form list of additional details. Spec-permitted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_response_round_trips_through_json() {
        let s = StatusResponse {
            source_kme_id: "KME-A".into(),
            target_kme_id: "KME-B".into(),
            master_sae_id: "SAE-A1".into(),
            slave_sae_id: "SAE-B1".into(),
            key_size: 256,
            stored_key_count: 1024,
            max_key_count: 100_000,
            max_key_per_request: 128,
            max_key_size: 4096,
            min_key_size: 64,
            max_sae_id_count: 0,
            link_qber: Some(0.018),
            link_key_rate_bps: Some(12_480),
        };
        let j = serde_json::to_string(&s).unwrap();
        // Field naming must match spec (capitalisation matters).
        assert!(j.contains("\"source_KME_ID\""));
        assert!(j.contains("\"target_KME_ID\""));
        assert!(j.contains("\"master_SAE_ID\""));
        assert!(j.contains("\"slave_SAE_ID\""));
        let back: StatusResponse = serde_json::from_str(&j).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn key_container_round_trips() {
        let c = KeyContainer {
            keys: vec![Key {
                key_id: "9c45e0a2-b7f4-4ed9-9e2a-1d33c2b9a0bb".into(),
                key: "BASE64=".into(),
            }],
        };
        let j = serde_json::to_string(&c).unwrap();
        assert!(j.contains("\"key_ID\""));
        let back: KeyContainer = serde_json::from_str(&j).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn vendor_extension_fields_omit_when_none() {
        let s = StatusResponse {
            source_kme_id: "KME-A".into(),
            target_kme_id: "KME-B".into(),
            master_sae_id: "SAE-A1".into(),
            slave_sae_id: "SAE-B1".into(),
            key_size: 256,
            stored_key_count: 0,
            max_key_count: 1,
            max_key_per_request: 1,
            max_key_size: 256,
            min_key_size: 256,
            max_sae_id_count: 0,
            link_qber: None,
            link_key_rate_bps: None,
        };
        let j = serde_json::to_string(&s).unwrap();
        assert!(
            !j.contains("link_qber"),
            "extension fields must be omitted when None: {j}"
        );
        assert!(
            !j.contains("link_key_rate_bps"),
            "extension fields must be omitted when None: {j}"
        );
    }
}
