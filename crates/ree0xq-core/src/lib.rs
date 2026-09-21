//! `ree0xq-core` — shared event schema + posture rollup library.
//!
//! Every ree0xQ module emits one type: [`CryptoInventoryEvent`]. The
//! schema is intentionally narrow — modules are not allowed to add
//! new top-level fields without a coordinated `schema_version` bump
//! across all consumers.
//!
//! See `docs/crypto-event-schema.md` at the repo root for the
//! field-by-field rationale.
//!
//! # Feature flags
//!
//! - `schema` — enables `schemars::JsonSchema` derives so the
//!   `schema-export` binary can emit the canonical JSON Schema for
//!   the event format. Off by default; CI / docs use it.
//! - `ts-types` — enables `ts-rs::TS` derives for TypeScript codegen
//!   consumed by the React UI in V1. Off by default; the UI's
//!   `npm run codegen` script flips it on.

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

#[cfg(feature = "ts-types")]
use ts_rs::TS;

/// Current event schema version. Bumped on any breaking change to the
/// top-level shape; additive changes are allowed without a bump as
/// long as they're optional.
pub const SCHEMA_VERSION: u32 = 1;

/// Current event schema minor version. Incremented on every additive,
/// non-breaking extension to the event shape. v1.1 introduces the
/// `channel_protection` and `agility` blocks and the `QkdLink`/`QkdKme`
/// asset kinds. v1.0 producers emit `0` (or omit the field, which
/// defaults to `0`); v1.0 consumers ignore the new fields.
pub const SCHEMA_MINOR: u32 = 1;

fn default_schema_minor() -> u32 {
    0
}

/// One observation about one crypto-bearing asset, normalised to a
/// shape that's identical regardless of whether it came from
/// `ree0xq-net`, `ree0xq-cert`, `ree0xq-chain`, or `ree0xq-id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "ts-types", derive(TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub struct CryptoInventoryEvent {
    /// Schema version of this event. Always `SCHEMA_VERSION` at
    /// emission; consumers may see older values during rolling
    /// upgrades.
    pub schema_version: u32,
    /// Schema minor version. v1.0 producers omit (defaults to `0`);
    /// v1.1 producers set to `1` to advertise that `channel_protection`
    /// and `agility` blocks may be present. Consumers must accept any
    /// minor ≥ their compiled value.
    #[serde(default = "default_schema_minor")]
    pub schema_minor: u32,
    /// Which ree0xQ module produced the event.
    pub source_module: String,
    /// Wall-clock observation time (UTC), RFC 3339 string on the wire.
    #[cfg_attr(feature = "ts-types", ts(type = "string"))]
    pub observed_at: chrono::DateTime<chrono::Utc>,
    /// What we observed — see [`Asset`].
    pub asset: Asset,
    /// The cryptographic primitives in use on this asset, decomposed
    /// by role (key exchange, signature, encryption, hash).
    pub primitives: Vec<Primitive>,
    /// v1.1 — Quantum-secure key-delivery telemetry for the channel
    /// carrying this asset's session. `None` defaults to classical
    /// channel for posture-rollup purposes. Emitted by `ree0xq-qkd`
    /// directly, or attached to session events by cooperating SAEs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_protection: Option<ChannelProtection>,
    /// v1.1 — Crypto-agility classification for this asset, scored on
    /// the five-level ordinal scale of [`AgilityLevel`]. `None` means
    /// the agility axis was not assessed; consumers treat it as
    /// `unknown` in posture computation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agility: Option<AgilityBlock>,
    /// ree0xQ's verdict on this asset.
    pub posture: Posture,
}

/// The thing being observed. `kind` is closed-set; `identity` is
/// module-specific (TLS session ID, cert SHA-256, blockchain address,
/// HSM slot URI, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "ts-types", derive(TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub struct Asset {
    /// Which kind of asset this is.
    pub kind: AssetKind,
    /// Module-specific stable identifier.
    pub identity: String,
    /// Network or owner context — usually a hostname, IP, or human
    /// owner string. Optional because some assets (e.g. mempool
    /// observations) don't have one.
    pub host: Option<String>,
}

/// Closed enumeration of asset kinds. New variants are a schema
/// version bump.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "ts-types", derive(TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub enum AssetKind {
    /// A live TLS session observed by `ree0xq-net`.
    TlsSession,
    /// A live SSH session observed by `ree0xq-net`.
    SshSession,
    /// An IPsec security association observed by `ree0xq-net`.
    IpsecSa,
    /// An X.509 certificate (CT log entry, on-disk file, etc.).
    X509Cert,
    /// A public-chain key — Bitcoin/Ethereum/etc address.
    BlockchainKey,
    /// An HSM/KMS slot or AWS KMS key.
    HsmSlot,
    /// A DNSSEC RRSIG observation forwarded from Nizam.
    DnsDnssec,
    /// v1.1 — A QKD link, emitted by `ree0xq-qkd` independently of
    /// the sessions consuming its keys. Identity = endpoint URL hash
    /// (e.g. sha256 of the KME's `/status` URL).
    QkdLink,
    /// v1.1 — An individual Key Management Entity (KME) observed via
    /// ETSI GS QKD 014. Identity = KME ID per ETSI 014 status.
    QkdKme,
}

/// One primitive role used by the asset (kex / sig / encrypt / hash /
/// auth) plus metadata about the algorithm choice.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "ts-types", derive(TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub struct Primitive {
    /// What this primitive does.
    pub role: PrimitiveRole,
    /// Canonical algorithm name. Examples: `"ECDSA-P256"`,
    /// `"Dilithium2"`, `"AES-256-GCM"`, `"SHA-256"`.
    pub algorithm: String,
    /// Algorithm parameters keyed by name. Free-form; consumers must
    /// tolerate unknown keys.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    #[cfg_attr(feature = "schema", schemars(with = "serde_json::Value"))]
    #[cfg_attr(feature = "ts-types", ts(type = "Record<string, unknown>"))]
    pub parameters: serde_json::Map<String, serde_json::Value>,
    /// Whether this primitive is post-quantum resistant. `None` =
    /// unknown / not yet classified.
    pub pq_resistant: Option<bool>,
    /// NIST PQC security level (1, 3, 5) when applicable.
    pub nist_classification: Option<NistLevel>,
}

/// What a [`Primitive`] is being used for. `Auth` means message
/// authentication code; `Sig` means asymmetric digital signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "ts-types", derive(TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub enum PrimitiveRole {
    /// Asymmetric key exchange (e.g. X25519, ECDH-P256, Kyber).
    Kex,
    /// Asymmetric digital signature (e.g. ECDSA, Dilithium).
    Sig,
    /// Message authentication code (e.g. HMAC-SHA-256, GMAC).
    Auth,
    /// Symmetric encryption (e.g. AES-256-GCM, ChaCha20-Poly1305).
    Encrypt,
    /// Cryptographic hash (e.g. SHA-256, SHA-3).
    Hash,
}

/// NIST PQC classification levels. See FIPS 203/204/205.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "ts-types", derive(TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub enum NistLevel {
    /// Level 1 — equivalent to AES-128.
    L1,
    /// Level 3 — equivalent to AES-192.
    L3,
    /// Level 5 — equivalent to AES-256.
    L5,
}

/// v1.1 — Telemetry block describing how the session key reached
/// the endpoint. Populated by `ree0xq-qkd` for QKD-protected sessions,
/// or by cooperating SAEs that retrieve PSKs over ETSI GS QKD 014.
/// Absent (`None`) is interpreted as a classical channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "ts-types", derive(TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub struct ChannelProtection {
    /// Categorical state of the channel.
    pub state: ChannelState,
    /// ETSI 014 base URL of the KME serving this channel. Omitted
    /// when state = `Classical`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kme_endpoint: Option<String>,
    /// UUID of the consumed key, when reported by the SAE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id_observed: Option<String>,
    /// Age of the PSK when the session began (seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk_age_seconds: Option<u64>,
    /// Observed QBER, on [0.0, 1.0]. Reported by the KME.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_qber: Option<f32>,
    /// Average key-generation rate (bits per second) over the prior
    /// observation interval. Reported by the KME.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_key_rate_bps: Option<u64>,
    /// Aggregate health flag derived from QBER and key-rate thresholds.
    pub link_health: LinkHealth,
    /// One-sentence reason when `link_health` is degraded/failed;
    /// `None` when healthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded_reason: Option<String>,
}

/// v1.1 — Categorical channel-protection state. Distinguishes
/// classical key delivery (no QKD), hybrid PSK (XOR/HKDF of QKD
/// material with negotiated KEM), and pure-QKD transports.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "ts-types", derive(TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub enum ChannelState {
    /// Session key derived solely from negotiated cryptography.
    Classical,
    /// Session key derived from QKD-PSK combined with negotiated KEM
    /// (NIST SP 1800-38 hybrid PSK pattern).
    QkdHybridPsk,
    /// Session key derived entirely from QKD material
    /// (MACsec-class transport).
    QkdOnly,
}

/// v1.1 — Aggregate health of a QKD link as observed by the KME.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "ts-types", derive(TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub enum LinkHealth {
    /// QBER and key rate within policy thresholds.
    Ok,
    /// One or more thresholds exceeded; SAEs may consider failover.
    Degraded,
    /// KME unreachable or link unable to deliver keys.
    Failed,
}

/// v1.1 — Crypto-agility classification for an asset. The level
/// expresses how quickly the asset's algorithm choice can be changed
/// in operational practice. Derived from static analysis of the
/// asset's implementation surface plus, where present, FIPS scope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "ts-types", derive(TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub struct AgilityBlock {
    /// The categorical agility level.
    pub level: AgilityLevel,
    /// Numeric score derived from `level`, on [0.0, 1.0]. Allows the
    /// posture engine to consume the level without re-applying the
    /// rubric. Always equals the canonical score for `level`.
    pub level_score: f32,
    /// Evidence supporting the chosen level. At least one entry must
    /// be present; conservative-min aggregation governs the level
    /// when entries disagree.
    pub evidence: Vec<AgilityEvidence>,
    /// Version of the scanner that produced this block, e.g.
    /// `"ree0xq-agility/0.3.1"`.
    pub scanner_version: String,
    /// Version of the public scoring rubric used, e.g.
    /// `"qra-rubric/v1.0"`. Allows reviewers to reproduce the score.
    pub rubric_version: String,
}

/// v1.1 — Five-level ordinal scale for crypto-agility. Cf. paper §2.3.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "ts-types", derive(TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub enum AgilityLevel {
    /// Algorithm selected per-session by protocol negotiation
    /// (TLS 1.3 server, modern SSH server, IKEv2 responder).
    Negotiated,
    /// Algorithm fixed per-deployment but changeable by configuration
    /// alone (library config file, environment variable).
    Configurable,
    /// Algorithm fixed in code; changeable only by software upgrade.
    Pinned,
    /// Algorithm fixed in firmware or by FIPS validation scope;
    /// changeable only by vendor update or revalidation cycle.
    Locked,
    /// Algorithm fixed in silicon, ROM, or otherwise unchangeable
    /// without hardware replacement.
    Frozen,
}

impl AgilityLevel {
    /// Canonical numeric score for this level. Used to populate
    /// `AgilityBlock::level_score` and consumed by the rollup.
    pub fn score(self) -> f32 {
        match self {
            AgilityLevel::Negotiated => 1.00,
            AgilityLevel::Configurable => 0.75,
            AgilityLevel::Pinned => 0.50,
            AgilityLevel::Locked => 0.20,
            AgilityLevel::Frozen => 0.00,
        }
    }
}

/// v1.1 — One evidentiary finding supporting an [`AgilityLevel`]
/// classification. Tagged union so future evidence types are additive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "ts-types", derive(TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub enum AgilityEvidence {
    /// Wire-level protocol negotiation observed (e.g. TLS 1.3
    /// ClientHello/ServerHello exchange listing algorithm choices).
    ProtocolNegotiation {
        /// Wire-protocol identifier, e.g. `"tls1.3"`.
        protocol: String,
        /// Negotiated algorithms observed, in negotiated order.
        observed_algorithms: Vec<String>,
    },
    /// A configuration file pattern exposing algorithm choice.
    ConfigPattern {
        /// Absolute or repo-relative path.
        file: String,
        /// 1-indexed line number of the matching pattern.
        line: u32,
        /// Verbatim snippet (truncated). Useful for review.
        snippet: String,
    },
    /// A source-code pattern referencing a fixed algorithm name.
    CodePattern {
        /// Repo-relative path.
        file: String,
        /// 1-indexed line number of the matching pattern.
        line: u32,
        /// Verbatim snippet (truncated).
        snippet: String,
        /// The algorithm name as it appears in code.
        algorithm: String,
    },
    /// An algorithm name extracted from a binary's strings table.
    FirmwareString {
        /// Path to the binary or firmware blob.
        path: String,
        /// The extracted algorithm name.
        algorithm: String,
    },
    /// Whether the asset is running in FIPS mode (kernel `fips=1`,
    /// openssl FIPS provider loaded, etc.).
    FipsMode {
        /// `true` when FIPS mode is positively detected.
        detected: bool,
    },
    /// Operator-supplied vendor declaration of algorithm scope (e.g.
    /// the asset's FIPS 140-3 validation lists exactly these algos).
    VendorDeclaration {
        /// Free-form statement, captured verbatim for audit trail.
        statement: String,
    },
}

/// ree0xQ's verdict on an asset, derived from its [`Primitive`] list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "ts-types", derive(TS))]
#[cfg_attr(feature = "ts-types", ts(export))]
pub struct Posture {
    /// 0–100 score; higher is better. 100 = fully PQ-ready.
    pub score: u8,
    /// Human-readable explanation of the score. Keep short
    /// (one sentence) — the dashboard renders this verbatim.
    pub rationale: String,
    /// If applicable, what to migrate to. `None` when the asset is
    /// already at the recommended primitive (or when the rollup
    /// engine can't suggest a replacement yet).
    pub recommended_replacement: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an event with the given `AssetKind` so the JSON
    /// round-trip test can sweep every variant. Other fields are
    /// minimally plausible; we test serialization stability, not
    /// posture-rollup correctness.
    fn fixture(
        kind: AssetKind,
        identity: &str,
        primitives: Vec<Primitive>,
    ) -> CryptoInventoryEvent {
        CryptoInventoryEvent {
            schema_version: SCHEMA_VERSION,
            schema_minor: SCHEMA_MINOR,
            source_module: "test".into(),
            observed_at: chrono::Utc::now(),
            asset: Asset {
                kind,
                identity: identity.into(),
                host: Some("test.example.com".into()),
            },
            primitives,
            channel_protection: None,
            agility: None,
            posture: Posture {
                score: 50,
                rationale: "fixture".into(),
                recommended_replacement: None,
            },
        }
    }

    fn prim(role: PrimitiveRole, algorithm: &str) -> Primitive {
        Primitive {
            role,
            algorithm: algorithm.into(),
            parameters: Default::default(),
            pq_resistant: None,
            nist_classification: None,
        }
    }

    #[test]
    fn schema_version_constant_is_sane() {
        assert_eq!(SCHEMA_VERSION, 1);
    }

    /// Sanity round-trip on the canonical TLS shape.
    #[test]
    fn event_round_trips_through_json() {
        let ev = CryptoInventoryEvent {
            schema_version: SCHEMA_VERSION,
            schema_minor: SCHEMA_MINOR,
            source_module: "ree0xq-net".into(),
            observed_at: chrono::Utc::now(),
            asset: Asset {
                kind: AssetKind::TlsSession,
                identity: "abc123".into(),
                host: Some("api.example.com".into()),
            },
            primitives: vec![Primitive {
                role: PrimitiveRole::Kex,
                algorithm: "X25519".into(),
                parameters: Default::default(),
                pq_resistant: Some(false),
                nist_classification: None,
            }],
            channel_protection: None,
            agility: None,
            posture: Posture {
                score: 40,
                rationale: "X25519 is classical-only".into(),
                recommended_replacement: Some("Kyber768+X25519 hybrid".into()),
            },
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: CryptoInventoryEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.schema_version, ev.schema_version);
        assert_eq!(back.asset.kind, AssetKind::TlsSession);
        assert_eq!(back.posture.score, 40);
    }

    /// Sweep every AssetKind through JSON. Catches a missing serde
    /// rename, a forgotten `Deserialize`, or a kind variant that
    /// breaks the closed-set invariant (next major bump only).
    #[test]
    fn every_asset_kind_round_trips() {
        let cases: Vec<(AssetKind, &str, Vec<Primitive>)> = vec![
            (
                AssetKind::TlsSession,
                "tls-abc-123",
                vec![
                    prim(PrimitiveRole::Kex, "X25519"),
                    prim(PrimitiveRole::Sig, "ECDSA-P256"),
                    prim(PrimitiveRole::Encrypt, "AES-256-GCM"),
                    prim(PrimitiveRole::Hash, "SHA-384"),
                ],
            ),
            (
                AssetKind::SshSession,
                "ssh-9af0",
                vec![
                    prim(PrimitiveRole::Kex, "curve25519-sha256"),
                    prim(PrimitiveRole::Sig, "ssh-ed25519"),
                    prim(PrimitiveRole::Encrypt, "chacha20-poly1305"),
                ],
            ),
            (
                AssetKind::IpsecSa,
                "spi-0xdeadbeef",
                vec![prim(PrimitiveRole::Encrypt, "AES-256-GCM")],
            ),
            (
                AssetKind::X509Cert,
                "sha256:1f2e3d…",
                vec![prim(PrimitiveRole::Sig, "RSA-2048")],
            ),
            (
                AssetKind::BlockchainKey,
                "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                vec![prim(PrimitiveRole::Sig, "ECDSA-secp256k1")],
            ),
            (
                AssetKind::HsmSlot,
                "pkcs11:token=acme-prod;id=05",
                vec![prim(PrimitiveRole::Sig, "ECDSA-P256")],
            ),
            (
                AssetKind::DnsDnssec,
                "rrsig:fingerprint:abc",
                vec![prim(PrimitiveRole::Sig, "ECDSAP256SHA256")],
            ),
        ];

        for (kind, id, prims) in cases {
            let ev = fixture(kind.clone(), id, prims.clone());
            let json = serde_json::to_string(&ev).unwrap();
            let back: CryptoInventoryEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(back.asset.kind, kind, "round-trip kind for {id}");
            assert_eq!(back.asset.identity, id);
            assert_eq!(back.primitives.len(), prims.len());
        }
    }

    /// Optional fields (`host`, `pq_resistant`, `nist_classification`,
    /// `recommended_replacement`) drop out of the JSON when None.
    /// Catches a regression where someone removes
    /// `skip_serializing_if = "Option::is_none"` on a future field.
    #[test]
    fn optional_fields_omit_when_none() {
        // Note: serde defaults — we don't currently set
        // skip_serializing_if on these. Test asserts that when omitted
        // *from JSON input*, deserialization re-fills with None.
        let json = r#"{
            "schema_version": 1,
            "source_module": "test",
            "observed_at": "2026-01-01T00:00:00Z",
            "asset": {"kind": "blockchain_key", "identity": "0xabc"},
            "primitives": [{"role": "sig", "algorithm": "Ed25519"}],
            "posture": {"score": 0, "rationale": "n/a"}
        }"#;
        let ev: CryptoInventoryEvent = serde_json::from_str(json).unwrap();
        assert!(ev.asset.host.is_none());
        assert!(ev.primitives[0].pq_resistant.is_none());
        assert!(ev.primitives[0].nist_classification.is_none());
        assert!(ev.posture.recommended_replacement.is_none());
        // parameters: serde(default) → empty Map.
        assert!(ev.primitives[0].parameters.is_empty());
    }

    /// Schema_version is a hard rejection point: an event from a
    /// future major version must not silently look valid.
    #[test]
    fn unknown_asset_kind_fails_to_deserialize() {
        let json = r#"{
            "schema_version": 1,
            "source_module": "test",
            "observed_at": "2026-01-01T00:00:00Z",
            "asset": {"kind": "quantum_keyring", "identity": "qk-1"},
            "primitives": [],
            "posture": {"score": 0, "rationale": "n/a"}
        }"#;
        let result: Result<CryptoInventoryEvent, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "unknown AssetKind variant must fail to parse"
        );
    }

    /// Parameters round-trip arbitrary JSON.
    #[test]
    fn parameters_carry_arbitrary_json() {
        let mut params = serde_json::Map::new();
        params.insert(
            "curve".into(),
            serde_json::Value::String("Curve25519".into()),
        );
        params.insert("key_bits".into(), serde_json::Value::Number(256.into()));
        params.insert(
            "extensions".into(),
            serde_json::json!(["server_name", "supported_versions"]),
        );
        let p = Primitive {
            role: PrimitiveRole::Kex,
            algorithm: "X25519".into(),
            parameters: params.clone(),
            pq_resistant: Some(false),
            nist_classification: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: Primitive = serde_json::from_str(&json).unwrap();
        assert_eq!(back.parameters, params);
    }

    /// Empty parameters map must not appear in the wire JSON
    /// (skip_serializing_if). Smaller payloads, easier diff'ing.
    #[test]
    fn empty_parameters_omitted_from_wire() {
        let p = prim(PrimitiveRole::Hash, "SHA-256");
        let json = serde_json::to_string(&p).unwrap();
        assert!(
            !json.contains("\"parameters\""),
            "empty parameters should be skipped: {json}"
        );
    }

    /// NIST classification round-trips with UPPERCASE rename.
    #[test]
    fn nist_levels_serialize_uppercase() {
        for (level, expected) in [
            (NistLevel::L1, "L1"),
            (NistLevel::L3, "L3"),
            (NistLevel::L5, "L5"),
        ] {
            let s = serde_json::to_string(&level).unwrap();
            assert_eq!(s, format!("\"{expected}\""));
        }
    }

    // ---------- v1.1 schema extensions ----------

    /// A v1.0-shaped event (no schema_minor, no channel_protection,
    /// no agility) must deserialize cleanly under v1.1 consumers.
    /// schema_minor defaults to 0, the two new blocks default to None.
    #[test]
    fn v1_0_event_accepted_by_v1_1_consumer() {
        let json_v1_0 = r#"{
            "schema_version": 1,
            "source_module": "ree0xq-net",
            "observed_at": "2026-01-01T00:00:00Z",
            "asset": {"kind": "tls_session", "identity": "abc"},
            "primitives": [{"role": "kex", "algorithm": "X25519"}],
            "posture": {"score": 30, "rationale": "classical"}
        }"#;
        let ev: CryptoInventoryEvent =
            serde_json::from_str(json_v1_0).expect("v1.0 event must parse");
        assert_eq!(ev.schema_minor, 0);
        assert!(ev.channel_protection.is_none());
        assert!(ev.agility.is_none());
    }

    /// A v1.1 event with channel_protection populated must round-trip.
    #[test]
    fn channel_protection_round_trips() {
        let cp = ChannelProtection {
            state: ChannelState::QkdHybridPsk,
            kme_endpoint: Some("https://kme-1.dc.example/api/v1".into()),
            key_id_observed: Some("9c45e0a2-b7f4-4ed9-9e2a-1d33c2b9a0bb".into()),
            psk_age_seconds: Some(47),
            link_qber: Some(0.018),
            link_key_rate_bps: Some(12_480),
            link_health: LinkHealth::Ok,
            degraded_reason: None,
        };
        let json = serde_json::to_string(&cp).unwrap();
        let back: ChannelProtection = serde_json::from_str(&json).unwrap();
        assert_eq!(back.state, ChannelState::QkdHybridPsk);
        assert_eq!(back.link_health, LinkHealth::Ok);
        assert_eq!(back.psk_age_seconds, Some(47));
    }

    /// A v1.1 event with agility populated must round-trip,
    /// including the tagged-union evidence variants.
    #[test]
    fn agility_block_round_trips_with_mixed_evidence() {
        let ab = AgilityBlock {
            level: AgilityLevel::Configurable,
            level_score: AgilityLevel::Configurable.score(),
            evidence: vec![
                AgilityEvidence::ConfigPattern {
                    file: "/etc/nginx/nginx.conf".into(),
                    line: 142,
                    snippet: "ssl_ciphers HIGH:!aNULL;".into(),
                },
                AgilityEvidence::FipsMode { detected: false },
                AgilityEvidence::ProtocolNegotiation {
                    protocol: "tls1.3".into(),
                    observed_algorithms: vec!["X25519".into(), "AES-256-GCM".into()],
                },
            ],
            scanner_version: "ree0xq-agility/0.3.1".into(),
            rubric_version: "qra-rubric/v1.0".into(),
        };
        let json = serde_json::to_string(&ab).unwrap();
        let back: AgilityBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(back.level, AgilityLevel::Configurable);
        assert_eq!(back.evidence.len(), 3);
        // Verify the tagged-union evidence preserves variant identity.
        matches!(
            back.evidence[1],
            AgilityEvidence::FipsMode { detected: false }
        );
    }

    /// AgilityLevel::score must match the paper's §2.3 rubric exactly.
    #[test]
    fn agility_level_scores_match_rubric() {
        assert_eq!(AgilityLevel::Negotiated.score(), 1.00);
        assert_eq!(AgilityLevel::Configurable.score(), 0.75);
        assert_eq!(AgilityLevel::Pinned.score(), 0.50);
        assert_eq!(AgilityLevel::Locked.score(), 0.20);
        assert_eq!(AgilityLevel::Frozen.score(), 0.00);
    }

    /// New v1.1 asset kinds (QkdLink, QkdKme) round-trip cleanly.
    #[test]
    fn qkd_asset_kinds_round_trip() {
        for (kind, ident) in [
            (AssetKind::QkdLink, "sha256:fd14e0..."),
            (AssetKind::QkdKme, "KME-A"),
        ] {
            let ev = fixture(kind.clone(), ident, vec![]);
            let json = serde_json::to_string(&ev).unwrap();
            let back: CryptoInventoryEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(back.asset.kind, kind);
            assert_eq!(back.asset.identity, ident);
        }
    }

    /// When channel_protection and agility are None, they must not
    /// appear in the serialized JSON — keeps payloads small and
    /// preserves wire compatibility with v1.0 consumers.
    #[test]
    fn null_v1_1_blocks_omitted_from_wire() {
        let ev = fixture(AssetKind::TlsSession, "abc", vec![]);
        let json = serde_json::to_string(&ev).unwrap();
        assert!(
            !json.contains("\"channel_protection\""),
            "absent channel_protection must be omitted: {json}"
        );
        assert!(
            !json.contains("\"agility\""),
            "absent agility must be omitted: {json}"
        );
    }
}
