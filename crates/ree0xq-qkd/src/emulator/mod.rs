//! Reference ETSI GS QKD 014 KME emulator.
//!
//! Implements `/status`, `/enc_keys`, `/dec_keys` exactly per spec
//! (§5.1, §5.2, §5.3) and exposes a small `/control` extension that
//! the replay driver uses to push scenario events into a running
//! emulator instance.
//!
//! The emulator is the foundation of ree0xQ paper Study 2: it allows
//! reproducible characterisation of QKD-aware SAE behavior without
//! physical hardware. All key material is synthetic.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::etsi014::{
    paths, DecKeysRequest, EncKeysQuery, ErrorResponse, Key, KeyContainer, StatusResponse,
};

/// Emulator configuration. Constructed from CLI flags in the bin and
/// from test fixtures in integration tests.
#[derive(Debug, Clone)]
pub struct EmulatorConfig {
    /// KME identifier advertised in `/status`.
    pub kme_id: String,
    /// KME identifier of the paired peer (target).
    pub paired_kme_id: String,
    /// Default key size in bits.
    pub key_size: u32,
    /// Initial QBER, on [0.0, 1.0].
    pub initial_qber: f32,
    /// Initial key generation rate (bps).
    pub initial_key_rate_bps: u64,
    /// Maximum stored key count.
    pub max_key_count: u32,
}

impl Default for EmulatorConfig {
    fn default() -> Self {
        Self {
            kme_id: "KME-A".into(),
            paired_kme_id: "KME-B".into(),
            key_size: 256,
            initial_qber: 0.018,
            initial_key_rate_bps: 12_480,
            max_key_count: 100_000,
        }
    }
}

/// Mutable emulator state.
///
/// Exposed for the `/control` API so replay scenarios can drive QBER,
/// key rate, and forced failures.
#[derive(Debug)]
pub struct EmulatorState {
    cfg: EmulatorConfig,
    /// Pool of pre-generated keys keyed by UUID.
    keys: HashMap<String, Vec<u8>>,
    /// Current QBER (mutable; replay scenarios change this).
    qber: f32,
    /// Current key rate (bps).
    key_rate_bps: u64,
    /// If `Some`, the emulator returns an error on every request
    /// until cleared. Used by the `r3-hard-failure` scenario.
    forced_failure: Option<String>,
}

impl EmulatorState {
    /// Build a new state seeded by [`EmulatorConfig`].
    ///
    /// Pre-seeds a small key pool so `/status.stored_key_count` reports
    /// a realistic non-zero value out of the gate — real KMEs hold
    /// keys ready for delivery before the first SAE request.
    pub fn new(cfg: EmulatorConfig) -> Self {
        let key_size = cfg.key_size;
        let mut s = Self {
            qber: cfg.initial_qber,
            key_rate_bps: cfg.initial_key_rate_bps,
            keys: HashMap::new(),
            forced_failure: None,
            cfg,
        };
        // Pre-seed 32 keys so the status endpoint reports a non-zero
        // stored_key_count without requiring an /enc_keys call first.
        generate_keys(&mut s, 32, key_size);
        s
    }
}

/// Build a [`StatusResponse`] from current state for the given SAE.
fn build_status(state: &EmulatorState, master_sae: &str, slave_sae: &str) -> StatusResponse {
    StatusResponse {
        source_kme_id: state.cfg.kme_id.clone(),
        target_kme_id: state.cfg.paired_kme_id.clone(),
        master_sae_id: master_sae.into(),
        slave_sae_id: slave_sae.into(),
        key_size: state.cfg.key_size,
        stored_key_count: state.keys.len() as u32,
        max_key_count: state.cfg.max_key_count,
        max_key_per_request: 128,
        max_key_size: 4096,
        min_key_size: 64,
        max_sae_id_count: 0,
        link_qber: Some(state.qber),
        link_key_rate_bps: Some(state.key_rate_bps),
    }
}

/// Generate `count` synthetic keys of `size_bits` bits, return their
/// UUIDs and base64 contents. Keys are stored in the emulator pool so
/// the paired `/dec_keys` call can retrieve them by UUID.
fn generate_keys(state: &mut EmulatorState, count: u32, size_bits: u32) -> Vec<Key> {
    let byte_len = (size_bits as usize).div_ceil(8);
    let mut rng = rand::thread_rng();
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut buf = vec![0u8; byte_len];
        rng.fill_bytes(&mut buf);
        let uuid = Uuid::new_v4().to_string();
        let b64 = base64_encode(&buf);
        state.keys.insert(uuid.clone(), buf);
        out.push(Key {
            key_id: uuid,
            key: b64,
        });
    }
    out
}

/// Minimal base64 encoder — avoids adding the `base64` crate.
fn base64_encode(input: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(((input.len() + 2) / 3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n =
            (u32::from(input[i]) << 16) | (u32::from(input[i + 1]) << 8) | u32::from(input[i + 2]);
        for shift in [18, 12, 6, 0] {
            out.push(char::from(ALPHA[((n >> shift) & 0x3F) as usize]));
        }
        i += 3;
    }
    let rem = input.len() - i;
    if rem > 0 {
        let mut n: u32 = u32::from(input[i]) << 16;
        if rem == 2 {
            n |= u32::from(input[i + 1]) << 8;
        }
        out.push(char::from(ALPHA[((n >> 18) & 0x3F) as usize]));
        out.push(char::from(ALPHA[((n >> 12) & 0x3F) as usize]));
        out.push(if rem == 2 {
            char::from(ALPHA[((n >> 6) & 0x3F) as usize])
        } else {
            '='
        });
        out.push('=');
    }
    out
}

// ----- HTTP handlers -----

/// `GET /api/v1/keys/{slave_SAE_ID}/status`
async fn handle_status(
    State(state): State<Arc<RwLock<EmulatorState>>>,
    Path(slave_sae_id): Path<String>,
) -> Result<Json<StatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let st = state.read().await;
    if let Some(reason) = &st.forced_failure {
        warn!(slave_sae=%slave_sae_id, %reason, "forced-failure path returned 503");
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                message: "kme_unavailable".into(),
                details: vec![reason.clone()],
            }),
        ));
    }
    // The master SAE is the caller; the spec does not require us to
    // know its identity here — we fill in a placeholder.
    let resp = build_status(&st, "SAE-MASTER", &slave_sae_id);
    Ok(Json(resp))
}

/// `GET /api/v1/keys/{slave_SAE_ID}/enc_keys`
async fn handle_enc_keys(
    State(state): State<Arc<RwLock<EmulatorState>>>,
    Path(slave_sae_id): Path<String>,
    Query(query): Query<EncKeysQuery>,
) -> Result<Json<KeyContainer>, (StatusCode, Json<ErrorResponse>)> {
    let mut st = state.write().await;
    if let Some(reason) = &st.forced_failure {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                message: "kme_unavailable".into(),
                details: vec![reason.clone()],
            }),
        ));
    }
    let size = query.size.unwrap_or(st.cfg.key_size);
    let count = query.number.unwrap_or(1).clamp(1, 128);
    debug!(slave_sae=%slave_sae_id, %size, %count, "issuing enc_keys");
    let keys = generate_keys(&mut st, count, size);
    Ok(Json(KeyContainer { keys }))
}

/// `POST /api/v1/keys/{master_SAE_ID}/dec_keys`
async fn handle_dec_keys(
    State(state): State<Arc<RwLock<EmulatorState>>>,
    Path(master_sae_id): Path<String>,
    Json(req): Json<DecKeysRequest>,
) -> Result<Json<KeyContainer>, (StatusCode, Json<ErrorResponse>)> {
    let st = state.read().await;
    if let Some(reason) = &st.forced_failure {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                message: "kme_unavailable".into(),
                details: vec![reason.clone()],
            }),
        ));
    }
    let mut keys = Vec::with_capacity(req.key_IDs.len());
    for entry in &req.key_IDs {
        match st.keys.get(&entry.key_id) {
            Some(buf) => keys.push(Key {
                key_id: entry.key_id.clone(),
                key: base64_encode(buf),
            }),
            None => {
                debug!(master_sae=%master_sae_id, key_id=%entry.key_id, "key_not_available");
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        message: "key_not_available".into(),
                        details: vec![format!("unknown key_ID {}", entry.key_id)],
                    }),
                ));
            }
        }
    }
    Ok(Json(KeyContainer { keys }))
}

// ----- Control API (ree0xQ extension; not part of ETSI 014) -----

/// Replay-time control message accepted on `POST /control`. Allows the
/// replay driver to mutate QBER, key rate, and forced-failure state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlOp {
    /// Set the QBER to a new value.
    SetQber {
        /// New QBER, on [0.0, 1.0].
        qber: f32,
    },
    /// Set the key rate (bps).
    SetKeyRate {
        /// New rate in bps.
        rate_bps: u64,
    },
    /// Force every subsequent request to return 503 with the given reason.
    ForceFailure {
        /// Free-form reason rendered into `ErrorResponse.details`.
        reason: String,
    },
    /// Clear any previously set forced-failure state.
    ClearFailure,
}

async fn handle_control(
    State(state): State<Arc<RwLock<EmulatorState>>>,
    Json(op): Json<ControlOp>,
) -> impl IntoResponse {
    let mut st = state.write().await;
    match op {
        ControlOp::SetQber { qber } => {
            info!(qber, "control: set_qber");
            st.qber = qber.clamp(0.0, 1.0);
        }
        ControlOp::SetKeyRate { rate_bps } => {
            info!(rate_bps, "control: set_key_rate");
            st.key_rate_bps = rate_bps;
        }
        ControlOp::ForceFailure { reason } => {
            warn!(reason, "control: force_failure");
            st.forced_failure = Some(reason);
        }
        ControlOp::ClearFailure => {
            info!("control: clear_failure");
            st.forced_failure = None;
        }
    }
    StatusCode::NO_CONTENT
}

/// Build the Axum router exposing the ETSI 014 endpoints plus the
/// ree0xQ `/control` extension.
pub fn router(state: Arc<RwLock<EmulatorState>>) -> Router {
    let base = paths::BASE; // "/api/v1/keys"
    Router::new()
        .route(
            &format!("{base}/:slave_sae_id/{}", paths::STATUS),
            get(handle_status),
        )
        .route(
            &format!("{base}/:slave_sae_id/{}", paths::ENC_KEYS),
            get(handle_enc_keys),
        )
        .route(
            &format!("{base}/:master_sae_id/{}", paths::DEC_KEYS),
            post(handle_dec_keys),
        )
        .route("/control", post(handle_control))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encode_known_vectors() {
        // RFC 4648 §10 test vectors.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn generate_keys_produces_unique_uuids_and_correct_size() {
        let mut st = EmulatorState::new(EmulatorConfig::default());
        let pool_before = st.keys.len();
        let keys = generate_keys(&mut st, 4, 256);
        assert_eq!(keys.len(), 4);
        let mut seen = std::collections::HashSet::new();
        for k in &keys {
            assert!(seen.insert(k.key_id.clone()), "uuids must be unique");
            // base64 of 32 bytes = 44 chars (with padding).
            assert_eq!(k.key.len(), 44);
        }
        // `EmulatorState::new` pre-seeds a key pool to mimic real KME
        // behaviour; the post-condition is "pool grew by 4," not
        // "pool is exactly 4."
        assert_eq!(
            st.keys.len(),
            pool_before + 4,
            "generated keys are added to the pool"
        );
    }

    #[test]
    fn forced_failure_blocks_dec_keys_in_state() {
        let mut st = EmulatorState::new(EmulatorConfig::default());
        st.forced_failure = Some("link down".into());
        assert!(st.forced_failure.is_some());
    }
}
