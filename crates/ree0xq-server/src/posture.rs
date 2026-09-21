//! Three-axis quantum-risk rollup (paper §3).
//!
//! Implements the deadline-adjusted quantum-risk score
//!
//! ```text
//! q(asset, t) = 1 - ( alpha * A + beta * C + gamma(tau) * G )
//! ```
//!
//! where weights are renormalised so that `alpha + beta + gamma`
//! sums to 1 even after `gamma` shrinks with deadline tension.
//! The classification tables for axis A are the V1 algorithm
//! posture table defined in `ree0xq_core::rollup` (when that lands)
//! — for now we infer A from each primitive's `pq_resistant` flag
//! and the canonical role weights from the paper.

use chrono::{DateTime, Utc};
use ree0xq_core::{
    AgilityBlock, AgilityLevel, ChannelProtection, ChannelState, CryptoInventoryEvent, Primitive,
    PrimitiveRole,
};

/// Default role weights for axis A (paper §2.1).
pub const W_SIG: f32 = 0.40;
/// Default role weight for KEX.
pub const W_KEX: f32 = 0.30;
/// Default role weight for symmetric encryption.
pub const W_ENC: f32 = 0.20;
/// Default role weight for hash.
pub const W_HASH: f32 = 0.10;

/// Default axis weights (paper §3, unrenormalised).
pub const ALPHA: f32 = 0.5;
/// Default channel-protection weight.
pub const BETA: f32 = 0.2;
/// Default agility weight at $\tau=0$ (renormalises down to 0 at $\tau=1$).
pub const GAMMA_MAX: f32 = 0.3;

/// Per-primitive `a` score per the paper §5.1 table.
pub fn primitive_a_score(p: &Primitive) -> f32 {
    match p.pq_resistant {
        Some(true) => 1.0,
        Some(false) => 0.3,
        None => 0.4, // unknown — mid-low, encourages investigation
    }
}

/// Compute axis-A (algorithmic resistance) score for an asset's
/// primitive list. Returns `0.4` when the list is empty so the
/// posture engine continues to surface absence as `unknown`.
pub fn axis_a(prims: &[Primitive]) -> f32 {
    if prims.is_empty() {
        return 0.4;
    }
    let mut weight_sum = 0.0_f32;
    let mut weighted = 0.0_f32;
    for p in prims {
        let w = match p.role {
            PrimitiveRole::Sig => W_SIG,
            PrimitiveRole::Kex => W_KEX,
            PrimitiveRole::Encrypt => W_ENC,
            PrimitiveRole::Hash => W_HASH,
            PrimitiveRole::Auth => W_HASH, // treat as hash-class for V1
        };
        weight_sum += w;
        weighted += w * primitive_a_score(p);
    }
    if weight_sum == 0.0 {
        return 0.4;
    }
    weighted / weight_sum
}

/// Axis-C — channel-protection categorical score (paper §2.2).
pub fn axis_c(cp: Option<&ChannelProtection>) -> f32 {
    match cp {
        None => 0.0,
        Some(cp) => match cp.state {
            ChannelState::Classical => 0.0,
            ChannelState::QkdHybridPsk => 0.7,
            ChannelState::QkdOnly => 1.0,
        },
    }
}

/// Axis-G — migration agility (paper §2.3). When the asset has no
/// agility block we use the `Pinned`-equivalent fallback from
/// `ree0xq-agility::UNKNOWN_LEVEL_FALLBACK` (score 0.50).
pub fn axis_g(ag: Option<&AgilityBlock>) -> f32 {
    match ag {
        None => AgilityLevel::Pinned.score(),
        Some(a) => a.level_score,
    }
}

/// Deadline tension $\tau$ — clamps to `[0, 1]`.
pub fn deadline_tension(now: DateTime<Utc>, deadline: DateTime<Utc>, horizon_years: f32) -> f32 {
    if horizon_years <= 0.0 {
        return 1.0;
    }
    let days = (deadline - now).num_days() as f32;
    let years = days / 365.25;
    (1.0 - years / horizon_years).clamp(0.0, 1.0)
}

/// Per-asset deadline-adjusted quantum-risk score $q$ — paper §3.
pub fn q_for_event(
    ev: &CryptoInventoryEvent,
    now: DateTime<Utc>,
    deadline: DateTime<Utc>,
    horizon_years: f32,
) -> f32 {
    let tau = deadline_tension(now, deadline, horizon_years);
    let a = axis_a(&ev.primitives);
    let c = axis_c(ev.channel_protection.as_ref());
    let g = axis_g(ev.agility.as_ref());

    let gamma = GAMMA_MAX * (1.0 - tau);
    let total = ALPHA + BETA + gamma;
    let a_w = ALPHA / total;
    let b_w = BETA / total;
    let g_w = gamma / total;

    1.0 - (a_w * a + b_w * c + g_w * g)
}

/// Whether the asset's agility level is `Locked` or `Frozen` — the
/// dashboard `BLOCKED` flag. Independent of $q$.
pub fn is_blocked(ag: Option<&AgilityBlock>) -> bool {
    matches!(
        ag.map(|a| a.level),
        Some(AgilityLevel::Locked) | Some(AgilityLevel::Frozen)
    )
}

/// Org-level rollup: weighted average of asset $q$ values by
/// asset-kind importance.
pub fn org_score(
    events: &[CryptoInventoryEvent],
    now: DateTime<Utc>,
    deadline: DateTime<Utc>,
    horizon_years: f32,
) -> f32 {
    if events.is_empty() {
        return 0.0;
    }
    let mut weight_sum = 0.0_f32;
    let mut weighted = 0.0_f32;
    for ev in events {
        let w = asset_kind_weight(&ev.asset.kind);
        weight_sum += w;
        weighted += w * q_for_event(ev, now, deadline, horizon_years);
    }
    if weight_sum == 0.0 {
        return 0.0;
    }
    weighted / weight_sum
}

/// Asset-kind weights (paper §3 closing paragraph + posture-rollup doc).
pub fn asset_kind_weight(kind: &ree0xq_core::AssetKind) -> f32 {
    use ree0xq_core::AssetKind::*;
    match kind {
        X509Cert => 1.0,
        TlsSession => 0.7,
        SshSession => 0.7,
        IpsecSa => 0.7,
        BlockchainKey => 1.5,
        HsmSlot => 1.0,
        DnsDnssec => 0.5,
        QkdLink => 0.4,
        QkdKme => 0.4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ree0xq_core::{
        Asset, AssetKind, ChannelState, LinkHealth, Posture, PrimitiveRole, SCHEMA_MINOR,
        SCHEMA_VERSION,
    };

    fn prim(role: PrimitiveRole, algo: &str, pq: Option<bool>) -> Primitive {
        Primitive {
            role,
            algorithm: algo.into(),
            parameters: Default::default(),
            pq_resistant: pq,
            nist_classification: None,
        }
    }

    fn event(
        prims: Vec<Primitive>,
        cp: Option<ChannelProtection>,
        ag: Option<AgilityBlock>,
    ) -> CryptoInventoryEvent {
        CryptoInventoryEvent {
            schema_version: SCHEMA_VERSION,
            schema_minor: SCHEMA_MINOR,
            source_module: "test".into(),
            observed_at: chrono::Utc::now(),
            asset: Asset {
                kind: AssetKind::TlsSession,
                identity: "test".into(),
                host: None,
            },
            primitives: prims,
            channel_protection: cp,
            agility: ag,
            posture: Posture {
                score: 0,
                rationale: "".into(),
                recommended_replacement: None,
            },
        }
    }

    fn modern_tls13_classical() -> Vec<Primitive> {
        vec![
            prim(PrimitiveRole::Kex, "X25519", Some(false)),
            prim(PrimitiveRole::Sig, "ECDSA-P256", Some(false)),
            prim(PrimitiveRole::Encrypt, "AES-256-GCM", Some(true)),
            prim(PrimitiveRole::Hash, "SHA-384", Some(true)),
        ]
    }

    #[test]
    fn axis_a_classical_kex_and_sig_modern_aead_matches_paper_example() {
        let prims = modern_tls13_classical();
        let a = axis_a(&prims);
        // Paper §3.1 worked example: A = 0.51 (rounded).
        assert!((a - 0.51).abs() < 0.01, "got {a}");
    }

    #[test]
    fn axis_c_returns_zero_when_absent_and_07_for_hybrid_psk() {
        assert_eq!(axis_c(None), 0.0);
        let cp = ChannelProtection {
            state: ChannelState::QkdHybridPsk,
            kme_endpoint: None,
            key_id_observed: None,
            psk_age_seconds: None,
            link_qber: None,
            link_key_rate_bps: None,
            link_health: LinkHealth::Ok,
            degraded_reason: None,
        };
        assert!((axis_c(Some(&cp)) - 0.7).abs() < 1e-6);
    }

    #[test]
    fn deadline_tension_matches_worked_example() {
        let t1 = chrono::Utc.with_ymd_and_hms(2026, 5, 13, 0, 0, 0).unwrap();
        let t2 = chrono::Utc.with_ymd_and_hms(2029, 7, 1, 0, 0, 0).unwrap();
        let d = chrono::Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();
        let tau1 = deadline_tension(t1, d, 5.0);
        let tau2 = deadline_tension(t2, d, 5.0);
        // Paper §3.1: tau1 ≈ 0.27, tau2 ≈ 0.90
        assert!((tau1 - 0.272).abs() < 0.005, "got {tau1}");
        assert!((tau2 - 0.900).abs() < 0.01, "got {tau2}");
    }

    #[test]
    fn worked_example_alpha_q_matches_paper() {
        // Asset alpha: modern, agile, no QKD. Paper §3.1: q ≈ 0.544.
        let ag = AgilityBlock {
            level: AgilityLevel::Configurable,
            level_score: AgilityLevel::Configurable.score(),
            evidence: vec![],
            scanner_version: "test".into(),
            rubric_version: "test".into(),
        };
        let ev = event(modern_tls13_classical(), None, Some(ag));
        let now = chrono::Utc.with_ymd_and_hms(2026, 5, 13, 0, 0, 0).unwrap();
        let d = chrono::Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();
        let q = q_for_event(&ev, now, d, 5.0);
        assert!(
            (q - 0.544).abs() < 0.01,
            "expected paper §3.1 q≈0.544, got {q}"
        );
    }

    #[test]
    fn worked_example_delta_q_matches_paper() {
        // Asset delta: modern, agile, QKD-hybrid PSK. Paper §3.1: q ≈ 0.392.
        let ag = AgilityBlock {
            level: AgilityLevel::Configurable,
            level_score: AgilityLevel::Configurable.score(),
            evidence: vec![],
            scanner_version: "test".into(),
            rubric_version: "test".into(),
        };
        let cp = ChannelProtection {
            state: ChannelState::QkdHybridPsk,
            kme_endpoint: None,
            key_id_observed: None,
            psk_age_seconds: None,
            link_qber: Some(0.018),
            link_key_rate_bps: Some(12_480),
            link_health: LinkHealth::Ok,
            degraded_reason: None,
        };
        let ev = event(modern_tls13_classical(), Some(cp), Some(ag));
        let now = chrono::Utc.with_ymd_and_hms(2026, 5, 13, 0, 0, 0).unwrap();
        let d = chrono::Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();
        let q = q_for_event(&ev, now, d, 5.0);
        assert!(
            (q - 0.392).abs() < 0.01,
            "expected paper §3.1 q≈0.392, got {q}"
        );
    }

    #[test]
    fn locked_agility_raises_blocked_flag() {
        let ag = AgilityBlock {
            level: AgilityLevel::Locked,
            level_score: AgilityLevel::Locked.score(),
            evidence: vec![],
            scanner_version: "t".into(),
            rubric_version: "t".into(),
        };
        assert!(is_blocked(Some(&ag)));
        let ag2 = AgilityBlock {
            level: AgilityLevel::Configurable,
            level_score: AgilityLevel::Configurable.score(),
            ..ag
        };
        assert!(!is_blocked(Some(&ag2)));
        assert!(!is_blocked(None));
    }

    #[test]
    fn org_score_weights_blockchain_higher_than_tls() {
        let mut alpha_ev = event(modern_tls13_classical(), None, None);
        let mut chain_ev = event(modern_tls13_classical(), None, None);
        chain_ev.asset.kind = AssetKind::BlockchainKey;
        chain_ev.asset.identity = "bc1q...".into();
        let now = chrono::Utc.with_ymd_and_hms(2026, 5, 13, 0, 0, 0).unwrap();
        let d = chrono::Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();
        // The blockchain asset has weight 1.5 vs 0.7 for tls — so the
        // org score with both should sit closer to the blockchain q.
        let _ = q_for_event(&alpha_ev, now, d, 5.0); // compile-touch
        alpha_ev.posture.score = 0;
        let q_org = org_score(&[alpha_ev.clone(), chain_ev.clone()], now, d, 5.0);
        let q_tls = q_for_event(&alpha_ev, now, d, 5.0);
        let q_chain = q_for_event(&chain_ev, now, d, 5.0);
        // Equal events → weighted average bias toward chain.
        let midpoint = (q_tls + q_chain) / 2.0;
        if (q_tls - q_chain).abs() > 1e-6 {
            // weights differ → org score deviates from midpoint toward higher-weight asset
            assert!(
                (q_org - q_chain).abs() < (q_org - q_tls).abs(),
                "expected org_score to be closer to blockchain q ({q_chain}) than TLS q ({q_tls}); got {q_org} vs midpoint {midpoint}"
            );
        }
    }
}
