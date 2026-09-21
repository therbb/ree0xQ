//! ETSI GS QKD 014 collector.
//!
//! Polls one or more KMEs at a configurable cadence, derives an
//! aggregate `link_health`, and emits `crypto_inventory_event`
//! records of kind `QkdLink` and `QkdKme` for downstream rollup.
//!
//! The collector is intentionally stateless across restarts; it
//! re-discovers KME status on every poll. State that matters
//! (event history, posture rollup) lives in `ree0xq-server`.

use std::time::Duration;

use ree0xq_core::{
    Asset, AssetKind, ChannelProtection, ChannelState, CryptoInventoryEvent, LinkHealth, Posture,
    SCHEMA_MINOR, SCHEMA_VERSION,
};
use reqwest::Client;
use tracing::{debug, error, info, warn};

use crate::etsi014::{paths, StatusResponse};
use crate::SOURCE_MODULE;

/// Collector configuration; one collector polls one or more KMEs.
#[derive(Debug, Clone)]
pub struct CollectorConfig {
    /// KME base URLs to poll (e.g. `https://kme-1.dc.example/api/v1`).
    pub kme_endpoints: Vec<String>,
    /// SAE ID used in the `/status` path. The spec requires it; for
    /// the collector role we use a documented synthetic SAE.
    pub slave_sae_id: String,
    /// Status poll cadence.
    pub status_interval: Duration,
    /// Downstream collector endpoint (ree0xq-server). When `None` the
    /// collector logs events to tracing instead.
    pub collector_endpoint: Option<String>,
    /// QBER threshold above which the link is reported as `Degraded`.
    pub qber_warn_threshold: f32,
    /// QBER threshold above which the link is reported as `Failed`.
    pub qber_fail_threshold: f32,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            kme_endpoints: vec!["http://127.0.0.1:11071/api/v1".into()],
            slave_sae_id: "SAE-REE0XQ-COLLECTOR".into(),
            status_interval: Duration::from_secs(5),
            collector_endpoint: None,
            qber_warn_threshold: 0.05,
            qber_fail_threshold: 0.11,
        }
    }
}

/// Derive an aggregate [`LinkHealth`] from a fresh [`StatusResponse`]
/// and the configured thresholds.
pub fn derive_link_health(
    status: &StatusResponse,
    warn_qber: f32,
    fail_qber: f32,
) -> (LinkHealth, Option<String>) {
    let qber = status.link_qber.unwrap_or(0.0);
    if qber >= fail_qber {
        return (
            LinkHealth::Failed,
            Some(format!(
                "QBER {:.3} ≥ fail threshold {:.3}",
                qber, fail_qber
            )),
        );
    }
    if qber >= warn_qber {
        return (
            LinkHealth::Degraded,
            Some(format!(
                "QBER {:.3} ≥ warn threshold {:.3}",
                qber, warn_qber
            )),
        );
    }
    if status.stored_key_count == 0 {
        return (
            LinkHealth::Degraded,
            Some("KME reports zero stored keys".into()),
        );
    }
    (LinkHealth::Ok, None)
}

/// Build a `qkd_kme` event from a fresh status response.
pub fn build_kme_event(
    kme_endpoint: &str,
    status: &StatusResponse,
    health: LinkHealth,
    degraded_reason: Option<String>,
) -> CryptoInventoryEvent {
    CryptoInventoryEvent {
        schema_version: SCHEMA_VERSION,
        schema_minor: SCHEMA_MINOR,
        source_module: SOURCE_MODULE.into(),
        observed_at: chrono::Utc::now(),
        asset: Asset {
            kind: AssetKind::QkdKme,
            identity: status.source_kme_id.clone(),
            host: Some(kme_endpoint.into()),
        },
        primitives: vec![],
        channel_protection: Some(ChannelProtection {
            // KME-level observation: the channel-state is the strongest
            // mode the KME can support; per-session reports refine.
            state: ChannelState::QkdHybridPsk,
            kme_endpoint: Some(kme_endpoint.into()),
            key_id_observed: None,
            psk_age_seconds: None,
            link_qber: status.link_qber,
            link_key_rate_bps: status.link_key_rate_bps,
            link_health: health,
            degraded_reason,
        }),
        agility: None,
        posture: Posture {
            score: match health {
                LinkHealth::Ok => 90,
                LinkHealth::Degraded => 50,
                LinkHealth::Failed => 10,
            },
            rationale: format!(
                "KME {} reported {:?}; stored_keys={}",
                status.source_kme_id, health, status.stored_key_count
            ),
            recommended_replacement: None,
        },
    }
}

/// Poll one KME once and return its derived event.
/// Build the canonical ETSI 014 `/status` URL from a base endpoint.
///
/// Operators typically pass `--kme http://host/api/v1` — we accept
/// that and append the spec-mandated `keys/{slave_SAE_ID}/status`
/// suffix. We also accept `--kme http://host/api/v1/keys` (already
/// includes the segment); the function is idempotent.
fn status_url(endpoint: &str, slave_sae_id: &str) -> String {
    let base = endpoint.trim_end_matches('/');
    if base.ends_with("/keys") {
        format!("{}/{}/{}", base, slave_sae_id, paths::STATUS)
    } else {
        format!("{}/keys/{}/{}", base, slave_sae_id, paths::STATUS)
    }
}

async fn poll_once(
    client: &Client,
    endpoint: &str,
    slave_sae_id: &str,
    cfg: &CollectorConfig,
) -> anyhow::Result<CryptoInventoryEvent> {
    let url = status_url(endpoint, slave_sae_id);
    debug!(%url, "polling KME");
    let resp = client.get(&url).send().await?;
    let status_code = resp.status();
    if !status_code.is_success() {
        warn!(%url, %status_code, "KME status request failed");
        let stub = StatusResponse {
            source_kme_id: format!("unreachable:{endpoint}"),
            target_kme_id: "unknown".into(),
            master_sae_id: "unknown".into(),
            slave_sae_id: slave_sae_id.into(),
            key_size: 0,
            stored_key_count: 0,
            max_key_count: 0,
            max_key_per_request: 0,
            max_key_size: 0,
            min_key_size: 0,
            max_sae_id_count: 0,
            link_qber: None,
            link_key_rate_bps: None,
        };
        return Ok(build_kme_event(
            endpoint,
            &stub,
            LinkHealth::Failed,
            Some(format!("HTTP {} from /status", status_code)),
        ));
    }
    let body: StatusResponse = resp.json().await?;
    let (health, reason) =
        derive_link_health(&body, cfg.qber_warn_threshold, cfg.qber_fail_threshold);
    Ok(build_kme_event(endpoint, &body, health, reason))
}

/// Run the collector loop until cancelled (Ctrl-C).
pub async fn run(cfg: CollectorConfig) -> anyhow::Result<()> {
    let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
    info!(
        endpoints = ?cfg.kme_endpoints,
        interval_s = cfg.status_interval.as_secs(),
        "ree0xq-qkd collector starting"
    );
    let mut tick = tokio::time::interval(cfg.status_interval);
    loop {
        tick.tick().await;
        for endpoint in &cfg.kme_endpoints {
            match poll_once(&client, endpoint, &cfg.slave_sae_id, &cfg).await {
                Ok(ev) => {
                    if let Some(downstream) = &cfg.collector_endpoint {
                        if let Err(e) = forward_event(&client, downstream, &ev).await {
                            error!(%endpoint, error=%e, "downstream forward failed");
                        }
                    } else {
                        debug!(event=?ev, "emitted (no downstream configured)");
                    }
                }
                Err(e) => {
                    error!(%endpoint, error=%e, "poll failed");
                }
            }
        }
    }
}

async fn forward_event(
    client: &Client,
    downstream: &str,
    event: &CryptoInventoryEvent,
) -> anyhow::Result<()> {
    let resp = client.post(downstream).json(event).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("downstream returned {}", resp.status());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_status(qber: f32, stored: u32) -> StatusResponse {
        StatusResponse {
            source_kme_id: "KME-T".into(),
            target_kme_id: "KME-T2".into(),
            master_sae_id: "SAE-M".into(),
            slave_sae_id: "SAE-S".into(),
            key_size: 256,
            stored_key_count: stored,
            max_key_count: 1024,
            max_key_per_request: 32,
            max_key_size: 4096,
            min_key_size: 64,
            max_sae_id_count: 0,
            link_qber: Some(qber),
            link_key_rate_bps: Some(12_000),
        }
    }

    #[test]
    fn health_thresholds_match_defaults() {
        let warn = 0.05;
        let fail = 0.11;
        assert!(matches!(
            derive_link_health(&fixture_status(0.02, 100), warn, fail).0,
            LinkHealth::Ok
        ));
        assert!(matches!(
            derive_link_health(&fixture_status(0.07, 100), warn, fail).0,
            LinkHealth::Degraded
        ));
        assert!(matches!(
            derive_link_health(&fixture_status(0.20, 100), warn, fail).0,
            LinkHealth::Failed
        ));
    }

    #[test]
    fn zero_stored_keys_reports_degraded_even_with_low_qber() {
        let (health, reason) = derive_link_health(&fixture_status(0.01, 0), 0.05, 0.11);
        assert!(matches!(health, LinkHealth::Degraded));
        assert!(reason.unwrap().contains("zero stored keys"));
    }

    #[test]
    fn status_url_appends_keys_segment_when_missing() {
        assert_eq!(
            status_url("http://kme.example/api/v1", "SAE-A"),
            "http://kme.example/api/v1/keys/SAE-A/status"
        );
        assert_eq!(
            status_url("http://kme.example/api/v1/keys", "SAE-A"),
            "http://kme.example/api/v1/keys/SAE-A/status"
        );
        assert_eq!(
            status_url("http://kme.example/api/v1/", "SAE-A"),
            "http://kme.example/api/v1/keys/SAE-A/status"
        );
    }

    #[test]
    fn build_kme_event_carries_channel_protection_block() {
        let status = fixture_status(0.018, 100);
        let ev = build_kme_event("http://kme.example/api/v1", &status, LinkHealth::Ok, None);
        assert_eq!(ev.asset.kind, AssetKind::QkdKme);
        let cp = ev
            .channel_protection
            .expect("must populate channel_protection");
        assert_eq!(cp.state, ChannelState::QkdHybridPsk);
        assert_eq!(cp.link_health, LinkHealth::Ok);
        assert_eq!(cp.link_qber, Some(0.018));
    }
}
