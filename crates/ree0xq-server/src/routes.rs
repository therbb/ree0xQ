//! HTTP route handlers.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use ree0xq_core::{AssetKind, CryptoInventoryEvent, SCHEMA_VERSION};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::posture;
use crate::AppState;

/// `GET /healthz` — liveness.
pub async fn healthz() -> &'static str {
    "ok"
}

/// `POST /v1/events` — single event.
pub async fn ingest_one(
    State(st): State<AppState>,
    Json(ev): Json<CryptoInventoryEvent>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    ingest(&st, vec![ev]).await.map(|_| StatusCode::ACCEPTED)
}

/// `POST /v1/events/batch` — array of events.
pub async fn ingest_batch(
    State(st): State<AppState>,
    Json(evs): Json<Vec<CryptoInventoryEvent>>,
) -> Result<Json<BatchIngestResponse>, (StatusCode, Json<ApiError>)> {
    let count = evs.len();
    ingest(&st, evs).await?;
    Ok(Json(BatchIngestResponse { ingested: count }))
}

async fn ingest(
    st: &AppState,
    evs: Vec<CryptoInventoryEvent>,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    for ev in &evs {
        if ev.schema_version != SCHEMA_VERSION {
            warn!(
                got = ev.schema_version,
                expected = SCHEMA_VERSION,
                source = %ev.source_module,
                "rejecting event with unsupported major schema_version"
            );
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ApiError {
                    code: "schema_version_mismatch".into(),
                    message: format!(
                        "schema_version {} not supported; expected {}",
                        ev.schema_version, SCHEMA_VERSION
                    ),
                }),
            ));
        }
    }
    for ev in evs {
        debug!(
            source = %ev.source_module,
            kind = ?ev.asset.kind,
            identity = %ev.asset.identity,
            "ingesting event"
        );
        st.store.append(ev).await.map_err(store_err)?;
    }
    Ok(())
}

fn store_err(e: anyhow::Error) -> (StatusCode, Json<ApiError>) {
    warn!(error = %e, "store error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiError {
            code: "store_failure".into(),
            message: e.to_string(),
        }),
    )
}

/// Query string for `GET /v1/events?limit=N`.
#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    /// Maximum number of events to return. Defaults to 100.
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}

/// `GET /v1/events` — most recent events.
pub async fn list_events(
    State(st): State<AppState>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<EventsResponse>, (StatusCode, Json<ApiError>)> {
    let events = st.store.recent(q.limit).await.map_err(store_err)?;
    Ok(Json(EventsResponse {
        count: events.len(),
        events,
    }))
}

/// `GET /v1/inventory` — per-asset latest event plus per-asset $q$.
pub async fn inventory(
    State(st): State<AppState>,
) -> Result<Json<InventoryResponse>, (StatusCode, Json<ApiError>)> {
    let now = chrono::Utc::now();
    let mut items = Vec::new();
    for ev in st.store.latest_per_asset().await.map_err(store_err)? {
        let q = posture::q_for_event(&ev, now, st.default_deadline, st.horizon_years);
        let blocked = posture::is_blocked(ev.agility.as_ref());
        items.push(InventoryItem {
            source_module: ev.source_module.clone(),
            asset_kind: ev.asset.kind.clone(),
            identity: ev.asset.identity.clone(),
            host: ev.asset.host.clone(),
            q,
            blocked,
            primitives: ev.primitives.iter().map(|p| p.algorithm.clone()).collect(),
            observed_at: ev.observed_at,
        });
    }
    items.sort_by(|a, b| b.q.partial_cmp(&a.q).unwrap_or(std::cmp::Ordering::Equal));
    Ok(Json(InventoryResponse {
        count: items.len(),
        items,
    }))
}

/// `GET /v1/posture` — org-level rollup under default weights.
pub async fn org_posture(
    State(st): State<AppState>,
) -> Result<Json<OrgPosture>, (StatusCode, Json<ApiError>)> {
    let now = chrono::Utc::now();
    let events = st.store.latest_per_asset().await.map_err(store_err)?;
    let org = posture::org_score(&events, now, st.default_deadline, st.horizon_years);
    let blocked_count = events
        .iter()
        .filter(|e| posture::is_blocked(e.agility.as_ref()))
        .count();
    let assets = events.len();
    Ok(Json(OrgPosture {
        org_q: org,
        deadline: st.default_deadline,
        horizon_years: st.horizon_years,
        assets,
        blocked_count,
    }))
}

/// `GET /v1/qkd/links` — assets of kind `qkd_link` / `qkd_kme`.
pub async fn qkd_links(
    State(st): State<AppState>,
) -> Result<Json<QkdLinksResponse>, (StatusCode, Json<ApiError>)> {
    let links: Vec<QkdLinkSummary> = st
        .store
        .latest_per_asset()
        .await
        .map_err(store_err)?
        .into_iter()
        .filter(|ev| matches!(ev.asset.kind, AssetKind::QkdLink | AssetKind::QkdKme))
        .map(QkdLinkSummary::from)
        .collect();
    Ok(Json(QkdLinksResponse {
        count: links.len(),
        links,
    }))
}

/// `GET /v1/blocked` — assets flagged BLOCKED (Locked/Frozen agility).
pub async fn blocked_assets(
    State(st): State<AppState>,
) -> Result<Json<InventoryResponse>, (StatusCode, Json<ApiError>)> {
    let now = chrono::Utc::now();
    let mut items = Vec::new();
    for ev in st.store.latest_per_asset().await.map_err(store_err)? {
        if !posture::is_blocked(ev.agility.as_ref()) {
            continue;
        }
        items.push(InventoryItem {
            source_module: ev.source_module.clone(),
            asset_kind: ev.asset.kind.clone(),
            identity: ev.asset.identity.clone(),
            host: ev.asset.host.clone(),
            q: posture::q_for_event(&ev, now, st.default_deadline, st.horizon_years),
            blocked: true,
            primitives: ev.primitives.iter().map(|p| p.algorithm.clone()).collect(),
            observed_at: ev.observed_at,
        });
    }
    items.sort_by(|a, b| b.q.partial_cmp(&a.q).unwrap_or(std::cmp::Ordering::Equal));
    Ok(Json(InventoryResponse {
        count: items.len(),
        items,
    }))
}

/// `GET /v1/recommendations` — per-asset PQ migration
/// recommendations. Walks the latest-per-asset map and
/// runs `ree0xq_agility::recommend::recommend_for` on each
/// event's primitives.
pub async fn recommendations(
    State(st): State<AppState>,
) -> Result<Json<RecommendationsResponse>, (StatusCode, Json<ApiError>)> {
    let events = st.store.latest_per_asset().await.map_err(store_err)?;
    let mut items = Vec::new();
    for ev in events {
        let recs = ree0xq_agility::recommend::recommend_for(&ev.primitives);
        if recs.is_empty() {
            continue;
        }
        items.push(RecommendationItem {
            source_module: ev.source_module.clone(),
            asset_kind: ev.asset.kind.clone(),
            identity: ev.asset.identity.clone(),
            host: ev.asset.host.clone(),
            current_primitives: ev.primitives.iter().map(|p| p.algorithm.clone()).collect(),
            recommendations: recs,
        });
    }
    Ok(Json(RecommendationsResponse {
        count: items.len(),
        items,
    }))
}

/// `GET /v1/agility/deadlines` — full regulator deadline
/// table. Optionally filter by `?jurisdiction=US`
/// (case-insensitive prefix) and/or `?horizon_days=N` to
/// surface only deadlines that fall within the next `N`
/// days from today.
pub async fn agility_deadlines(Query(q): Query<DeadlinesQuery>) -> Json<DeadlinesResponse> {
    let mut items = if let Some(prefix) = q.jurisdiction.as_deref() {
        ree0xq_agility::deadlines::for_jurisdiction(prefix)
    } else {
        ree0xq_agility::deadlines::all()
    };
    if let Some(days) = q.horizon_days {
        let now = chrono::Utc::now();
        let end = now + chrono::Duration::days(days as i64);
        items.retain(|e| e.effective_date >= now && e.effective_date <= end);
    }
    Json(DeadlinesResponse {
        count: items.len(),
        items,
    })
}

/// `GET /v1/agility/compat` — TLS-stack ↔ algorithm
/// compatibility matrix. Filter shape:
/// `?stack=<name>` returns one stack's entries;
/// `?stack=<name>&algorithm=<algo>` returns the single
/// pair (404 if absent). With no query string the full
/// matrix is returned, useful for the dashboard's overview.
pub async fn agility_compat(
    Query(q): Query<CompatQuery>,
) -> Result<Json<CompatResponse>, (StatusCode, Json<ApiError>)> {
    match (q.stack.as_deref(), q.algorithm.as_deref()) {
        (Some(stack), Some(algo)) => match ree0xq_agility::compat::lookup(stack, algo) {
            Some(e) => Ok(Json(CompatResponse {
                count: 1,
                items: vec![e],
            })),
            None => Err((
                StatusCode::NOT_FOUND,
                Json(ApiError {
                    code: "compat_unknown".into(),
                    message: format!("no entry for stack={stack} algorithm={algo}"),
                }),
            )),
        },
        (Some(stack), None) => {
            let items = ree0xq_agility::compat::list_stack(stack);
            Ok(Json(CompatResponse {
                count: items.len(),
                items,
            }))
        }
        (None, _) => {
            // Full dump. We don't expose an "everything"
            // helper on the agility module, so flatten the
            // matrix via the documented per-stack accessor.
            // Stack names match the ones the matrix is
            // keyed under — see `crates/ree0xq-agility/src/compat.rs`.
            let stacks = [
                "openssl-3.x",
                "boringssl",
                "rustls-post-quantum",
                "go-crypto-tls",
                "bouncycastle",
                "nss",
            ];
            let mut items = Vec::new();
            for s in stacks {
                items.extend(ree0xq_agility::compat::list_stack(s));
            }
            Ok(Json(CompatResponse {
                count: items.len(),
                items,
            }))
        }
    }
}

/// `POST /v1/agility/roadmap` — project the supplied
/// migration plan against the current inventory. The
/// inventory snapshot is sourced from
/// [`crate::store::Store::latest_per_asset`] so the
/// operator doesn't have to re-send it; the plan is the
/// body.
pub async fn agility_roadmap(
    State(st): State<AppState>,
    Json(plan): Json<RoadmapRequest>,
) -> Result<Json<ree0xq_agility::roadmap::RoadmapProjection>, (StatusCode, Json<ApiError>)> {
    let events = st.store.latest_per_asset().await.map_err(store_err)?;
    let now = chrono::Utc::now();
    let inventory: Vec<ree0xq_agility::roadmap::AssetSnapshot> = events
        .iter()
        .map(|ev| {
            let q = posture::q_for_event(ev, now, st.default_deadline, st.horizon_years);
            let blocked = posture::is_blocked(ev.agility.as_ref());
            ree0xq_agility::roadmap::AssetSnapshot {
                identity: ev.asset.identity.clone(),
                q,
                blocked,
                primitives: ev.primitives.iter().map(|p| p.algorithm.clone()).collect(),
            }
        })
        .collect();
    let projection = ree0xq_agility::roadmap::project_roadmap(&inventory, &plan.milestones)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ApiError {
                    code: "roadmap_projection_failed".into(),
                    message: e.to_string(),
                }),
            )
        })?;
    Ok(Json(projection))
}

// ----- response shapes -----

/// Error body shared by every endpoint.
#[derive(Debug, Serialize)]
pub struct ApiError {
    /// Stable machine-readable error code.
    pub code: String,
    /// Human-readable message.
    pub message: String,
}

/// Response shape for `POST /v1/events/batch`.
#[derive(Debug, Serialize)]
pub struct BatchIngestResponse {
    /// Number of events ingested.
    pub ingested: usize,
}

/// Response shape for `GET /v1/events`.
#[derive(Debug, Serialize)]
pub struct EventsResponse {
    /// Count returned.
    pub count: usize,
    /// Events, most recent first.
    pub events: Vec<CryptoInventoryEvent>,
}

/// Per-asset inventory entry.
#[derive(Debug, Serialize)]
pub struct InventoryItem {
    /// Source module name.
    pub source_module: String,
    /// Asset kind.
    pub asset_kind: AssetKind,
    /// Module-scoped identity.
    pub identity: String,
    /// Optional host hint.
    pub host: Option<String>,
    /// Computed q under default weights.
    pub q: f32,
    /// True when agility ≤ Locked.
    pub blocked: bool,
    /// Algorithm names of the asset's primitives.
    pub primitives: Vec<String>,
    /// Observation time.
    pub observed_at: chrono::DateTime<chrono::Utc>,
}

/// Response shape for `GET /v1/inventory` and `GET /v1/blocked`.
#[derive(Debug, Serialize)]
pub struct InventoryResponse {
    /// Number of inventory rows.
    pub count: usize,
    /// Inventory rows.
    pub items: Vec<InventoryItem>,
}

/// Response shape for `GET /v1/posture`.
#[derive(Debug, Serialize)]
pub struct OrgPosture {
    /// Org-level $q$.
    pub org_q: f32,
    /// The deadline used for the computation.
    pub deadline: chrono::DateTime<chrono::Utc>,
    /// Horizon constant (years).
    pub horizon_years: f32,
    /// Total asset count in the rollup.
    pub assets: usize,
    /// Assets whose agility ≤ Locked.
    pub blocked_count: usize,
}

/// QKD link summary row.
#[derive(Debug, Serialize)]
pub struct QkdLinkSummary {
    /// The KME / link identity.
    pub identity: String,
    /// KME endpoint URL when known.
    pub kme_endpoint: Option<String>,
    /// Aggregate link health, snake_case.
    pub link_health: String,
    /// Observed QBER.
    pub link_qber: Option<f32>,
    /// Average key rate (bps).
    pub link_key_rate_bps: Option<u64>,
    /// Observation timestamp.
    pub observed_at: chrono::DateTime<chrono::Utc>,
}

impl From<CryptoInventoryEvent> for QkdLinkSummary {
    fn from(ev: CryptoInventoryEvent) -> Self {
        let cp = ev.channel_protection.as_ref();
        Self {
            identity: ev.asset.identity.clone(),
            kme_endpoint: cp.and_then(|c| c.kme_endpoint.clone()),
            link_health: cp
                .map(|c| format!("{:?}", c.link_health).to_lowercase())
                .unwrap_or_else(|| "unknown".into()),
            link_qber: cp.and_then(|c| c.link_qber),
            link_key_rate_bps: cp.and_then(|c| c.link_key_rate_bps),
            observed_at: ev.observed_at,
        }
    }
}

/// Response shape for `GET /v1/qkd/links`.
#[derive(Debug, Serialize)]
pub struct QkdLinksResponse {
    /// Number of QKD links observed.
    pub count: usize,
    /// QKD link rows.
    pub links: Vec<QkdLinkSummary>,
}

/// One asset's recommendation row.
#[derive(Debug, Serialize)]
pub struct RecommendationItem {
    /// Source module that emitted the asset.
    pub source_module: String,
    /// Asset kind.
    pub asset_kind: AssetKind,
    /// Module-scoped identity.
    pub identity: String,
    /// Optional host.
    pub host: Option<String>,
    /// Algorithm names currently observed on the asset.
    pub current_primitives: Vec<String>,
    /// Ranked replacement recommendations (cheapest first).
    pub recommendations: Vec<ree0xq_agility::recommend::Recommendation>,
}

/// Response shape for `GET /v1/recommendations`.
#[derive(Debug, Serialize)]
pub struct RecommendationsResponse {
    /// Number of assets with at least one recommendation.
    pub count: usize,
    /// Per-asset rows.
    pub items: Vec<RecommendationItem>,
}

/// Query-string shape for `GET /v1/agility/deadlines`.
#[derive(Debug, Deserialize)]
pub struct DeadlinesQuery {
    /// Optional jurisdiction prefix (case-insensitive),
    /// e.g. `US` or `EU-ANSSI`.
    pub jurisdiction: Option<String>,
    /// Optional window — only return deadlines that fall
    /// within `[now, now + horizon_days]`.
    pub horizon_days: Option<u32>,
}

/// Response shape for `GET /v1/agility/deadlines`.
#[derive(Debug, Serialize)]
pub struct DeadlinesResponse {
    /// Number of entries returned after filtering.
    pub count: usize,
    /// Entries (chronologically sorted by the underlying
    /// table; filters preserve order).
    pub items: Vec<ree0xq_agility::deadlines::DeadlineEntry>,
}

/// Query-string shape for `GET /v1/agility/compat`.
#[derive(Debug, Deserialize)]
pub struct CompatQuery {
    /// Optional stack name (case-insensitive),
    /// e.g. `openssl`.
    pub stack: Option<String>,
    /// Optional algorithm name (case-insensitive),
    /// e.g. `ML-DSA-65`.
    pub algorithm: Option<String>,
}

/// Response shape for `GET /v1/agility/compat`.
#[derive(Debug, Serialize)]
pub struct CompatResponse {
    /// Number of matrix entries returned.
    pub count: usize,
    /// Matrix entries.
    pub items: Vec<ree0xq_agility::compat::CompatEntry>,
}

/// Request body for `POST /v1/agility/roadmap`.
#[derive(Debug, Deserialize)]
pub struct RoadmapRequest {
    /// Operator-supplied migration plan.
    pub milestones: Vec<ree0xq_agility::roadmap::Milestone>,
}
