//! `ree0xq-server` — collector library.
//!
//! The library exposes the Axum [`Router`] and the in-memory state
//! type behind it. The binary entry-point (`bin/main.rs`) wires
//! these together with CLI flags. Splitting library from binary
//! lets integration tests spin the whole server up against an
//! ephemeral port without going through the CLI.
//!
//! # V1 surface
//!
//! ```text
//! POST /v1/events                    ingest a single event (JSON body)
//! POST /v1/events/batch              ingest an array of events
//! GET  /v1/events?limit=N            paginated event log (most recent first)
//! GET  /v1/inventory                 deduplicated asset list with latest posture
//! GET  /v1/posture                   org-level rollup under default weights
//! GET  /v1/qkd/links                 QKD links observed by ree0xq-qkd
//! GET  /v1/blocked                   assets flagged BLOCKED (low agility)
//! POST /v1/enrol                     redeem a bootstrap token → agent cert
//! POST /v1/admin/bootstrap-tokens    admin-only: mint a new bootstrap token
//! GET  /healthz                      liveness probe
//! ```
//!
//! Storage is in-memory (DashMap) in V1; Postgres swap-in lives at
//! `store::EventStore` so the upgrade is a single trait swap.

#![warn(rust_2018_idioms)]

pub mod ca;
pub mod enrol;
pub mod posture;
pub mod ratelimit;
pub mod routes;
pub mod store;
pub mod store_pg;
pub mod tls;

use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    response::IntoResponse,
    routing::{get, post},
    Router,
};

/// Maximum accepted request-body size, in bytes. Applied to every
/// route on both listeners. The largest legitimate body is a
/// `POST /v1/events/batch` array; 8 MiB comfortably holds a few
/// thousand events while capping the memory a single malicious or
/// runaway client can force the collector to buffer. axum's default
/// is 2 MiB — we raise it for batches but keep a hard ceiling so an
/// oversize POST is rejected with 413 rather than streamed into RAM.
pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Shared application state injected into every handler.
#[derive(Clone)]
pub struct AppState {
    /// Event store — trait object so the Postgres backend can swap
    /// in without touching any handler.
    pub store: Arc<dyn store::EventStore>,
    /// Default deadline used by org-level rollup. May be operator-tunable.
    pub default_deadline: chrono::DateTime<chrono::Utc>,
    /// Horizon constant (years) for deadline-tension computation.
    pub horizon_years: f32,
    /// Internal CA — signs agent certs at enrolment time.
    pub ca: ca::Ca,
    /// One-time bootstrap-token store. Tokens are admin-issued
    /// and consumed on first successful `/v1/enrol`.
    pub tokens: Arc<enrol::BootstrapTokenStore>,
    /// Admin secret expected in `X-Admin-Token` on
    /// `/v1/admin/bootstrap-tokens`. When `None`, the admin
    /// endpoint short-circuits to 503 — operators must boot
    /// with `--admin-token` (or `REE0XQ_ADMIN_TOKEN`) to enable
    /// token issuance.
    pub admin_token: Option<String>,
    /// Per-client rate limiter guarding the bootstrap endpoints
    /// (`/v1/enrol`, `/v1/admin/bootstrap-tokens`).
    pub rate_limiter: Arc<ratelimit::RateLimiter>,
}

impl AppState {
    /// Construct an in-memory state with defaults matching the paper
    /// (NSA CNSA 2.0 browser/server class deadline). The CA is
    /// loaded from (or generated into) `ca_dir`; `admin_token` is
    /// used for `/v1/admin/bootstrap-tokens` auth.
    pub fn new_in_memory(
        ca_dir: &std::path::Path,
        admin_token: Option<String>,
    ) -> anyhow::Result<Self> {
        Self::with_store(
            Arc::new(store::InMemoryEventStore::new()),
            ca_dir,
            admin_token,
        )
    }

    /// Same as [`Self::new_in_memory`] but uses a caller-supplied
    /// event store — the path the binary takes when
    /// `--database-url` is set (Postgres) or any custom impl
    /// that satisfies the trait.
    pub fn with_store(
        store: Arc<dyn store::EventStore>,
        ca_dir: &std::path::Path,
        admin_token: Option<String>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            store,
            default_deadline: chrono::DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            horizon_years: 5.0,
            ca: ca::Ca::load_or_init(ca_dir)?,
            tokens: enrol::BootstrapTokenStore::new(),
            admin_token,
            rate_limiter: Arc::new(ratelimit::RateLimiter::with_defaults()),
        })
    }
}

/// Combined router carrying every V1 route on a single listener.
///
/// **Security note.** This collapses the bootstrap routes
/// (`/v1/enrol`, `/v1/admin/bootstrap-tokens`) and the main routes
/// onto one listener with no mTLS client-cert boundary between
/// them. It exists for development, the in-process integration
/// tests, and the `scripts/acceptance.sh` smoke — *not* for
/// production. In production run with `--tls`, which boots
/// [`router_main`] (behind the mTLS listener) and
/// [`router_bootstrap`] (the cert-less enrolment listener) on
/// separate ports so the two trust domains stay split.
pub fn router(state: AppState) -> Router {
    router_bootstrap(state.clone()).merge(router_main(state))
}

/// Bootstrap-side routes: reachable on the TLS-without-client-
/// cert listener so un-enrolled agents can still pick up a
/// cert. Carries `/healthz`, `/v1/enrol`,
/// `/v1/admin/bootstrap-tokens`.
pub fn router_bootstrap(state: AppState) -> Router {
    // The token-bearing endpoints are rate-limited per client; the
    // liveness probe is not, so monitoring never trips the limit.
    let limited = Router::new()
        .route("/v1/enrol", post(enrol::enrol))
        .route(
            "/v1/admin/bootstrap-tokens",
            post(enrol::issue_bootstrap_token),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.rate_limiter.clone(),
            rate_limit_mw,
        ))
        .with_state(state.clone());

    Router::new()
        .route("/healthz", get(routes::healthz))
        .with_state(state)
        .merge(limited)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// Middleware: reject a request with 429 when the client has
/// exceeded the bootstrap-endpoint rate limit. The client key is
/// derived from `X-Forwarded-For` / `X-Real-IP` / peer address —
/// see [`ratelimit::client_key`].
async fn rate_limit_mw(
    axum::extract::State(limiter): axum::extract::State<Arc<ratelimit::RateLimiter>>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let key = ratelimit::client_key(peer.map(|c| c.0), req.headers());
    if !limiter.check(&key) {
        return (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded; retry later\n",
        )
            .into_response();
    }
    next.run(req).await
}

/// Main routes: served behind the mTLS listener when `--tls` is
/// on. A successful TLS handshake on this listener already
/// proved the peer holds a CA-signed client cert, so handlers
/// don't need to re-check.
pub fn router_main(state: AppState) -> Router {
    Router::new()
        .route(
            "/v1/events",
            post(routes::ingest_one).get(routes::list_events),
        )
        .route("/v1/events/batch", post(routes::ingest_batch))
        .route("/v1/inventory", get(routes::inventory))
        .route("/v1/posture", get(routes::org_posture))
        .route("/v1/qkd/links", get(routes::qkd_links))
        .route("/v1/blocked", get(routes::blocked_assets))
        .route("/v1/recommendations", get(routes::recommendations))
        .route("/v1/agility/deadlines", get(routes::agility_deadlines))
        .route("/v1/agility/compat", get(routes::agility_compat))
        .route("/v1/agility/roadmap", post(routes::agility_roadmap))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}
