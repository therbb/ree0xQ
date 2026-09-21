//! Postgres-backed [`crate::store::EventStore`] (SEZ-2).
//!
//! Two tables (see `migrations/0001_init.sql`):
//!
//! - `events`  — append-only history. Every ingested event lands
//!   here in arrival order. `GET /v1/events?limit=N` walks this
//!   table newest-first via the `idx_events_observed_at_desc`
//!   index.
//! - `assets` — per-`(source_module, asset_kind, asset_identity)`
//!   current state. Updated on each ingest where the incoming
//!   event's `observed_at` is at-or-after the row's current
//!   `observed_at`. `GET /v1/inventory`, `GET /v1/posture`, and
//!   `GET /v1/blocked` all read from here.
//!
//! Both columns hold the full event in JSONB so adding
//! optional schema-minor fields stays migration-free; the
//! columns we filter / order on (`observed_at`, `asset_kind`,
//! …) are denormalised for index-friendly queries.

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use ree0xq_core::{Asset, CryptoInventoryEvent};
use sqlx::postgres::{PgPoolOptions, Postgres};
use sqlx::{Pool, Row};
use tracing::{info, instrument};

use crate::store::EventStore;

/// Migrations bundled into the binary so a fresh boot against
/// an empty database can self-provision.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Pool sized for the V1 ingest profile. Operators bump this
/// (and Postgres `max_connections`) for production deployments;
/// 16 matches the in-memory throughput probe's concurrency
/// floor.
const DEFAULT_MAX_CONNECTIONS: u32 = 16;
const DEFAULT_CONNECT_TIMEOUT_S: u64 = 10;

/// Postgres-backed event store.
pub struct PgEventStore {
    pool: Pool<Postgres>,
}

impl PgEventStore {
    /// Connect to `database_url`, run the bundled migrations,
    /// and return a ready-to-use store.
    pub async fn connect(database_url: &str) -> Result<Self> {
        Self::connect_with(database_url, DEFAULT_MAX_CONNECTIONS).await
    }

    /// As [`Self::connect`] but lets the caller size the pool.
    /// Used by the load tests.
    pub async fn connect_with(database_url: &str, max_connections: u32) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_S))
            .connect(database_url)
            .await
            .with_context(|| format!("connect to Postgres at {}", sanitised_url(database_url)))?;
        info!(
            url = %sanitised_url(database_url),
            max_connections,
            "Postgres pool ready; running migrations"
        );
        MIGRATOR
            .run(&pool)
            .await
            .context("run ree0xq-server migrations")?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl EventStore for PgEventStore {
    #[instrument(skip(self, ev), fields(source = %ev.source_module, identity = %ev.asset.identity))]
    async fn append(&self, ev: CryptoInventoryEvent) -> Result<()> {
        // One transaction: append to the history log, then
        // conditionally upsert the per-asset snapshot. The
        // conditional `WHERE` clause inside the UPSERT keeps
        // out-of-order events (older observed_at than the
        // current row) from clobbering the latest snapshot.
        let body = serde_json::to_value(&ev).context("serialize event")?;
        let asset_kind = serde_json::to_value(&ev.asset.kind)
            .context("serialize asset kind")?
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("asset kind did not serialize as string"))?
            .to_string();

        let mut tx = self.pool.begin().await.context("begin tx")?;

        sqlx::query(
            "INSERT INTO events
                (observed_at, source_module, asset_kind, asset_identity, body)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(ev.observed_at)
        .bind(&ev.source_module)
        .bind(&asset_kind)
        .bind(&ev.asset.identity)
        .bind(&body)
        .execute(&mut *tx)
        .await
        .context("insert into events")?;

        sqlx::query(
            "INSERT INTO assets
                (source_module, asset_kind, asset_identity, observed_at, body)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (source_module, asset_kind, asset_identity) DO UPDATE
                SET observed_at = EXCLUDED.observed_at,
                    body        = EXCLUDED.body
                WHERE assets.observed_at <= EXCLUDED.observed_at",
        )
        .bind(&ev.source_module)
        .bind(&asset_kind)
        .bind(&ev.asset.identity)
        .bind(ev.observed_at)
        .bind(&body)
        .execute(&mut *tx)
        .await
        .context("upsert into assets")?;

        tx.commit().await.context("commit ingest tx")?;
        Ok(())
    }

    async fn len(&self) -> Result<usize> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM events")
            .fetch_one(&self.pool)
            .await
            .context("count events")?;
        Ok(row.0 as usize)
    }

    async fn recent(&self, limit: usize) -> Result<Vec<CryptoInventoryEvent>> {
        // i64 is what sqlx wants for a postgres BIGINT bind.
        let lim: i64 = limit.try_into().unwrap_or(i64::MAX);
        let rows = sqlx::query("SELECT body FROM events ORDER BY observed_at DESC LIMIT $1")
            .bind(lim)
            .fetch_all(&self.pool)
            .await
            .context("select recent events")?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let body: serde_json::Value = row.try_get("body")?;
            out.push(serde_json::from_value(body).context("deserialize event body")?);
        }
        Ok(out)
    }

    async fn latest_per_asset(&self) -> Result<Vec<CryptoInventoryEvent>> {
        let rows = sqlx::query("SELECT body FROM assets")
            .fetch_all(&self.pool)
            .await
            .context("select latest per asset")?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let body: serde_json::Value = row.try_get("body")?;
            out.push(serde_json::from_value(body).context("deserialize asset body")?);
        }
        Ok(out)
    }

    async fn latest_for(
        &self,
        asset: &Asset,
        source_module: &str,
    ) -> Result<Option<CryptoInventoryEvent>> {
        let asset_kind = serde_json::to_value(&asset.kind)
            .context("serialize asset kind")?
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("asset kind did not serialize as string"))?
            .to_string();
        let row = sqlx::query(
            "SELECT body FROM assets
             WHERE source_module = $1
               AND asset_kind = $2
               AND asset_identity = $3",
        )
        .bind(source_module)
        .bind(&asset_kind)
        .bind(&asset.identity)
        .fetch_optional(&self.pool)
        .await
        .context("select latest_for")?;
        match row {
            None => Ok(None),
            Some(row) => {
                let body: serde_json::Value = row.try_get("body")?;
                Ok(Some(serde_json::from_value(body)?))
            }
        }
    }
}

/// Strip any `password=...` (libpq style) or
/// `://user:password@` from a connection URL before we put it
/// in a log line.
fn sanitised_url(url: &str) -> String {
    // postgres://user:pass@host:port/db → postgres://user@host:port/db
    if let Some(scheme_end) = url.find("://") {
        let rest = &url[scheme_end + 3..];
        if let Some(at) = rest.find('@') {
            if let Some(colon) = rest[..at].find(':') {
                let scheme = &url[..scheme_end + 3];
                let user = &rest[..colon];
                let tail = &rest[at..];
                return format!("{scheme}{user}{tail}");
            }
        }
    }
    url.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitises_password_in_url() {
        assert_eq!(
            sanitised_url("postgres://ree0xq:secret@localhost:5432/ree0xq"),
            "postgres://ree0xq@localhost:5432/ree0xq"
        );
        // No password — pass through.
        assert_eq!(
            sanitised_url("postgres://ree0xq@localhost/ree0xq"),
            "postgres://ree0xq@localhost/ree0xq"
        );
    }
}
