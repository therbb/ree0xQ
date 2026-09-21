//! `ree0xq-qkd` — ETSI GS QKD 014 collector.
//!
//! Polls one or more KMEs and emits `crypto_inventory_event` records
//! of kind `QkdLink` / `QkdKme` to a configured downstream collector
//! (typically `ree0xq-server`). Without a downstream URL the events
//! are logged via `tracing` for local inspection.

use std::time::Duration;

use clap::Parser;
use ree0xq_qkd::collector::{run, CollectorConfig};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "ree0xq-qkd", author, version, about)]
struct Args {
    /// One or more KME base URLs (`http(s)://host:port/api/v1`).
    /// Repeat the flag to poll multiple KMEs.
    #[arg(long = "kme", required = true)]
    kme_endpoints: Vec<String>,

    /// Slave SAE ID used in `/status` requests.
    #[arg(long, default_value = "SAE-REE0XQ-COLLECTOR")]
    slave_sae_id: String,

    /// Status poll cadence, in seconds.
    #[arg(long, default_value_t = 5)]
    status_poll_interval: u64,

    /// Optional downstream collector URL to forward events to.
    #[arg(long)]
    collector: Option<String>,

    /// QBER above which the link is reported as `degraded`.
    #[arg(long, default_value_t = 0.05)]
    qber_warn: f32,

    /// QBER above which the link is reported as `failed`.
    #[arg(long, default_value_t = 0.11)]
    qber_fail: f32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let cfg = CollectorConfig {
        kme_endpoints: args.kme_endpoints,
        slave_sae_id: args.slave_sae_id,
        status_interval: Duration::from_secs(args.status_poll_interval),
        collector_endpoint: args.collector,
        qber_warn_threshold: args.qber_warn,
        qber_fail_threshold: args.qber_fail,
    };
    run(cfg).await
}
