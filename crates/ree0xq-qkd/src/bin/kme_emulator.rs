//! `ree0xq-qkd-kme-emulator` — ETSI GS QKD 014 V1.1.1 reference KME.
//!
//! Spawn one instance per KME. Endpoints:
//!
//! - `GET  /api/v1/keys/{slave_SAE_ID}/status`
//! - `GET  /api/v1/keys/{slave_SAE_ID}/enc_keys?size=N&number=K`
//! - `POST /api/v1/keys/{master_SAE_ID}/dec_keys`
//! - `POST /control`  (ree0xQ extension — replay driver)
//!
//! Example:
//!
//! ```bash
//! ree0xq-qkd-kme-emulator \
//!     --listen 127.0.0.1:11071 \
//!     --kme-id KME-A \
//!     --paired-kme KME-B \
//!     --key-rate-bps 12000 \
//!     --qber 0.018
//! ```

use std::sync::Arc;

use clap::Parser;
use ree0xq_qkd::emulator::{router, EmulatorConfig, EmulatorState};
use tokio::sync::RwLock;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "ree0xq-qkd-kme-emulator", author, version, about)]
struct Args {
    /// Bind address (e.g. `127.0.0.1:11071`).
    #[arg(long, default_value = "127.0.0.1:11071")]
    listen: String,

    /// This KME's identifier (advertised as `source_KME_ID`).
    #[arg(long, default_value = "KME-A")]
    kme_id: String,

    /// Paired KME identifier (advertised as `target_KME_ID`).
    #[arg(long, default_value = "KME-B")]
    paired_kme: String,

    /// Default key size in bits.
    #[arg(long, default_value_t = 256)]
    key_size: u32,

    /// Initial QBER on [0.0, 1.0].
    #[arg(long, default_value_t = 0.018)]
    qber: f32,

    /// Initial key rate (bps).
    #[arg(long, default_value_t = 12_000)]
    key_rate_bps: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let cfg = EmulatorConfig {
        kme_id: args.kme_id,
        paired_kme_id: args.paired_kme,
        key_size: args.key_size,
        initial_qber: args.qber,
        initial_key_rate_bps: args.key_rate_bps,
        max_key_count: 100_000,
    };
    let state = Arc::new(RwLock::new(EmulatorState::new(cfg.clone())));
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    info!(addr=%args.listen, kme_id=%cfg.kme_id, "KME emulator listening");
    axum::serve(listener, app).await?;
    Ok(())
}
