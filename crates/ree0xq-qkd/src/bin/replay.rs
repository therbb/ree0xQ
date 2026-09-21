//! `ree0xq-qkd-replay` — drive a running KME emulator through a replay scenario.
//!
//! Reads a scenario file, validates it, and posts each timed
//! [`ControlOp`](ree0xq_qkd::emulator::ControlOp) to the emulator's
//! `/control` endpoint at the right offset.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;
use ree0xq_qkd::replay::ReplayScenario;
use reqwest::Client;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "ree0xq-qkd-replay", author, version, about)]
struct Args {
    /// URL of the emulator's control endpoint
    /// (e.g. `http://127.0.0.1:11071/control`).
    #[arg(long)]
    emulator_control: String,

    /// Path to the YAML/JSON replay scenario.
    #[arg(long)]
    replay: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let raw = std::fs::read_to_string(&args.replay)?;
    let scenario: ReplayScenario = if args
        .replay
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s == "json")
    {
        serde_json::from_str(&raw)?
    } else {
        serde_yaml::from_str(&raw)?
    };
    scenario.validate()?;
    info!(id=%scenario.id, events=scenario.events.len(),
          duration_s=scenario.duration_seconds, "replay loaded");

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let start = Instant::now();
    for ev in scenario.events {
        let target = Duration::from_secs(ev.at_seconds);
        let elapsed = start.elapsed();
        if target > elapsed {
            tokio::time::sleep(target - elapsed).await;
        }
        let resp = client
            .post(&args.emulator_control)
            .json(&ev.op)
            .send()
            .await?;
        if !resp.status().is_success() {
            warn!(at=ev.at_seconds, status=%resp.status(), "control op failed");
        } else {
            info!(
                at = ev.at_seconds,
                label = ev.label.unwrap_or_default(),
                "applied"
            );
        }
    }
    // Sleep through the rest of the scenario duration so collectors
    // observe the post-final-op steady state. Without this, scenarios
    // whose last event is at t=0 (e.g. r1-steady, r4-stale-psk) finish
    // in milliseconds and the operator captures almost no events.
    let scenario_end = Duration::from_secs(scenario.duration_seconds);
    let elapsed = start.elapsed();
    if scenario_end > elapsed {
        let remaining = scenario_end - elapsed;
        info!(
            remaining_s = remaining.as_secs(),
            "sleeping until scenario end"
        );
        tokio::time::sleep(remaining).await;
    }
    info!("replay complete");
    Ok(())
}
