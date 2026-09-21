//! `ree0xq-chain` — V3 CLI.
//!
//! Three offline address-list scanners ship in V3:
//!
//! - `bitcoin-scan`  — P2PKH / P2SH / P2WPKH / P2WSH / P2TR
//!   classifier (SEZ-12).
//! - `ethereum-scan` — secp256k1-ECDSA + Keccak-256 (SEZ-13).
//! - `qrl-scan`      — XMSS + SHA-256, PQ-resistant
//!   (SEZ-14).
//!
//! Each takes `--addresses <file>` (one address per line,
//! `-` for stdin, `#` lines skipped) plus the same
//! `--collector` / `--spool-dir` shape the other ree0xq-N
//! binaries expose.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use ree0xq_chain::{bitcoin, ethereum, event, qrl};
use ree0xq_core::CryptoInventoryEvent;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "ree0xq-chain", author, version, about)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
// Variant names become the CLI subcommands (`bitcoin-scan`, ...);
// dropping the shared `Scan` suffix would rename them and break
// operator scripts + systemd units.
#[allow(clippy::enum_variant_names)]
enum Cmd {
    /// Bitcoin address-type classifier.
    BitcoinScan {
        /// File of one Bitcoin address per line. `-` reads stdin.
        #[arg(long)]
        addresses: String,
        /// Optional downstream collector URL.
        #[arg(long)]
        collector: Option<String>,
        /// Optional spool directory (no-op in V3.0 — same
        /// caveat as ree0xq-cert host-scan; the spool module
        /// stays in ree0xq-net for now).
        #[arg(long)]
        spool_dir: Option<PathBuf>,
    },
    /// Ethereum address classifier.
    EthereumScan {
        #[arg(long)]
        addresses: String,
        #[arg(long)]
        collector: Option<String>,
        #[arg(long)]
        spool_dir: Option<PathBuf>,
    },
    /// QRL (Quantum Resistant Ledger) address classifier.
    QrlScan {
        #[arg(long)]
        addresses: String,
        #[arg(long)]
        collector: Option<String>,
        #[arg(long)]
        spool_dir: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    match args.cmd {
        Cmd::BitcoinScan {
            addresses,
            collector,
            spool_dir,
        } => run_bitcoin(addresses, collector, spool_dir),
        Cmd::EthereumScan {
            addresses,
            collector,
            spool_dir,
        } => run_ethereum(addresses, collector, spool_dir),
        Cmd::QrlScan {
            addresses,
            collector,
            spool_dir,
        } => run_qrl(addresses, collector, spool_dir),
    }
}

/// Shared Sink — same shape as ree0xq-cert.
struct Sink {
    collector: Option<String>,
    client: Option<reqwest::blocking::Client>,
}

impl Sink {
    fn new(collector: Option<String>, _spool_dir: Option<PathBuf>) -> anyhow::Result<Self> {
        let client = collector
            .as_deref()
            .map(|_| {
                reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(5))
                    .build()
            })
            .transpose()
            .map_err(|e| anyhow::anyhow!("client build: {e}"))?;
        if collector.is_some() && _spool_dir.is_some() {
            warn!("--spool-dir on ree0xq-chain is a no-op in V3.0; ree0xq-net::spool reuse follows in a later commit");
        }
        Ok(Self { collector, client })
    }

    fn send(&self, ev: &CryptoInventoryEvent) {
        let Some(url) = self.collector.as_deref() else {
            match serde_json::to_string(ev) {
                Ok(s) => println!("{s}"),
                Err(e) => error!(error = %e, "serialize failed"),
            }
            return;
        };
        let client = self.client.as_ref().expect("client present when url is");
        match client.post(url).json(ev).send() {
            Ok(r) if r.status().is_success() => {}
            Ok(r) => warn!(status = %r.status(), "downstream rejected event"),
            Err(e) => error!(error = %e, "downstream POST failed"),
        }
    }
}

fn run_bitcoin(
    addresses_path: String,
    collector: Option<String>,
    spool_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    let addrs = event::load_addresses(&addresses_path)?;
    info!(count = addrs.len(), "bitcoin-scan started");
    let sink = Sink::new(collector, spool_dir)?;
    let stats = bitcoin::scan_addresses(&addrs, |ev| sink.send(&ev));
    info!(
        seen = stats.addresses_seen,
        classified = stats.addresses_classified,
        skipped = stats.addresses_skipped_unknown,
        emitted = stats.events_emitted,
        "bitcoin-scan complete"
    );
    Ok(())
}

fn run_ethereum(
    addresses_path: String,
    collector: Option<String>,
    spool_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    let addrs = event::load_addresses(&addresses_path)?;
    info!(count = addrs.len(), "ethereum-scan started");
    let sink = Sink::new(collector, spool_dir)?;
    let stats = ethereum::scan_addresses(&addrs, |ev| sink.send(&ev));
    info!(
        seen = stats.addresses_seen,
        classified = stats.addresses_classified,
        skipped = stats.addresses_skipped_invalid,
        emitted = stats.events_emitted,
        "ethereum-scan complete"
    );
    Ok(())
}

fn run_qrl(
    addresses_path: String,
    collector: Option<String>,
    spool_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    let addrs = event::load_addresses(&addresses_path)?;
    info!(count = addrs.len(), "qrl-scan started");
    let sink = Sink::new(collector, spool_dir)?;
    let stats = qrl::scan_addresses(&addrs, |ev| sink.send(&ev));
    info!(
        seen = stats.addresses_seen,
        classified = stats.addresses_classified,
        skipped = stats.addresses_skipped_invalid,
        emitted = stats.events_emitted,
        "qrl-scan complete"
    );
    Ok(())
}
