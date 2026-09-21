//! `ree0xq-id` — V4 CLI.
//!
//! Subcommands:
//!
//! - `inventory-scan` — offline JSON classifier (SEZ-15).
//!   Default, no extra build feature.
//! - `pkcs11-scan`    — live PKCS#11 walker (SEZ-16,
//!   feature `pkcs11`).
//! - `aws-kms-scan`   — AWS KMS lister (SEZ-17, feature
//!   `aws-kms`).
//!
//! YubiHSM 2 + PIV / OpenPGP smart-card paths are
//! operator-driven (SEZ-18). See `docs/ree0xq-id-yubihsm.md`
//! and `docs/ree0xq-id-smartcard.md` for the runbooks and
//! `scripts/ree0xq-id-bringup.sh` for the host-side
//! reproducer.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use ree0xq_core::CryptoInventoryEvent;
use ree0xq_id::inventory;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "ree0xq-id", author, version, about)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
// Variant names become the CLI subcommands (`inventory-scan`,
// `pkcs11-scan`, ...); dropping the shared `Scan` suffix would
// rename them and break operator scripts + systemd units.
#[allow(clippy::enum_variant_names)]
enum Cmd {
    /// Offline JSON HSM-inventory scanner.
    InventoryScan {
        /// Path to the inventory JSON (operator-exported).
        #[arg(long)]
        input: String,
        /// Optional downstream collector URL.
        #[arg(long)]
        collector: Option<String>,
        /// Optional spool dir (no-op stub in V4.0; same
        /// caveat as ree0xq-cert and ree0xq-chain).
        #[arg(long)]
        spool_dir: Option<PathBuf>,
    },
    /// Live PKCS#11 walker (feature `pkcs11`).
    Pkcs11Scan {
        /// Vendor PKCS#11 library, e.g.
        /// `/usr/lib/softhsm/libsofthsm2.so`.
        #[arg(long)]
        library: PathBuf,
        /// Env var name to read the user PIN from. Optional;
        /// without a PIN ree0xq-id sees only public objects.
        #[arg(long)]
        pin_env: Option<String>,
        /// Restrict to a single slot id.
        #[arg(long)]
        slot: Option<u64>,
        /// Optional downstream collector URL.
        #[arg(long)]
        collector: Option<String>,
        /// Optional spool dir (no-op stub).
        #[arg(long)]
        spool_dir: Option<PathBuf>,
    },
    /// AWS KMS lister (feature `aws-kms`).
    AwsKmsScan {
        /// AWS region; falls back to the SDK's default
        /// resolution chain when unset.
        #[arg(long)]
        region: Option<String>,
        /// Optional downstream collector URL.
        #[arg(long)]
        collector: Option<String>,
        /// Optional spool dir (no-op stub).
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
        Cmd::InventoryScan {
            input,
            collector,
            spool_dir,
        } => run_inventory_scan(input, collector, spool_dir),
        Cmd::Pkcs11Scan {
            library,
            pin_env,
            slot,
            collector,
            spool_dir,
        } => run_pkcs11_scan(library, pin_env, slot, collector, spool_dir),
        Cmd::AwsKmsScan {
            region,
            collector,
            spool_dir,
        } => run_aws_kms_scan(region, collector, spool_dir),
    }
}

/// Shared Sink — same shape as ree0xq-cert / ree0xq-chain.
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
            warn!("--spool-dir on ree0xq-id is a no-op in V4.0; ree0xq-net::spool reuse follows in a later commit");
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

fn run_inventory_scan(
    input: String,
    collector: Option<String>,
    spool_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    info!(?input, "inventory-scan starting");
    let sink = Sink::new(collector, spool_dir)?;
    let stats = inventory::scan_file(&input, |ev| sink.send(&ev))?;
    info!(
        slots_seen = stats.slots_seen,
        keys_seen = stats.keys_seen,
        events_emitted = stats.events_emitted,
        "inventory-scan complete"
    );
    Ok(())
}

#[cfg(feature = "pkcs11")]
fn run_pkcs11_scan(
    library: PathBuf,
    pin_env: Option<String>,
    slot: Option<u64>,
    collector: Option<String>,
    spool_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    use ree0xq_id::pkcs11;

    let pin = match pin_env {
        Some(v) => Some(
            std::env::var(&v)
                .map_err(|_| anyhow::anyhow!("--pin-env `{v}` not present in process env"))?,
        ),
        None => None,
    };
    info!(?library, ?slot, pin = pin.is_some(), "pkcs11-scan starting");
    let cfg = pkcs11::Pkcs11Config {
        library: &library,
        user_pin: pin.as_deref(),
        only_slot: slot,
    };
    let sink = Sink::new(collector, spool_dir)?;
    let stats = pkcs11::scan(&cfg, |ev| sink.send(&ev))?;
    info!(
        slots_seen = stats.slots_seen,
        objects_seen = stats.objects_seen,
        events_emitted = stats.events_emitted,
        objects_skipped = stats.objects_skipped,
        "pkcs11-scan complete"
    );
    Ok(())
}

#[cfg(not(feature = "pkcs11"))]
fn run_pkcs11_scan(
    _library: PathBuf,
    _pin_env: Option<String>,
    _slot: Option<u64>,
    _collector: Option<String>,
    _spool_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "pkcs11-scan requires the `pkcs11` feature. \
         Rebuild with: cargo build -p ree0xq-id --features pkcs11 \
         (a vendor PKCS#11 library must be installed; see \
         docs/ree0xq-id-pkcs11.md for the SoftHSM bring-up)."
    )
}

#[cfg(feature = "aws-kms")]
fn run_aws_kms_scan(
    region: Option<String>,
    collector: Option<String>,
    spool_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    use ree0xq_id::aws_kms::{self, KmsBackend};

    let sink = Sink::new(collector, spool_dir)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let backend = aws_kms::AwsKmsBackend::new(region.as_deref()).await?;
        info!(backend = backend.backend_label(), "aws-kms-scan starting");
        let stats = aws_kms::kms_scan(&backend, |ev| sink.send(&ev)).await?;
        info!(
            keys_seen = stats.keys_seen,
            events_emitted = stats.events_emitted,
            "aws-kms-scan complete"
        );
        Ok::<_, anyhow::Error>(())
    })?;
    Ok(())
}

#[cfg(not(feature = "aws-kms"))]
fn run_aws_kms_scan(
    _region: Option<String>,
    _collector: Option<String>,
    _spool_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "aws-kms-scan requires the `aws-kms` feature. \
         Rebuild with: cargo build -p ree0xq-id --features aws-kms \
         (pulls in aws-sdk-kms; see docs/ree0xq-id-aws-kms.md)."
    )
}
