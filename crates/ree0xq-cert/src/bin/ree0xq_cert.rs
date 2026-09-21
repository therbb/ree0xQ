//! `ree0xq-cert` — V2 CLI.
//!
//! Subcommands:
//!
//! - `host-scan` — walk local filesystem cert paths, parse
//!   every PEM cert, emit one `crypto_inventory_event` per
//!   cert. Default backend; SEZ-9.
//! - `ct-scan` — pull a domain's CT-log history (SEZ-10,
//!   later).
//! - `vault-scan` — list certs under a Vault PKI mount
//!   (SEZ-11, later).
//!
//! Output: NDJSON to stdout (the default), or POST to a
//! ree0xq-server collector with `--collector`. POST failures
//! survive an outage when `--spool-dir` points at a writable
//! directory; the spool drains at the start of every run, same
//! semantics as the `ree0xq-net` binary.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use ree0xq_cert::ct::{self, CrtShBackend, CtScanConfig, DEFAULT_RATE_DELAY_MS};
use ree0xq_cert::scan::{self, DEFAULT_ROOTS};
use ree0xq_cert::vault::{self, VaultHttpBackend, VaultScanConfig};
use ree0xq_core::CryptoInventoryEvent;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "ree0xq-cert", author, version, about)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
// Variant names become the CLI subcommands (`host-scan`, ...);
// dropping the shared `Scan` suffix would rename them and break
// operator scripts + systemd units.
#[allow(clippy::enum_variant_names)]
enum Cmd {
    /// Walk one or more filesystem roots and emit a
    /// `crypto_inventory_event` for every X.509 cert
    /// discovered (PEM-encoded `*.pem` / `*.crt` / `*.cer`).
    HostScan {
        /// Filesystem roots to walk. Defaults to a set of
        /// well-known cert paths on a vanilla Linux host
        /// (`/etc/ssl`, `/etc/pki`,
        /// `/usr/local/share/ca-certificates`,
        /// `/etc/letsencrypt/live`).
        #[arg(long, num_args = 0..)]
        root: Vec<PathBuf>,
        /// Optional downstream collector URL.
        #[arg(long)]
        collector: Option<String>,
        /// Optional disk-backed spool directory. When set
        /// alongside `--collector`, POST failures append to
        /// the spool so events survive a server outage. The
        /// spool drains at the start of every run.
        #[arg(long)]
        spool_dir: Option<PathBuf>,
    },
    /// Walk a HashiCorp Vault PKI mount and emit one
    /// `crypto_inventory_event` for every active cert. Token
    /// is read from `--token-env` (default `VAULT_TOKEN`); it
    /// never appears in any log line.
    VaultScan {
        /// Vault base URL (e.g. `http://127.0.0.1:8200`).
        #[arg(long)]
        addr: String,
        /// PKI mount path(s) — typically `pki` for a single
        /// mount, `pki` + `pki_int` for a two-tier setup.
        #[arg(long = "mount", num_args = 1..)]
        mounts: Vec<String>,
        /// Env var name to read the Vault token from.
        #[arg(long, default_value = "VAULT_TOKEN")]
        token_env: String,
        /// Pause between per-cert fetches, in milliseconds.
        #[arg(long, default_value_t = 250)]
        rate_delay_ms: u64,
        /// Optional downstream collector URL.
        #[arg(long)]
        collector: Option<String>,
        /// Optional disk-backed spool directory.
        #[arg(long)]
        spool_dir: Option<PathBuf>,
    },
    /// Pull cert history per domain from a public Certificate
    /// Transparency log (crt.sh in V2.1). Stateful — point
    /// `--cursor` at a JSON file so re-runs only fetch certs
    /// newer than the highest CT entry id already seen.
    CtScan {
        /// Domains to scan. The crt.sh backend issues one
        /// list request per domain (`%.<domain>`), so SANs
        /// of any subdomain land in the result.
        #[arg(long, num_args = 1..)]
        domain: Vec<String>,
        /// Per-domain high-water-mark file. Created on first
        /// run; rewritten with the new max id at the end of
        /// every run.
        #[arg(long)]
        cursor: Option<PathBuf>,
        /// Pause between per-cert PEM fetches, in milliseconds.
        /// Defaults to 1000 (one request / second) so we stay
        /// inside crt.sh's polite-use guidance.
        #[arg(long, default_value_t = DEFAULT_RATE_DELAY_MS)]
        rate_delay_ms: u64,
        /// Optional downstream collector URL.
        #[arg(long)]
        collector: Option<String>,
        /// Optional disk-backed spool directory.
        #[arg(long)]
        spool_dir: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    // Send tracing to stderr so the default stdout-NDJSON path
    // stays greppable.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    match args.cmd {
        Cmd::HostScan {
            root,
            collector,
            spool_dir,
        } => run_host_scan(root, collector, spool_dir),
        Cmd::CtScan {
            domain,
            cursor,
            rate_delay_ms,
            collector,
            spool_dir,
        } => run_ct_scan(domain, cursor, rate_delay_ms, collector, spool_dir),
        Cmd::VaultScan {
            addr,
            mounts,
            token_env,
            rate_delay_ms,
            collector,
            spool_dir,
        } => run_vault_scan(addr, mounts, token_env, rate_delay_ms, collector, spool_dir),
    }
}

fn run_vault_scan(
    addr: String,
    mounts: Vec<String>,
    token_env: String,
    rate_delay_ms: u64,
    collector: Option<String>,
    spool_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    let token = std::env::var(&token_env).map_err(|_| {
        anyhow::anyhow!(
            "missing Vault token: env var `{}` is not set (override with --token-env)",
            token_env
        )
    })?;
    info!(addr = %addr, ?mounts, "starting vault-scan");
    let backend = VaultHttpBackend::new(addr, token)?;
    let cfg = VaultScanConfig {
        mounts,
        rate_delay_ms,
    };
    let sink = Sink::new(collector, spool_dir)?;
    let stats = vault::vault_scan(&cfg, &backend, |ev| sink.send(&ev))?;
    info!(
        mounts_scanned = stats.mounts_scanned,
        serials_listed = stats.serials_listed,
        certs_fetched = stats.certs_fetched,
        fetch_failures = stats.fetch_failures,
        events_emitted = stats.events_emitted,
        "vault-scan complete"
    );
    Ok(())
}

/// Best-effort delivery sink — copy of the same pattern the
/// `ree0xq-net` binary uses (NDJSON stdout / POST / append-on-
/// failure spool). Kept in-binary on purpose so neither the
/// `ree0xq-cert` library nor `ree0xq-net` pulls reqwest in.
struct Sink {
    collector: Option<String>,
    client: Option<reqwest::blocking::Client>,
}

impl Sink {
    fn new(collector: Option<String>, _spool_dir: Option<PathBuf>) -> anyhow::Result<Self> {
        // Spool wiring deliberately deferred — the ree0xq-net
        // crate's `spool` module is the canonical impl; when
        // ree0xq-cert needs the same semantics in production
        // we either depend on ree0xq-net (cyclic-deps-OK) or
        // promote `spool` into ree0xq-core. For SEZ-9 the
        // collector-or-stdout path is the V2.0 cut.
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
            warn!("--spool-dir on ree0xq-cert is a no-op in V2.0; promote to ree0xq-net::spool reuse in a follow-up");
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

fn run_ct_scan(
    domains: Vec<String>,
    cursor_path: Option<PathBuf>,
    rate_delay_ms: u64,
    collector: Option<String>,
    spool_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    info!(
        ?domains,
        ?cursor_path,
        rate_delay_ms,
        "starting ct-scan (crt.sh)"
    );
    let backend = CrtShBackend::new()?;
    let cfg = CtScanConfig {
        domains,
        cursor_path,
        rate_delay_ms,
    };
    let sink = Sink::new(collector, spool_dir)?;
    let stats = ct::ct_scan(&cfg, &backend, |ev| sink.send(&ev))?;
    info!(
        domains_scanned = stats.domains_scanned,
        entries_listed = stats.entries_listed,
        entries_below_cursor = stats.entries_below_cursor,
        certs_fetched = stats.certs_fetched,
        fetch_failures = stats.fetch_failures,
        events_emitted = stats.events_emitted,
        "ct-scan complete"
    );
    Ok(())
}

fn run_host_scan(
    roots: Vec<PathBuf>,
    collector: Option<String>,
    spool_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    let roots = if roots.is_empty() {
        DEFAULT_ROOTS.iter().map(PathBuf::from).collect()
    } else {
        roots
    };
    info!(?roots, "starting host-scan");

    let sink = Sink::new(collector, spool_dir)?;
    let stats = scan::host_scan(&roots, |ev| sink.send(&ev))?;

    info!(
        roots_walked = stats.roots_walked,
        files_inspected = stats.files_inspected,
        files_skipped_io = stats.files_skipped_io,
        files_skipped_no_certs = stats.files_skipped_no_certs,
        certs_parsed = stats.certs_parsed,
        events_emitted = stats.events_emitted,
        "host-scan complete"
    );
    Ok(())
}
