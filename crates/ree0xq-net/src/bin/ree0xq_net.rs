//! `ree0xq-net` — Phase 1 CLI.
//!
//! Subcommands:
//!
//! - `from-zgrab` — read `zgrab2 tls` JSON output (one record per
//!   line OR a wrapping JSON array) and emit one
//!   `crypto_inventory_event` per record, either to stdout (NDJSON)
//!   or to a downstream collector URL.
//! - `parse-handshake` — read raw TLS handshake bytes (hex on
//!   stdin or a file path) and pretty-print the parsed summary plus
//!   the resolved primitives. Handy for debugging captures.
//! - `pq-probe` — open a single TLS 1.3 handshake per host
//!   advertising `X25519MLKEM768`, record the negotiated kex group
//!   plus cert sig algo, emit NDJSON. Phase-1.5 PQ-readiness probe.
//!
//! Phase 2 (eBPF live mode) ships as `ree0xq-net live`.

use std::io::{BufRead, Read};
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use ree0xq_net::{live, pq_probe, spool, tls, zgrab};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "ree0xq-net", author, version, about)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Read zgrab2 JSON output and emit crypto_inventory_event records.
    FromZgrab {
        /// Input path. `-` (default) reads stdin. NDJSON or a JSON array.
        #[arg(long, default_value = "-")]
        input: String,
        /// Optional downstream collector URL. When set, POST each
        /// event; otherwise print NDJSON to stdout.
        #[arg(long)]
        collector: Option<String>,
        /// Optional disk-backed spool directory. When set and a
        /// `--collector` is given, POST failures are appended to
        /// the spool so the events survive a server outage; the
        /// spool is drained at the start of every run.
        #[arg(long)]
        spool_dir: Option<PathBuf>,
    },
    /// Parse raw TLS handshake bytes (hex) and dump the summary.
    ParseHandshake {
        /// Hex-encoded handshake bytes (or `-` to read stdin).
        #[arg(long)]
        hex: String,
    },
    /// PQ-capable TLS probe. One handshake per host advertising
    /// `X25519MLKEM768`. Emits NDJSON to stdout.
    PqProbe {
        /// Path to hosts file (one hostname per line). `-` for stdin.
        #[arg(long, default_value = "-")]
        hosts: String,
        /// Port (default 443).
        #[arg(long, default_value_t = 443)]
        port: u16,
        /// Per-host timeout in seconds.
        #[arg(long, default_value_t = 5)]
        timeout_s: u64,
        /// Rate cap — pause this many milliseconds between hosts.
        #[arg(long, default_value_t = 1000)]
        rate_delay_ms: u64,
    },
    /// Phase 2 — passively observe TLS handshakes. Source is either
    /// a pcap file (Phase 2.0, default build) or a live interface
    /// via libpcap (Phase 2.2, `--features live-pcap`). Emits one
    /// `crypto_inventory_event` per ClientHello/ServerHello.
    Live {
        /// Path to a `.pcap` or `.pcapng` capture. Mutually
        /// exclusive with `--iface`.
        #[arg(long, conflicts_with = "iface")]
        pcap: Option<String>,
        /// Live capture from this network interface (e.g. `lo`,
        /// `eth0`). Needs `--features live-pcap` at build time and
        /// `CAP_NET_RAW` at run time. Mutually exclusive with
        /// `--pcap`.
        #[arg(long, conflicts_with = "pcap")]
        iface: Option<String>,
        /// BPF filter for live capture. Default keeps the surface
        /// to TLS ports.
        #[arg(long, default_value = "tcp port 443")]
        filter: String,
        /// Enable promiscuous mode on live capture. Off by default;
        /// not needed for `lo` or for traffic addressed to the host.
        #[arg(long, default_value_t = false)]
        promiscuous: bool,
        /// Snaplen (bytes per frame) for live capture.
        #[arg(long, default_value_t = 1500)]
        snaplen: i32,
        /// Optional downstream collector URL. When set, POST each
        /// event; otherwise print NDJSON to stdout.
        #[arg(long)]
        collector: Option<String>,
        /// Optional disk-backed spool directory. When set and a
        /// `--collector` is given, POST failures are appended to
        /// the spool so the events survive a server outage; the
        /// spool is drained at the start of every run.
        #[arg(long)]
        spool_dir: Option<PathBuf>,
        /// Recent-session dedup TTL in seconds. Within this window
        /// repeat ClientHello / ServerHello observations on the
        /// same 4-tuple are dropped rather than re-emitted (see
        /// `module-net.md` § userspace dedup). Pass `0` to disable
        /// dedup entirely — useful for forensic captures where
        /// every retransmit should land. Default 300 (5 min).
        #[arg(long, default_value_t = 300)]
        dedup_ttl_secs: u64,
        /// Max distinct sessions held in the dedup cache. Capacity
        /// only matters under sustained unique-flow burst; the
        /// design-doc baseline is 10 k handshakes/s, so the
        /// default of 65 536 gives ~6.5 s of headroom before the
        /// cache starts force-evicting.
        #[arg(long, default_value_t = 65_536)]
        dedup_capacity: usize,
    },
    /// Phase 2.1 — kernel-side eBPF TC classifier (requires the
    /// `live-interface` feature, a pre-built BPF object, and
    /// `CAP_BPF` + `CAP_NET_ADMIN` at run time). The userspace
    /// loader attaches to the interface's TC ingress, parses
    /// TLS handshake bytes from the kernel ring buffer, and
    /// emits one `crypto_inventory_event` per ClientHello /
    /// ServerHello. See `docs/ree0xq-net-ebpf.md` for the full
    /// bring-up runbook.
    LiveEbpf {
        /// Network interface to attach to (e.g. `lo`, `eth0`).
        #[arg(long)]
        iface: String,
        /// Path to the compiled BPF object. Typically
        /// `target/bpfel-unknown-none/release/ree0xq-net-ebpf`
        /// after building the sibling `ree0xq-net-ebpf` crate
        /// with the nightly toolchain.
        #[arg(long)]
        ebpf_object: PathBuf,
        /// Optional downstream collector URL. When set, POST
        /// each event; otherwise print NDJSON to stdout.
        #[arg(long)]
        collector: Option<String>,
        /// Optional disk-backed spool directory. Same semantics
        /// as on `live` and `from-zgrab`.
        #[arg(long)]
        spool_dir: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    // Send tracing output to stderr so subcommands that emit NDJSON
    // on stdout (e.g. `pq-probe`, `from-zgrab`) stay greppable.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    match args.cmd {
        Cmd::FromZgrab {
            input,
            collector,
            spool_dir,
        } => run_from_zgrab(input, collector, spool_dir),
        Cmd::ParseHandshake { hex } => run_parse_handshake(hex),
        Cmd::PqProbe {
            hosts,
            port,
            timeout_s,
            rate_delay_ms,
        } => run_pq_probe(hosts, port, timeout_s, rate_delay_ms),
        Cmd::Live {
            pcap,
            iface,
            filter,
            promiscuous,
            snaplen,
            collector,
            spool_dir,
            dedup_ttl_secs,
            dedup_capacity,
        } => run_live(
            pcap,
            iface,
            filter,
            promiscuous,
            snaplen,
            collector,
            spool_dir,
            dedup_ttl_secs,
            dedup_capacity,
        ),
        Cmd::LiveEbpf {
            iface,
            ebpf_object,
            collector,
            spool_dir,
        } => run_live_ebpf(iface, ebpf_object, collector, spool_dir),
    }
}

#[cfg(feature = "live-interface")]
fn run_live_ebpf(
    iface: String,
    ebpf_object: PathBuf,
    collector: Option<String>,
    spool_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    use ree0xq_net::live_iface::{self, LiveInterfaceConfig};

    let sink = Sink::new(collector, spool_dir)?;
    let cfg = LiveInterfaceConfig {
        iface: iface.clone(),
        ebpf_object: ebpf_object.clone(),
    };

    // The aya loader is async; spin up a current-thread runtime
    // so a Ctrl-C interrupting the surrounding shell still
    // unwinds cleanly.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let stats = rt.block_on(async { live_iface::run(cfg, |ev| sink.send(&ev)).await })?;
    info!(
        source = "live-ebpf",
        iface = %iface,
        ebpf_object = %ebpf_object.display(),
        packets_seen = stats.packets_seen,
        handshake_packets = stats.handshake_packets,
        events_emitted = stats.events_emitted,
        skipped_unparseable = stats.packets_skipped_unparseable,
        "ebpf observation complete"
    );
    Ok(())
}

#[cfg(not(feature = "live-interface"))]
fn run_live_ebpf(
    _iface: String,
    _ebpf_object: PathBuf,
    _collector: Option<String>,
    _spool_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "live-ebpf requires the `live-interface` feature. \
         Build with: cargo build -p ree0xq-net --features live-interface \
         (after compiling the ree0xq-net-ebpf crate; see \
         docs/ree0xq-net-ebpf.md for the full bring-up dance)."
    )
}

/// Best-effort delivery sink for emitted events.
///
/// Three modes:
/// - no `collector`           → NDJSON to stdout
/// - `collector` only         → POST; on failure, log + drop
/// - `collector` + `spool`    → POST; on failure, append to the
///   disk spool. The spool is drained once at construction
///   time so outage-buffered events go out first.
struct Sink {
    collector: Option<String>,
    client: Option<reqwest::blocking::Client>,
    spool: Option<spool::Spool>,
}

impl Sink {
    fn new(collector: Option<String>, spool_dir: Option<PathBuf>) -> anyhow::Result<Self> {
        let client = collector
            .as_deref()
            .map(|_| {
                reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()
            })
            .transpose()
            .map_err(|e| anyhow::anyhow!("client build: {e}"))?;
        let spool = match (spool_dir.as_deref(), collector.as_deref()) {
            (Some(dir), Some(_)) => Some(spool::Spool::open(dir)?),
            (Some(_), None) => {
                warn!("--spool-dir without --collector is a no-op; ignoring");
                None
            }
            _ => None,
        };
        let me = Self {
            collector,
            client,
            spool,
        };
        me.drain_spool();
        Ok(me)
    }

    fn drain_spool(&self) {
        let (Some(spool), Some(url), Some(client)) = (&self.spool, &self.collector, &self.client)
        else {
            return;
        };
        let stats = match spool.drain(|ev| match client.post(url).json(ev).send() {
            Ok(r) if r.status().is_success() => Ok(()),
            Ok(r) => Err(anyhow::anyhow!("status {}", r.status())),
            Err(e) => Err(anyhow::anyhow!(e)),
        }) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "spool drain failed");
                return;
            }
        };
        if stats.seen > 0 {
            info!(
                seen = stats.seen,
                delivered = stats.delivered,
                retained = stats.retained,
                corrupt_dropped = stats.corrupt_dropped,
                "spool drained"
            );
        }
    }

    fn send(&self, ev: &ree0xq_core::CryptoInventoryEvent) {
        let Some(url) = self.collector.as_deref() else {
            // stdout NDJSON
            match serde_json::to_string(ev) {
                Ok(s) => println!("{s}"),
                Err(e) => error!(error = %e, "serialize failed"),
            }
            return;
        };
        let client = self.client.as_ref().expect("client present when url is");
        match client.post(url).json(ev).send() {
            Ok(r) if r.status().is_success() => return,
            Ok(r) => warn!(status = %r.status(), "downstream rejected event"),
            Err(e) => error!(error = %e, "downstream POST failed"),
        }
        // Above match fell through: POST didn't deliver. Spool if configured.
        if let Some(spool) = &self.spool {
            if let Err(e) = spool.append(ev) {
                error!(error = %e, "failed to spool event after POST failure");
            }
        }
    }
}

// Mirrors the `live` subcommand's CLI flags one-to-one; bundling
// them into a struct is a refactor, not a lint fix.
#[allow(clippy::too_many_arguments)]
fn run_live(
    pcap_path: Option<String>,
    iface: Option<String>,
    filter: String,
    promiscuous: bool,
    snaplen: i32,
    collector: Option<String>,
    spool_dir: Option<PathBuf>,
    dedup_ttl_secs: u64,
    dedup_capacity: usize,
) -> anyhow::Result<()> {
    let sink = Sink::new(collector, spool_dir)?;
    let emit = |ev: &ree0xq_core::CryptoInventoryEvent| sink.send(ev);

    // ttl=0 disables dedup entirely (forensic mode).
    let mut dedup_cache = if dedup_ttl_secs == 0 {
        None
    } else {
        Some(ree0xq_net::dedup::DedupCache::new(
            std::time::Duration::from_secs(dedup_ttl_secs),
            dedup_capacity,
        ))
    };

    match (pcap_path, iface) {
        (Some(p), None) => {
            let stats = live::observe_pcap_with_dedup(&p, dedup_cache.as_mut(), |ev| emit(&ev))?;
            info!(
                source = "pcap-file",
                packets_seen = stats.packets_seen,
                handshake_packets = stats.handshake_packets,
                handshakes_deduplicated = stats.handshakes_deduplicated,
                events_emitted = stats.events_emitted,
                skipped_unparseable = stats.packets_skipped_unparseable,
                dedup_forced_evictions = dedup_cache
                    .as_ref()
                    .map(|c| c.forced_evictions())
                    .unwrap_or(0),
                "observation complete"
            );
            Ok(())
        }
        (None, Some(if_name)) => {
            run_live_iface(if_name, filter, promiscuous, snaplen, dedup_cache, emit)
        }
        (None, None) => {
            anyhow::bail!("live: pass either --pcap <file> or --iface <name>")
        }
        (Some(_), Some(_)) => unreachable!("clap conflicts_with should have rejected this"),
    }
}

#[cfg(feature = "live-pcap")]
fn run_live_iface<E>(
    iface: String,
    filter: String,
    promiscuous: bool,
    snaplen: i32,
    mut dedup_cache: Option<ree0xq_net::dedup::DedupCache>,
    emit: E,
) -> anyhow::Result<()>
where
    E: Fn(&ree0xq_core::CryptoInventoryEvent),
{
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let cfg = live::InterfaceConfig {
        iface: iface.clone(),
        snaplen,
        read_timeout_ms: 100,
        filter: if filter.is_empty() {
            None
        } else {
            Some(filter)
        },
        promiscuous,
    };

    // Wire Ctrl-C to a shared atomic the capture loop polls between
    // packets. Single Ctrl-C exits cleanly; second one panics out.
    let should_stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&should_stop);
        ctrlc::set_handler(move || {
            if stop.swap(true, Ordering::Relaxed) {
                std::process::exit(130);
            }
            eprintln!("\n[ree0xq-net] Ctrl-C — finishing in-flight packet…");
        })
        .ok();
    }

    info!(iface = %cfg.iface, filter = ?cfg.filter, "live-pcap observation starting");
    let stats =
        live::observe_interface_with_dedup(&cfg, &should_stop, dedup_cache.as_mut(), |ev| {
            emit(&ev)
        })?;
    info!(
        source = "live-pcap",
        iface = %iface,
        packets_seen = stats.packets_seen,
        handshake_packets = stats.handshake_packets,
        handshakes_deduplicated = stats.handshakes_deduplicated,
        events_emitted = stats.events_emitted,
        skipped_unparseable = stats.packets_skipped_unparseable,
        dedup_forced_evictions =
            dedup_cache.as_ref().map(|c| c.forced_evictions()).unwrap_or(0),
        "observation complete"
    );
    Ok(())
}

#[cfg(not(feature = "live-pcap"))]
fn run_live_iface<E>(
    _iface: String,
    _filter: String,
    _promiscuous: bool,
    _snaplen: i32,
    _dedup_cache: Option<ree0xq_net::dedup::DedupCache>,
    _emit: E,
) -> anyhow::Result<()>
where
    E: Fn(&ree0xq_core::CryptoInventoryEvent),
{
    anyhow::bail!(
        "--iface requires the `live-pcap` feature. Rebuild with: \
         cargo build -p ree0xq-net --features live-pcap"
    )
}

fn run_pq_probe(
    hosts_path: String,
    port: u16,
    timeout_s: u64,
    rate_delay_ms: u64,
) -> anyhow::Result<()> {
    let raw = read_input(&hosts_path)?;
    let hosts: Vec<String> = raw
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    info!(count = hosts.len(), "pq probe loaded host list");

    // We use a current-thread tokio runtime: every host probe is
    // sequential by design (rate cap + ethics) so the multi-thread
    // pool would add nothing.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let timeout = Duration::from_secs(timeout_s);
    let delay = Duration::from_millis(rate_delay_ms);

    for (i, host) in hosts.iter().enumerate() {
        let result = rt.block_on(pq_probe::probe(host, port, timeout));
        if result.ok {
            info!(
                "[{:3}/{}] {host} {} {} kex={} pq={}",
                i + 1,
                hosts.len(),
                result.protocol_version.as_deref().unwrap_or("?"),
                result.cipher_suite.as_deref().unwrap_or("?"),
                result.kex_group.as_deref().unwrap_or("?"),
                result.kex_pq,
            );
        } else {
            warn!(
                "[{:3}/{}] {host} FAIL: {}",
                i + 1,
                hosts.len(),
                result.error.as_deref().unwrap_or("unknown")
            );
        }
        println!("{}", serde_json::to_string(&result)?);
        if i + 1 < hosts.len() {
            std::thread::sleep(delay);
        }
    }
    Ok(())
}

fn run_from_zgrab(
    input: String,
    collector: Option<String>,
    spool_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    let raw = read_input(&input)?;
    let records = parse_zgrab_payload(&raw)?;
    info!(count = records.len(), "zgrab records loaded");

    let sink = Sink::new(collector, spool_dir)?;
    for rec in records {
        let ev = zgrab::event_from_zgrab(&rec);
        sink.send(&ev);
    }
    Ok(())
}

/// Accept either NDJSON (one record per line) or a single JSON array.
fn parse_zgrab_payload(raw: &str) -> anyhow::Result<Vec<zgrab::ZgrabRecord>> {
    let trimmed = raw.trim_start();
    if trimmed.starts_with('[') {
        let v: Vec<zgrab::ZgrabRecord> = serde_json::from_str(trimmed)?;
        return Ok(v);
    }
    let mut out = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<zgrab::ZgrabRecord>(line) {
            Ok(r) => out.push(r),
            Err(e) => {
                error!(line = i + 1, error = %e, "skipping malformed record");
            }
        }
    }
    Ok(out)
}

fn run_parse_handshake(hex_arg: String) -> anyhow::Result<()> {
    let raw_hex = if hex_arg == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s
    } else if let Ok(meta) = std::fs::metadata(&hex_arg) {
        if meta.is_file() {
            std::fs::read_to_string(&hex_arg)?
        } else {
            hex_arg
        }
    } else {
        hex_arg
    };
    let clean: String = raw_hex.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = hex::decode(clean.trim_start_matches("0x"))?;
    let summary = tls::parse_handshake(&bytes)?;
    let prims = tls::primitives_from_summary(&summary);
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "summary": summary,
            "primitives": prims,
        }))?
    );
    Ok(())
}

fn read_input(path: &str) -> anyhow::Result<String> {
    if path == "-" {
        let mut buf = String::new();
        let stdin = std::io::stdin();
        let mut handle = stdin.lock();
        let mut tmp = String::new();
        while handle.read_line(&mut tmp)? > 0 {
            buf.push_str(&tmp);
            tmp.clear();
        }
        Ok(buf)
    } else {
        Ok(std::fs::read_to_string(PathBuf::from(path))?)
    }
}
