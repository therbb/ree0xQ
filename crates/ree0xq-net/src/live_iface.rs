//! Phase 2.1 — live-interface capture (feature-gated).
//!
//! Userspace loader for the kernel-side `ree0xq-net-ebpf` TC
//! classifier. Attaches the BPF object to a network interface's
//! ingress hook, consumes ring-buffer entries (one per observed
//! TLS handshake), parses each handshake with
//! [`crate::tls::parse_handshake`], and emits a
//! `crypto_inventory_event` for each.
//!
//! # Why feature-gated
//!
//! The default build of ree0xq-net produces a single binary that
//! works on any Linux machine and needs only Rust's stable
//! toolchain. The live-interface path additionally needs:
//!
//! - The pre-built BPF object at
//!   `target/bpfel-unknown-none/release/ree0xq-net-ebpf` (built from
//!   the sibling `ree0xq-net-ebpf` crate with a nightly toolchain
//!   and `bpf-linker`).
//! - `CAP_BPF` + `CAP_NET_ADMIN` at run time (or `CAP_SYS_ADMIN` on
//!   older kernels).
//! - Linux 5.8+ for the ring-buffer map type.
//!
//! Gating these behind `--features live-interface` keeps the
//! offline pcap-file path (`crate::live`) friction-free for
//! everyone else.
//!
//! # Status
//!
//! Skeleton only — the parts that don't require an attached BPF
//! program (event-type definitions, handshake-bytes → event
//! emitter) are wired up; the actual `aya::Ebpf::load` /
//! `SchedClassifier::attach` calls are gated behind the feature so
//! the workspace builds without the BPF object present.

#![cfg(feature = "live-interface")]

use std::convert::TryInto;
use std::path::Path;
use std::time::Duration;

use aya::maps::{MapData, RingBuf};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Ebpf;
use ree0xq_core::CryptoInventoryEvent;
use tokio::io::unix::AsyncFd;
use tracing::{debug, error, info, warn};

use crate::live::{self, ObservationStats};
use crate::tls::{parse_handshake, primitives_from_summary};

/// Matches the kernel-side struct layout in `ree0xq-net-ebpf::main`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HandshakeEvent {
    /// Source IPv4 (network order).
    pub src_ip: u32,
    /// Destination IPv4 (network order).
    pub dst_ip: u32,
    /// Source port (host order).
    pub src_port: u16,
    /// Destination port (host order).
    pub dst_port: u16,
    /// How many bytes of `bytes` are valid.
    pub len: u16,
    /// Reserved padding.
    pub _pad: u16,
    /// TLS handshake bytes from the inner msg_type onward.
    pub bytes: [u8; 1024],
}

/// Configuration for the live-interface runtime.
#[derive(Debug, Clone)]
pub struct LiveInterfaceConfig {
    /// Interface name (e.g. `eth0`).
    pub iface: String,
    /// Path to the pre-built BPF object.
    pub ebpf_object: std::path::PathBuf,
}

/// Run the live-interface observer. Blocks until the runtime is
/// torn down by Ctrl-C.
pub async fn run<F>(cfg: LiveInterfaceConfig, mut on_event: F) -> anyhow::Result<ObservationStats>
where
    F: FnMut(CryptoInventoryEvent),
{
    info!(iface = %cfg.iface, "live-interface starting");

    // Load the compiled eBPF object from disk.
    let mut ebpf = Ebpf::load_file(&cfg.ebpf_object)?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!(error = ?e, "failed to attach aya-log; continuing without kernel-side log");
    }

    // Attach the TC classifier to the interface's ingress hook.
    let _ = tc::qdisc_add_clsact(&cfg.iface);
    let program: &mut SchedClassifier = ebpf
        .program_mut("ree0xq_net_tc")
        .ok_or_else(|| anyhow::anyhow!("eBPF program `ree0xq_net_tc` not in object"))?
        .try_into()?;
    program.load()?;
    program.attach(&cfg.iface, TcAttachType::Ingress)?;
    info!(iface = %cfg.iface, "TC classifier attached to ingress");

    // Take the ring-buffer map.
    let ring: RingBuf<MapData> = ebpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow::anyhow!("ring buffer `EVENTS` not in object"))?
        .try_into()?;
    let mut async_ring = AsyncFd::new(ring)?;

    let mut stats = ObservationStats::default();

    loop {
        let mut guard = async_ring.readable_mut().await?;
        let ring = guard.get_inner_mut();
        while let Some(item) = ring.next() {
            stats.packets_seen += 1;
            stats.handshake_packets += 1;
            let raw: &[u8] = &item;
            if raw.len() < std::mem::size_of::<HandshakeEvent>() {
                stats.packets_skipped_unparseable += 1;
                continue;
            }
            // Safety: kernel-side writes a HandshakeEvent into the
            // ring with C layout (#[repr(C)]); we read it back here.
            let ev = unsafe { &*(raw.as_ptr() as *const HandshakeEvent) };
            let body = &ev.bytes[..(ev.len as usize)];
            match parse_handshake(body) {
                Ok(summary) => {
                    stats.handshakes_parsed += 1;
                    let primitives = primitives_from_summary(&summary);
                    let host = format!(
                        "{}.{}.{}.{}:{}",
                        (ev.dst_ip >> 24) & 0xff,
                        (ev.dst_ip >> 16) & 0xff,
                        (ev.dst_ip >> 8) & 0xff,
                        ev.dst_ip & 0xff,
                        ev.dst_port
                    );
                    let identity = live::session_identity_for_loader(
                        ev.src_ip,
                        ev.src_port,
                        ev.dst_ip,
                        ev.dst_port,
                    );
                    let event =
                        live::build_loader_event(host, identity, summary.msg_kind, primitives);
                    stats.events_emitted += 1;
                    on_event(event);
                }
                Err(e) => {
                    debug!(?e, "handshake parse failed");
                    stats.handshakes_parse_failed += 1;
                }
            }
        }
        guard.clear_ready();
        // Yield briefly so other tasks make progress.
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
