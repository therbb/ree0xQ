//! Phase 2 — passive live TLS observation.
//!
//! Three packet sources share one frame-handling path:
//!
//! 1. **Pcap-file replay** (Phase 2.0; default build). Read a
//!    `.pcap` or `.pcapng` file (e.g. captured by
//!    `tcpdump -w port-443.pcap port 443`), walk each captured
//!    frame, parse the Ethernet / IP / TCP layers with
//!    `etherparse`, look for TLS record-layer handshake messages
//!    (record type `0x16`, msg_type `0x01`/`0x02`), and feed them
//!    to [`crate::tls::parse_handshake`]. Each parsed handshake
//!    becomes one `tls_session` event.
//!
//! 2. **Libpcap live interface** (Phase 2.2; gated behind the
//!    `live-pcap` cargo feature). Same frame-handling path but the
//!    packet source is libpcap on a network interface. Requires
//!    `libpcap-devel` at build time and `CAP_NET_RAW` at run time.
//!    Friendly for `lo` smoke tests and small-scale capture.
//!
//! 3. **eBPF TC classifier** (Phase 2.1; gated behind the
//!    `live-interface` cargo feature). Higher-throughput path that
//!    pushes parsed handshake bytes from the kernel into userspace
//!    via a ring buffer. Wired up in [`crate::live_iface`]. Needs
//!    a pre-built BPF object and `CAP_BPF` + `CAP_NET_ADMIN`.
//!
//! # Reassembly policy
//!
//! TLS 1.3 ClientHello / ServerHello typically fit in one TCP
//! segment (≤ a few hundred bytes). We follow the "single-segment"
//! observability convention: if a handshake message is split across
//! segments we drop the asset on the floor and emit a warning.
//! Full TCP reassembly belongs in `ree0xq-net-ebpf` (Phase 2.1)
//! where kernel-side reassembly is free.
//!
//! # Caveats
//!
//! - No decryption. We only see ClientHello / ServerHello in the
//!   clear because they sit before the TLS key-exchange completes.
//! - Source IP / TCP-port pairs identify the session for dedup
//!   purposes; the schema-side identity is a 16-byte FNV-1a hash
//!   of `(src_ip, src_port, dst_ip, dst_port)` matching the
//!   convention used by [`crate::zgrab::event_from_zgrab`].

use std::path::Path;

use pcap_file::pcap::PcapReader;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::dedup::DedupCache;
use crate::tls::{parse_handshake, primitives_from_summary, HandshakeKind};
use ree0xq_core::{
    Asset, AssetKind, CryptoInventoryEvent, Posture, Primitive, SCHEMA_MINOR, SCHEMA_VERSION,
};

/// Errors raised by the live observer.
#[derive(Debug, Error)]
pub enum LiveError {
    /// Failed to open the pcap file.
    #[error("pcap open: {0}")]
    Open(String),
    /// Underlying IO error reading the file.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Statistics from one observation pass.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ObservationStats {
    /// Total packets seen in the pcap.
    pub packets_seen: usize,
    /// Packets we couldn't parse at the link/IP/TCP layer.
    pub packets_skipped_unparseable: usize,
    /// Packets whose TCP payload was empty.
    pub packets_skipped_empty_payload: usize,
    /// Packets carrying a TLS handshake (msg_type 0x01 or 0x02).
    pub handshake_packets: usize,
    /// Handshake messages we successfully parsed.
    pub handshakes_parsed: usize,
    /// Handshake messages whose parse failed (truncation, unknown variant).
    pub handshakes_parse_failed: usize,
    /// Handshake messages dropped by the dedup cache (already seen
    /// within the recent-session TTL). `0` when no dedup cache is
    /// supplied — matching the pre-dedup behaviour.
    pub handshakes_deduplicated: usize,
    /// Events emitted (one per parsed handshake).
    pub events_emitted: usize,
}

/// Observe a pcap file and call `on_event` for each emitted event.
///
/// The caller decides what to do with each event — print as NDJSON,
/// forward to a collector, batch, drop. The function blocks until
/// the file is fully consumed.
///
/// This is a thin wrapper over [`observe_pcap_with_dedup`] with no
/// dedup cache attached — every parsed handshake becomes an event.
pub fn observe_pcap<P, F>(path: P, on_event: F) -> Result<ObservationStats, LiveError>
where
    P: AsRef<Path>,
    F: FnMut(CryptoInventoryEvent),
{
    observe_pcap_with_dedup(path, None, on_event)
}

/// Like [`observe_pcap`] but optionally consults a [`DedupCache`]
/// before emitting events. A `Some(cache)` here is what the live
/// agent uses to avoid re-emitting the same session on every
/// retransmit — see `module-net.md` § "userspace dedup".
pub fn observe_pcap_with_dedup<P, F>(
    path: P,
    mut dedup: Option<&mut DedupCache>,
    mut on_event: F,
) -> Result<ObservationStats, LiveError>
where
    P: AsRef<Path>,
    F: FnMut(CryptoInventoryEvent),
{
    let path = path.as_ref();
    let file = std::fs::File::open(path).map_err(|e| LiveError::Open(e.to_string()))?;
    let mut reader = PcapReader::new(file).map_err(|e| LiveError::Open(e.to_string()))?;
    let mut stats = ObservationStats::default();

    while let Some(pkt) = reader.next_packet() {
        stats.packets_seen += 1;
        let pkt = match pkt {
            Ok(p) => p,
            Err(_) => {
                stats.packets_skipped_unparseable += 1;
                continue;
            }
        };
        match handle_frame(&pkt.data, &mut stats, dedup.as_deref_mut(), &mut on_event) {
            Ok(()) => {}
            Err(_) => {
                stats.packets_skipped_unparseable += 1;
            }
        }
    }
    Ok(stats)
}

/// Per-frame observation. The frame is whatever the packet source
/// hands us as Ethernet payload (pcap-file, libpcap, eBPF map). Errors
/// are folded into `stats` by the caller; success means either an
/// event was emitted or the frame was uninteresting.
fn handle_frame<F>(
    frame: &[u8],
    stats: &mut ObservationStats,
    dedup: Option<&mut DedupCache>,
    on_event: &mut F,
) -> Result<(), ()>
where
    F: FnMut(CryptoInventoryEvent),
{
    // etherparse accepts a raw frame and returns a sliced view we
    // can step through layer by layer.
    let parsed = match etherparse::SlicedPacket::from_ethernet(frame) {
        Ok(p) => p,
        Err(_) => return Err(()),
    };

    // Need TCP for src/dst ports — and extract the TCP payload via
    // the TransportSlice (etherparse 0.16 exposes `.payload()` on
    // TcpSlice).
    let (src_port, dst_port, payload) = match &parsed.transport {
        Some(etherparse::TransportSlice::Tcp(tcp)) => {
            (tcp.source_port(), tcp.destination_port(), tcp.payload())
        }
        _ => return Ok(()),
    };
    if payload.is_empty() {
        stats.packets_skipped_empty_payload += 1;
        return Ok(());
    }
    let (src_ip, dst_ip) = ips_from_parsed(&parsed);

    // TLSPlaintext record header: ContentType(1) Version(2) Length(2).
    // Handshake content type is 0x16.
    if payload.len() < 6 || payload[0] != 0x16 {
        return Ok(());
    }
    // Inner handshake msg_type is at payload[5].
    let msg_type = payload[5];
    if msg_type != 0x01 && msg_type != 0x02 {
        return Ok(());
    }
    stats.handshake_packets += 1;

    // Inner handshake body starts at payload[5..]. parse_handshake
    // expects the handshake message body — the 4-byte handshake
    // header (msg_type + 3-byte length) included.
    let body = &payload[5..];
    let summary = match parse_handshake(body) {
        Ok(s) => s,
        Err(_) => {
            stats.handshakes_parse_failed += 1;
            return Ok(());
        }
    };
    stats.handshakes_parsed += 1;

    let primitives = primitives_from_summary(&summary);
    let identity = session_identity(src_ip.as_deref(), src_port, dst_ip.as_deref(), dst_port);
    if let Some(cache) = dedup {
        if !cache.observe(&identity) {
            stats.handshakes_deduplicated += 1;
            return Ok(());
        }
    }
    let host = dst_ip
        .clone()
        .map(|ip| format!("{ip}:{dst_port}"))
        .unwrap_or_else(|| format!("port:{dst_port}"));
    let ev = build_live_event(host, identity, summary.msg_kind, primitives);
    on_event(ev);
    stats.events_emitted += 1;
    Ok(())
}

/// Extract IPv4/IPv6 src+dst from an etherparse SlicedPacket.
fn ips_from_parsed(parsed: &etherparse::SlicedPacket<'_>) -> (Option<String>, Option<String>) {
    use etherparse::NetSlice;
    match &parsed.net {
        Some(NetSlice::Ipv4(v4)) => {
            let h = v4.header();
            (
                Some(std::net::Ipv4Addr::from(h.source()).to_string()),
                Some(std::net::Ipv4Addr::from(h.destination()).to_string()),
            )
        }
        Some(NetSlice::Ipv6(v6)) => {
            let h = v6.header();
            (
                Some(std::net::Ipv6Addr::from(h.source()).to_string()),
                Some(std::net::Ipv6Addr::from(h.destination()).to_string()),
            )
        }
        _ => (None, None),
    }
}

/// Stable, short identity for a TCP session built from a u32 IPv4
/// 4-tuple. Public so the `live-interface` loader (Phase 2.1) can
/// reuse the same hashing convention as the pcap path.
pub fn session_identity_for_loader(
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
) -> String {
    let src = format!(
        "{}.{}.{}.{}",
        (src_ip >> 24) & 0xff,
        (src_ip >> 16) & 0xff,
        (src_ip >> 8) & 0xff,
        src_ip & 0xff
    );
    let dst = format!(
        "{}.{}.{}.{}",
        (dst_ip >> 24) & 0xff,
        (dst_ip >> 16) & 0xff,
        (dst_ip >> 8) & 0xff,
        dst_ip & 0xff
    );
    session_identity(Some(&src), src_port, Some(&dst), dst_port)
}

/// Build a `tls_session` event with the loader's 4-tuple → IP+port
/// already stringified into `host`. Public so the `live-interface`
/// loader can produce events identical to the pcap path.
pub fn build_loader_event(
    host: String,
    identity: String,
    kind: HandshakeKind,
    primitives: Vec<Primitive>,
) -> CryptoInventoryEvent {
    build_live_event(host, identity, kind, primitives)
}

/// Stable, short identity for a TCP session — FNV-1a over the
/// 4-tuple. Matches the spirit of `zgrab::synthetic_identity`.
fn session_identity(
    src_ip: Option<&str>,
    src_port: u16,
    dst_ip: Option<&str>,
    dst_port: u16,
) -> String {
    const SALT: u64 = 0xcbf29ce484222325;
    let mut h: u64 = SALT;
    let push = |h: &mut u64, s: &str| {
        for b in s.bytes() {
            *h ^= u64::from(b);
            *h = h.wrapping_mul(0x100000001b3);
        }
    };
    push(&mut h, src_ip.unwrap_or("?"));
    push(&mut h, ":");
    push(&mut h, &src_port.to_string());
    push(&mut h, "|");
    push(&mut h, dst_ip.unwrap_or("?"));
    push(&mut h, ":");
    push(&mut h, &dst_port.to_string());
    format!("live-{:016x}", h)
}

/// Build a `tls_session` event from a parsed handshake.
fn build_live_event(
    host: String,
    identity: String,
    kind: HandshakeKind,
    primitives: Vec<Primitive>,
) -> CryptoInventoryEvent {
    let rationale = if primitives.is_empty() {
        format!("{:?} observed but no primitives extracted", kind)
    } else {
        format!(
            "{:?}: {} primitive(s) [{}]",
            kind,
            primitives.len(),
            primitives
                .iter()
                .map(|p| p.algorithm.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };

    CryptoInventoryEvent {
        schema_version: SCHEMA_VERSION,
        schema_minor: SCHEMA_MINOR,
        source_module: crate::MODULE_NAME.into(),
        observed_at: chrono::Utc::now(),
        asset: Asset {
            kind: AssetKind::TlsSession,
            identity,
            host: Some(host),
        },
        primitives,
        channel_protection: None,
        agility: None,
        posture: Posture {
            score: 50,
            rationale,
            recommended_replacement: None,
        },
    }
}

/// Configuration for the libpcap-backed live interface observer.
#[cfg(feature = "live-pcap")]
#[derive(Debug, Clone)]
pub struct InterfaceConfig {
    /// Interface name (e.g. `lo`, `eth0`).
    pub iface: String,
    /// Snaplen — bytes captured per frame. 1500 is enough for any
    /// single-MTU TLS ClientHello on Ethernet; bump for jumbo
    /// frames.
    pub snaplen: i32,
    /// Read timeout in milliseconds — controls how long
    /// `pcap_next_ex` blocks between batches before returning
    /// `TimeoutExpired`. 100 ms keeps Ctrl-C responsive without
    /// busy-looping.
    pub read_timeout_ms: i32,
    /// Optional BPF filter expression. Default `"tcp port 443"`
    /// keeps the capture surface to TLS hosts; pass `None` to
    /// disable filtering entirely.
    pub filter: Option<String>,
    /// Promiscuous mode. Required for capturing traffic not
    /// addressed to the host on a shared segment; leave off for
    /// loopback and host-local capture.
    pub promiscuous: bool,
}

#[cfg(feature = "live-pcap")]
impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            iface: "lo".into(),
            snaplen: 1500,
            read_timeout_ms: 100,
            filter: Some("tcp port 443".into()),
            promiscuous: false,
        }
    }
}

/// Observe a live network interface via libpcap. Blocks until the
/// caller signals shutdown by setting `should_stop` to `true`.
/// `on_event` is called inline (single-threaded) for each emitted
/// `crypto_inventory_event`.
///
/// Requires `CAP_NET_RAW` (or root) at run time. Build with
/// `--features live-pcap` and a system `libpcap-devel`.
#[cfg(feature = "live-pcap")]
pub fn observe_interface<F>(
    cfg: &InterfaceConfig,
    should_stop: &std::sync::atomic::AtomicBool,
    on_event: F,
) -> Result<ObservationStats, LiveError>
where
    F: FnMut(CryptoInventoryEvent),
{
    observe_interface_with_dedup(cfg, should_stop, None, on_event)
}

/// Like [`observe_interface`] but optionally consults a
/// [`DedupCache`] before emitting each event. The live agent uses
/// this variant so a continuously-retried session doesn't generate
/// a fresh event on every ClientHello retransmit.
#[cfg(feature = "live-pcap")]
pub fn observe_interface_with_dedup<F>(
    cfg: &InterfaceConfig,
    should_stop: &std::sync::atomic::AtomicBool,
    mut dedup: Option<&mut DedupCache>,
    mut on_event: F,
) -> Result<ObservationStats, LiveError>
where
    F: FnMut(CryptoInventoryEvent),
{
    use std::sync::atomic::Ordering;

    let mut cap = pcap::Capture::from_device(cfg.iface.as_str())
        .map_err(|e| LiveError::Open(format!("from_device({}): {e}", cfg.iface)))?
        .snaplen(cfg.snaplen)
        .timeout(cfg.read_timeout_ms)
        .promisc(cfg.promiscuous)
        .immediate_mode(true)
        .open()
        .map_err(|e| LiveError::Open(format!("open({}): {e}", cfg.iface)))?;

    if let Some(filter) = cfg.filter.as_deref() {
        cap.filter(filter, true)
            .map_err(|e| LiveError::Open(format!("filter({filter}): {e}")))?;
    }

    let mut stats = ObservationStats::default();
    while !should_stop.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(pkt) => {
                stats.packets_seen += 1;
                if handle_frame(pkt.data, &mut stats, dedup.as_deref_mut(), &mut on_event).is_err()
                {
                    stats.packets_skipped_unparseable += 1;
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => return Err(LiveError::Open(format!("next_packet: {e}"))),
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_identity_is_deterministic_and_unique() {
        let a = session_identity(Some("10.0.0.1"), 1234, Some("203.0.113.1"), 443);
        let b = session_identity(Some("10.0.0.1"), 1234, Some("203.0.113.1"), 443);
        let c = session_identity(Some("10.0.0.2"), 1234, Some("203.0.113.1"), 443);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("live-"));
        // 5 prefix + 16 hex chars.
        assert_eq!(a.len(), 5 + 16);
    }

    #[test]
    fn build_live_event_carries_module_identity() {
        use ree0xq_core::PrimitiveRole;
        let ev = build_live_event(
            "10.0.0.1:443".into(),
            "live-deadbeef".into(),
            HandshakeKind::ClientHello,
            vec![Primitive {
                role: PrimitiveRole::Kex,
                algorithm: "X25519MLKEM768".into(),
                parameters: Default::default(),
                pq_resistant: Some(true),
                nist_classification: None,
            }],
        );
        assert_eq!(ev.source_module, crate::MODULE_NAME);
        assert_eq!(ev.asset.kind, AssetKind::TlsSession);
        assert!(ev.posture.rationale.contains("X25519MLKEM768"));
        assert!(ev.posture.rationale.contains("ClientHello"));
    }
}
