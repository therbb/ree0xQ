//! Integration test for `ree0xq_net::live`.
//!
//! Synthesises a tiny pcap file holding one Ethernet + IPv4 + TCP
//! frame whose payload is a TLS 1.3 ClientHello advertising
//! `X25519MLKEM768` + classical `x25519`, plus `mldsa65` and
//! `ecdsa_secp256r1_sha256` in `signature_algorithms`. Then calls
//! `observe_pcap` and asserts the emitted event has the expected
//! shape.

use std::io::Cursor;
use std::time::Duration;

use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use pcap_file::DataLink;
use ree0xq_net::live;

/// Build a minimal TLS 1.3 ClientHello *body* (everything after the
/// 5-byte TLSPlaintext record header). Includes:
/// - cipher_suites = [TLS_AES_256_GCM_SHA384 (0x1302),
///                    TLS_AES_128_GCM_SHA256 (0x1301)]
/// - supported_groups = [X25519MLKEM768 (0x11ec), x25519 (0x001d)]
/// - signature_algorithms = [mldsa65 (0x0905),
///                           ecdsa_secp256r1_sha256 (0x0403)]
/// - supported_versions = [0x0304]
fn sample_client_hello() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session id length
    body.extend_from_slice(&(4u16).to_be_bytes()); // cipher_suites length
    body.extend_from_slice(&[0x13, 0x02, 0x13, 0x01]); // 0x1302, 0x1301
    body.push(1); // legacy_compression_methods length
    body.push(0); // compression: null

    let mut ext = Vec::new();

    // supported_groups: type 0x000a
    let mut sg = Vec::new();
    sg.extend_from_slice(&(4u16).to_be_bytes());
    sg.extend_from_slice(&[0x11, 0xec, 0x00, 0x1d]);
    ext.extend_from_slice(&0x000au16.to_be_bytes());
    ext.extend_from_slice(&(sg.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sg);

    // signature_algorithms: type 0x000d
    let mut sa = Vec::new();
    sa.extend_from_slice(&(4u16).to_be_bytes());
    sa.extend_from_slice(&[0x09, 0x05, 0x04, 0x03]);
    ext.extend_from_slice(&0x000du16.to_be_bytes());
    ext.extend_from_slice(&(sa.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sa);

    // supported_versions: type 0x002b (ClientHello variant: 1-byte length)
    let mut sv = Vec::new();
    sv.push(2u8);
    sv.extend_from_slice(&[0x03, 0x04]);
    ext.extend_from_slice(&0x002bu16.to_be_bytes());
    ext.extend_from_slice(&(sv.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sv);

    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    // Prepend the 4-byte handshake header (msg_type + 3-byte length).
    let blen = body.len() as u32;
    let mut hs = Vec::new();
    hs.push(0x01u8); // msg_type = ClientHello
    hs.extend_from_slice(&[(blen >> 16) as u8, (blen >> 8) as u8, blen as u8]);
    hs.extend_from_slice(&body);
    hs
}

/// IPv4 header checksum. Standard one's-complement sum of the 20-byte
/// header with checksum field zeroed.
fn ipv4_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < hdr.len() {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([hdr[i], hdr[i + 1]])));
        i += 2;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Wrap a TLS handshake payload in a synthetic
/// Ethernet(14) + IPv4(20) + TCP(20) frame and return the raw bytes.
fn build_eth_ipv4_tcp_frame(tls_handshake_body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();

    // --- Ethernet (14) ---
    let dst_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let src_mac = [0x52, 0x54, 0x00, 0x00, 0x00, 0x01];
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType: IPv4

    // TLS record header: ContentType=0x16, Version=0x0303, length.
    let tls_record_len = tls_handshake_body.len() as u16;
    let mut tls_record = Vec::with_capacity(5 + tls_handshake_body.len());
    tls_record.push(0x16);
    tls_record.push(0x03);
    tls_record.push(0x03);
    tls_record.extend_from_slice(&tls_record_len.to_be_bytes());
    tls_record.extend_from_slice(tls_handshake_body);

    let tcp_payload_len = tls_record.len();
    let total_ipv4 = 20 + 20 + tcp_payload_len;

    // --- IPv4 (20) ---
    let mut ip = Vec::with_capacity(20);
    ip.push(0x45); // version=4, IHL=5
    ip.push(0x00); // DSCP/ECN
    ip.extend_from_slice(&(total_ipv4 as u16).to_be_bytes()); // total length
    ip.extend_from_slice(&0u16.to_be_bytes()); // id
    ip.extend_from_slice(&0x4000u16.to_be_bytes()); // flags=DF, frag=0
    ip.push(64); // TTL
    ip.push(6); // protocol: TCP
    ip.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    ip.extend_from_slice(&[10, 0, 0, 1]); // src
    ip.extend_from_slice(&[203, 0, 113, 7]); // dst
    let cksum = ipv4_checksum(&ip);
    ip[10..12].copy_from_slice(&cksum.to_be_bytes());
    frame.extend_from_slice(&ip);

    // --- TCP (20, no options) ---
    let mut tcp = Vec::with_capacity(20);
    tcp.extend_from_slice(&50001u16.to_be_bytes()); // src port
    tcp.extend_from_slice(&443u16.to_be_bytes()); // dst port
    tcp.extend_from_slice(&0u32.to_be_bytes()); // seq
    tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
    tcp.push(0x50); // data offset = 5
    tcp.push(0x18); // flags: PSH+ACK
    tcp.extend_from_slice(&65535u16.to_be_bytes()); // window
    tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum (skipped)
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent ptr
    frame.extend_from_slice(&tcp);

    frame.extend_from_slice(&tls_record);
    frame
}

#[test]
fn observe_pcap_emits_event_for_synthesised_client_hello() {
    // Build synthetic pcap in memory.
    let mut buf = Vec::<u8>::new();
    {
        let header = PcapHeader {
            version_major: 2,
            version_minor: 4,
            ts_correction: 0,
            ts_accuracy: 0,
            snaplen: 65535,
            datalink: DataLink::ETHERNET,
            ts_resolution: pcap_file::TsResolution::MicroSecond,
            endianness: pcap_file::Endianness::Little,
        };
        let mut writer = PcapWriter::with_header(Cursor::new(&mut buf), header).unwrap();
        let body = sample_client_hello();
        let frame = build_eth_ipv4_tcp_frame(&body);
        writer
            .write_packet(&PcapPacket::new(
                Duration::from_secs(1_700_000_000),
                frame.len() as u32,
                &frame,
            ))
            .unwrap();
    }

    // Persist to a tempfile because observe_pcap takes a path. Also
    // refresh the committed fixture so docs/scripts can drive the
    // CLI against a known-good pcap without rebuilding it.
    let dir = tempfile::tempdir().unwrap();
    let pcap_path = dir.path().join("synth.pcap");
    std::fs::write(&pcap_path, &buf).unwrap();
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/synth-clienthello.pcap");
    if let Some(parent) = fixture.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&fixture, &buf);

    let mut emitted = Vec::new();
    let stats = live::observe_pcap(&pcap_path, |ev| emitted.push(ev)).unwrap();

    assert_eq!(stats.packets_seen, 1);
    assert_eq!(stats.handshake_packets, 1);
    assert_eq!(stats.handshakes_parsed, 1);
    assert_eq!(stats.events_emitted, 1);
    assert_eq!(emitted.len(), 1);

    let ev = &emitted[0];
    assert_eq!(ev.source_module, "ree0xq-net");
    assert_eq!(
        ev.asset.kind,
        ree0xq_core::AssetKind::TlsSession,
        "asset kind"
    );
    assert!(ev.asset.host.as_deref().unwrap().contains("203.0.113.7"));
    assert!(ev.asset.identity.starts_with("live-"));

    // Confirm the expected primitives surfaced.
    let names: Vec<&str> = ev.primitives.iter().map(|p| p.algorithm.as_str()).collect();
    assert!(
        names.contains(&"X25519+ML-KEM-768"),
        "missing PQ kex; got {names:?}"
    );
    assert!(
        names.contains(&"X25519"),
        "missing classical kex; got {names:?}"
    );
    assert!(
        names.contains(&"ML-DSA-65"),
        "missing PQ sig; got {names:?}"
    );
    assert!(
        names.contains(&"AES-256-GCM"),
        "missing AEAD; got {names:?}"
    );
}
