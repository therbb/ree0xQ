//! Minimal TLS handshake parser.
//!
//! Parses ClientHello and ServerHello frames at the level needed to
//! classify a session under the three-axis posture model. We
//! intentionally do *not* implement a full TLS state machine — we
//! parse only the handshake headers, the ciphersuite list, and the
//! `supported_groups` (0x000a) and `signature_algorithms` (0x000d)
//! extensions.
//!
//! Reference:
//! - RFC 8446 (TLS 1.3) §4.1.2 (ClientHello) and §4.1.3 (ServerHello)
//! - RFC 5246 (TLS 1.2) §7.4.1.2 (ClientHello)
//! - IANA TLS parameters registry for the named-group / signature
//!   algorithm identifiers
//!
//! Caller obligations: pass in the *handshake body* — i.e., what comes
//! after the record-layer header. If you're handing us bytes from a
//! pcap, strip the TLSPlaintext header first (5 bytes:
//! `type=0x16 version=0x0303 length=u16`). The parser will reject
//! frames whose msg_type byte is not `0x01` (ClientHello) or `0x02`
//! (ServerHello).

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::algos;
use ree0xq_core::Primitive;

/// Parsed snapshot of a TLS handshake message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandshakeSummary {
    /// `client_hello` or `server_hello`.
    pub msg_kind: HandshakeKind,
    /// Protocol version on the wire (legacy field; for TLS 1.3
    /// `supported_versions` is more reliable, exposed below).
    pub legacy_version: u16,
    /// IANA codepoint of every ciphersuite advertised (ClientHello)
    /// or the single chosen suite (ServerHello).
    pub ciphersuites: Vec<u16>,
    /// IANA named-group codepoint list from the `supported_groups`
    /// extension (0x000a). Empty when absent.
    pub supported_groups: Vec<u16>,
    /// IANA signature-algorithm codepoints from the
    /// `signature_algorithms` extension (0x000d). Empty when absent.
    pub signature_schemes: Vec<u16>,
    /// `supported_versions` extension (0x002b) entries, if present.
    pub supported_versions: Vec<u16>,
}

/// Which kind of handshake message we parsed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HandshakeKind {
    /// 0x01
    ClientHello,
    /// 0x02
    ServerHello,
}

/// Errors raised by the parser.
#[derive(Debug, Error)]
pub enum ParseError {
    /// Buffer ended before the field could be read.
    #[error("truncated at offset {at}: needed {need} more bytes")]
    Truncated {
        /// Offset where the read ran out.
        at: usize,
        /// Number of bytes still needed.
        need: usize,
    },
    /// Handshake msg_type was not 0x01 / 0x02.
    #[error("unsupported handshake msg_type 0x{kind:02x} (expected 0x01 ClientHello or 0x02 ServerHello)")]
    UnsupportedKind {
        /// The unrecognised msg_type byte.
        kind: u8,
    },
    /// Handshake length header lied about the buffer.
    #[error("handshake length {claimed} exceeds buffer {available}")]
    LengthMismatch {
        /// Length the handshake header claimed.
        claimed: usize,
        /// Bytes actually available.
        available: usize,
    },
}

/// Parse a handshake message and return its summary.
pub fn parse_handshake(buf: &[u8]) -> Result<HandshakeSummary, ParseError> {
    let mut c = Cursor::new(buf);
    let kind_byte = c.read_u8()?;
    let kind = match kind_byte {
        0x01 => HandshakeKind::ClientHello,
        0x02 => HandshakeKind::ServerHello,
        b => return Err(ParseError::UnsupportedKind { kind: b }),
    };
    let total_len = c.read_u24()? as usize;
    if total_len > c.remaining() {
        return Err(ParseError::LengthMismatch {
            claimed: total_len,
            available: c.remaining(),
        });
    }
    // legacy_version (2 bytes)
    let legacy_version = c.read_u16()?;
    // random (32 bytes)
    c.advance(32)?;
    // legacy_session_id <0..32>
    let sid_len = c.read_u8()? as usize;
    c.advance(sid_len)?;

    let mut summary = HandshakeSummary {
        msg_kind: kind,
        legacy_version,
        ciphersuites: Vec::new(),
        supported_groups: Vec::new(),
        signature_schemes: Vec::new(),
        supported_versions: Vec::new(),
    };

    match kind {
        HandshakeKind::ClientHello => {
            // cipher_suites <2..2^16-2>
            let cs_bytes = c.read_u16()? as usize;
            if cs_bytes % 2 != 0 {
                return Err(ParseError::LengthMismatch {
                    claimed: cs_bytes,
                    available: c.remaining(),
                });
            }
            let n = cs_bytes / 2;
            for _ in 0..n {
                summary.ciphersuites.push(c.read_u16()?);
            }
            // legacy_compression_methods <1..2^8-1>
            let comp_len = c.read_u8()? as usize;
            c.advance(comp_len)?;
        }
        HandshakeKind::ServerHello => {
            // single cipher_suite
            summary.ciphersuites.push(c.read_u16()?);
            // legacy_compression_method (1 byte)
            c.advance(1)?;
        }
    }

    // extensions <0..2^16-1>
    if c.remaining() < 2 {
        // Some legacy TLS 1.0 servers omit the extensions block.
        return Ok(summary);
    }
    let ext_bytes = c.read_u16()? as usize;
    if ext_bytes > c.remaining() {
        return Err(ParseError::LengthMismatch {
            claimed: ext_bytes,
            available: c.remaining(),
        });
    }
    let ext_end = c.pos + ext_bytes;
    while c.pos < ext_end {
        let ext_type = c.read_u16()?;
        let ext_len = c.read_u16()? as usize;
        let ext_data_end = c.pos + ext_len;
        match ext_type {
            0x000a => {
                // supported_groups: vector<NamedGroup> (each 2 bytes)
                let inner_len = c.read_u16()? as usize;
                let inner_end = c.pos + inner_len;
                while c.pos < inner_end {
                    summary.supported_groups.push(c.read_u16()?);
                }
            }
            0x000d => {
                // signature_algorithms: vector<SignatureScheme> (each 2 bytes)
                let inner_len = c.read_u16()? as usize;
                let inner_end = c.pos + inner_len;
                while c.pos < inner_end {
                    summary.signature_schemes.push(c.read_u16()?);
                }
            }
            0x002b => {
                // supported_versions — shape differs CH vs SH.
                if kind == HandshakeKind::ClientHello {
                    let inner_len = c.read_u8()? as usize;
                    let inner_end = c.pos + inner_len;
                    while c.pos < inner_end {
                        summary.supported_versions.push(c.read_u16()?);
                    }
                } else {
                    summary.supported_versions.push(c.read_u16()?);
                }
            }
            _ => {
                // skip
            }
        }
        // Resync to the declared extension end — some servers pack
        // padding inside extensions and we treat the declared length
        // as authoritative.
        c.pos = ext_data_end;
    }
    Ok(summary)
}

/// Resolve a parsed [`HandshakeSummary`] to a `Vec<Primitive>` by
/// crossing the IANA codepoint maps against the [`crate::algos`]
/// tables. Returns one or more primitives per role observed.
pub fn primitives_from_summary(summary: &HandshakeSummary) -> Vec<Primitive> {
    let mut out = Vec::new();

    // Choose the strongest signal for ciphersuites first.
    for cs in &summary.ciphersuites {
        if let Some(name) = ciphersuite_name(*cs) {
            // TLS 1.3 names begin with `TLS_AES`/`TLS_CHACHA`; TLS 1.2
            // names begin with `TLS_E?CDH...`/`TLS_RSA_WITH_...`.
            let p = if name.starts_with("TLS_AES_") || name.starts_with("TLS_CHACHA20_") {
                algos::primitives_from_tls13_ciphersuite(name)
            } else {
                algos::primitives_from_tls12_ciphersuite(name)
            };
            out.extend(p);
            // We want only one ciphersuite worth of primitives — the
            // first known one is the one the server actually selected
            // (for ServerHello) or the client's top preference (for
            // ClientHello).
            break;
        }
    }

    for g in &summary.supported_groups {
        if let Some(name) = named_group_name(*g) {
            if let Some(p) = algos::primitive_from_supported_group(name) {
                out.push(p);
            }
        }
    }

    for s in &summary.signature_schemes {
        if let Some(name) = signature_scheme_name(*s) {
            if let Some(p) = algos::primitive_from_signature_scheme(name) {
                out.push(p);
            }
        }
    }

    out
}

/// IANA TLS Ciphersuite registry — the subset relevant for posture
/// classification. Add codepoints as needed; the unknown branch is
/// safe (the algos table will simply not contribute primitives).
fn ciphersuite_name(code: u16) -> Option<&'static str> {
    Some(match code {
        // TLS 1.3
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x1305 => "TLS_AES_128_CCM_8_SHA256",
        // TLS 1.2 — ECDHE+RSA / ECDSA
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        // TLS 1.2 — older suites, useful for legacy detection
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA",
        _ => return None,
    })
}

/// IANA Supported Groups (named-group) registry — the subset
/// relevant for posture classification. Returns the algos-table-
/// recognised name when known.
fn named_group_name(code: u16) -> Option<&'static str> {
    Some(match code {
        0x0017 => "secp256r1",
        0x0018 => "secp384r1",
        0x0019 => "secp521r1",
        0x001d => "x25519",
        0x001e => "x448",
        0x0100 => "ffdhe2048",
        0x0101 => "ffdhe3072",
        0x0102 => "ffdhe4096",
        // Hybrid PQ — IANA-registered codepoints
        0x11ec => "X25519MLKEM768",
        0x11eb => "SecP256r1MLKEM768",
        0x11ed => "P384MLKEM1024",
        // Pure ML-KEM
        0x0768 => "MLKEM768",
        0x0769 => "MLKEM512",
        0x076a => "MLKEM1024",
        _ => return None,
    })
}

/// IANA Signature Algorithms registry — the subset relevant for
/// posture classification.
fn signature_scheme_name(code: u16) -> Option<&'static str> {
    Some(match code {
        // RSA-PKCS1
        0x0201 => "rsa_pkcs1_sha1",
        0x0401 => "rsa_pkcs1_sha256",
        0x0501 => "rsa_pkcs1_sha384",
        0x0601 => "rsa_pkcs1_sha512",
        // RSA-PSS
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0806 => "rsa_pss_rsae_sha512",
        0x0809 => "rsa_pss_pss_sha256",
        0x080a => "rsa_pss_pss_sha384",
        0x080b => "rsa_pss_pss_sha512",
        // ECDSA
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0603 => "ecdsa_secp521r1_sha512",
        // EdDSA
        0x0807 => "ed25519",
        0x0808 => "ed448",
        // ML-DSA / Dilithium (IANA-registered codepoints — provisional)
        0x0904 => "mldsa44",
        0x0905 => "mldsa65",
        0x0906 => "mldsa87",
        // SLH-DSA / SPHINCS+
        0x0910 => "slhdsa_sha2_128s",
        0x0911 => "slhdsa_sha2_256s",
        _ => return None,
    })
}

// ----- minimal cursor helper -----

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn need(&self, n: usize) -> Result<(), ParseError> {
        if self.remaining() < n {
            Err(ParseError::Truncated {
                at: self.pos,
                need: n - self.remaining(),
            })
        } else {
            Ok(())
        }
    }
    fn read_u8(&mut self) -> Result<u8, ParseError> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }
    fn read_u16(&mut self) -> Result<u16, ParseError> {
        self.need(2)?;
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }
    fn read_u24(&mut self) -> Result<u32, ParseError> {
        self.need(3)?;
        let v = (u32::from(self.buf[self.pos]) << 16)
            | (u32::from(self.buf[self.pos + 1]) << 8)
            | u32::from(self.buf[self.pos + 2]);
        self.pos += 3;
        Ok(v)
    }
    fn advance(&mut self, n: usize) -> Result<(), ParseError> {
        self.need(n)?;
        self.pos += n;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-rolled minimal TLS 1.3 ClientHello:
    /// - msg_type = 0x01
    /// - length = (computed)
    /// - legacy_version = 0x0303
    /// - random = 32 zero bytes
    /// - legacy_session_id = empty (1 length byte = 0)
    /// - cipher_suites = [TLS_AES_256_GCM_SHA384 (0x1302),
    ///   TLS_AES_128_GCM_SHA256 (0x1301)]
    /// - legacy_compression_methods = [0]
    /// - extensions:
    ///   - supported_groups (0x000a): [X25519MLKEM768 (0x11ec), x25519 (0x001d)]
    ///   - signature_algorithms (0x000d): [mldsa65 (0x0905),
    ///     ecdsa_secp256r1_sha256 (0x0403)]
    ///   - supported_versions (0x002b): [0x0304]
    fn sample_client_hello() -> Vec<u8> {
        let mut body = Vec::new();
        // legacy_version
        body.extend_from_slice(&[0x03, 0x03]);
        // random
        body.extend_from_slice(&[0u8; 32]);
        // session id length
        body.push(0);
        // cipher_suites length + entries
        body.extend_from_slice(&(4u16).to_be_bytes());
        body.extend_from_slice(&[0x13, 0x02, 0x13, 0x01]);
        // legacy_compression_methods
        body.push(1);
        body.push(0);

        // extensions
        let mut ext = Vec::new();

        // supported_groups: type 0x000a
        let mut sg = Vec::new();
        sg.extend_from_slice(&(4u16).to_be_bytes()); // inner length
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
        sv.push(2u8); // inner length
        sv.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
        ext.extend_from_slice(&0x002bu16.to_be_bytes());
        ext.extend_from_slice(&(sv.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sv);

        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut out = Vec::new();
        out.push(0x01u8); // msg_type
        let blen = body.len() as u32;
        out.extend_from_slice(&[(blen >> 16) as u8, (blen >> 8) as u8, blen as u8]);
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn parses_a_pq_capable_client_hello() {
        let buf = sample_client_hello();
        let s = parse_handshake(&buf).expect("must parse");
        assert_eq!(s.msg_kind, HandshakeKind::ClientHello);
        assert_eq!(s.ciphersuites, vec![0x1302, 0x1301]);
        assert_eq!(s.supported_groups, vec![0x11ec, 0x001d]);
        assert_eq!(s.signature_schemes, vec![0x0905, 0x0403]);
        assert_eq!(s.supported_versions, vec![0x0304]);
    }

    #[test]
    fn resolves_pq_client_hello_to_primitives() {
        let buf = sample_client_hello();
        let s = parse_handshake(&buf).unwrap();
        let prims = primitives_from_summary(&s);
        // Expect: encrypt+hash from TLS_AES_256_GCM_SHA384 +
        //         kex for x25519mlkem768 + kex for x25519 +
        //         sig for ML-DSA-65 + sig for ECDSA-P256.
        let names: Vec<&str> = prims.iter().map(|p| p.algorithm.as_str()).collect();
        assert!(names.contains(&"AES-256-GCM"));
        assert!(names.contains(&"SHA-384"));
        assert!(names.contains(&"X25519+ML-KEM-768"));
        assert!(names.contains(&"X25519"));
        assert!(names.contains(&"ML-DSA-65"));
        assert!(names.contains(&"ECDSA-P256"));
    }

    #[test]
    fn truncated_buffer_returns_error_not_panic() {
        let buf = sample_client_hello();
        let trunc = &buf[..buf.len() / 2];
        assert!(parse_handshake(trunc).is_err());
    }

    #[test]
    fn unsupported_msg_type_rejected() {
        // 0x14 (Finished)
        let buf = [0x14u8, 0, 0, 0];
        assert!(matches!(
            parse_handshake(&buf),
            Err(ParseError::UnsupportedKind { kind: 0x14 })
        ));
    }
}
