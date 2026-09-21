//! Host-filesystem cert walker.
//!
//! Given one or more root directories, walks every regular
//! file under them, picks out the ones whose extension matches
//! `*.pem` / `*.crt` / `*.cer`, and hands each file's contents
//! to [`crate::cert::parse_pem_bundle`]. Files that aren't
//! readable or aren't PEM are counted, logged at `warn`, and
//! skipped — a misconfigured host shouldn't take the scan
//! down.
//!
//! Symlinks are followed but cycles are caught by `walkdir`'s
//! built-in cycle detector.

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use walkdir::WalkDir;

use crate::cert::{event_from_cert, parse_pem_bundle, ParsedCert};

/// Default cert-bearing paths an operator most likely cares
/// about on a vanilla Linux host. The caller can replace or
/// extend this with `--root` flags on the CLI.
pub const DEFAULT_ROOTS: &[&str] = &[
    "/etc/ssl",
    "/etc/pki",
    "/usr/local/share/ca-certificates",
    "/etc/letsencrypt/live",
];

const CERT_EXTENSIONS: &[&str] = &["pem", "crt", "cer"];

/// Per-run statistics from [`host_scan`].
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ScanStats {
    /// Roots walked (every entry in the caller's `--root` list).
    pub roots_walked: usize,
    /// Regular files inspected (had a matching extension).
    pub files_inspected: usize,
    /// Files that didn't read (permission denied, IO error).
    pub files_skipped_io: usize,
    /// PEM blocks that didn't parse as a cert (skipped).
    pub files_skipped_no_certs: usize,
    /// Certificates extracted from PEM bundles.
    pub certs_parsed: usize,
    /// Events emitted to the caller's sink (one per cert).
    pub events_emitted: usize,
}

/// Walk every root in `roots` and call `on_event` once per
/// discovered cert. Errors thrown by the visitor close out the
/// scan with that error; everything else (read errors, parse
/// errors) is folded into [`ScanStats`].
pub fn host_scan<F>(roots: &[PathBuf], mut on_event: F) -> Result<ScanStats>
where
    F: FnMut(ree0xq_core::CryptoInventoryEvent),
{
    let mut stats = ScanStats::default();
    for root in roots {
        stats.roots_walked += 1;
        if !root.exists() {
            warn!(root = %root.display(), "root does not exist; skipping");
            continue;
        }
        info!(root = %root.display(), "walking root");
        for entry in WalkDir::new(root).follow_links(true).into_iter() {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warn!(error = %e, "walk error; continuing");
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            if !has_cert_extension(entry.path()) {
                continue;
            }
            stats.files_inspected += 1;
            match std::fs::read(entry.path()) {
                Ok(bytes) => match parse_pem_bundle(&bytes, Some(entry.path())) {
                    Ok(certs) if certs.is_empty() => {
                        debug!(
                            path = %entry.path().display(),
                            "no CERTIFICATE blocks; skipping"
                        );
                        stats.files_skipped_no_certs += 1;
                    }
                    Ok(certs) => emit_certs(&certs, &mut stats, &mut on_event),
                    Err(e) => {
                        warn!(
                            path = %entry.path().display(),
                            error = %e,
                            "PEM parse failed; skipping file"
                        );
                        stats.files_skipped_no_certs += 1;
                    }
                },
                Err(e) => {
                    warn!(
                        path = %entry.path().display(),
                        error = %e,
                        "file read failed; skipping"
                    );
                    stats.files_skipped_io += 1;
                }
            }
        }
    }
    Ok(stats)
}

fn emit_certs<F>(certs: &[ParsedCert], stats: &mut ScanStats, on_event: &mut F)
where
    F: FnMut(ree0xq_core::CryptoInventoryEvent),
{
    for cert in certs {
        stats.certs_parsed += 1;
        match event_from_cert(cert) {
            Ok(ev) => {
                stats.events_emitted += 1;
                on_event(ev);
            }
            Err(e) => warn!(
                source = ?cert.source_path,
                bundle_index = cert.bundle_index,
                error = %e,
                "event_from_cert failed; skipping cert"
            ),
        }
    }
}

fn has_cert_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .map(|s| {
            let s = s.to_ascii_lowercase();
            CERT_EXTENSIONS.iter().any(|e| *e == s)
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_fixture_cert(dir: &Path, name: &str) {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
        let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec![format!("{name}.example.com")]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("{name}.example.com"));
        params.distinguished_name = dn;
        let cert = params.self_signed(&kp).unwrap();
        let mut f = std::fs::File::create(dir.join(format!("{name}.pem"))).unwrap();
        f.write_all(cert.pem().as_bytes()).unwrap();
    }

    #[test]
    fn walks_a_temp_root_and_emits_per_cert() {
        let d = tempdir().unwrap();
        write_fixture_cert(d.path(), "a");
        write_fixture_cert(d.path(), "b");
        // Plant a non-cert file in the same dir.
        std::fs::write(d.path().join("note.txt"), "hello").unwrap();

        let mut emitted = Vec::new();
        let stats = host_scan(&[d.path().to_path_buf()], |ev| emitted.push(ev)).unwrap();
        assert_eq!(stats.roots_walked, 1);
        assert_eq!(stats.files_inspected, 2);
        assert_eq!(stats.certs_parsed, 2);
        assert_eq!(stats.events_emitted, 2);
        assert_eq!(emitted.len(), 2);
        for ev in emitted {
            assert_eq!(ev.asset.kind, ree0xq_core::AssetKind::X509Cert);
            assert!(ev.asset.identity.starts_with("sha256:"));
        }
    }

    #[test]
    fn nonexistent_root_does_not_error() {
        let stats =
            host_scan(&[PathBuf::from("/tmp/ree0xq-does-not-exist-xyzzy")], |_| {}).unwrap();
        assert_eq!(stats.roots_walked, 1);
        assert_eq!(stats.events_emitted, 0);
    }

    #[test]
    fn malformed_pem_file_skipped_not_panic() {
        let d = tempdir().unwrap();
        std::fs::write(d.path().join("broken.pem"), "garbage").unwrap();
        let stats = host_scan(&[d.path().to_path_buf()], |_| {}).unwrap();
        assert_eq!(stats.files_inspected, 1);
        assert_eq!(stats.certs_parsed, 0);
        assert_eq!(stats.events_emitted, 0);
        assert_eq!(stats.files_skipped_no_certs, 1);
    }
}
