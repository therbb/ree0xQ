//! Certificate Transparency log scanner.
//!
//! Pulls every cert ever issued for a given domain out of a
//! public CT log and emits one
//! `crypto_inventory_event` per discovered cert. The first
//! V2.1 backend is [`CrtShBackend`] (crt.sh JSON API); the
//! trait is intentionally narrow so a future Google Argon or
//! Let's Encrypt Oak backend can drop in without touching the
//! scanner loop.
//!
//! ## Why two HTTP calls per cert
//!
//! crt.sh's JSON list endpoint returns metadata only (issuer,
//! CN, SANs, dates, plus a stable per-cert id). To parse a
//! cert into the same shape the host-scan and vault-scan
//! paths produce, we need the DER bytes — that's
//! `https://crt.sh/?d=<id>` (returns a PEM blob). Two HTTP
//! calls per new cert is fine at the scales we care about
//! (~hundreds to a few thousand certs per domain over the
//! lifetime); the per-run cursor avoids re-fetching anything
//! we've already seen.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::cert::{event_from_cert, parse_pem_bundle};

/// Default polite poll cap. crt.sh asks integrators in their
/// FAQ to "not hammer the database"; one request per second is
/// well within that and still finishes a 500-cert domain in
/// under 20 minutes including the per-cert PEM fetches.
pub const DEFAULT_RATE_DELAY_MS: u64 = 1_000;

/// Per-domain entry from the JSON list endpoint. crt.sh
/// returns several other fields (entry_timestamp,
/// serial_number, name_value, etc.); we keep only what the
/// scanner needs.
#[derive(Debug, Clone, Deserialize)]
pub struct CtListEntry {
    /// Stable per-cert identifier in crt.sh's database. The
    /// scanner's cursor records the highest `id` seen for each
    /// domain.
    pub id: u64,
    /// Common Name from the certificate, when present.
    #[serde(default)]
    pub common_name: Option<String>,
}

/// CT-log backend trait. Implement to add a non-crt.sh source.
pub trait CtBackend {
    /// List every cert known for `domain`, in crt.sh ordering
    /// (latest first; the scanner re-sorts by id ascending so
    /// the cursor advance is monotone).
    fn list(&self, domain: &str) -> Result<Vec<CtListEntry>>;

    /// Fetch the PEM bytes for one cert by `id`. The returned
    /// bytes are a single `CERTIFICATE` block.
    fn fetch_pem(&self, id: u64) -> Result<Vec<u8>>;

    /// Human-readable backend label for log lines.
    fn backend_label(&self) -> &'static str;
}

/// crt.sh JSON-API backend. Uses a blocking reqwest client so
/// it can sit alongside the host-scan path without dragging
/// the whole binary onto an async runtime.
pub struct CrtShBackend {
    client: reqwest::blocking::Client,
}

impl Default for CrtShBackend {
    fn default() -> Self {
        Self::new().expect("crt.sh client build")
    }
}

impl CrtShBackend {
    pub fn new() -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("ree0xq-cert/0.1 (+https://github.com/e2esolutions-tech/ree0xQ)")
            .build()
            .map_err(|e| anyhow!("crt.sh client build: {e}"))?;
        Ok(Self { client })
    }
}

impl CtBackend for CrtShBackend {
    fn list(&self, domain: &str) -> Result<Vec<CtListEntry>> {
        // The `%25.<domain>` (URL-encoded `%.<domain>`) is the
        // crt.sh convention for "any cert whose name field
        // matches a SQL LIKE on `%.domain`" — equivalent to
        // wildcard. Plain `q=<domain>` would miss subdomain
        // certs.
        let url = format!("https://crt.sh/?q=%25.{domain}&output=json");
        debug!(url = %url, "crt.sh list");
        let r = self
            .client
            .get(&url)
            .send()
            .map_err(|e| anyhow!("crt.sh list: {e}"))?;
        if !r.status().is_success() {
            return Err(anyhow!("crt.sh list returned {}", r.status()));
        }
        let entries: Vec<CtListEntry> = r.json().map_err(|e| anyhow!("crt.sh list JSON: {e}"))?;
        Ok(entries)
    }

    fn fetch_pem(&self, id: u64) -> Result<Vec<u8>> {
        let url = format!("https://crt.sh/?d={id}");
        debug!(url = %url, id = id, "crt.sh fetch");
        let r = self
            .client
            .get(&url)
            .send()
            .map_err(|e| anyhow!("crt.sh fetch id={id}: {e}"))?;
        if !r.status().is_success() {
            return Err(anyhow!("crt.sh fetch id={id} returned {}", r.status()));
        }
        Ok(r.bytes()
            .map_err(|e| anyhow!("crt.sh fetch body: {e}"))?
            .to_vec())
    }

    fn backend_label(&self) -> &'static str {
        "crt.sh"
    }
}

/// Caller-supplied configuration for [`ct_scan`].
#[derive(Debug, Clone)]
pub struct CtScanConfig {
    /// Domains to scan; the scanner does one [`CtBackend::list`]
    /// per domain.
    pub domains: Vec<String>,
    /// Optional cursor file. When present the scanner reads
    /// the per-domain `max_id_seen` map at start, only fetches
    /// entries with `id > max_id_seen`, and rewrites the file
    /// with the new high-water marks at end.
    pub cursor_path: Option<PathBuf>,
    /// Pause between per-cert HTTP fetches, in milliseconds.
    /// Defaults to [`DEFAULT_RATE_DELAY_MS`].
    pub rate_delay_ms: u64,
}

/// Statistics from one [`ct_scan`] pass.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CtScanStats {
    /// Domains processed.
    pub domains_scanned: usize,
    /// Entries returned from CT lists, across all domains.
    pub entries_listed: usize,
    /// Entries skipped because their id was already in the
    /// cursor.
    pub entries_below_cursor: usize,
    /// PEM fetches that returned a usable cert.
    pub certs_fetched: usize,
    /// Fetches that failed (HTTP error, parse error).
    pub fetch_failures: usize,
    /// Events emitted to the caller's sink.
    pub events_emitted: usize,
}

/// Per-domain cursor: highest `id` we've already seen and
/// shipped an event for.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Cursor {
    seen: HashMap<String, u64>,
}

impl Cursor {
    fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw =
            fs::read_to_string(path).with_context(|| format!("read cursor {}", path.display()))?;
        if raw.trim().is_empty() {
            return Ok(Self::default());
        }
        serde_json::from_str(&raw).with_context(|| format!("parse cursor {}", path.display()))
    }

    fn save(&self, path: &Path) -> Result<()> {
        let dir = path.parent().unwrap_or(Path::new("."));
        fs::create_dir_all(dir).ok();
        let raw = serde_json::to_string_pretty(self)?;
        fs::write(path, raw).with_context(|| format!("write cursor {}", path.display()))
    }
}

/// Run a CT scan across `cfg.domains` using `backend`, calling
/// `on_event` for every newly-discovered cert. Returns the
/// per-run statistics; the cursor file (if configured) has
/// already been rewritten when this function returns.
pub fn ct_scan<B: CtBackend, F>(
    cfg: &CtScanConfig,
    backend: &B,
    mut on_event: F,
) -> Result<CtScanStats>
where
    F: FnMut(ree0xq_core::CryptoInventoryEvent),
{
    let mut cursor = cfg
        .cursor_path
        .as_deref()
        .map(Cursor::load)
        .transpose()?
        .unwrap_or_default();

    let mut stats = CtScanStats::default();
    let delay = Duration::from_millis(cfg.rate_delay_ms);

    for domain in &cfg.domains {
        stats.domains_scanned += 1;
        info!(domain = %domain, backend = backend.backend_label(), "CT list");
        let mut entries = match backend.list(domain) {
            Ok(e) => e,
            Err(e) => {
                warn!(domain = %domain, error = %e, "CT list failed; skipping domain");
                continue;
            }
        };
        // Sort ascending so cursor advances monotonically; the
        // crt.sh response order is "latest first" which would
        // walk the cursor backwards.
        entries.sort_by_key(|e| e.id);
        stats.entries_listed += entries.len();

        let prev_max = cursor.seen.get(domain).copied().unwrap_or(0);
        let mut new_max = prev_max;

        for (idx, entry) in entries.iter().enumerate() {
            if entry.id <= prev_max {
                stats.entries_below_cursor += 1;
                continue;
            }
            // Rate cap: skip the sleep for the first request
            // of the run, otherwise hold to `rate_delay_ms`
            // between fetches.
            if idx > 0 {
                std::thread::sleep(delay);
            }
            match backend.fetch_pem(entry.id) {
                Ok(pem) => {
                    let parsed = match parse_pem_bundle(&pem, None) {
                        Ok(v) if !v.is_empty() => v,
                        Ok(_) => {
                            warn!(id = entry.id, "CT fetch returned no CERTIFICATE block");
                            stats.fetch_failures += 1;
                            continue;
                        }
                        Err(e) => {
                            warn!(id = entry.id, error = %e, "CT PEM parse failed");
                            stats.fetch_failures += 1;
                            continue;
                        }
                    };
                    stats.certs_fetched += 1;
                    for cert in &parsed {
                        match event_from_cert(cert) {
                            Ok(mut ev) => {
                                // Decorate with the queried
                                // domain so the dashboard can
                                // group certs by the org
                                // that owns them, even when
                                // the cert's own SAN list is
                                // wildcards.
                                if ev.asset.host.is_none() {
                                    ev.asset.host = Some(domain.clone());
                                }
                                stats.events_emitted += 1;
                                on_event(ev);
                            }
                            Err(e) => warn!(id = entry.id, error = %e, "event_from_cert"),
                        }
                    }
                    new_max = new_max.max(entry.id);
                }
                Err(e) => {
                    warn!(id = entry.id, error = %e, "CT fetch failed");
                    stats.fetch_failures += 1;
                }
            }
        }
        cursor.seen.insert(domain.clone(), new_max);
    }

    if let Some(path) = cfg.cursor_path.as_deref() {
        cursor.save(path)?;
        info!(path = %path.display(), "cursor saved");
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use tempfile::tempdir;

    /// Hardcoded fixture mimicking a crt.sh response.
    /// Cropped to the fields the deserialiser actually
    /// consumes; we don't pretend to replay everything.
    const SAMPLE_LIST_JSON: &str = r#"[
        {"id": 100, "common_name": "*.example.com"},
        {"id": 101, "common_name": "www.example.com"},
        {"id": 102, "common_name": "api.example.com"}
    ]"#;

    fn fixture_cert_pem(cn: &str) -> Vec<u8> {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
        let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec![cn.to_string()]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        params.self_signed(&kp).unwrap().pem().into_bytes()
    }

    /// In-memory fake CT backend. Records every fetch_pem id
    /// it was asked for so we can assert cursor behaviour.
    struct FakeBackend {
        entries: Vec<CtListEntry>,
        fetched: RefCell<Vec<u64>>,
    }

    impl FakeBackend {
        fn from_json(json: &str) -> Self {
            Self {
                entries: serde_json::from_str(json).unwrap(),
                fetched: RefCell::new(Vec::new()),
            }
        }
    }

    impl CtBackend for FakeBackend {
        fn list(&self, _: &str) -> Result<Vec<CtListEntry>> {
            Ok(self.entries.clone())
        }
        fn fetch_pem(&self, id: u64) -> Result<Vec<u8>> {
            self.fetched.borrow_mut().push(id);
            Ok(fixture_cert_pem(&format!("ct-{id}.example.com")))
        }
        fn backend_label(&self) -> &'static str {
            "fake"
        }
    }

    #[test]
    fn list_response_deserialises() {
        let parsed: Vec<CtListEntry> = serde_json::from_str(SAMPLE_LIST_JSON).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].id, 100);
        assert_eq!(parsed[2].common_name.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn fresh_run_emits_every_entry_and_advances_cursor() {
        let d = tempdir().unwrap();
        let cursor_path = d.path().join("cursor.json");
        let backend = FakeBackend::from_json(SAMPLE_LIST_JSON);
        let cfg = CtScanConfig {
            domains: vec!["example.com".into()],
            cursor_path: Some(cursor_path.clone()),
            rate_delay_ms: 0,
        };
        let mut emitted = Vec::new();
        let stats = ct_scan(&cfg, &backend, |ev| emitted.push(ev.asset.identity.clone())).unwrap();

        assert_eq!(stats.domains_scanned, 1);
        assert_eq!(stats.entries_listed, 3);
        assert_eq!(stats.entries_below_cursor, 0);
        assert_eq!(stats.certs_fetched, 3);
        assert_eq!(stats.events_emitted, 3);
        assert_eq!(emitted.len(), 3);

        // Cursor file persisted with high-water mark 102.
        let cursor = Cursor::load(&cursor_path).unwrap();
        assert_eq!(cursor.seen.get("example.com").copied(), Some(102));
    }

    #[test]
    fn second_run_only_fetches_entries_above_cursor() {
        let d = tempdir().unwrap();
        let cursor_path = d.path().join("cursor.json");

        // Pre-seed the cursor at id=101 — we should only fetch
        // 102 on the next run.
        let mut seen = HashMap::new();
        seen.insert("example.com".into(), 101u64);
        Cursor { seen }.save(&cursor_path).unwrap();

        let backend = FakeBackend::from_json(SAMPLE_LIST_JSON);
        let cfg = CtScanConfig {
            domains: vec!["example.com".into()],
            cursor_path: Some(cursor_path.clone()),
            rate_delay_ms: 0,
        };
        let stats = ct_scan(&cfg, &backend, |_| {}).unwrap();
        assert_eq!(stats.entries_listed, 3);
        assert_eq!(
            stats.entries_below_cursor, 2,
            "ids 100 and 101 already seen"
        );
        assert_eq!(stats.certs_fetched, 1);
        assert_eq!(stats.events_emitted, 1);

        let cursor = Cursor::load(&cursor_path).unwrap();
        assert_eq!(cursor.seen.get("example.com").copied(), Some(102));
    }

    #[test]
    fn empty_domain_list_is_noop() {
        let backend = FakeBackend::from_json("[]");
        let cfg = CtScanConfig {
            domains: vec![],
            cursor_path: None,
            rate_delay_ms: 0,
        };
        let stats = ct_scan(&cfg, &backend, |_| {}).unwrap();
        assert_eq!(stats.domains_scanned, 0);
        assert_eq!(stats.events_emitted, 0);
    }
}
