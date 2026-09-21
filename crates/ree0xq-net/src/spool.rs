//! Disk-backed spool for events that couldn't reach the
//! collector (SEZ-6 fourth acceptance criterion).
//!
//! Failure model: a `ree0xq-net` agent runs with `--collector
//! <url>` and POSTs events. When the collector is unreachable,
//! the event would normally be dropped on the floor and logged.
//! With a configured `--spool-dir`, the agent instead appends
//! the JSON-serialized event to an on-disk NDJSON file. The
//! next agent run drains the spool before processing fresh
//! events.
//!
//! Concurrency: single-writer. Two `ree0xq-net` processes
//! pointed at the same spool dir is undefined behaviour (no
//! lockfile in V1). One agent per host is the V1 deployment
//! shape; SEZ-2's Postgres swap will give us a real
//! reservation model for the V2 multi-agent case.
//!
//! Corruption: drain is tolerant. Lines that don't parse as
//! `CryptoInventoryEvent` are counted, logged, and dropped —
//! the surviving valid lines still get retried.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ree0xq_core::CryptoInventoryEvent;
use tracing::{debug, warn};

const SPOOL_FILE: &str = "ree0xq-net.spool.ndjson";

/// Disk-backed NDJSON event spool.
pub struct Spool {
    /// Directory holding the spool file. Owned by the spool —
    /// the caller decides where it lives, the spool decides
    /// what's inside.
    dir: PathBuf,
}

/// Statistics from one [`Spool::drain`] pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct DrainStats {
    /// Lines read from the spool.
    pub seen: usize,
    /// Lines successfully re-delivered (the callback returned `Ok`).
    pub delivered: usize,
    /// Lines the callback rejected — these are retained for the
    /// next drain pass.
    pub retained: usize,
    /// Lines that didn't deserialize as `CryptoInventoryEvent`;
    /// dropped from the spool because retrying them will never
    /// help.
    pub corrupt_dropped: usize,
}

impl Spool {
    /// Open or create a spool under `dir`. The directory is
    /// created if it doesn't exist.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create spool dir {}", dir.display()))?;
        Ok(Self { dir })
    }

    fn file_path(&self) -> PathBuf {
        self.dir.join(SPOOL_FILE)
    }

    /// Append one event to the spool. Survives a process crash:
    /// each call performs an `fsync` so the entry is on disk
    /// before we return.
    pub fn append(&self, ev: &CryptoInventoryEvent) -> Result<()> {
        let line = serde_json::to_string(ev).context("serialize event for spool")?;
        let path = self.file_path();
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("open spool {}", path.display()))?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        debug!(path = %path.display(), "appended event to spool");
        Ok(())
    }

    /// Number of lines currently in the spool. Returns 0 when
    /// the file doesn't exist.
    pub fn len(&self) -> Result<usize> {
        let path = self.file_path();
        if !path.exists() {
            return Ok(0);
        }
        let f = File::open(&path)?;
        Ok(BufReader::new(f).lines().count())
    }

    /// `true` when the spool holds no lines (or doesn't exist).
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Drain the spool: for each NDJSON line in order, call
    /// `emit`. Lines for which `emit` returned `Ok` are dropped
    /// from the spool; lines for which it returned `Err` are
    /// retained for the next call. Corrupt lines (failed JSON
    /// parse) are counted and dropped — they will never become
    /// re-deliverable.
    ///
    /// The retention path uses an atomic-rename: surviving
    /// lines are written to a sibling temp file and then
    /// `rename(2)`d over the original so a crash mid-drain
    /// can't lose events (worst case, a few lines get retried
    /// next pass — at-least-once delivery, idempotent on the
    /// collector side via the event identity hash).
    pub fn drain<F>(&self, mut emit: F) -> Result<DrainStats>
    where
        F: FnMut(&CryptoInventoryEvent) -> Result<()>,
    {
        let path = self.file_path();
        if !path.exists() {
            return Ok(DrainStats::default());
        }

        let input = File::open(&path).with_context(|| format!("open spool {}", path.display()))?;
        let reader = BufReader::new(input);

        let tmp_path = path.with_extension("draining");
        let tmp = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .with_context(|| format!("create drain tmp {}", tmp_path.display()))?;
        let mut tmp_w = BufWriter::new(tmp);

        let mut stats = DrainStats::default();
        for (idx, line) in reader.lines().enumerate() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    warn!(error = %e, line = idx + 1, "spool read error; halting drain");
                    break;
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            stats.seen += 1;
            let ev: CryptoInventoryEvent = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(e) => {
                    warn!(error = %e, line = idx + 1, "spool line is not valid event JSON; dropping");
                    stats.corrupt_dropped += 1;
                    continue;
                }
            };
            match emit(&ev) {
                Ok(()) => {
                    stats.delivered += 1;
                }
                Err(e) => {
                    debug!(error = %e, "spool entry retained for next drain");
                    stats.retained += 1;
                    // Re-serialize from the parsed event so the
                    // canonical form persists (defends against
                    // upstream whitespace / field-order drift).
                    let line = serde_json::to_string(&ev)?;
                    tmp_w.write_all(line.as_bytes())?;
                    tmp_w.write_all(b"\n")?;
                }
            }
        }
        tmp_w.flush()?;
        tmp_w.into_inner()?.sync_all()?;

        if stats.retained == 0 {
            // Nothing left — remove both the tmp and the
            // original so the next append starts fresh.
            std::fs::remove_file(&tmp_path).ok();
            std::fs::remove_file(&path).ok();
        } else {
            // Atomically replace the spool with the retained
            // lines.
            std::fs::rename(&tmp_path, &path)
                .with_context(|| format!("rename {} -> {}", tmp_path.display(), path.display()))?;
        }
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ree0xq_core::{
        Asset, AssetKind, Posture, Primitive, PrimitiveRole, SCHEMA_MINOR, SCHEMA_VERSION,
    };
    use tempfile::tempdir;

    fn fixture(identity: &str) -> CryptoInventoryEvent {
        CryptoInventoryEvent {
            schema_version: SCHEMA_VERSION,
            schema_minor: SCHEMA_MINOR,
            source_module: "spool-test".into(),
            observed_at: chrono::Utc::now(),
            asset: Asset {
                kind: AssetKind::TlsSession,
                identity: identity.into(),
                host: Some("test".into()),
            },
            primitives: vec![Primitive {
                role: PrimitiveRole::Kex,
                algorithm: "X25519MLKEM768".into(),
                parameters: Default::default(),
                pq_resistant: Some(true),
                nist_classification: None,
            }],
            channel_protection: None,
            agility: None,
            posture: Posture {
                score: 0,
                rationale: "test".into(),
                recommended_replacement: None,
            },
        }
    }

    #[test]
    fn empty_dir_len_is_zero() {
        let d = tempdir().unwrap();
        let s = Spool::open(d.path()).unwrap();
        assert_eq!(s.len().unwrap(), 0);
    }

    #[test]
    fn append_then_drain_delivers_in_order_and_clears() {
        let d = tempdir().unwrap();
        let s = Spool::open(d.path()).unwrap();
        s.append(&fixture("a")).unwrap();
        s.append(&fixture("b")).unwrap();
        s.append(&fixture("c")).unwrap();
        assert_eq!(s.len().unwrap(), 3);

        let mut delivered = Vec::new();
        let stats = s
            .drain(|ev| {
                delivered.push(ev.asset.identity.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(stats.seen, 3);
        assert_eq!(stats.delivered, 3);
        assert_eq!(stats.retained, 0);
        assert_eq!(stats.corrupt_dropped, 0);
        assert_eq!(delivered, vec!["a", "b", "c"]);
        // Spool is now empty.
        assert_eq!(s.len().unwrap(), 0);
    }

    #[test]
    fn drain_retains_failing_lines() {
        let d = tempdir().unwrap();
        let s = Spool::open(d.path()).unwrap();
        s.append(&fixture("a")).unwrap();
        s.append(&fixture("b")).unwrap();
        s.append(&fixture("c")).unwrap();

        // Fail on identity "b".
        let stats = s
            .drain(|ev| {
                if ev.asset.identity == "b" {
                    Err(anyhow::anyhow!("simulated transport failure"))
                } else {
                    Ok(())
                }
            })
            .unwrap();
        assert_eq!(stats.seen, 3);
        assert_eq!(stats.delivered, 2);
        assert_eq!(stats.retained, 1);
        assert_eq!(s.len().unwrap(), 1);

        // Next drain redelivers the retained entry.
        let mut delivered = Vec::new();
        let stats = s
            .drain(|ev| {
                delivered.push(ev.asset.identity.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(stats.delivered, 1);
        assert_eq!(delivered, vec!["b"]);
        assert_eq!(s.len().unwrap(), 0);
    }

    #[test]
    fn corrupt_line_is_dropped_not_retained() {
        let d = tempdir().unwrap();
        let s = Spool::open(d.path()).unwrap();
        s.append(&fixture("a")).unwrap();
        // Inject a garbage line directly.
        std::fs::OpenOptions::new()
            .append(true)
            .open(d.path().join("ree0xq-net.spool.ndjson"))
            .unwrap()
            .write_all(b"this is not json\n")
            .unwrap();
        s.append(&fixture("b")).unwrap();

        let mut delivered = Vec::new();
        let stats = s
            .drain(|ev| {
                delivered.push(ev.asset.identity.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(stats.delivered, 2);
        assert_eq!(stats.corrupt_dropped, 1);
        assert_eq!(stats.retained, 0);
        assert_eq!(delivered, vec!["a", "b"]);
    }
}
