//! `ree0xq-agility` — CLI entry point.
//!
//! Subcommands:
//!
//! - `scan` — V1 static crypto-agility scanner (5-level
//!   `AgilityBlock` over source / installed-package
//!   layouts). The original ree0xq-agility surface; backs
//!   Study 3 of the paper.
//! - `recommend` (V5.0) — per-asset PQ replacement
//!   recommendations from a `/v1/inventory` snapshot.
//! - `roadmap` (V5.1) — org_q trajectory projection
//!   under a migration plan.
//! - `compat` (V5.2) — TLS-stack ↔ PQ-algo support matrix.
//! - `deadlines` (V5.3) — regulator PQ-mandate dates.

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use ree0xq_agility::compat::{self, SupportStatus};
use ree0xq_agility::deadlines;
use ree0xq_agility::recommend;
use ree0xq_agility::roadmap::{self, AssetSnapshot, Milestone};
use ree0xq_agility::rules::load_ruleset;
use ree0xq_agility::scanner::{scan_target, ScanTarget};
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "ree0xq-agility", author, version, about)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Scan a target directory and emit the agility block as JSON.
    Scan {
        /// Path to the target (source repo or installed package root).
        #[arg(long)]
        target: PathBuf,
        /// Path to the ruleset directory (e.g. `rules/v1`).
        #[arg(long)]
        rules: PathBuf,
        /// Maximum file size to scan (bytes).
        #[arg(long, default_value_t = 5 * 1024 * 1024)]
        max_file_bytes: u64,
        /// Maximum lines per file to scan.
        #[arg(long, default_value_t = 50_000)]
        max_lines: usize,
    },
    /// V5.0 — per-asset PQ replacement recommendations.
    Recommend {
        /// Inventory source — `http://...` URL pointing at
        /// `/v1/inventory`, or a local file containing the
        /// same JSON body.
        #[arg(long)]
        inventory: String,
        /// Restrict to one asset kind (`tls_session`,
        /// `x509_cert`, `hsm_slot`, `blockchain_key`, …).
        #[arg(long)]
        filter_kind: Option<String>,
    },
    /// V5.1 — project org_q trajectory under a migration plan.
    Roadmap {
        /// Inventory source (URL or file).
        #[arg(long)]
        inventory: String,
        /// Plan JSON file:
        /// `[{ "label": "Q1", "date": "2027-01-01T00:00:00Z",
        ///     "asset_ids": [...], "target_primitives": [...] }]`.
        #[arg(long)]
        plan: String,
    },
    /// V5.2 — TLS-stack ↔ PQ-algorithm compatibility lookup.
    Compat {
        /// Stack name (e.g. `openssl-3.x`, `boringssl`,
        /// `rustls-post-quantum`, `bouncycastle`, `nss`,
        /// `go-crypto-tls`).
        #[arg(long)]
        stack: String,
        /// Specific algorithm to query; when omitted the
        /// CLI lists every algo entry for the stack.
        #[arg(long)]
        algo: Option<String>,
    },
    /// V5.3 — regulator PQ-mandate deadline tracker.
    Deadlines {
        /// Jurisdiction prefix filter (e.g. `US`, `EU`,
        /// `US-NIST`). Case-insensitive.
        #[arg(long)]
        jurisdiction: Option<String>,
        /// Only show deadlines within this horizon (days
        /// from today). Omit to print every deadline in
        /// the table.
        #[arg(long)]
        horizon_days: Option<i64>,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    match args.cmd {
        Cmd::Scan {
            target,
            rules,
            max_file_bytes,
            max_lines,
        } => {
            let compiled = load_ruleset(&rules)?;
            let st = ScanTarget {
                root: target,
                max_file_bytes,
                max_lines,
            };
            let block = scan_target(&st, &compiled);
            println!("{}", serde_json::to_string_pretty(&block)?);
        }
        Cmd::Recommend {
            inventory,
            filter_kind,
        } => run_recommend(&inventory, filter_kind.as_deref())?,
        Cmd::Roadmap { inventory, plan } => run_roadmap(&inventory, &plan)?,
        Cmd::Compat { stack, algo } => run_compat(&stack, algo.as_deref()),
        Cmd::Deadlines {
            jurisdiction,
            horizon_days,
        } => run_deadlines(jurisdiction.as_deref(), horizon_days),
    }
    Ok(())
}

// ----- V5 subcommand handlers -----

/// Shape the `/v1/inventory` endpoint returns.
#[derive(Debug, Deserialize)]
struct InventoryResponse {
    items: Vec<InventoryItem>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct InventoryItem {
    source_module: String,
    asset_kind: String,
    identity: String,
    #[serde(default)]
    host: Option<String>,
    q: f32,
    blocked: bool,
    primitives: Vec<String>,
    observed_at: String,
}

fn fetch_inventory(source: &str) -> anyhow::Result<Vec<InventoryItem>> {
    let raw = if source.starts_with("http://") || source.starts_with("https://") {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?
            .get(source)
            .send()?
            .text()?
    } else {
        std::fs::read_to_string(source).with_context(|| format!("read {source}"))?
    };
    let parsed: InventoryResponse =
        serde_json::from_str(&raw).context("parse /v1/inventory body")?;
    Ok(parsed.items)
}

fn run_recommend(source: &str, filter_kind: Option<&str>) -> anyhow::Result<()> {
    use ree0xq_core::Primitive;
    let items = fetch_inventory(source)?;
    for item in items {
        if let Some(k) = filter_kind {
            if item.asset_kind != k {
                continue;
            }
        }
        // The inventory item carries primitives as just
        // names; rebuild thin `Primitive` records so the
        // recommender's role-based dispatch works. We tag
        // each as `Sig` or `Encrypt` based on a small
        // heuristic that catches the canonical cases.
        let prims: Vec<Primitive> = item
            .primitives
            .iter()
            .map(|name| Primitive {
                role: classify_role(name),
                algorithm: name.clone(),
                parameters: Default::default(),
                pq_resistant: None,
                nist_classification: None,
            })
            .collect();
        let recs = recommend::recommend_for(&prims);
        if recs.is_empty() {
            continue;
        }
        let body = serde_json::json!({
            "asset": {
                "identity": item.identity,
                "kind": item.asset_kind,
                "host": item.host,
                "current_q": item.q,
                "blocked": item.blocked,
            },
            "primitives": item.primitives,
            "recommendations": recs,
        });
        println!("{}", serde_json::to_string(&body)?);
    }
    Ok(())
}

fn classify_role(algorithm: &str) -> ree0xq_core::PrimitiveRole {
    use ree0xq_core::PrimitiveRole;
    let upper = algorithm.to_ascii_uppercase();
    if upper.contains("AES")
        || upper.contains("CHACHA")
        || upper.contains("DES")
        || upper.contains("RC4")
    {
        return PrimitiveRole::Encrypt;
    }
    if upper.starts_with("SHA")
        || upper.starts_with("KECCAK")
        || upper.starts_with("MD5")
        || upper.starts_with("HMAC")
    {
        return PrimitiveRole::Hash;
    }
    if upper.contains("X25519")
        || upper.contains("ML-KEM")
        || upper.contains("MLKEM")
        || upper.contains("ECDH")
        || upper.contains("DH-")
    {
        return PrimitiveRole::Kex;
    }
    // Default: signature surface (covers RSA-PKCS1, ECDSA,
    // Ed25519, ML-DSA, Schnorr, XMSS, …).
    PrimitiveRole::Sig
}

fn run_roadmap(source: &str, plan_path: &str) -> anyhow::Result<()> {
    let items = fetch_inventory(source)?;
    let snapshots: Vec<AssetSnapshot> = items
        .into_iter()
        .map(|it| AssetSnapshot {
            identity: it.identity,
            q: it.q,
            blocked: it.blocked,
            primitives: it.primitives,
        })
        .collect();
    let plan_raw =
        std::fs::read_to_string(plan_path).with_context(|| format!("read {plan_path}"))?;
    let plan: Vec<Milestone> = serde_json::from_str(&plan_raw).context("parse plan")?;
    let projection = roadmap::project_roadmap(&snapshots, &plan)?;
    println!("{}", serde_json::to_string_pretty(&projection)?);
    Ok(())
}

fn run_compat(stack: &str, algo: Option<&str>) {
    if let Some(a) = algo {
        let status = compat::stack_supports(stack, a);
        if let Some(entry) = compat::lookup(stack, a) {
            let body = serde_json::json!({
                "stack": entry.stack,
                "algorithm": entry.algorithm,
                "status": entry.status,
                "min_version": entry.min_version,
                "source": entry.source,
            });
            println!("{}", serde_json::to_string_pretty(&body).unwrap());
        } else {
            // Unknown — still print the status verdict.
            let body = serde_json::json!({
                "stack": stack,
                "algorithm": a,
                "status": status,
            });
            println!("{}", serde_json::to_string_pretty(&body).unwrap());
        }
    } else {
        let entries = compat::list_stack(stack);
        let body = serde_json::json!({
            "stack": stack,
            "entries": entries,
        });
        println!("{}", serde_json::to_string_pretty(&body).unwrap());
    }
}

fn run_deadlines(jurisdiction: Option<&str>, horizon_days: Option<i64>) {
    let now = chrono::Utc::now();
    let mut entries = match jurisdiction {
        Some(j) => deadlines::for_jurisdiction(j),
        None => deadlines::all(),
    };
    if let Some(d) = horizon_days {
        let end = now + chrono::Duration::days(d);
        entries.retain(|e| e.effective_date >= now && e.effective_date <= end);
    }
    let body = serde_json::json!({
        "now": now,
        "horizon_days": horizon_days,
        "jurisdiction_filter": jurisdiction,
        "deadlines": entries,
    });
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
}

// Silence the unused-import lint for binaries that never
// reach the `SupportStatus` branch (clippy throws a
// false-positive on the `use` line otherwise).
#[allow(dead_code)]
fn _unused_status(_: SupportStatus) {}
