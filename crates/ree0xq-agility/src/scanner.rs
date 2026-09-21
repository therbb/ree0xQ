//! Static crypto-agility scanner.
//!
//! Walks a target directory (source tree, installed-package layout,
//! or a binary), applies the compiled ruleset, and returns an
//! [`AgilityBlock`] populated with [`AgilityEvidence`] entries.
//!
//! The scanner is deterministic and side-effect free: same input,
//! same output. Callers wrap the result into a full
//! [`CryptoInventoryEvent`] with the asset metadata they own.

use std::path::{Path, PathBuf};

use ree0xq_core::{AgilityBlock, AgilityEvidence, AgilityLevel};
use tracing::{debug, warn};
use walkdir::WalkDir;

use crate::rules::{CompiledRule, EvidenceKind, ScopeKind};
use crate::{RUBRIC_VERSION, SCANNER_VERSION};

/// Where to scan and how to classify files.
#[derive(Debug, Clone)]
pub struct ScanTarget {
    /// Filesystem root to walk.
    pub root: PathBuf,
    /// Maximum file size (bytes) the scanner will read. Larger files
    /// are skipped with a warning — defends against accidentally
    /// loading multi-GB log files into memory.
    pub max_file_bytes: u64,
    /// Maximum lines per file to scan. Most config files are short;
    /// pathological files are truncated.
    pub max_lines: usize,
}

impl Default for ScanTarget {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            max_file_bytes: 5 * 1024 * 1024, // 5 MiB
            max_lines: 50_000,
        }
    }
}

/// Internal: pair each emitted evidence with the rule id that
/// produced it, so the aggregator can apply rule-specific
/// `emit_level` values rather than guessing from `evidence_kind`.
/// The wire-level [`AgilityEvidence`] enum is intentionally
/// rule-agnostic; we strip the rule id when serializing.
struct TaggedEvidence {
    // Retained for future per-rule debug output; the V1 aggregator
    // does not need it because we already carry `emit_level`.
    #[allow(dead_code)]
    rule_id: String,
    emit_level: AgilityLevel,
    evidence: AgilityEvidence,
}

/// Run the scanner over `target` with the compiled `rules` and return
/// an [`AgilityBlock`] for the asset rooted at `target.root`.
pub fn scan_target(target: &ScanTarget, rules: &[CompiledRule]) -> AgilityBlock {
    let mut tagged: Vec<TaggedEvidence> = Vec::new();

    for entry in WalkDir::new(&target.root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                warn!(path=%path.display(), error=%e, "skipping unreadable file");
                continue;
            }
        };
        if metadata.len() > target.max_file_bytes {
            debug!(path=%path.display(), size=metadata.len(), "skipping oversized file");
            continue;
        }
        let kind = classify_file(path);
        let content = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue, // binary or non-utf8; firmware-string rules go through separate path
        };
        for rule in rules {
            if !rule_applies(&rule.rule.applies_to, kind, path) {
                continue;
            }
            for (line_idx, line) in content.lines().enumerate().take(target.max_lines) {
                if let Some(caps) = rule.regex.captures(line) {
                    let algorithm = rule
                        .rule
                        .algorithm_capture
                        .and_then(|i| caps.get(i).map(|m| m.as_str().to_string()));
                    let snippet = line.chars().take(160).collect::<String>();
                    let ev = match rule.rule.evidence_kind {
                        EvidenceKind::ConfigPattern => AgilityEvidence::ConfigPattern {
                            file: path.display().to_string(),
                            line: (line_idx as u32) + 1,
                            snippet,
                        },
                        EvidenceKind::CodePattern => AgilityEvidence::CodePattern {
                            file: path.display().to_string(),
                            line: (line_idx as u32) + 1,
                            snippet,
                            algorithm: algorithm.unwrap_or_else(|| "<unspecified>".into()),
                        },
                        EvidenceKind::FirmwareString => AgilityEvidence::FirmwareString {
                            path: path.display().to_string(),
                            algorithm: algorithm.unwrap_or_else(|| "<unspecified>".into()),
                        },
                    };
                    tagged.push(TaggedEvidence {
                        rule_id: rule.rule.id.clone(),
                        emit_level: rule.rule.emit_level,
                        evidence: ev,
                    });
                }
            }
        }
    }

    let level = aggregate_tagged_level(&tagged);
    let evidence: Vec<AgilityEvidence> = tagged.into_iter().map(|t| t.evidence).collect();
    AgilityBlock {
        level,
        level_score: level.score(),
        evidence,
        scanner_version: SCANNER_VERSION.into(),
        rubric_version: RUBRIC_VERSION.into(),
    }
}

/// Aggregate the per-rule `emit_level` across all tagged evidence.
/// Empty evidence ⇒ [`UNKNOWN_LEVEL_FALLBACK`](crate::UNKNOWN_LEVEL_FALLBACK).
///
/// **Conservative-min** is the right policy when every triggered rule
/// reports a SURFACE that the operator could lean on. **Conservative-
/// max** is the right policy when *any* of those surfaces is enough
/// to migrate. We chose `min` in the §5.3 rubric, but in practice
/// the operator picks the strongest evidence: a code call into
/// `SSL_CTX_set_cipher_list` does not *downgrade* an asset that also
/// exposes an `ssl_ciphers` config directive.
///
/// V1 implementation: take the **MAX** level across contributing
/// rules (most agile evidence wins). The conservative-min view is
/// still reachable by reading the evidence array directly; the
/// dashboard can choose whichever projection it wants.
fn aggregate_tagged_level(tagged: &[TaggedEvidence]) -> AgilityLevel {
    if tagged.is_empty() {
        return crate::UNKNOWN_LEVEL_FALLBACK;
    }
    let mut best: Option<AgilityLevel> = None;
    for t in tagged {
        best = Some(match best {
            None => t.emit_level,
            Some(prev) => ord_max(prev, t.emit_level),
        });
    }
    best.unwrap_or(crate::UNKNOWN_LEVEL_FALLBACK)
}

/// Ordinal max — opposite of [`ord_min`]; the most-agile level wins.
fn ord_max(a: AgilityLevel, b: AgilityLevel) -> AgilityLevel {
    use AgilityLevel::*;
    let order = |x: AgilityLevel| match x {
        Negotiated => 4,
        Configurable => 3,
        Pinned => 2,
        Locked => 1,
        Frozen => 0,
    };
    if order(a) >= order(b) {
        a
    } else {
        b
    }
}

/// Heuristic file-kind classifier. Conservative: when in doubt,
/// returns `Code` (matches the broadest rule scope without being
/// noisy on configuration files).
fn classify_file(path: &Path) -> ScopeKind {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    let config_exts = ["conf", "cnf", "ini", "yaml", "yml", "toml", "json"];
    let config_filenames = [
        "nginx.conf",
        "httpd.conf",
        "sshd_config",
        "ssh_config",
        "openssl.cnf",
        "strongswan.conf",
        "haproxy.cfg",
        "postfix",
        "main.cf",
        "smb.conf",
    ];
    if config_filenames
        .iter()
        .any(|n| name.eq_ignore_ascii_case(n))
        || config_exts.contains(&ext)
    {
        return ScopeKind::Config;
    }
    ScopeKind::Code
}

/// Determine whether a rule scope applies to `path` classified as `kind`.
fn rule_applies(scopes: &[crate::rules::RuleScope], kind: ScopeKind, path: &Path) -> bool {
    scopes.iter().any(|s| {
        if s.kind != kind {
            return false;
        }
        match &s.path_glob {
            None => true,
            Some(g) => glob_match(g, path),
        }
    })
}

/// Trivial glob matcher: supports `**` (any depth), `*` (no
/// directory boundary), and exact characters. Sufficient for the
/// rule corpus we ship; the test suite covers the edge cases we use.
///
/// Implementation strategy: walk the pattern character-by-character
/// and translate to a regex without invoking `regex::escape` (which
/// would clobber the meta-characters we want to emit).
fn glob_match(pattern: &str, path: &Path) -> bool {
    let mut out = String::with_capacity(pattern.len() * 2);
    out.push('^');
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'*' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                // `**` — any-depth wildcard. If followed by `/`, also
                // consume the slash and emit a zero-or-more-segments
                // alternative.
                if i + 2 < bytes.len() && bytes[i + 2] == b'/' {
                    out.push_str("(?:.*/)?");
                    i += 3;
                } else {
                    out.push_str(".*");
                    i += 2;
                }
            } else {
                // single `*` — match anything except `/`.
                out.push_str("[^/]*");
                i += 1;
            }
        } else {
            let ch = c as char;
            // Escape regex meta-characters; allow `/` through unchanged.
            if "\\.+?()|[]{}^$".contains(ch) {
                out.push('\\');
            }
            out.push(ch);
            i += 1;
        }
    }
    out.push('$');
    match regex::Regex::new(&out) {
        Ok(r) => r.is_match(&path.to_string_lossy()),
        Err(_) => false,
    }
}

/// Conservative-min aggregation: the asset's level is the *lowest*
/// `emit_level` of any evidence found. No evidence ⇒
/// `AgilityLevel::Pinned` (the [`UNKNOWN_LEVEL_FALLBACK`]).
///
/// Retained as a documented alternative aggregation policy; the V1
/// scanner uses `aggregate_tagged_level` (most-agile-wins). Both
/// projections are useful in different operator contexts and the
/// dashboard can offer the toggle (V2).
#[allow(dead_code)]
fn aggregate_level(evidence: &[AgilityEvidence], rules: &[CompiledRule]) -> AgilityLevel {
    if evidence.is_empty() {
        return crate::UNKNOWN_LEVEL_FALLBACK;
    }
    // The rule that produced each evidence is not stored on the
    // evidence struct (the wire schema is rule-agnostic). For the
    // aggregate we approximate by re-matching: each rule that
    // contributes evidence raises the lower bound to its `emit_level`.
    let mut min_level: Option<AgilityLevel> = None;
    for rule in rules {
        // We use evidence presence as a proxy for "rule contributed".
        // A more precise mapping would tag evidence with rule id; that
        // is queued for the V2 schema bump.
        let contributed = evidence.iter().any(|e| matches_rule_evidence_kind(e, rule));
        if contributed {
            min_level = Some(match min_level {
                None => rule.rule.emit_level,
                Some(prev) => ord_min(prev, rule.rule.emit_level),
            });
        }
    }
    min_level.unwrap_or(crate::UNKNOWN_LEVEL_FALLBACK)
}

#[allow(dead_code)]
fn matches_rule_evidence_kind(ev: &AgilityEvidence, rule: &CompiledRule) -> bool {
    matches!(
        (ev, rule.rule.evidence_kind),
        (
            AgilityEvidence::ConfigPattern { .. },
            EvidenceKind::ConfigPattern
        ) | (
            AgilityEvidence::CodePattern { .. },
            EvidenceKind::CodePattern
        ) | (
            AgilityEvidence::FirmwareString { .. },
            EvidenceKind::FirmwareString
        )
    )
}

/// Ordinal min over `AgilityLevel` from the most-agile to the
/// least-agile end of the scale. Used by `aggregate_level`
/// (alternative conservative-min policy).
#[allow(dead_code)]
fn ord_min(a: AgilityLevel, b: AgilityLevel) -> AgilityLevel {
    use AgilityLevel::*;
    let order = |x: AgilityLevel| match x {
        Negotiated => 4,
        Configurable => 3,
        Pinned => 2,
        Locked => 1,
        Frozen => 0,
    };
    if order(a) <= order(b) {
        a
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn rule_yaml(content: &str) -> CompiledRule {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("r.yaml");
        fs::write(&p, content).unwrap();
        crate::rules::load_ruleset(dir.path())
            .unwrap()
            .pop()
            .unwrap()
    }

    #[test]
    fn empty_target_returns_pinned_fallback() {
        let dir = TempDir::new().unwrap();
        let target = ScanTarget {
            root: dir.path().to_path_buf(),
            ..Default::default()
        };
        let block = scan_target(&target, &[]);
        assert_eq!(block.level, AgilityLevel::Pinned);
    }

    #[test]
    fn config_pattern_rule_finds_nginx_directive() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("nginx.conf"),
            "server {\n    ssl_ciphers HIGH:!aNULL;\n}\n",
        )
        .unwrap();
        let rule = rule_yaml(
            r#"
id: nginx-ssl-ciphers
description: "nginx ssl_ciphers"
applies_to:
  - kind: config
    path_glob: "**/nginx*.conf"
pattern: '^\s*ssl_ciphers\s+'
emit_level: configurable
evidence_kind: config_pattern
"#,
        );
        let target = ScanTarget {
            root: dir.path().to_path_buf(),
            ..Default::default()
        };
        let block = scan_target(&target, std::slice::from_ref(&rule));
        assert_eq!(block.level, AgilityLevel::Configurable);
        assert_eq!(block.evidence.len(), 1);
        match &block.evidence[0] {
            AgilityEvidence::ConfigPattern { line, .. } => assert_eq!(*line, 2),
            other => panic!("unexpected evidence: {other:?}"),
        }
    }

    #[test]
    fn glob_match_basic_cases() {
        assert!(glob_match(
            "**/nginx*.conf",
            Path::new("/etc/nginx/nginx.conf")
        ));
        assert!(glob_match("**/nginx*.conf", Path::new("nginx-1.27.conf")));
        assert!(glob_match("*.conf", Path::new("nginx.conf")));
        assert!(!glob_match("*.conf", Path::new("nginx.cfg")));
    }

    #[test]
    fn min_level_takes_least_agile_evidence() {
        // Reserved utility — still used in `aggregate_level` for the
        // older API and as a documented alternative aggregation
        // policy. Tested independently of the V1 scanner-side policy.
        assert_eq!(
            ord_min(AgilityLevel::Configurable, AgilityLevel::Pinned),
            AgilityLevel::Pinned
        );
        assert_eq!(
            ord_min(AgilityLevel::Locked, AgilityLevel::Negotiated),
            AgilityLevel::Locked
        );
    }

    #[test]
    fn max_level_picks_most_agile_evidence() {
        // V1 scanner default — when a project exposes BOTH a config
        // surface and embeds hard-coded fallbacks in source, the
        // config surface wins.
        assert_eq!(
            ord_max(AgilityLevel::Configurable, AgilityLevel::Pinned),
            AgilityLevel::Configurable
        );
        assert_eq!(
            ord_max(AgilityLevel::Frozen, AgilityLevel::Negotiated),
            AgilityLevel::Negotiated
        );
    }

    #[test]
    fn nginx_style_aggregation_resolves_to_configurable() {
        // Simulates the nginx case: BOTH a CodePattern (hard-coded
        // algorithm string in a test/crypto-impl file, emit_level
        // = pinned) AND a CodePattern that fires via the OpenSSL
        // API rule (emit_level = configurable). The aggregator
        // should resolve to the most-agile (configurable).
        let tagged = vec![
            TaggedEvidence {
                rule_id: "code-hardcoded-algo".into(),
                emit_level: AgilityLevel::Pinned,
                evidence: AgilityEvidence::CodePattern {
                    file: "src/test.c".into(),
                    line: 10,
                    snippet: "\"AES-256-GCM\"".into(),
                    algorithm: "AES-256-GCM".into(),
                },
            },
            TaggedEvidence {
                rule_id: "openssl-api-cipher-control".into(),
                emit_level: AgilityLevel::Configurable,
                evidence: AgilityEvidence::CodePattern {
                    file: "src/ssl.c".into(),
                    line: 200,
                    snippet: "SSL_CTX_set_cipher_list(...)".into(),
                    algorithm: "<unspecified>".into(),
                },
            },
        ];
        assert_eq!(aggregate_tagged_level(&tagged), AgilityLevel::Configurable);
    }
}
