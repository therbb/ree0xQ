//! Rule loader and rule data model for the agility scanner.
//!
//! A *rule* is one regex + metadata describing the agility signal it
//! captures. Rules are loaded from YAML files under `rules/v1/` so
//! contributors don't have to recompile to add coverage. The bundled
//! rules cover nginx, Apache, OpenSSL config, OpenSSH, strongSwan,
//! Postfix, HAProxy, and a small set of binary-string heuristics.
//!
//! # Schema
//!
//! ```yaml
//! id: nginx-ssl-ciphers
//! description: "nginx ssl_ciphers directive — TLS suite list."
//! applies_to:
//!   - kind: config
//!     path_glob: "**/nginx*.conf"
//! pattern: '^\s*ssl_ciphers\s+'
//! emit_level: configurable
//! evidence_kind: config_pattern
//! algorithm_capture: null    # optional: regex group index
//! ```

use std::path::{Path, PathBuf};

use ree0xq_core::AgilityLevel;
use serde::{Deserialize, Serialize};

/// One rule in the published ruleset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Stable identifier (used in logs and the corpus CSV).
    pub id: String,
    /// One-sentence description; rendered in operator review.
    pub description: String,
    /// Where the rule applies.
    pub applies_to: Vec<RuleScope>,
    /// PCRE-style regex to match within the target.
    pub pattern: String,
    /// Agility level the rule contributes when matched.
    pub emit_level: AgilityLevel,
    /// Evidence kind that should be emitted on match. Names match
    /// the `AgilityEvidence` tagged-union variants.
    pub evidence_kind: EvidenceKind,
    /// Optional capture-group index whose match contains a literal
    /// algorithm name. Populates `algorithm` on emitted evidence.
    #[serde(default)]
    pub algorithm_capture: Option<usize>,
}

/// Tag for the [`ree0xq_core::AgilityEvidence`] variant the rule emits.
/// Kept distinct from the core enum so rule files stay
/// version-stable across schema bumps.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Emits `AgilityEvidence::ConfigPattern`.
    ConfigPattern,
    /// Emits `AgilityEvidence::CodePattern`.
    CodePattern,
    /// Emits `AgilityEvidence::FirmwareString`.
    FirmwareString,
}

/// Where a rule applies — a kind (config / code / binary) and an
/// optional glob filter on the file path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleScope {
    /// File-class this scope matches.
    pub kind: ScopeKind,
    /// Optional glob filter applied to the file path (e.g.
    /// `"**/nginx*.conf"`). If absent, the rule applies to every
    /// file of `kind`.
    #[serde(default)]
    pub path_glob: Option<String>,
}

/// File classes scanned by the engine.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    /// Configuration files (nginx.conf, sshd_config, openssl.cnf, ...).
    Config,
    /// Source code files (any text under a source tree).
    Code,
    /// Binary or firmware artefacts inspected via string extraction.
    Binary,
}

/// Errors raised while loading or compiling rules.
#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    /// The rule file did not parse as YAML matching the [`Rule`] schema.
    #[error("rule {file}: parse error: {source}")]
    Parse {
        /// Path that failed to parse.
        file: PathBuf,
        /// Underlying parse error.
        #[source]
        source: serde_yaml::Error,
    },
    /// The rule's regex did not compile.
    #[error("rule {id}: invalid regex: {source}")]
    BadRegex {
        /// Rule id that owns the bad regex.
        id: String,
        /// Underlying regex error.
        #[source]
        source: regex::Error,
    },
    /// Filesystem error reading the rule file.
    #[error("io error reading {file}: {source}")]
    Io {
        /// Offending path.
        file: PathBuf,
        /// Underlying IO error.
        #[source]
        source: std::io::Error,
    },
}

/// A rule with its compiled regex.
pub struct CompiledRule {
    /// The source rule.
    pub rule: Rule,
    /// Pre-compiled regex.
    pub regex: regex::Regex,
}

/// Load every `*.yaml` rule from `dir` (non-recursive), compiling
/// each regex. Failures abort the load; partial loads risk silent
/// gaps in coverage that the operator cannot diagnose from the
/// dashboard.
pub fn load_ruleset(dir: &Path) -> Result<Vec<CompiledRule>, RuleError> {
    let mut out = Vec::new();
    let read = std::fs::read_dir(dir).map_err(|e| RuleError::Io {
        file: dir.to_path_buf(),
        source: e,
    })?;
    for entry in read {
        let entry = entry.map_err(|e| RuleError::Io {
            file: dir.to_path_buf(),
            source: e,
        })?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        let raw = std::fs::read_to_string(&path).map_err(|e| RuleError::Io {
            file: path.clone(),
            source: e,
        })?;
        let rule: Rule = serde_yaml::from_str(&raw).map_err(|e| RuleError::Parse {
            file: path.clone(),
            source: e,
        })?;
        let regex = regex::Regex::new(&rule.pattern).map_err(|e| RuleError::BadRegex {
            id: rule.id.clone(),
            source: e,
        })?;
        out.push(CompiledRule { rule, regex });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn load_ruleset_parses_a_minimal_yaml_rule() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("nginx.yaml");
        fs::write(
            &p,
            r#"
id: nginx-ssl-ciphers
description: "nginx ssl_ciphers directive."
applies_to:
  - kind: config
    path_glob: "**/nginx*.conf"
pattern: '^\s*ssl_ciphers\s+'
emit_level: configurable
evidence_kind: config_pattern
"#,
        )
        .unwrap();
        let rs = load_ruleset(dir.path()).unwrap();
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].rule.id, "nginx-ssl-ciphers");
        assert_eq!(rs[0].rule.emit_level, AgilityLevel::Configurable);
    }

    #[test]
    fn load_ruleset_rejects_bad_regex() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("broken.yaml");
        fs::write(
            &p,
            r#"
id: broken
description: "bad regex"
applies_to:
  - kind: config
pattern: '[unterminated'
emit_level: pinned
evidence_kind: config_pattern
"#,
        )
        .unwrap();
        assert!(matches!(
            load_ruleset(dir.path()),
            Err(RuleError::BadRegex { .. })
        ));
    }
}
