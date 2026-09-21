//! TLS-stack ↔ PQ-algorithm compatibility matrix (SEZ-21).
//!
//! Operators filter recommendations against the stacks they
//! actually deploy. Recommending `ML-DSA-65` for an asset
//! that's terminated by a stack with no ML-DSA support
//! costs the operator a wasted migration cycle, so the
//! recommendation engine consults this matrix before
//! emitting cost-bearing replacements.
//!
//! The table is embedded as a static Rust map. Maintainers
//! update it by editing this file when an upstream stack
//! ships a new release. The check is intentionally
//! conservative — when a stack/algorithm pair isn't in the
//! table, we return [`SupportStatus::Unknown`] rather than
//! claim support that may not exist.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// Per-pair support state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupportStatus {
    /// Released — operators can deploy today.
    Supported,
    /// Behind an experimental flag or pre-release.
    Experimental,
    /// Explicitly not implemented in any released version.
    NotImplemented,
    /// We don't have an entry for this pair; the caller
    /// decides whether absence means "no" or "ask upstream".
    Unknown,
}

/// One entry in the compatibility matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatEntry {
    pub stack: String,
    pub algorithm: String,
    pub status: SupportStatus,
    /// Minimum stack version that ships the support; `None`
    /// when the table doesn't pin a version.
    pub min_version: Option<String>,
    /// Source / reference URL (release notes, RFC, upstream
    /// blog). Used by `--show-source`.
    pub source: Option<String>,
}

/// Look up one pair. The lookup is case-insensitive on both
/// `stack` and `algorithm`.
pub fn stack_supports(stack: &str, algorithm: &str) -> SupportStatus {
    let key = (stack.to_ascii_lowercase(), algorithm.to_ascii_lowercase());
    matrix()
        .get(&key)
        .map(|e| e.status)
        .unwrap_or(SupportStatus::Unknown)
}

/// Lookup with the full entry (including version + source).
pub fn lookup(stack: &str, algorithm: &str) -> Option<CompatEntry> {
    let key = (stack.to_ascii_lowercase(), algorithm.to_ascii_lowercase());
    matrix().get(&key).cloned()
}

/// All entries for one stack — useful for the
/// `ree0xq-agility compat --list <stack>` CLI.
pub fn list_stack(stack: &str) -> Vec<CompatEntry> {
    let s = stack.to_ascii_lowercase();
    matrix()
        .iter()
        .filter(|((st, _), _)| st == &s)
        .map(|(_, e)| e.clone())
        .collect()
}

fn matrix() -> &'static HashMap<(String, String), CompatEntry> {
    static MATRIX: OnceLock<HashMap<(String, String), CompatEntry>> = OnceLock::new();
    MATRIX.get_or_init(build_matrix)
}

fn build_matrix() -> HashMap<(String, String), CompatEntry> {
    let mut m = HashMap::new();
    let add = |m: &mut HashMap<(String, String), CompatEntry>,
               stack: &str,
               algo: &str,
               status: SupportStatus,
               min_version: Option<&str>,
               source: Option<&str>| {
        m.insert(
            (stack.to_ascii_lowercase(), algo.to_ascii_lowercase()),
            CompatEntry {
                stack: stack.into(),
                algorithm: algo.into(),
                status,
                min_version: min_version.map(String::from),
                source: source.map(String::from),
            },
        );
    };

    // OpenSSL 3.x — PQ signatures arrived with the oqs-provider
    // bridge; native ML-KEM landed in 3.4. ML-DSA is
    // provider-mediated as of 3.5 at write time.
    add(
        &mut m,
        "openssl-3.x",
        "ML-KEM-768",
        SupportStatus::Supported,
        Some("3.4.0"),
        Some("https://github.com/openssl/openssl/blob/master/NEWS.md"),
    );
    add(
        &mut m,
        "openssl-3.x",
        "X25519MLKEM768",
        SupportStatus::Supported,
        Some("3.4.0"),
        Some("https://github.com/openssl/openssl/blob/master/NEWS.md"),
    );
    add(
        &mut m,
        "openssl-3.x",
        "ML-DSA-65",
        SupportStatus::Experimental,
        Some("3.5.0"),
        Some("https://github.com/open-quantum-safe/oqs-provider"),
    );
    add(
        &mut m,
        "openssl-3.x",
        "SLH-DSA-SHA2-128s",
        SupportStatus::Experimental,
        Some("3.5.0"),
        Some("https://github.com/open-quantum-safe/oqs-provider"),
    );

    // BoringSSL — Google ships ML-KEM-768 in the X25519MLKEM768
    // hybrid for Chrome; ML-DSA is still preview / not in
    // release branches.
    add(
        &mut m,
        "boringssl",
        "X25519MLKEM768",
        SupportStatus::Supported,
        None,
        Some("https://chromestatus.com/feature/5119878464176128"),
    );
    add(
        &mut m,
        "boringssl",
        "ML-DSA-65",
        SupportStatus::NotImplemented,
        None,
        Some("https://boringssl.googlesource.com/boringssl/+/refs/heads/main/include/openssl/experimental"),
    );

    // rustls + rustls-post-quantum.
    add(
        &mut m,
        "rustls-post-quantum",
        "X25519MLKEM768",
        SupportStatus::Supported,
        Some("0.2.0"),
        Some("https://crates.io/crates/rustls-post-quantum"),
    );
    add(
        &mut m,
        "rustls-post-quantum",
        "ML-DSA-65",
        SupportStatus::NotImplemented,
        None,
        None,
    );

    // Go crypto/tls — Go 1.24 shipped ML-KEM-768 hybrid.
    add(
        &mut m,
        "go-crypto-tls",
        "X25519MLKEM768",
        SupportStatus::Supported,
        Some("1.24"),
        Some("https://go.dev/doc/go1.24"),
    );
    add(
        &mut m,
        "go-crypto-tls",
        "ML-DSA-65",
        SupportStatus::NotImplemented,
        None,
        None,
    );

    // BouncyCastle Java — PQ algorithms in the bcjsse +
    // bcprov provider artifacts.
    add(
        &mut m,
        "bouncycastle",
        "ML-DSA-65",
        SupportStatus::Supported,
        Some("1.78"),
        Some("https://www.bouncycastle.org/releasenotes.html"),
    );
    add(
        &mut m,
        "bouncycastle",
        "SLH-DSA-SHA2-128s",
        SupportStatus::Supported,
        Some("1.78"),
        Some("https://www.bouncycastle.org/releasenotes.html"),
    );
    add(
        &mut m,
        "bouncycastle",
        "ML-KEM-768",
        SupportStatus::Supported,
        Some("1.78"),
        Some("https://www.bouncycastle.org/releasenotes.html"),
    );

    // NSS — Firefox / Thunderbird crypto library.
    add(
        &mut m,
        "nss",
        "X25519MLKEM768",
        SupportStatus::Supported,
        Some("3.95"),
        Some("https://firefox-source-docs.mozilla.org/security/nss/releases/index.html"),
    );
    add(
        &mut m,
        "nss",
        "ML-DSA-65",
        SupportStatus::NotImplemented,
        None,
        None,
    );

    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_insensitive_lookup() {
        assert_eq!(
            stack_supports("OpenSSL-3.x", "ML-KEM-768"),
            SupportStatus::Supported
        );
        assert_eq!(
            stack_supports("openssl-3.x", "ml-kem-768"),
            SupportStatus::Supported
        );
    }

    #[test]
    fn missing_entry_reads_unknown() {
        // Stack the matrix doesn't know about.
        assert_eq!(
            stack_supports("imaginary-tls", "ML-DSA-65"),
            SupportStatus::Unknown
        );
        // Known stack, unknown algorithm.
        assert_eq!(
            stack_supports("openssl-3.x", "FUTURE-PQ-2030"),
            SupportStatus::Unknown
        );
    }

    #[test]
    fn matrix_covers_at_least_four_stacks() {
        let stacks: std::collections::HashSet<String> =
            matrix().keys().map(|(s, _)| s.clone()).collect();
        assert!(
            stacks.len() >= 4,
            "compat matrix should cover ≥ 4 stacks; got {stacks:?}"
        );
    }

    #[test]
    fn list_stack_returns_entries() {
        let openssl = list_stack("OpenSSL-3.x");
        assert!(openssl.len() >= 3, "OpenSSL list too short: {openssl:?}");
        // ML-KEM-768 must be in the OpenSSL list.
        assert!(openssl.iter().any(|e| e.algorithm == "ML-KEM-768"));
    }

    #[test]
    fn entry_carries_source_and_min_version_when_known() {
        let entry = lookup("OpenSSL-3.x", "ML-KEM-768").unwrap();
        assert_eq!(entry.status, SupportStatus::Supported);
        assert_eq!(entry.min_version.as_deref(), Some("3.4.0"));
        assert!(entry.source.is_some());
    }
}
