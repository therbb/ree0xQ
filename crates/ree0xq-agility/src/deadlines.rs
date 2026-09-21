//! Regulator deadline tracker (SEZ-22).
//!
//! Per-jurisdiction PQ-mandate dates, surfaced so the
//! recommendation engine can prioritise migrations against
//! the operator's regulatory horizon. The table ships
//! embedded (no network fetch); maintainers refresh it as
//! agencies publish new dates.
//!
//! Every entry carries the public document URL so the
//! operator can audit the claim — important for a tool a
//! CISO uses to justify migration budget.

use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use serde::Serialize;

/// One regulator deadline.
#[derive(Debug, Clone, Serialize)]
pub struct DeadlineEntry {
    /// ISO 3166 country/region code prefix plus regulator
    /// initialism — e.g. `US-NSA`, `EU-ANSSI`, `DE-BSI`.
    pub jurisdiction: String,
    /// Operator-friendly label, e.g. `CNSA 2.0 browsers
    /// and servers`.
    pub label: String,
    /// The calendar date the mandate takes effect.
    pub effective_date: DateTime<Utc>,
    /// What's affected — `browsers`, `network equipment`,
    /// `code-signing`, `operating systems`, …
    pub asset_class: String,
    /// Source URL — the public document the date came from.
    pub source: String,
}

/// All known deadlines, sorted by `effective_date`
/// ascending.
pub fn all() -> Vec<DeadlineEntry> {
    table().to_vec()
}

/// Deadlines that fall within `[now, now + horizon]`.
pub fn within(now: DateTime<Utc>, horizon: chrono::Duration) -> Vec<DeadlineEntry> {
    let end = now + horizon;
    table()
        .iter()
        .filter(|e| e.effective_date >= now && e.effective_date <= end)
        .cloned()
        .collect()
}

/// Deadlines for one jurisdiction (case-insensitive prefix
/// match, e.g. `US` matches `US-NSA` and `US-NIST`).
pub fn for_jurisdiction(prefix: &str) -> Vec<DeadlineEntry> {
    let p = prefix.to_ascii_uppercase();
    table()
        .iter()
        .filter(|e| e.jurisdiction.to_ascii_uppercase().starts_with(&p))
        .cloned()
        .collect()
}

fn table() -> &'static Vec<DeadlineEntry> {
    static T: OnceLock<Vec<DeadlineEntry>> = OnceLock::new();
    T.get_or_init(build_table)
}

fn build_table() -> Vec<DeadlineEntry> {
    fn d(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, year, month, day, 0, 0, 0).unwrap()
    }

    let mut t = vec![
        DeadlineEntry {
            jurisdiction: "US-NSA".into(),
            label: "CNSA 2.0 — software / firmware signing in PQC".into(),
            effective_date: d(2025, 1, 1),
            asset_class: "code-signing".into(),
            source: "https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF".into(),
        },
        DeadlineEntry {
            jurisdiction: "US-NSA".into(),
            label: "CNSA 2.0 — browsers and servers".into(),
            effective_date: d(2030, 1, 1),
            asset_class: "browsers, servers".into(),
            source: "https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF".into(),
        },
        DeadlineEntry {
            jurisdiction: "US-NSA".into(),
            label: "CNSA 2.0 — network equipment".into(),
            effective_date: d(2030, 1, 1),
            asset_class: "network equipment".into(),
            source: "https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF".into(),
        },
        DeadlineEntry {
            jurisdiction: "US-NSA".into(),
            label: "CNSA 2.0 — operating systems and traditional networking".into(),
            effective_date: d(2033, 1, 1),
            asset_class: "operating systems".into(),
            source: "https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF".into(),
        },
        DeadlineEntry {
            jurisdiction: "US-NIST".into(),
            label: "NIST IR 8547 — deprecation of RSA-2048 / ECDSA-P256 for federal systems".into(),
            effective_date: d(2030, 12, 31),
            asset_class: "federal systems".into(),
            source: "https://csrc.nist.gov/pubs/ir/8547/ipd".into(),
        },
        DeadlineEntry {
            jurisdiction: "US-NIST".into(),
            label: "NIST IR 8547 — disallowance of RSA / ECDSA / DH".into(),
            effective_date: d(2035, 12, 31),
            asset_class: "federal systems".into(),
            source: "https://csrc.nist.gov/pubs/ir/8547/ipd".into(),
        },
        DeadlineEntry {
            jurisdiction: "EU-ANSSI".into(),
            label: "ANSSI Phase 2 — hybrid PQ in production for high-assurance".into(),
            effective_date: d(2030, 1, 1),
            asset_class: "high-assurance".into(),
            source: "https://www.ssi.gouv.fr/uploads/2022/01/anssi-technical_position_papers-post_quantum_cryptography_transition.pdf".into(),
        },
        DeadlineEntry {
            jurisdiction: "EU-ANSSI".into(),
            label: "ANSSI Phase 3 — PQ-only requirement".into(),
            effective_date: d(2035, 1, 1),
            asset_class: "high-assurance".into(),
            source: "https://www.ssi.gouv.fr/uploads/2022/01/anssi-technical_position_papers-post_quantum_cryptography_transition.pdf".into(),
        },
        DeadlineEntry {
            jurisdiction: "DE-BSI".into(),
            label: "BSI TR-02102-1 — hybrid PQ recommendation".into(),
            effective_date: d(2026, 1, 1),
            asset_class: "general".into(),
            source: "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.html".into(),
        },
        DeadlineEntry {
            jurisdiction: "UK-NCSC".into(),
            label: "NCSC — start of PQ deployment window for CNI operators".into(),
            effective_date: d(2028, 1, 1),
            asset_class: "critical national infrastructure".into(),
            source: "https://www.ncsc.gov.uk/whitepaper/next-steps-preparing-for-post-quantum-cryptography".into(),
        },
        DeadlineEntry {
            jurisdiction: "UK-NCSC".into(),
            label: "NCSC — PQ-complete migration target for CNI".into(),
            effective_date: d(2035, 1, 1),
            asset_class: "critical national infrastructure".into(),
            source: "https://www.ncsc.gov.uk/whitepaper/next-steps-preparing-for-post-quantum-cryptography".into(),
        },
    ];
    t.sort_by_key(|e| e.effective_date);
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn table_has_five_or_more_jurisdictions() {
        let js: std::collections::HashSet<String> =
            all().into_iter().map(|e| e.jurisdiction).collect();
        // US-NSA, US-NIST, EU-ANSSI, DE-BSI, UK-NCSC.
        assert!(js.len() >= 5, "got jurisdictions: {js:?}");
    }

    #[test]
    fn every_entry_has_a_source_url() {
        for e in all() {
            assert!(e.source.starts_with("http"), "entry without source: {e:?}");
        }
    }

    #[test]
    fn within_filters_by_horizon() {
        let now = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let one_year = chrono::Duration::days(365);
        let near = within(now, one_year);
        // BSI 2026-01-01 deadline is already past on
        // 2026-05-01; nothing within [now, now+1y] from this
        // jurisdiction. So `near` should not contain that
        // 2026-01-01 entry.
        assert!(near.iter().all(|e| e.effective_date >= now));
        assert!(near.iter().all(|e| e.effective_date <= now + one_year));
    }

    #[test]
    fn for_jurisdiction_matches_prefix() {
        let us = for_jurisdiction("US");
        // Both US-NSA and US-NIST entries should land.
        let labels: Vec<&str> = us.iter().map(|e| e.label.as_str()).collect();
        assert!(labels.iter().any(|l| l.contains("CNSA 2.0")));
        assert!(labels.iter().any(|l| l.contains("NIST IR 8547")));
    }

    #[test]
    fn table_is_chronologically_sorted() {
        let all = all();
        for w in all.windows(2) {
            assert!(w[0].effective_date <= w[1].effective_date);
        }
    }
}
