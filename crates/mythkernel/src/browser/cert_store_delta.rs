//! Browser cert store delta (TASK-265, FEAT-210, Phase 10 Wave 2).
//!
//! Snapshots each browser's root cert store and diffs against the
//! previous snapshot. Any root CA added in the last `window_days`
//! window surfaces as a finding. The actual NSS database (`cert9.db`)
//! and Chromium `Certificates` table parsers land in the closeout
//! pass; this module owns the snapshot shape + the diff logic so the
//! upstream readers feed structured rows in.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::BrowserFamily;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RootCert {
    pub family: BrowserFamily,
    /// X.509 subject DN, as printed by the browser. Free-form text
    /// from the cert store; we match by `(family, subject, sha256_hex)`
    /// so subject-only collisions across families don't collapse.
    pub subject: String,
    /// Lower-case hex SHA-256 of the certificate's DER encoding.
    pub sha256_hex: String,
    /// Cert "not before" timestamp (UNIX seconds). May be `0` when
    /// the reader cannot parse it; the diff ignores zero values.
    pub not_before_unix_s: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootCertSnapshot {
    /// Unix seconds the snapshot was taken.
    pub captured_unix_s: i64,
    pub certs: Vec<RootCert>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RootCertDelta {
    pub added: Vec<RootCert>,
    pub removed: Vec<RootCert>,
    pub unchanged: usize,
}

/// Diff two snapshots. A cert key is `(family, sha256_hex)` — the
/// subject is included for the UI explainer but two certs with the
/// same hash are the same root regardless of subject (handles the
/// browser-vendor practice of re-encoding the same root with a
/// slightly-different printable subject form).
pub fn diff(previous: &RootCertSnapshot, current: &RootCertSnapshot) -> RootCertDelta {
    let prev_keys: HashSet<(BrowserFamily, String)> = previous
        .certs
        .iter()
        .map(|c| (c.family, c.sha256_hex.to_ascii_lowercase()))
        .collect();
    let curr_keys: HashSet<(BrowserFamily, String)> = current
        .certs
        .iter()
        .map(|c| (c.family, c.sha256_hex.to_ascii_lowercase()))
        .collect();

    let added: Vec<RootCert> = current
        .certs
        .iter()
        .filter(|c| !prev_keys.contains(&(c.family, c.sha256_hex.to_ascii_lowercase())))
        .cloned()
        .collect();
    let removed: Vec<RootCert> = previous
        .certs
        .iter()
        .filter(|c| !curr_keys.contains(&(c.family, c.sha256_hex.to_ascii_lowercase())))
        .cloned()
        .collect();
    let unchanged = prev_keys.intersection(&curr_keys).count();
    RootCertDelta {
        added,
        removed,
        unchanged,
    }
}

/// Filter a delta's `added` list to only the entries inserted within
/// the last `window_days` (per `now_unix_s`). The roadmap calls out
/// 30 days as the surface threshold.
pub fn added_within_window(
    delta: &RootCertDelta,
    now_unix_s: i64,
    window_days: i64,
) -> Vec<RootCert> {
    let cutoff = now_unix_s - window_days * 86_400;
    delta
        .added
        .iter()
        .filter(|c| c.not_before_unix_s == 0 || c.not_before_unix_s >= cutoff)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(family: BrowserFamily, sha: &str, subject: &str, not_before: i64) -> RootCert {
        RootCert {
            family,
            subject: subject.into(),
            sha256_hex: sha.into(),
            not_before_unix_s: not_before,
        }
    }

    #[test]
    fn diff_finds_added_and_removed() {
        let prev = RootCertSnapshot {
            captured_unix_s: 0,
            certs: vec![
                cert(BrowserFamily::Chrome, "aa", "CN=A", 100),
                cert(BrowserFamily::Chrome, "bb", "CN=B", 100),
            ],
        };
        let curr = RootCertSnapshot {
            captured_unix_s: 100,
            certs: vec![
                cert(BrowserFamily::Chrome, "aa", "CN=A", 100),
                cert(BrowserFamily::Chrome, "cc", "CN=C", 1_700_000_000),
            ],
        };
        let d = diff(&prev, &curr);
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].sha256_hex, "cc");
        assert_eq!(d.removed.len(), 1);
        assert_eq!(d.removed[0].sha256_hex, "bb");
        assert_eq!(d.unchanged, 1);
    }

    #[test]
    fn sha_match_is_case_insensitive() {
        let prev = RootCertSnapshot {
            captured_unix_s: 0,
            certs: vec![cert(BrowserFamily::Firefox, "DEADBEEF", "CN=A", 0)],
        };
        let curr = RootCertSnapshot {
            captured_unix_s: 0,
            certs: vec![cert(BrowserFamily::Firefox, "deadbeef", "CN=A", 0)],
        };
        let d = diff(&prev, &curr);
        assert!(d.added.is_empty());
        assert!(d.removed.is_empty());
        assert_eq!(d.unchanged, 1);
    }

    #[test]
    fn cross_family_certs_dont_collapse() {
        let prev = RootCertSnapshot::default();
        let curr = RootCertSnapshot {
            captured_unix_s: 0,
            certs: vec![
                cert(BrowserFamily::Chrome, "aa", "CN=Shared", 1_700_000_000),
                cert(BrowserFamily::Firefox, "aa", "CN=Shared", 1_700_000_000),
            ],
        };
        let d = diff(&prev, &curr);
        assert_eq!(d.added.len(), 2);
    }

    #[test]
    fn added_within_window_filters_old_not_before() {
        let delta = RootCertDelta {
            added: vec![
                cert(BrowserFamily::Chrome, "new", "CN=Recent", 1_700_000_000),
                cert(BrowserFamily::Chrome, "old", "CN=Ancient", 1_500_000_000),
            ],
            removed: vec![],
            unchanged: 0,
        };
        // Now = 1_700_500_000, window = 30 days.
        let recent = added_within_window(&delta, 1_700_500_000, 30);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].sha256_hex, "new");
    }

    #[test]
    fn added_within_window_keeps_unknown_not_before() {
        let delta = RootCertDelta {
            added: vec![cert(BrowserFamily::Chrome, "x", "CN=X", 0)],
            removed: vec![],
            unchanged: 0,
        };
        let recent = added_within_window(&delta, 1_700_500_000, 30);
        assert_eq!(recent.len(), 1);
    }
}
