//! Saved-password store integrity (TASK-264, FEAT-209, Phase 10 Wave 2).
//!
//! Read-only audit: at scan time, the daemon side enumerates which
//! process currently holds each browser's saved-password store open
//! (`Login Data` for Chromium, `logins.json` for Firefox). Any holder
//! that is **not** the owning browser process raises a P1 finding.
//! This module is the pure integrity check given that mapping.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::BrowserFamily;

/// One snapshot of "process X is holding file Y open" — caller side
/// produces these from `lsof` / `handle.exe` / `/proc/<pid>/fd/*`
/// equivalents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HolderRecord {
    pub path: PathBuf,
    pub pid: u32,
    pub process_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordStoreFinding {
    pub family: BrowserFamily,
    pub path: PathBuf,
    pub offending_pid: u32,
    pub offending_process: String,
}

/// Set of process-name prefixes the integrity check accepts as
/// legitimate holders. Substring + lower-case match. Helpers and
/// renderer sub-processes are intentionally included because they
/// can legitimately hold the file when site-isolation IPC is active.
const LEGITIMATE_HOLDERS: &[(BrowserFamily, &[&str])] = &[
    (BrowserFamily::Chrome, &["chrome", "google chrome"]),
    (BrowserFamily::Edge, &["msedge", "microsoft edge"]),
    (BrowserFamily::Brave, &["brave"]),
    (BrowserFamily::Arc, &["arc"]),
    (BrowserFamily::Firefox, &["firefox"]),
];

fn is_legitimate(family: BrowserFamily, process_name: &str) -> bool {
    let lc = process_name.to_ascii_lowercase();
    LEGITIMATE_HOLDERS
        .iter()
        .find(|(f, _)| *f == family)
        .map(|(_, names)| names.iter().any(|n| lc.contains(n)))
        .unwrap_or(false)
}

/// Check holders against the per-file expected family. `expected`
/// is the (path → family) catalogue the daemon precomputed from
/// [`super::master_key_watch::enumerate`]; `holders` is the live
/// "who's holding what" snapshot.
pub fn check(
    holders: &[HolderRecord],
    expected: &[(PathBuf, BrowserFamily)],
) -> Vec<PasswordStoreFinding> {
    let mut out = Vec::new();
    for h in holders {
        let Some((_, family)) = expected.iter().find(|(p, _)| p == &h.path) else {
            continue;
        };
        if !is_legitimate(*family, &h.process_name) {
            out.push(PasswordStoreFinding {
                family: *family,
                path: h.path.clone(),
                offending_pid: h.pid,
                offending_process: h.process_name.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legitimate_chrome_holder_passes() {
        let holders = vec![HolderRecord {
            path: PathBuf::from("/p/Default/Login Data"),
            pid: 1,
            process_name: "chrome.exe".into(),
        }];
        let expected = vec![(
            PathBuf::from("/p/Default/Login Data"),
            BrowserFamily::Chrome,
        )];
        assert!(check(&holders, &expected).is_empty());
    }

    #[test]
    fn non_browser_process_fires_finding() {
        let holders = vec![HolderRecord {
            path: PathBuf::from("/p/Default/Login Data"),
            pid: 1234,
            process_name: "stealer.exe".into(),
        }];
        let expected = vec![(
            PathBuf::from("/p/Default/Login Data"),
            BrowserFamily::Chrome,
        )];
        let hits = check(&holders, &expected);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].family, BrowserFamily::Chrome);
        assert_eq!(hits[0].offending_pid, 1234);
    }

    #[test]
    fn other_browser_holding_competitor_file_is_offending() {
        // Firefox holding a Chromium Login Data file is an
        // offending pattern even though firefox is a known
        // browser — the file isn't its.
        let holders = vec![HolderRecord {
            path: PathBuf::from("/chrome/Login Data"),
            pid: 5,
            process_name: "firefox".into(),
        }];
        let expected = vec![(PathBuf::from("/chrome/Login Data"), BrowserFamily::Chrome)];
        let hits = check(&holders, &expected);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn holder_for_unknown_path_is_ignored() {
        let holders = vec![HolderRecord {
            path: PathBuf::from("/elsewhere"),
            pid: 1,
            process_name: "anything".into(),
        }];
        assert!(check(&holders, &[]).is_empty());
    }

    #[test]
    fn helper_processes_match_substring() {
        let holders = vec![HolderRecord {
            path: PathBuf::from("/p/Login Data"),
            pid: 1,
            process_name: "Google Chrome Helper (Renderer)".into(),
        }];
        let expected = vec![(PathBuf::from("/p/Login Data"), BrowserFamily::Chrome)];
        assert!(check(&holders, &expected).is_empty());
    }
}
