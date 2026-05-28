//! Cookie-jar exfil pattern detector (TASK-263, FEAT-208, Phase 10 Wave 2).
//!
//! Heuristic over the FS-event ring (TASK-091..094) for the
//! infostealer shape: a single non-browser process reading multiple
//! browser cookie jars in a tight window. The matcher here is pure
//! over an event list so callers can feed it from any source (live
//! ring buffer, replay log, test). P1 finding when the threshold
//! count is met inside the time window.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::BrowserFamily;
use super::master_key_watch::{SensitiveFile, SensitiveFileKind};

/// One observed file-open event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookieOpenEvent {
    pub pid: u32,
    pub process_name: String,
    pub path: std::path::PathBuf,
    pub family: BrowserFamily,
    pub kind: SensitiveFileKind,
    pub at_unix_ms: i64,
}

/// One detected exfil pattern instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookieExfilFinding {
    pub pid: u32,
    pub process_name: String,
    pub families_touched: Vec<BrowserFamily>,
    /// Number of distinct cookie jars opened inside the window.
    pub jar_count: usize,
    pub window_start_ms: i64,
    pub window_end_ms: i64,
}

/// Threshold + window tuning. Defaults: 2 distinct cookie jars within
/// 5 seconds raises a finding.
#[derive(Debug, Clone, Copy)]
pub struct ExfilThresholds {
    pub min_distinct_jars: usize,
    pub window_ms: i64,
}

impl Default for ExfilThresholds {
    fn default() -> Self {
        Self {
            min_distinct_jars: 2,
            window_ms: 5_000,
        }
    }
}

/// Filter the input events to cookie-related kinds only. Helper used
/// by the daemon side that feeds a mixed event stream in.
pub fn filter_cookie_events(events: &[CookieOpenEvent]) -> impl Iterator<Item = &CookieOpenEvent> {
    events.iter().filter(|e| {
        matches!(
            e.kind,
            SensitiveFileKind::Cookies | SensitiveFileKind::FirefoxCookies
        )
    })
}

/// Browser binary basenames the detector knows are legitimate
/// cookie-jar readers. Lower-case match against `process_name`.
const KNOWN_BROWSER_NAMES: &[&str] = &[
    "chrome",
    "chrome.exe",
    "google chrome",
    "google chrome helper",
    "msedge",
    "msedge.exe",
    "microsoft edge",
    "microsoft edge helper",
    "brave",
    "brave.exe",
    "brave browser",
    "brave browser helper",
    "arc",
    "arc helper",
    "firefox",
    "firefox.exe",
    "firefox-bin",
    "safari",
];

fn is_known_browser(process_name: &str) -> bool {
    let lc = process_name.to_ascii_lowercase();
    KNOWN_BROWSER_NAMES
        .iter()
        .any(|n| lc == *n || lc.contains(n))
}

/// Detect the exfil pattern in a chronologically-ordered event list.
/// Returns one finding per pid that meets the threshold inside the
/// window. Caller is expected to dedupe across replay batches.
pub fn detect(events: &[CookieOpenEvent], thresholds: ExfilThresholds) -> Vec<CookieExfilFinding> {
    // Per-pid ring of (timestamp, path, family) tuples; we sweep
    // through events in order so the oldest entry in the window
    // is always at index 0 of each pid's vec.
    let mut per_pid: HashMap<u32, Vec<&CookieOpenEvent>> = HashMap::new();
    let mut out: Vec<CookieExfilFinding> = Vec::new();
    let mut already_emitted: std::collections::HashSet<u32> = Default::default();

    for ev in filter_cookie_events(events) {
        if is_known_browser(&ev.process_name) {
            continue;
        }
        let ring = per_pid.entry(ev.pid).or_default();
        // Drop entries older than the window.
        ring.retain(|e| ev.at_unix_ms - e.at_unix_ms <= thresholds.window_ms);
        ring.push(ev);

        // Count distinct jars by (family, path).
        let mut distinct = std::collections::HashSet::new();
        let mut families = std::collections::HashSet::new();
        for entry in ring.iter() {
            distinct.insert((entry.family, entry.path.clone()));
            families.insert(entry.family);
        }
        if distinct.len() >= thresholds.min_distinct_jars && !already_emitted.contains(&ev.pid) {
            let window_start = ring.first().map(|e| e.at_unix_ms).unwrap_or(ev.at_unix_ms);
            let mut families_vec: Vec<BrowserFamily> = families.into_iter().collect();
            families_vec.sort_by_key(|f| f.as_str());
            out.push(CookieExfilFinding {
                pid: ev.pid,
                process_name: ev.process_name.clone(),
                families_touched: families_vec,
                jar_count: distinct.len(),
                window_start_ms: window_start,
                window_end_ms: ev.at_unix_ms,
            });
            already_emitted.insert(ev.pid);
        }
    }
    out
}

/// Build a [`CookieOpenEvent`] from a daemon side `(pid, process,
/// path, ts)` tuple plus the static [`SensitiveFile`] catalogue. Used
/// when consuming the cross-platform FS event ring.
pub fn classify(
    pid: u32,
    process_name: impl Into<String>,
    path: std::path::PathBuf,
    at_unix_ms: i64,
    catalogue: &[SensitiveFile],
) -> Option<CookieOpenEvent> {
    let entry = catalogue.iter().find(|sf| sf.path == path)?;
    Some(CookieOpenEvent {
        pid,
        process_name: process_name.into(),
        path,
        family: entry.family,
        kind: entry.kind,
        at_unix_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ev(
        pid: u32,
        name: &str,
        family: BrowserFamily,
        path: &str,
        kind: SensitiveFileKind,
        ts: i64,
    ) -> CookieOpenEvent {
        CookieOpenEvent {
            pid,
            process_name: name.into(),
            path: PathBuf::from(path),
            family,
            kind,
            at_unix_ms: ts,
        }
    }

    #[test]
    fn single_pid_two_distinct_jars_fires_finding() {
        let events = vec![
            ev(
                1234,
                "stealer.exe",
                BrowserFamily::Chrome,
                "/chrome/cookies",
                SensitiveFileKind::Cookies,
                1000,
            ),
            ev(
                1234,
                "stealer.exe",
                BrowserFamily::Firefox,
                "/firefox/cookies.sqlite",
                SensitiveFileKind::FirefoxCookies,
                2000,
            ),
        ];
        let hits = detect(&events, ExfilThresholds::default());
        assert_eq!(hits.len(), 1);
        let hit = &hits[0];
        assert_eq!(hit.pid, 1234);
        assert_eq!(hit.jar_count, 2);
        assert_eq!(hit.families_touched.len(), 2);
    }

    #[test]
    fn browser_processes_themselves_are_ignored() {
        let events = vec![
            ev(
                1,
                "chrome.exe",
                BrowserFamily::Chrome,
                "/chrome/cookies",
                SensitiveFileKind::Cookies,
                100,
            ),
            ev(
                1,
                "chrome.exe",
                BrowserFamily::Firefox,
                "/firefox/cookies.sqlite",
                SensitiveFileKind::FirefoxCookies,
                200,
            ),
        ];
        assert!(detect(&events, ExfilThresholds::default()).is_empty());
    }

    #[test]
    fn window_resets_on_old_events() {
        let events = vec![
            ev(
                7,
                "stealer",
                BrowserFamily::Chrome,
                "/c",
                SensitiveFileKind::Cookies,
                0,
            ),
            // 10 seconds later — outside the default 5s window.
            ev(
                7,
                "stealer",
                BrowserFamily::Firefox,
                "/f",
                SensitiveFileKind::FirefoxCookies,
                10_000,
            ),
        ];
        assert!(detect(&events, ExfilThresholds::default()).is_empty());
    }

    #[test]
    fn one_finding_per_pid_until_cleared() {
        let events = vec![
            ev(
                9,
                "x",
                BrowserFamily::Chrome,
                "/c",
                SensitiveFileKind::Cookies,
                0,
            ),
            ev(
                9,
                "x",
                BrowserFamily::Firefox,
                "/f",
                SensitiveFileKind::FirefoxCookies,
                100,
            ),
            ev(
                9,
                "x",
                BrowserFamily::Edge,
                "/e",
                SensitiveFileKind::Cookies,
                200,
            ),
        ];
        let hits = detect(&events, ExfilThresholds::default());
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn filter_drops_non_cookie_kinds() {
        let events = vec![
            ev(
                1,
                "x",
                BrowserFamily::Chrome,
                "/login",
                SensitiveFileKind::LoginData,
                0,
            ),
            ev(
                1,
                "x",
                BrowserFamily::Chrome,
                "/cookies",
                SensitiveFileKind::Cookies,
                1,
            ),
        ];
        let kept: Vec<_> = filter_cookie_events(&events).collect();
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn classify_resolves_event_against_catalogue() {
        let catalogue = vec![SensitiveFile {
            family: BrowserFamily::Chrome,
            kind: SensitiveFileKind::Cookies,
            path: PathBuf::from("/cookies"),
        }];
        let event = classify(1, "stealer", PathBuf::from("/cookies"), 5, &catalogue).unwrap();
        assert_eq!(event.kind, SensitiveFileKind::Cookies);
        assert_eq!(event.family, BrowserFamily::Chrome);
    }

    #[test]
    fn classify_returns_none_for_unknown_path() {
        let catalogue = vec![SensitiveFile {
            family: BrowserFamily::Chrome,
            kind: SensitiveFileKind::Cookies,
            path: PathBuf::from("/cookies"),
        }];
        assert!(classify(1, "x", PathBuf::from("/other"), 0, &catalogue).is_none());
    }
}
