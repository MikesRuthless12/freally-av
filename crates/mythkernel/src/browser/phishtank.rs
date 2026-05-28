//! Phishing-URL flat-file check (TASK-261, FEAT-206, Phase 10 Wave 2).
//!
//! Parses PhishTank's free `verified_online.csv` export and joins host
//! names from browser history against the verified set. PhishTank
//! ships the CSV at no cost with no API key requirement — exactly the
//! sort of feed `docs/prd.md` § 1.5 calls for. The updater that
//! periodically fetches the CSV lands in the closeout pass via
//! [`crate::updater`]; this module is the pure parser + matcher.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// One verified phishing URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhishEntry {
    pub url: String,
    pub host: String,
}

/// Loaded PhishTank set. Host-keyed lookup for the join against
/// browser history; full URL list retained for the finding-row
/// explainer.
#[derive(Debug, Clone, Default)]
pub struct PhishSet {
    hosts: HashSet<String>,
    entries: Vec<PhishEntry>,
}

impl PhishSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn contains_host(&self, host: &str) -> bool {
        self.hosts.contains(&host.to_ascii_lowercase())
    }

    /// Look up the original entry by host (returns the first match
    /// per host). Useful for the finding-row explainer's verbatim
    /// "matched URL: …" line.
    pub fn first_entry_for_host(&self, host: &str) -> Option<&PhishEntry> {
        let lc = host.to_ascii_lowercase();
        self.entries.iter().find(|e| e.host == lc)
    }
}

/// Parse a PhishTank `verified_online.csv` body.
///
/// The published header is:
/// `phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target`
///
/// We only care about `url`. The parser tolerates the header row, CR
/// line endings, quoted URL fields (PhishTank quotes URLs containing
/// commas), and trailing whitespace. Lines that fail URL parsing are
/// silently dropped — the feed is best-effort.
pub fn parse_phishtank_csv(body: &str) -> PhishSet {
    let mut set = PhishSet::default();
    for line in body.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        // Skip header — feed always leads with `phish_id,...`.
        if line.starts_with("phish_id,") {
            continue;
        }
        let Some(url) = extract_url_field(line) else {
            continue;
        };
        let Some(host) = extract_host(&url) else {
            continue;
        };
        let host_lc = host.to_ascii_lowercase();
        set.hosts.insert(host_lc.clone());
        set.entries.push(PhishEntry { url, host: host_lc });
    }
    set
}

/// Extract the second CSV column (the URL). Handles either bare or
/// double-quoted second field. Hand-rolled rather than pulling a CSV
/// dep — PhishTank's format is fixed and tiny.
fn extract_url_field(line: &str) -> Option<String> {
    // Skip phish_id (first column) up to the first comma.
    let after_id = line.find(',').map(|i| &line[i + 1..])?;
    if let Some(rest) = after_id.strip_prefix('"') {
        // Quoted form: read until the next unescaped quote.
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    } else {
        // Bare form: read until the next comma.
        let end = after_id.find(',').unwrap_or(after_id.len());
        Some(after_id[..end].to_string())
    }
}

/// Extract the lower-case host from a URL. Pure-string parser — no
/// dep on `url` crate to keep the engine's dep tree tight.
pub fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.find("://").map(|i| &url[i + 3..]).unwrap_or(url);
    // Strip userinfo `user[:pass]@host`.
    let after_userinfo = match after_scheme.find('@') {
        Some(i) => &after_scheme[i + 1..],
        None => after_scheme,
    };
    // Host runs until `/`, `?`, `#`, or end of string. Port is
    // separated by `:`; we drop it.
    let end = after_userinfo
        .find(['/', '?', '#'])
        .unwrap_or(after_userinfo.len());
    let host_port = &after_userinfo[..end];
    let host = host_port.split(':').next().unwrap_or(host_port);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// One row from a browser-history table. Caller side reads Chromium
/// `urls.url` or Firefox `moz_places.url`; this is the in-process
/// row shape used for the join.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRow {
    pub browser: super::BrowserFamily,
    pub url: String,
    pub last_visit_unix_s: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhishMatch {
    pub history_row: HistoryRow,
    pub matched_url: String,
}

/// Match every history row's host against `set`. Returns the
/// matched-PhishTank-entry URL alongside the visited URL so the
/// finding explainer can show both.
pub fn match_history(history: &[HistoryRow], set: &PhishSet) -> Vec<PhishMatch> {
    let mut out = Vec::new();
    if set.host_count() == 0 {
        return out;
    }
    for row in history {
        let Some(host) = extract_host(&row.url) else {
            continue;
        };
        if let Some(e) = set.first_entry_for_host(&host) {
            out.push(PhishMatch {
                history_row: row.clone(),
                matched_url: e.url.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_skips_header_and_blank_lines() {
        let body = "\
phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target

1,http://bad.example.com/path,a,b,c,d,e,f
2,https://other.example.org/q,,,,,,
";
        let set = parse_phishtank_csv(body);
        assert_eq!(set.entry_count(), 2);
        assert!(set.contains_host("bad.example.com"));
        assert!(set.contains_host("other.example.org"));
        assert!(!set.contains_host("good.example.com"));
    }

    #[test]
    fn parse_handles_quoted_url_with_comma() {
        let body = r#"1,"http://bad.example.com/a,b,c",_,_,_,_,_,_"#;
        let set = parse_phishtank_csv(body);
        assert_eq!(set.entry_count(), 1);
        assert!(set.contains_host("bad.example.com"));
        assert_eq!(set.entries[0].url, "http://bad.example.com/a,b,c");
    }

    #[test]
    fn extract_host_drops_userinfo_and_port_and_path() {
        assert_eq!(
            extract_host("https://user:pass@example.com:8443/path?q=1#frag"),
            Some("example.com".into())
        );
        assert_eq!(
            extract_host("http://EXAMPLE.com/"),
            Some("EXAMPLE.com".into())
        );
        assert_eq!(
            extract_host("ftp://files.example.org"),
            Some("files.example.org".into())
        );
        // No scheme — accept the path-prefix form too.
        assert_eq!(extract_host("example.com/foo"), Some("example.com".into()));
    }

    #[test]
    fn contains_host_is_case_insensitive() {
        let mut set = PhishSet::default();
        set.hosts.insert("bad.example.com".into());
        assert!(set.contains_host("BAD.example.COM"));
    }

    #[test]
    fn match_history_finds_hosts_in_history_rows() {
        let csv = "1,http://bad.example.com/page,a,b,c,d,e,f";
        let set = parse_phishtank_csv(csv);
        let history = vec![
            HistoryRow {
                browser: super::super::BrowserFamily::Chrome,
                url: "https://bad.example.com/somewhere".into(),
                last_visit_unix_s: 1_700_000_000,
            },
            HistoryRow {
                browser: super::super::BrowserFamily::Firefox,
                url: "https://safe.example.org/".into(),
                last_visit_unix_s: 1_700_000_001,
            },
        ];
        let hits = match_history(&history, &set);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched_url, "http://bad.example.com/page");
    }

    #[test]
    fn empty_phish_set_yields_no_matches() {
        let history = vec![HistoryRow {
            browser: super::super::BrowserFamily::Chrome,
            url: "https://anywhere".into(),
            last_visit_unix_s: 0,
        }];
        assert!(match_history(&history, &PhishSet::default()).is_empty());
    }

    #[test]
    fn extract_url_field_returns_none_on_malformed_row() {
        assert!(extract_url_field("no_commas_here").is_none());
    }
}
