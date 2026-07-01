//! Tab → process map (TASK-259, FEAT-204, Phase 10 Wave 2).
//!
//! Chromium spawns one renderer process per site-isolated origin and
//! tags it with two cmdline flags: `--type=renderer` plus a
//! `--renderer-client-id=<N>` integer that the browser process uses
//! to route IPC. This module is the pure parser layer over those
//! cmdlines. Per-OS process-table enumeration (the caller side that
//! produces the list of `pid + cmdline` pairs) lives under the
//! existing platform process surfaces (TASK-091..094); they feed
//! `parse_chromium_cmdline` here so the matcher is OS-agnostic and
//! trivially testable.
//!
//! No DevTools Protocol attachment is ever made — this surface is
//! local-only and forensic. The "which tab is this process serving?"
//! join is performed against the user's manual export from
//! `chrome://process-internals`, since DevTools attachment requires
//! a user action and goes beyond what the read-only NOTIFY-class
//! posture allows.

use serde::{Deserialize, Serialize};

/// One Chromium renderer process attributed by cmdline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChromiumRenderer {
    pub pid: u32,
    pub renderer_client_id: u64,
    /// `--site-isolation-trial-opt-out`/`--site-per-process` are
    /// noisy; `--field-trial-handle` carries no forensic value. We
    /// extract only the small set of flags that name the origin
    /// when present.
    pub site_url: Option<String>,
    /// Caller-supplied browser family the cmdline came from. Lets
    /// one matcher run across Chrome + Edge + Brave + Arc in one go.
    pub family: super::BrowserFamily,
}

/// Parse one Chromium-style command-line tokenisation. Returns `None`
/// when the cmdline does not contain `--type=renderer` or the client
/// id is missing/non-numeric.
pub fn parse_chromium_cmdline(
    family: super::BrowserFamily,
    pid: u32,
    argv: &[&str],
) -> Option<ChromiumRenderer> {
    if !argv.contains(&"--type=renderer") {
        return None;
    }
    let client_id_raw = argv
        .iter()
        .find_map(|a| a.strip_prefix("--renderer-client-id="))?;
    let renderer_client_id: u64 = client_id_raw.parse().ok()?;

    // Chromium also stamps `--site-url=...` on per-site dedicated
    // renderers when site-isolation is on. Older builds drop the
    // flag for the same-origin general renderer; we tolerate either.
    let site_url = argv
        .iter()
        .find_map(|a| a.strip_prefix("--site-url="))
        .map(|s| s.to_string());

    Some(ChromiumRenderer {
        pid,
        renderer_client_id,
        site_url,
        family,
    })
}

/// One row from the user's `chrome://process-internals` snapshot. The
/// user copy-pastes a tab-separated dump; this module exposes the
/// shape so [`join_renderer_to_tab`] can match against it. Daemon
/// side glue lands with the UI export wizard in the closeout pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInternalsRow {
    pub renderer_client_id: u64,
    pub last_visible_url: String,
}

/// One attributed tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TabAttribution {
    pub renderer: ChromiumRenderer,
    pub last_visible_url: String,
}

/// Match each renderer to the user's process-internals export by
/// `renderer_client_id`. Rows present on only one side are dropped
/// (forensic display surfaces only attributed tuples — unattributed
/// renderers remain visible in the Processes page anyway).
pub fn join_renderer_to_tab(
    renderers: &[ChromiumRenderer],
    rows: &[ProcessInternalsRow],
) -> Vec<TabAttribution> {
    let mut out = Vec::new();
    for r in renderers {
        if let Some(row) = rows
            .iter()
            .find(|x| x.renderer_client_id == r.renderer_client_id)
        {
            out.push(TabAttribution {
                renderer: r.clone(),
                last_visible_url: row.last_visible_url.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_renderer_cmdline_with_client_id_and_site() {
        let argv = [
            "/opt/google/chrome/chrome",
            "--type=renderer",
            "--field-trial-handle=12345",
            "--renderer-client-id=42",
            "--site-url=https://example.com",
        ];
        let r = parse_chromium_cmdline(super::super::BrowserFamily::Chrome, 1234, &argv).unwrap();
        assert_eq!(r.pid, 1234);
        assert_eq!(r.renderer_client_id, 42);
        assert_eq!(r.site_url.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn skips_non_renderer_processes() {
        let argv = ["/opt/google/chrome/chrome", "--type=gpu-process"];
        assert!(parse_chromium_cmdline(super::super::BrowserFamily::Chrome, 1, &argv).is_none());
    }

    #[test]
    fn requires_client_id_to_attribute() {
        let argv = ["/opt/google/chrome/chrome", "--type=renderer"];
        assert!(parse_chromium_cmdline(super::super::BrowserFamily::Chrome, 1, &argv).is_none());
    }

    #[test]
    fn malformed_client_id_returns_none() {
        let argv = [
            "/opt/google/chrome/chrome",
            "--type=renderer",
            "--renderer-client-id=not-a-number",
        ];
        assert!(parse_chromium_cmdline(super::super::BrowserFamily::Chrome, 1, &argv).is_none());
    }

    #[test]
    fn missing_site_url_is_ok() {
        let argv = [
            "/opt/google/chrome/chrome",
            "--type=renderer",
            "--renderer-client-id=7",
        ];
        let r = parse_chromium_cmdline(super::super::BrowserFamily::Edge, 99, &argv).unwrap();
        assert_eq!(r.renderer_client_id, 7);
        assert!(r.site_url.is_none());
    }

    #[test]
    fn join_pairs_renderer_with_internals_row() {
        let r = ChromiumRenderer {
            pid: 1,
            renderer_client_id: 5,
            site_url: None,
            family: super::super::BrowserFamily::Chrome,
        };
        let row = ProcessInternalsRow {
            renderer_client_id: 5,
            last_visible_url: "https://example.com/tab".into(),
        };
        let pairs = join_renderer_to_tab(std::slice::from_ref(&r), &[row]);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].last_visible_url, "https://example.com/tab");
    }

    #[test]
    fn join_drops_unmatched_rows() {
        let r = ChromiumRenderer {
            pid: 1,
            renderer_client_id: 5,
            site_url: None,
            family: super::super::BrowserFamily::Chrome,
        };
        let row = ProcessInternalsRow {
            renderer_client_id: 99,
            last_visible_url: "https://other".into(),
        };
        assert!(join_renderer_to_tab(&[r], &[row]).is_empty());
    }
}
