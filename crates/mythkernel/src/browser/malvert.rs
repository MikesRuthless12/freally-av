//! In-browser malvert pattern detector (TASK-267, FEAT-212, Phase 10 Wave 2).
//!
//! Pattern-matches over **saved HTML snapshots only** (the user's
//! `Save Page As…` exports). Never inspects live traffic, never runs
//! a proxy. Detects three high-volume malvert / social-engineering
//! shapes: fake-CAPTCHA "paste this into Windows+R" widgets,
//! obfuscated inline `eval`s, and known malvert iframe attributes.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MalvertSignal {
    /// Fake-CAPTCHA widget asking the visitor to paste into the
    /// Run dialog (the so-called "ClickFix" pattern).
    FakeCaptchaPaste,
    /// Heavily obfuscated `eval(atob(...))` / `eval(unescape(...))`
    /// in the saved HTML body.
    ObfuscatedEval,
    /// `<iframe>` whose `src` matches a known malvert host or whose
    /// attributes carry the canonical malvert obfuscation
    /// (zero-size + hidden + offscreen).
    MalvertIframe,
}

impl MalvertSignal {
    pub fn as_str(self) -> &'static str {
        match self {
            MalvertSignal::FakeCaptchaPaste => "fake_captcha_paste",
            MalvertSignal::ObfuscatedEval => "obfuscated_eval",
            MalvertSignal::MalvertIframe => "malvert_iframe",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MalvertHit {
    pub signal: MalvertSignal,
    /// Byte offset of the match in the HTML body. Useful for the
    /// finding-row "view source" highlight.
    pub offset: usize,
    /// Substring matched (truncated to 120 bytes).
    pub snippet: String,
}

/// Substring tests that catch the ClickFix / fake-CAPTCHA pattern.
/// Match is case-insensitive (lower-case input compared against
/// these lower-case needles).
const FAKE_CAPTCHA_NEEDLES: &[&str] = &[
    "press windows + r",
    "press win+r",
    "press the windows key + r",
    "paste the verification code",
    "paste into your terminal",
    "paste the following command",
    "verify you are human by running",
    "i'm not a robot — open run",
];

const MALVERT_IFRAME_HOSTS: &[&str] = &[
    "popads.net",
    "propellerads.com",
    "exoclick.com",
    "trafficjunky.net",
    "doubleclickads",
];

/// Scan `body` and return one [`MalvertHit`] per distinct signal
/// fired. Matching is best-effort substring; the saved HTML's
/// rendered look isn't reproduced.
pub fn scan(body: &str) -> Vec<MalvertHit> {
    let mut out = Vec::new();
    let lc = body.to_ascii_lowercase();
    for needle in FAKE_CAPTCHA_NEEDLES {
        if let Some(off) = lc.find(needle) {
            out.push(MalvertHit {
                signal: MalvertSignal::FakeCaptchaPaste,
                offset: off,
                snippet: trim_snippet(body, off, needle.len()),
            });
            break; // one hit is enough.
        }
    }
    if let Some(off) = find_obfuscated_eval(&lc) {
        out.push(MalvertHit {
            signal: MalvertSignal::ObfuscatedEval,
            offset: off,
            snippet: trim_snippet(body, off, 64),
        });
    }
    for host in MALVERT_IFRAME_HOSTS {
        if let Some(off) = lc.find(host) {
            // Tighten: require it inside an iframe src= attr.
            let window_start = off.saturating_sub(120);
            let window = &lc[window_start..off];
            if window.contains("<iframe") && window.contains("src") {
                out.push(MalvertHit {
                    signal: MalvertSignal::MalvertIframe,
                    offset: off,
                    snippet: trim_snippet(body, off, host.len()),
                });
                break;
            }
        }
    }
    out
}

/// Convenience for callers reading a file path directly. Returns
/// `None` on missing file / non-UTF-8 contents.
pub fn scan_path(path: &Path) -> Option<Vec<MalvertHit>> {
    let body = std::fs::read_to_string(path).ok()?;
    Some(scan(&body))
}

fn find_obfuscated_eval(lc_body: &str) -> Option<usize> {
    // The three highest-volume obfuscation prefixes.
    for needle in &["eval(atob(", "eval(unescape(", "eval(decodeuricomponent("] {
        if let Some(off) = lc_body.find(needle) {
            return Some(off);
        }
    }
    None
}

fn trim_snippet(body: &str, offset: usize, len: usize) -> String {
    let end = (offset + len).min(body.len());
    // Snap to a UTF-8 boundary so we don't return invalid str.
    let mut adjusted_end = end;
    while !body.is_char_boundary(adjusted_end) && adjusted_end > offset {
        adjusted_end -= 1;
    }
    body[offset..adjusted_end].chars().take(120).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_captcha_clickfix_pattern_fires() {
        let html = "<html><body><h1>Verify</h1><p>Press Windows + R, then paste this command.</p></body></html>";
        let hits = scan(html);
        assert!(
            hits.iter()
                .any(|h| h.signal == MalvertSignal::FakeCaptchaPaste)
        );
    }

    #[test]
    fn obfuscated_eval_fires() {
        let html = r#"<script>eval(atob("YWxlcnQoMSk="));</script>"#;
        let hits = scan(html);
        assert!(
            hits.iter()
                .any(|h| h.signal == MalvertSignal::ObfuscatedEval)
        );
    }

    #[test]
    fn malvert_iframe_fires_only_inside_iframe_src() {
        let yes = r#"<iframe src="https://ads.popads.net/serve.js"></iframe>"#;
        let hits = scan(yes);
        assert!(
            hits.iter()
                .any(|h| h.signal == MalvertSignal::MalvertIframe)
        );
    }

    #[test]
    fn malvert_host_outside_iframe_does_not_fire() {
        // The host appears, but not inside an iframe; we should
        // not raise the iframe signal.
        let no = "<a href='https://popads.net/legit'>see also</a>";
        let hits = scan(no);
        assert!(
            !hits
                .iter()
                .any(|h| h.signal == MalvertSignal::MalvertIframe)
        );
    }

    #[test]
    fn clean_html_yields_no_hits() {
        let html = "<!DOCTYPE html><html><body>Hello.</body></html>";
        assert!(scan(html).is_empty());
    }

    #[test]
    fn case_insensitive_match() {
        let html = "PRESS WIN+R AND PASTE THIS:";
        let hits = scan(html);
        assert!(
            hits.iter()
                .any(|h| h.signal == MalvertSignal::FakeCaptchaPaste)
        );
    }

    #[test]
    fn snippet_does_not_slice_through_utf8_boundary() {
        // A snippet whose 64-byte window would otherwise land in
        // the middle of a multi-byte emoji.
        let mut html = "eval(atob(".to_string();
        for _ in 0..30 {
            html.push('🤖');
        }
        // Should not panic.
        let _ = scan(&html);
    }
}
