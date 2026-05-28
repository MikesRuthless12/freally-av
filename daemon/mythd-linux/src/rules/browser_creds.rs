//! Browser credential-store access detector — Linux (TASK-141, FR-140).
//!
//! Fires when a **non-allowlisted** process opens one of the known
//! Chromium / Firefox / Brave credential paths.
//!
//! The matched-path set is **glob-against-the-canonical-form** so a
//! re-symlinked profile dir (e.g. `~/.config/google-chrome` →
//! `~/.var/app/com.google.Chrome/config/google-chrome` on Flatpak)
//! still trips. The canonicalization happens on the daemon side
//! before this rule sees the path.

use std::path::Path;

/// One credential-store template. `pattern` is a path fragment that
/// the daemon matches against the canonical path's tail; matching is
/// case-sensitive (Linux filesystems usually are).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialPattern {
    pub browser: &'static str,
    pub pattern: &'static str,
    pub severity: &'static str,
}

pub const CREDENTIAL_PATTERNS: &[CredentialPattern] = &[
    CredentialPattern {
        browser: "chrome",
        pattern: "/google-chrome/Default/Login Data",
        severity: "high",
    },
    CredentialPattern {
        browser: "chrome",
        pattern: "/google-chrome/Default/Cookies",
        severity: "high",
    },
    CredentialPattern {
        browser: "chromium",
        pattern: "/chromium/Default/Login Data",
        severity: "high",
    },
    CredentialPattern {
        browser: "chromium",
        pattern: "/chromium/Default/Cookies",
        severity: "high",
    },
    CredentialPattern {
        browser: "brave",
        pattern: "/BraveSoftware/Brave-Browser/Default/Login Data",
        severity: "high",
    },
    CredentialPattern {
        browser: "firefox",
        pattern: "/.mozilla/firefox/",
        severity: "high",
    },
];

/// One finding shape — the daemon emits this to the engine when a
/// non-allowlisted process opens a credential path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialAccessFinding {
    pub pid: i32,
    pub exe_path: String,
    pub credential_path: String,
    pub browser: &'static str,
    pub severity: &'static str,
}

/// Match `path` against [`CREDENTIAL_PATTERNS`]. Returns the
/// matching template, or `None`.
pub fn matched_pattern(path: &Path) -> Option<&'static CredentialPattern> {
    let s = path.to_string_lossy();
    CREDENTIAL_PATTERNS.iter().find(|p| {
        s.contains(p.pattern)
            && (p.browser != "firefox" || (s.contains("key4.db") || s.contains("logins.json")))
    })
}

/// Allowlist hook — when the opener `exe_path` matches a known
/// browser binary, the rule does NOT fire. The set is intentionally
/// generous: the user can opt every browser into Mythodikal's strict
/// mode through the per-process exclusion (TASK-042).
pub fn is_allowlisted_opener(exe_path: &str) -> bool {
    const ALLOWLIST: &[&str] = &[
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/brave-browser",
        "/usr/bin/firefox",
        "/snap/firefox/current/usr/lib/firefox/firefox",
        "/var/lib/flatpak/exports/bin/com.google.Chrome",
    ];
    ALLOWLIST.contains(&exe_path)
}

/// Combine the pattern and allowlist checks into one helper the
/// daemon calls from its fanotify hot path.
pub fn try_emit(
    pid: i32,
    exe_path: &str,
    credential_path: &Path,
) -> Option<CredentialAccessFinding> {
    if is_allowlisted_opener(exe_path) {
        return None;
    }
    let matched = matched_pattern(credential_path)?;
    Some(CredentialAccessFinding {
        pid,
        exe_path: exe_path.to_string(),
        credential_path: credential_path.to_string_lossy().to_string(),
        browser: matched.browser,
        severity: matched.severity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn chrome_login_data_is_matched() {
        let p = Path::new("/home/me/.config/google-chrome/Default/Login Data");
        let m = matched_pattern(p).expect("expected match");
        assert_eq!(m.browser, "chrome");
    }

    #[test]
    fn firefox_only_matches_key4_or_logins_json() {
        let p = Path::new("/home/me/.mozilla/firefox/abc.default/key4.db");
        assert!(matched_pattern(p).is_some());
        let p2 = Path::new("/home/me/.mozilla/firefox/abc.default/logins.json");
        assert!(matched_pattern(p2).is_some());
        // Unrelated firefox path does not match.
        let p3 = Path::new("/home/me/.mozilla/firefox/abc.default/places.sqlite");
        assert!(matched_pattern(p3).is_none());
    }

    #[test]
    fn allowlisted_opener_skips() {
        let f = try_emit(
            42,
            "/usr/bin/google-chrome",
            Path::new("/home/me/.config/google-chrome/Default/Login Data"),
        );
        assert!(f.is_none());
    }

    #[test]
    fn unknown_opener_fires() {
        let f = try_emit(
            42,
            "/tmp/sketchy",
            Path::new("/home/me/.config/google-chrome/Default/Login Data"),
        );
        let f = f.expect("expected finding");
        assert_eq!(f.browser, "chrome");
        assert_eq!(f.severity, "high");
    }
}
