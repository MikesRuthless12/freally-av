//! ISO / IMG autorun.inf detector (TASK-288).
//!
//! Once the engine mounts an ISO/IMG (TASK-283 mount-and-scan
//! lands the mount), the daemon hands a flat listing of root-
//! level entries to [`detect_autorun`]. We surface "ISO with
//! autorun payload" at P1 when:
//!
//!   * `autorun.inf` exists in the root
//!   * the parsed `open=…` / `shellexecute=…` directive
//!     references a `.exe` / `.bat` / `.cmd` / `.scr` / `.com`
//!     /`.lnk` that also exists in the root listing
//!
//! Pure-text parser — no Windows install required.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutorunFinding {
    /// Path of the referenced executable, exactly as it
    /// appeared in autorun.inf.
    pub referenced_payload: String,
    /// `true` if the daemon-side root listing confirms the
    /// payload is present alongside autorun.inf.
    pub payload_present: bool,
    /// The directive that named the payload (`open` /
    /// `shellexecute` / `shell\<verb>\command`).
    pub directive: String,
}

const RISKY_EXTENSIONS: &[&str] = &[
    ".exe", ".bat", ".cmd", ".scr", ".com", ".lnk", ".vbs", ".ps1",
];

/// Parse an autorun.inf text and check the root listing for the
/// referenced payload. Returns `None` when no `open` /
/// `shellexecute` directive points at an executable.
pub fn detect_autorun(autorun_inf: &str, root_listing: &[String]) -> Option<AutorunFinding> {
    let mut directive: Option<(String, String)> = None;
    for line in autorun_inf.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
            continue;
        }
        if let Some(eq) = trimmed.find('=') {
            let key = trimmed[..eq].trim().to_ascii_lowercase();
            let value = trimmed[eq + 1..].trim().to_string();
            if matches!(key.as_str(), "open" | "shellexecute") {
                directive = Some((key, value));
                break;
            }
            if key.starts_with("shell\\") && key.ends_with("\\command") {
                directive = Some((key, value));
                break;
            }
        }
    }

    let (directive, raw_value) = directive?;
    let payload = parse_payload(&raw_value);
    let lc = payload.to_ascii_lowercase();
    if !RISKY_EXTENSIONS.iter().any(|ext| lc.ends_with(ext)) {
        return None;
    }
    let lc_listing: Vec<String> = root_listing
        .iter()
        .map(|e| e.to_ascii_lowercase())
        .collect();
    let payload_present = lc_listing.iter().any(|e| e == &lc);
    Some(AutorunFinding {
        referenced_payload: payload,
        payload_present,
        directive,
    })
}

fn parse_payload(directive_value: &str) -> String {
    let mut s = directive_value.trim().to_string();
    // Strip surrounding quotes.
    if s.starts_with('"') {
        if let Some(end) = s[1..].find('"') {
            s = s[1..1 + end].to_string();
        }
    }
    // First whitespace-separated token is the program path; the
    // rest are args. Take only the program.
    s.split_whitespace().next().unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_open_directive_with_payload_present() {
        let inf = "[autorun]\nopen=setup.exe\nicon=icon.ico\n";
        let listing = vec!["setup.exe".to_string(), "icon.ico".to_string()];
        let f = detect_autorun(inf, &listing).expect("flagged");
        assert_eq!(f.referenced_payload, "setup.exe");
        assert_eq!(f.directive, "open");
        assert!(f.payload_present);
    }

    #[test]
    fn shellexecute_with_quoted_path_and_args() {
        let inf = "[autorun]\nshellexecute=\"loader.exe\" /silent\n";
        let listing = vec!["loader.exe".to_string()];
        let f = detect_autorun(inf, &listing).expect("flagged");
        assert_eq!(f.referenced_payload, "loader.exe");
        assert_eq!(f.directive, "shellexecute");
    }

    #[test]
    fn benign_pdf_directive_isnt_flagged() {
        let inf = "[autorun]\nopen=readme.pdf\n";
        let listing = vec!["readme.pdf".to_string()];
        assert!(detect_autorun(inf, &listing).is_none());
    }

    #[test]
    fn payload_referenced_but_missing_still_flagged() {
        let inf = "[autorun]\nopen=phantom.exe\n";
        let listing = vec!["readme.txt".to_string()];
        let f = detect_autorun(inf, &listing).expect("still flagged");
        assert!(!f.payload_present);
    }

    #[test]
    fn shell_verb_command_directive_recognised() {
        let inf = "[autorun]\nshell\\install\\command=run.bat\n";
        let listing = vec!["run.bat".to_string()];
        let f = detect_autorun(inf, &listing).expect("flagged");
        assert!(f.directive.ends_with("\\command"));
        assert_eq!(f.referenced_payload, "run.bat");
    }

    #[test]
    fn no_executable_directive_returns_none() {
        let inf = "[autorun]\nlabel=My Disk\n";
        assert!(detect_autorun(inf, &[]).is_none());
    }

    #[test]
    fn comments_and_blank_lines_tolerated() {
        let inf = "; vendor banner\n\n[autorun]\n# more comments\nopen=installer.scr\n";
        let listing = vec!["installer.scr".to_string()];
        let f = detect_autorun(inf, &listing).expect("flagged");
        assert_eq!(f.referenced_payload, "installer.scr");
    }
}
