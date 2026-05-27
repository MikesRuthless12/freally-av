//! TASK-227 — Auto-quarantine stale temp executables.
//!
//! Flags executables that live in well-known temp / staging directories
//! and haven't been read or written for at least `STALE_AFTER_DAYS`
//! days. Common malware persistence pattern: a dropper lands an `.exe`
//! in `%TEMP%` or `/tmp`, runs once, and the binary sits there forever.
//! Legitimate temp execs are typically launched then deleted quickly;
//! a year-old `.exe` in `%TEMP%` is a strong signal.
//!
//! The classifier doesn't quarantine on its own — it emits a finding
//! that the quarantine action handler picks up. User toggle is
//! exposed via Settings → Privacy & cleanup.

use std::path::Path;
use std::time::SystemTime;

/// Default freshness window. Files older than this in a temp dir
/// get flagged. 30 days is generous — a legitimate temp install
/// staging usually completes within a session.
pub const DEFAULT_STALE_AFTER_DAYS: u64 = 30;

/// Cross-platform temp/staging path prefixes. Anchored as substrings
/// because Windows paths and Unix paths take different forms; the
/// `path.to_string_lossy().contains(prefix)` match accepts both
/// `C:\Users\miken\AppData\Local\Temp\foo.exe` and `/tmp/foo`.
const TEMP_PREFIXES: &[&str] = &[
    "\\Temp\\",
    "/tmp/",
    "/var/tmp/",
    "/var/folders/", // macOS per-user temp
    "\\AppData\\Local\\Temp\\",
    "\\Windows\\Temp\\",
    "\\Users\\Public\\Downloads\\",
];

/// Common executable / loadable extensions. Lowercase comparison;
/// the heuristic deliberately covers script droppers + shell loaders
/// since those are the bulk of "old file in temp" detections.
const EXEC_EXTS: &[&str] = &[
    "exe", "dll", "scr", "msi", "bat", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh",
    "hta", "cpl", "lnk", "elf", "so", "dylib", "command", "sh", "bash", "py", "pyc",
];

/// Stale-temp probe result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleTempVerdict {
    /// True when the path is in a temp prefix AND has an exec ext.
    pub is_temp_exec: bool,
    /// Age of the file in days at probe time (None if no temp match).
    pub age_days: Option<u64>,
    /// True when `age_days > stale_after_days` — the trigger for the
    /// auto-quarantine action.
    pub is_stale: bool,
}

/// Classify a candidate path + its modified time against the staleness
/// policy. `now` is unix seconds; `mtime_secs` is the file's last
/// modification time. Pure function — no filesystem access.
pub fn classify(
    path: &Path,
    mtime_secs: i64,
    now_unix_secs: i64,
    stale_after_days: u64,
) -> StaleTempVerdict {
    if !is_in_temp(path) || !has_exec_ext(path) {
        return StaleTempVerdict {
            is_temp_exec: false,
            age_days: None,
            is_stale: false,
        };
    }
    let age_secs = (now_unix_secs - mtime_secs).max(0) as u64;
    let age_days = age_secs / 86_400;
    StaleTempVerdict {
        is_temp_exec: true,
        age_days: Some(age_days),
        is_stale: age_days > stale_after_days,
    }
}

/// Convenience wrapper: use real "now" from the system clock.
pub fn classify_now(path: &Path, mtime_secs: i64, stale_after_days: u64) -> StaleTempVerdict {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    classify(path, mtime_secs, now, stale_after_days)
}

fn is_in_temp(path: &Path) -> bool {
    let s = path.to_string_lossy();
    TEMP_PREFIXES.iter().any(|p| s.contains(p))
}

fn has_exec_ext(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    match ext {
        Some(e) => EXEC_EXTS.contains(&e.as_str()),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const DAY: i64 = 86_400;

    #[test]
    fn non_temp_path_returns_no_match() {
        let v = classify(
            &PathBuf::from("/home/user/projects/app/bin/x.exe"),
            0,
            DAY * 365,
            30,
        );
        assert!(!v.is_temp_exec);
        assert!(!v.is_stale);
    }

    #[test]
    fn temp_exe_within_window_is_not_stale() {
        let v = classify(
            &PathBuf::from("/tmp/installer.exe"),
            DAY * 365,
            DAY * 366,
            30,
        );
        assert!(v.is_temp_exec);
        assert_eq!(v.age_days, Some(1));
        assert!(!v.is_stale);
    }

    #[test]
    fn temp_exe_past_window_is_stale() {
        let v = classify(&PathBuf::from("/tmp/old.exe"), DAY * 100, DAY * 200, 30);
        assert!(v.is_temp_exec);
        assert_eq!(v.age_days, Some(100));
        assert!(v.is_stale);
    }

    #[test]
    fn windows_temp_path_matches() {
        let v = classify(
            &PathBuf::from("C:\\Users\\miken\\AppData\\Local\\Temp\\bad.dll"),
            0,
            DAY * 365,
            30,
        );
        assert!(v.is_temp_exec);
        assert!(v.is_stale);
    }

    #[test]
    fn macos_temp_path_matches() {
        let v = classify(
            &PathBuf::from("/var/folders/xy/abcdef/T/dropper.sh"),
            0,
            DAY * 365,
            30,
        );
        assert!(v.is_temp_exec);
        assert!(v.is_stale);
    }

    #[test]
    fn non_exec_in_temp_is_skipped() {
        let v = classify(&PathBuf::from("/tmp/document.txt"), 0, DAY * 365, 30);
        assert!(!v.is_temp_exec);
    }

    #[test]
    fn negative_age_clamps_to_zero() {
        // mtime in the future (clock skew, restored from backup).
        let v = classify(&PathBuf::from("/tmp/x.exe"), DAY * 1000, DAY * 500, 30);
        assert_eq!(v.age_days, Some(0));
        assert!(!v.is_stale);
    }
}
