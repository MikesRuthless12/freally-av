//! Drive-by binary detector (TASK-266, FEAT-211, Phase 10 Wave 2).
//!
//! Pattern: a freshly downloaded executable (`.exe`, `.dmg`,
//! `.AppImage`, `.msi`, `.pkg`) executes within `window_seconds` of
//! the `.crdownload`→final-name rename. Browsers rename the temp
//! file as soon as the download completes; running it immediately
//! after is the canonical drive-by shape (vs. the user genuinely
//! choosing to run an installer later, where the gap is large).
//!
//! Pure matcher over `(rename, exec)` event pairs. The actual
//! confirm-before-run modal is a frontend concern surfaced via the
//! finding row.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenameEvent {
    pub final_path: PathBuf,
    pub at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecEvent {
    pub path: PathBuf,
    pub at_unix_ms: i64,
    pub pid: u32,
    pub process_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriveByFinding {
    pub path: PathBuf,
    pub rename_at_unix_ms: i64,
    pub exec_at_unix_ms: i64,
    pub exec_pid: u32,
    pub exec_process: String,
    /// Number of milliseconds between the rename and the exec.
    pub gap_ms: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct DriveByThresholds {
    pub window_ms: i64,
}

impl Default for DriveByThresholds {
    fn default() -> Self {
        Self {
            window_ms: 60_000, // 60 s per the roadmap
        }
    }
}

/// Match each exec against the most-recent rename whose final path
/// equals the executed path and whose timestamp lies inside the
/// window. Both lists may arrive in any order — the matcher indexes
/// renames by path.
pub fn detect(
    renames: &[RenameEvent],
    execs: &[ExecEvent],
    thresholds: DriveByThresholds,
) -> Vec<DriveByFinding> {
    if !looks_like_executable_listing(execs) {
        // Cheap short-circuit when none of the execs are interesting.
    }
    let mut index: HashMap<PathBuf, Vec<i64>> = HashMap::new();
    for r in renames {
        index
            .entry(r.final_path.clone())
            .or_default()
            .push(r.at_unix_ms);
    }
    for v in index.values_mut() {
        v.sort();
    }
    let mut out = Vec::new();
    for ex in execs {
        if !looks_like_executable_path(&ex.path) {
            continue;
        }
        let Some(rename_ts_list) = index.get(&ex.path) else {
            continue;
        };
        // Pick the latest rename <= the exec timestamp.
        let best = rename_ts_list.iter().rev().find(|t| **t <= ex.at_unix_ms);
        let Some(rename_at) = best else { continue };
        let gap = ex.at_unix_ms - rename_at;
        if gap <= thresholds.window_ms && gap >= 0 {
            out.push(DriveByFinding {
                path: ex.path.clone(),
                rename_at_unix_ms: *rename_at,
                exec_at_unix_ms: ex.at_unix_ms,
                exec_pid: ex.pid,
                exec_process: ex.process_name.clone(),
                gap_ms: gap,
            });
        }
    }
    out
}

const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "msi", "dmg", "pkg", "AppImage", "appimage", "bat", "cmd", "ps1", "scr",
];

fn looks_like_executable_path(path: &std::path::Path) -> bool {
    match path.extension().and_then(|s| s.to_str()) {
        Some(e) => EXECUTABLE_EXTENSIONS
            .iter()
            .any(|x| e.eq_ignore_ascii_case(x)),
        None => false,
    }
}

fn looks_like_executable_listing(execs: &[ExecEvent]) -> bool {
    execs.iter().any(|e| looks_like_executable_path(&e.path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rename_then_quick_exec_fires_finding() {
        let r = RenameEvent {
            final_path: PathBuf::from("/u/Downloads/installer.exe"),
            at_unix_ms: 1000,
        };
        let e = ExecEvent {
            path: PathBuf::from("/u/Downloads/installer.exe"),
            at_unix_ms: 1500,
            pid: 7,
            process_name: "installer.exe".into(),
        };
        let hits = detect(&[r], &[e], DriveByThresholds::default());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].gap_ms, 500);
    }

    #[test]
    fn exec_outside_window_does_not_fire() {
        let r = RenameEvent {
            final_path: PathBuf::from("/u/a.exe"),
            at_unix_ms: 0,
        };
        let e = ExecEvent {
            path: PathBuf::from("/u/a.exe"),
            at_unix_ms: 120_000, // 2 minutes later
            pid: 1,
            process_name: "a.exe".into(),
        };
        assert!(detect(&[r], &[e], DriveByThresholds::default()).is_empty());
    }

    #[test]
    fn non_executable_extensions_are_skipped() {
        let r = RenameEvent {
            final_path: PathBuf::from("/u/notes.pdf"),
            at_unix_ms: 0,
        };
        let e = ExecEvent {
            path: PathBuf::from("/u/notes.pdf"),
            at_unix_ms: 100,
            pid: 1,
            process_name: "reader".into(),
        };
        assert!(detect(&[r], &[e], DriveByThresholds::default()).is_empty());
    }

    #[test]
    fn picks_latest_rename_when_path_seen_twice() {
        let r1 = RenameEvent {
            final_path: PathBuf::from("/u/a.exe"),
            at_unix_ms: 0,
        };
        let r2 = RenameEvent {
            final_path: PathBuf::from("/u/a.exe"),
            at_unix_ms: 10_000,
        };
        let e = ExecEvent {
            path: PathBuf::from("/u/a.exe"),
            at_unix_ms: 11_000,
            pid: 1,
            process_name: "a.exe".into(),
        };
        let hits = detect(&[r1, r2], &[e], DriveByThresholds::default());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rename_at_unix_ms, 10_000);
        assert_eq!(hits[0].gap_ms, 1_000);
    }

    #[test]
    fn exec_before_rename_does_not_fire() {
        // Negative gap — exec strictly precedes rename.
        let r = RenameEvent {
            final_path: PathBuf::from("/u/a.exe"),
            at_unix_ms: 5000,
        };
        let e = ExecEvent {
            path: PathBuf::from("/u/a.exe"),
            at_unix_ms: 1000,
            pid: 1,
            process_name: "a.exe".into(),
        };
        assert!(detect(&[r], &[e], DriveByThresholds::default()).is_empty());
    }

    #[test]
    fn appimage_and_dmg_recognised() {
        let r1 = RenameEvent {
            final_path: PathBuf::from("/u/Downloads/app.AppImage"),
            at_unix_ms: 0,
        };
        let r2 = RenameEvent {
            final_path: PathBuf::from("/u/Downloads/installer.dmg"),
            at_unix_ms: 0,
        };
        let e1 = ExecEvent {
            path: PathBuf::from("/u/Downloads/app.AppImage"),
            at_unix_ms: 100,
            pid: 1,
            process_name: "app".into(),
        };
        let e2 = ExecEvent {
            path: PathBuf::from("/u/Downloads/installer.dmg"),
            at_unix_ms: 100,
            pid: 2,
            process_name: "open".into(),
        };
        let hits = detect(&[r1, r2], &[e1, e2], DriveByThresholds::default());
        assert_eq!(hits.len(), 2);
    }
}
