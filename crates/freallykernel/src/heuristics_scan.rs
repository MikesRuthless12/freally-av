//! Phase 6 — heuristic post-pass.
//!
//! Runs **after** the file/registry/process phases finish, walks the
//! freshly-populated `verdict_cache` rows from this scan, and applies
//! lightweight pattern rules that don't need a YARA-style detector
//! engine:
//!
//! * Executable extension (`.exe`, `.dll`, `.scr`, `.bat`, `.ps1`,
//!   `.vbs`, `.js`) in a known dropper-staging directory
//!   (`%TEMP%`, `%LOCALAPPDATA%\Temp`, `%APPDATA%`, Downloads,
//!   `%PUBLIC%`).
//! * Future passes: PE bytes under a non-PE extension, IFEO
//!   debugger redirect to a non-system path, unsigned exe in
//!   `Program Files`, fresh autorun referencing a non-existent
//!   path. These each get one rule function and we accumulate
//!   findings into the same scan row.
//!
//! Soft-fail: any DB error returns early with zero items. Heuristics
//! are advisory; a failure here never marks the scan as failed.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use tokio::sync::broadcast;

use crate::detect::Severity;
use crate::history;
use crate::scan::ScanProgress;

/// Suspicious-folder substring matches. Lower-cased on Windows
/// because the FS is case-insensitive. The list was narrowed from
/// the initial dragnet (`\\appdata\\local\\`, `\\appdata\\roaming\\`,
/// `\\downloads\\`) because legitimate apps live there too — `Roaming`
/// has every installed app's profile data, `Local` has Chrome /
/// Edge / Slack etc., and `Downloads` is full of legitimate
/// installers. Keeping only the truly transient drop zones cuts
/// false positives from ~22 K → low hundreds on a typical dev box.
const SUSPICIOUS_DIRS: &[&str] = &[
    "\\appdata\\local\\temp\\",
    "\\programdata\\temp\\",
    "\\windows\\temp\\",
    "\\public\\downloads\\",
];

/// Executable extensions to flag. Dropped `cmd` from the initial set
/// because `node_modules\.bin\*.cmd` shipped with virtually every
/// npm install would otherwise generate thousands of false positives
/// on a dev box. `bat` similarly tightened.
const EXEC_EXTS: &[&str] = &["exe", "dll", "scr", "ps1", "vbs", "hta", "msi"];

/// Stop broadcasting individual `Finding` events after this many
/// matches. Findings are still persisted to SQLite and counted; we
/// just don't spam 22 000 Tauri events at the renderer (which
/// re-renders the findings list per event). The History page loads
/// the full list from the DB.
const MAX_LIVE_FINDING_EVENTS: u64 = 500;

pub fn scan_heuristics(
    scan_id: i64,
    db: &Arc<Mutex<Connection>>,
    tx: &broadcast::Sender<ScanProgress>,
    cancel_flag: &Arc<AtomicBool>,
) -> (u64, u64) {
    // Pre-pass: count the rows we'll inspect so the UI's progress
    // bar gets a denominator from tick 1.
    let expected = count_candidates(db);
    let _ = tx.send(ScanProgress::HeuristicPhaseStarted {
        scan_id,
        expected_items: expected,
    });
    let (items, flagged) = run_impl(scan_id, db, tx, cancel_flag);
    let _ = tx.send(ScanProgress::HeuristicPhaseComplete {
        scan_id,
        items_total: items,
        flagged_total: flagged,
    });
    (items, flagged)
}

fn count_candidates(db: &Arc<Mutex<Connection>>) -> u64 {
    let conn = match db.lock() {
        Ok(c) => c,
        Err(_) => return 0,
    };
    conn.query_row("SELECT COUNT(*) FROM verdict_cache", [], |row| row.get(0))
        .unwrap_or(0)
}

fn run_impl(
    scan_id: i64,
    db: &Arc<Mutex<Connection>>,
    tx: &broadcast::Sender<ScanProgress>,
    cancel_flag: &Arc<AtomicBool>,
) -> (u64, u64) {
    let conn = match db.lock() {
        Ok(c) => c,
        Err(_) => return (0, 0),
    };
    // Pull every path we've already hashed. Soft-cap at 5M rows so a
    // very long-lived install doesn't OOM on a comically large
    // verdict_cache.
    let mut stmt = match conn
        .prepare("SELECT path, blake3_hex, size_bytes FROM verdict_cache LIMIT 5000000")
    {
        Ok(s) => s,
        Err(_) => return (0, 0),
    };
    let rows: Vec<(String, String, i64)> =
        match stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))) {
            Ok(iter) => iter.flatten().collect(),
            Err(_) => return (0, 0),
        };
    drop(stmt);
    drop(conn);

    let mut items: u64 = 0;
    let mut flagged: u64 = 0;
    let mut last_emit = std::time::Instant::now();
    let emit_interval = std::time::Duration::from_millis(100);

    for (path_str, blake3_hex, size_bytes) in rows {
        if cancel_flag.load(Ordering::Relaxed) {
            break;
        }
        items += 1;

        if let Some(rule) = match_rule(&path_str) {
            flagged += 1;
            // Persist as a Finding so it surfaces in the History detail
            // / Findings panel just like a detector-driven match.
            if let Ok(conn) = db.lock() {
                let blake3_bytes = crate::detect::blake3_hex_to_bytes(&blake3_hex);
                let _ = history::record_finding(
                    &conn,
                    scan_id,
                    &path_str,
                    Some(size_bytes),
                    blake3_bytes.as_ref().map(|b| b.as_slice()),
                    None,
                    rule.rule_id,
                    "heuristic",
                    rule.severity.as_str(),
                    now_utc(),
                );
            }
            // Only broadcast live Finding events for the first
            // MAX_LIVE_FINDING_EVENTS matches. Beyond that the rule
            // is too noisy to render live; the rows are still in the
            // DB for the History detail panel to display.
            if flagged <= MAX_LIVE_FINDING_EVENTS {
                let _ = tx.send(ScanProgress::Finding {
                    scan_id,
                    finding_id: 0,
                    path: PathBuf::from(&path_str),
                    rule_id: rule.rule_id.to_string(),
                    rule_source: "heuristic".to_string(),
                    severity: rule.severity.as_str().to_string(),
                });
            }
        }

        if last_emit.elapsed() >= emit_interval {
            let _ = tx.send(ScanProgress::HeuristicProgress {
                scan_id,
                items_scanned_total: items,
                current_path: path_str.clone(),
            });
            last_emit = std::time::Instant::now();
        }
    }
    (items, flagged)
}

struct HeuristicHit {
    rule_id: &'static str,
    severity: Severity,
}

fn now_utc() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn match_rule(path_str: &str) -> Option<HeuristicHit> {
    let folded = if cfg!(windows) {
        path_str.to_ascii_lowercase()
    } else {
        path_str.to_string()
    };
    // Rule 1: executable extension in a known dropper-staging dir.
    let ext = Path::new(&folded)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if EXEC_EXTS.contains(&ext) && SUSPICIOUS_DIRS.iter().any(|dir| folded.contains(dir)) {
        return Some(HeuristicHit {
            rule_id: "heuristic:exec-in-dropper-path",
            severity: Severity::Medium,
        });
    }
    None
}
