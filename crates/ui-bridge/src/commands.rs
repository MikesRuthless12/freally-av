//! Tauri commands (TASK-028, Phase 3).
//!
//! Each `#[tauri::command]` is a thin async wrapper around mythkernel.
//! Error path: every command returns `Result<T, String>` — Tauri
//! serializes that natively to TS `Promise<T>` / rejection.
//!
//! Scan progress events flow from the engine's `tokio::broadcast`
//! receiver into Tauri events on a per-scan basis. `scan_start` spawns
//! a forwarder task that drains the receiver and emits:
//!
//!   * `scan:started`   — when the engine kicks off
//!   * `scan:progress`  — for every `ScanProgress::File` event
//!   * `scan:finding`   — for every `ScanProgress::Finding` event
//!   * `scan:error`     — for per-file walker / hasher errors
//!   * `scan:completed` — terminal success
//!   * `scan:failed`    — terminal failure
//!
//! UI subscribers should throttle their own re-render rate (≤ 10 Hz
//! per FR-085); the engine emits hot and the channel can fall behind.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use mythkernel::{
    detect::{
        DetectionPipeline, HashKind, goodware_allowlist::GoodwareAllowlistDetector,
        hash_blacklist::HashBlacklistDetector,
    },
    engine::ScanEngine,
    findings::{self, FindingAction as KernelAction},
    quarantine::{BatchProgress, ProgressCallback, QuarantineVault},
    scan::{ScanOptions, ScanProgress, ScanTarget},
    updater::{abusech::AbuseChUpdater, nsrl::NsrlSource, nsrl::NsrlUpdater},
};
use rusqlite::Connection;
use tauri::{AppHandle, Emitter, State};

use crate::types::*;

/// Shared engine state. `App::manage()`'d at startup, accessed via
/// `tauri::State<'_, AppState>` from every command.
pub struct AppState {
    /// The single ScanEngine instance (holds Arc<Connection> + pipeline).
    pub engine: Arc<ScanEngine>,
    /// Same SQLite connection the engine writes to. Wrapped in a `Mutex`
    /// because rusqlite::Connection is `!Sync` and our commands run on
    /// the tokio multi-thread runtime.
    pub db: Arc<Mutex<Connection>>,
    pub vault: Arc<QuarantineVault>,
    pub data_dir: PathBuf,
    pub engine_version: String,
}

/// Resolve the canonical feeds directory under `<data_dir>/feeds/`.
pub fn feeds_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("feeds")
}

// ============================================================================
// Scan commands
// ============================================================================

#[tauri::command]
pub async fn scan_start(
    app: AppHandle,
    state: State<'_, AppState>,
    request: ScanRequest,
) -> Result<ScanId, String> {
    if !request.target_path.exists() {
        return Err(format!(
            "target path does not exist: {}",
            request.target_path.display()
        ));
    }
    let target = ScanTarget::Path(request.target_path);
    let opts = ScanOptions {
        compute_sha256: request.compute_sha256,
        follow_symlinks: request.follow_symlinks,
        ..ScanOptions::default()
    };
    let handle = state.engine.scan(target, opts).map_err(stringify)?;
    let scan_id = handle.scan_id;
    let mut rx = handle.progress;
    let app_for_task = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let topic = match &event {
                        ScanProgress::Started { .. } => "scan:started",
                        ScanProgress::File { .. } => "scan:progress",
                        ScanProgress::Finding { .. } => "scan:finding",
                        ScanProgress::Error { .. } => "scan:error",
                        ScanProgress::Completed { .. } => "scan:completed",
                        ScanProgress::Failed { .. } => "scan:failed",
                    };
                    let terminal = matches!(
                        &event,
                        ScanProgress::Completed { .. } | ScanProgress::Failed { .. }
                    );
                    if let Err(err) = app_for_task.emit(topic, &event) {
                        tracing::warn!(error = %err, "tauri emit failed");
                    }
                    if terminal {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(lagged_events = n, "scan progress channel lagged");
                }
            }
        }
    });
    Ok(scan_id)
}

/// Phase 3 stub: returns the current row state. Pause/resume land in
/// Phase 4 (TASK-040 / FR-011). This exists so the UI can poll scan
/// state if a Tauri event was missed.
#[tauri::command]
pub async fn scan_status(
    state: State<'_, AppState>,
    scan_id: ScanId,
) -> Result<ScanSummary, String> {
    let conn = state
        .db
        .lock()
        .map_err(|_| "db lock poisoned".to_string())?;
    fetch_scan_summary(&conn, scan_id).map_err(stringify)
}

/// Phase 3 stub: not yet implementable without TASK-040 pause/resume.
/// Returns an error so the UI surfaces "not supported yet" cleanly.
#[tauri::command]
pub async fn scan_cancel(_scan_id: ScanId) -> Result<(), String> {
    Err("scan_cancel: pause/resume + cancel are Phase 4 (TASK-040).".to_string())
}

// ============================================================================
// History
// ============================================================================

#[tauri::command]
pub async fn history_list(
    state: State<'_, AppState>,
    limit: Option<u32>,
    offset: Option<u32>,
) -> Result<Vec<ScanSummary>, String> {
    let limit = limit.unwrap_or(100).min(1000) as i64;
    let offset = offset.unwrap_or(0) as i64;
    let conn = state
        .db
        .lock()
        .map_err(|_| "db lock poisoned".to_string())?;
    let mut stmt = conn
        .prepare(
            "SELECT id, started_at_utc, ended_at_utc, trigger, target_paths, status,
                    files_visited, findings_count, bytes_visited
             FROM scans ORDER BY started_at_utc DESC, id DESC LIMIT ?1 OFFSET ?2",
        )
        .map_err(stringify)?;
    let rows = stmt
        .query_map([limit, offset], row_to_summary)
        .map_err(stringify)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(stringify)?);
    }
    Ok(out)
}

#[tauri::command]
pub async fn history_get(
    state: State<'_, AppState>,
    scan_id: ScanId,
) -> Result<ScanDetail, String> {
    let conn = state
        .db
        .lock()
        .map_err(|_| "db lock poisoned".to_string())?;
    let summary = fetch_scan_summary(&conn, scan_id).map_err(stringify)?;
    let findings = findings::list_by_scan(&conn, scan_id)
        .map_err(stringify)?
        .into_iter()
        .map(finding_to_view)
        .collect();
    Ok(ScanDetail { summary, findings })
}

// ============================================================================
// Findings
// ============================================================================

#[tauri::command]
pub async fn finding_list(
    state: State<'_, AppState>,
    scan_id: ScanId,
) -> Result<Vec<FindingView>, String> {
    let conn = state
        .db
        .lock()
        .map_err(|_| "db lock poisoned".to_string())?;
    let rows = findings::list_by_scan(&conn, scan_id).map_err(stringify)?;
    Ok(rows.into_iter().map(finding_to_view).collect())
}

#[tauri::command]
pub async fn finding_action(
    app: AppHandle,
    state: State<'_, AppState>,
    finding_id: FindingId,
    action: FindingAction,
) -> Result<String, String> {
    let kernel_action: KernelAction = action.into();
    // Some actions (Quarantine, Restore) need filesystem work as well as
    // a DB state transition. Do the filesystem step first; if it fails,
    // we never mark the row.
    let mut conn = state
        .db
        .lock()
        .map_err(|_| "db lock poisoned".to_string())?;
    let current = findings::current_state(&conn, finding_id).map_err(stringify)?;
    match (kernel_action, current) {
        (KernelAction::Quarantine, _) => {
            // Look up the finding's path, move into vault, then transition.
            let finding = findings::get(&conn, finding_id).map_err(stringify)?;
            let path = std::path::PathBuf::from(&finding.path);
            state
                .vault
                .quarantine(&mut conn, Some(finding_id), &path)
                .map_err(stringify)?;
        }
        (KernelAction::Restore, _) => {
            // Find the matching quarantine row by finding_id.
            let q_id: Option<i64> = conn
                .query_row(
                    "SELECT id FROM quarantine WHERE finding_id = ?1",
                    [finding_id],
                    |r| r.get(0),
                )
                .ok();
            if let Some(qid) = q_id {
                state.vault.restore(&mut conn, qid).map_err(stringify)?;
            }
        }
        (KernelAction::Delete, _) => {
            // If quarantined, shred the vault file too.
            let q_id: Option<i64> = conn
                .query_row(
                    "SELECT id FROM quarantine WHERE finding_id = ?1",
                    [finding_id],
                    |r| r.get(0),
                )
                .ok();
            if let Some(qid) = q_id {
                state.vault.delete(&mut conn, qid).map_err(stringify)?;
            }
        }
        (KernelAction::Ignore, _) => {} // pure DB transition
    }
    let next = findings::apply_action(&conn, finding_id, kernel_action).map_err(stringify)?;
    let _ = app.emit(
        "finding:updated",
        serde_json::json!({ "finding_id": finding_id, "state": next.as_str() }),
    );
    Ok(next.as_str().to_string())
}

// ============================================================================
// Quarantine
// ============================================================================

#[tauri::command]
pub async fn quarantine_list(state: State<'_, AppState>) -> Result<Vec<QuarantineItem>, String> {
    let conn = state
        .db
        .lock()
        .map_err(|_| "db lock poisoned".to_string())?;
    let rows = state.vault.list(&conn).map_err(stringify)?;
    Ok(rows
        .into_iter()
        .map(|e| QuarantineItem {
            id: e.id,
            finding_id: e.finding_id,
            original_path: e.original_path.to_string_lossy().to_string(),
            vault_path: e.vault_path.to_string_lossy().to_string(),
            size_bytes: e.size_bytes,
            quarantined_at_utc: e.quarantined_at_utc,
        })
        .collect())
}

#[tauri::command]
pub async fn quarantine_restore(
    state: State<'_, AppState>,
    id: QuarantineId,
) -> Result<String, String> {
    let mut conn = state
        .db
        .lock()
        .map_err(|_| "db lock poisoned".to_string())?;
    let restored = state.vault.restore(&mut conn, id).map_err(stringify)?;
    Ok(restored.to_string_lossy().to_string())
}

#[tauri::command]
pub async fn quarantine_delete(state: State<'_, AppState>, id: QuarantineId) -> Result<(), String> {
    let mut conn = state
        .db
        .lock()
        .map_err(|_| "db lock poisoned".to_string())?;
    state.vault.delete(&mut conn, id).map_err(stringify)
}

#[tauri::command]
pub async fn quarantine_restore_all(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BatchOpReport, String> {
    let cb = make_batch_callback(app);
    let mut conn = state
        .db
        .lock()
        .map_err(|_| "db lock poisoned".to_string())?;
    let report = state
        .vault
        .restore_all(&mut conn, Some(&cb))
        .map_err(stringify)?;
    Ok(report_to_wire(&report))
}

#[tauri::command]
pub async fn quarantine_delete_all(
    app: AppHandle,
    state: State<'_, AppState>,
    confirm: bool,
) -> Result<BatchOpReport, String> {
    if !confirm {
        return Err(
            "quarantine_delete_all requires `confirm: true` (FR-046 destructive-action gate)"
                .to_string(),
        );
    }
    let cb = make_batch_callback(app);
    let mut conn = state
        .db
        .lock()
        .map_err(|_| "db lock poisoned".to_string())?;
    let report = state
        .vault
        .delete_all(&mut conn, Some(&cb))
        .map_err(stringify)?;
    Ok(report_to_wire(&report))
}

#[tauri::command]
pub async fn quarantine_restore_many(
    app: AppHandle,
    state: State<'_, AppState>,
    ids: Vec<QuarantineId>,
) -> Result<BatchOpReport, String> {
    let cb = make_batch_callback(app);
    let mut conn = state
        .db
        .lock()
        .map_err(|_| "db lock poisoned".to_string())?;
    let report = state
        .vault
        .restore_many(&mut conn, &ids, Some(&cb))
        .map_err(stringify)?;
    Ok(report_to_wire(&report))
}

#[tauri::command]
pub async fn quarantine_delete_many(
    app: AppHandle,
    state: State<'_, AppState>,
    ids: Vec<QuarantineId>,
) -> Result<BatchOpReport, String> {
    let cb = make_batch_callback(app);
    let mut conn = state
        .db
        .lock()
        .map_err(|_| "db lock poisoned".to_string())?;
    let report = state
        .vault
        .delete_many(&mut conn, &ids, Some(&cb))
        .map_err(stringify)?;
    Ok(report_to_wire(&report))
}

// ============================================================================
// Feeds / Settings / System
// ============================================================================

#[tauri::command]
pub async fn feed_status(state: State<'_, AppState>) -> Result<Vec<FeedState>, String> {
    let feeds_dir = feeds_dir(&state.data_dir);
    let mut out = Vec::new();
    for (id, file) in &[
        ("abusech", "abusech_sha256.bin"),
        ("nsrl", "nsrl_sha256.bin"),
    ] {
        let path = feeds_dir.join(file);
        let (hash_count, last_updated_utc) = if path.exists() {
            let n = mythkernel::detect::hash_set_file::HashSetFile::open(&path)
                .map(|f| f.len())
                .unwrap_or(0);
            let mtime = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .map(|t| {
                    t.duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0)
                })
                .ok();
            (n, mtime)
        } else {
            (0, None)
        };
        out.push(FeedState {
            feed_id: id.to_string(),
            path: path.to_string_lossy().to_string(),
            hash_count,
            last_updated_utc,
        });
    }
    Ok(out)
}

#[tauri::command]
pub async fn feed_update_now(
    state: State<'_, AppState>,
    abusech_auth_key: Option<String>,
    nsrl_local: Option<PathBuf>,
    nsrl_url: Option<String>,
) -> Result<Vec<FeedUpdateResult>, String> {
    let feeds_dir = feeds_dir(&state.data_dir);
    std::fs::create_dir_all(&feeds_dir).map_err(stringify)?;
    let mut results = Vec::new();

    if let Some(key) = abusech_auth_key.filter(|k| !k.trim().is_empty()) {
        let updater = AbuseChUpdater::new(key, &feeds_dir);
        match updater.update().await {
            Ok(r) => results.push(FeedUpdateResult {
                feed_id: "abusech".to_string(),
                parsed_count: r.malwarebazaar_count + r.threatfox_count,
                merged_count: r.merged_count,
                elapsed_ms: r.elapsed.as_millis() as u64,
                error: None,
            }),
            Err(e) => results.push(FeedUpdateResult {
                feed_id: "abusech".to_string(),
                parsed_count: 0,
                merged_count: 0,
                elapsed_ms: 0,
                error: Some(e.to_string()),
            }),
        }
    }

    let nsrl_source = match (nsrl_local, nsrl_url) {
        (Some(p), _) => Some(NsrlSource::Local(p)),
        (_, Some(u)) => Some(NsrlSource::Url(u)),
        _ => None,
    };
    if let Some(src) = nsrl_source {
        let updater = NsrlUpdater::new(src, &feeds_dir);
        match updater.update().await {
            Ok(r) => results.push(FeedUpdateResult {
                feed_id: "nsrl".to_string(),
                parsed_count: r.parsed_count,
                merged_count: r.merged_count,
                elapsed_ms: r.elapsed.as_millis() as u64,
                error: None,
            }),
            Err(e) => results.push(FeedUpdateResult {
                feed_id: "nsrl".to_string(),
                parsed_count: 0,
                merged_count: 0,
                elapsed_ms: 0,
                error: Some(e.to_string()),
            }),
        }
    }
    Ok(results)
}

#[tauri::command]
pub async fn definition_count(state: State<'_, AppState>) -> Result<DefinitionCount, String> {
    Ok(compute_definition_count(&state.data_dir))
}

/// Synchronous, non-Tauri-State variant for code paths that need the
/// definition counts but already have a `&Path` instead of `&State`.
fn compute_definition_count(data_dir: &std::path::Path) -> DefinitionCount {
    let feeds_dir = feeds_dir(data_dir);
    let count_for = |name: &str| -> u64 {
        let path = feeds_dir.join(name);
        if !path.exists() {
            return 0;
        }
        mythkernel::detect::hash_set_file::HashSetFile::open(&path)
            .map(|f| f.len())
            .unwrap_or(0)
    };
    let abusech_hashes = count_for("abusech_sha256.bin");
    let nsrl_hashes = count_for("nsrl_sha256.bin");
    let total = abusech_hashes + nsrl_hashes;
    DefinitionCount {
        abusech_hashes,
        nsrl_hashes,
        yara_rules_compiled: 0,
        byovd_entries: 0,
        user_rules: 0,
        total,
    }
}

#[tauri::command]
pub async fn settings_get(state: State<'_, AppState>) -> Result<SettingsSnapshot, String> {
    let definitions = compute_definition_count(&state.data_dir);
    Ok(SettingsSnapshot {
        general: GeneralSettings {
            start_with_os: false,
            show_tray_icon: true,
            close_action: "minimize_to_tray".to_string(),
        },
        privacy: PrivacySettings {
            telemetry_enabled: false,
        },
        scanning: ScanningSettings {
            archives_enabled: true,
            follow_symlinks: false,
            skip_hidden: false,
        },
        about: AboutInfo {
            engine_version: state.engine_version.clone(),
            definition_count: definitions,
        },
    })
}

/// Phase 3 stub: accepts the patch shape but persists nothing. Real
/// persistence (with OS-state mirrors for FR-161/162) lands in Phase 4
/// TASK-041.
#[tauri::command]
pub async fn settings_update(_patch: SettingsPatch) -> Result<(), String> {
    tracing::info!("settings_update called — Phase 3 stub, no-op until TASK-041");
    Ok(())
}

#[tauri::command]
pub async fn engine_version(state: State<'_, AppState>) -> Result<EngineVersionInfo, String> {
    Ok(EngineVersionInfo {
        version: state.engine_version.clone(),
    })
}

// ============================================================================
// Helpers
// ============================================================================

fn stringify<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn fetch_scan_summary(conn: &Connection, scan_id: ScanId) -> Result<ScanSummary, rusqlite::Error> {
    conn.query_row(
        "SELECT id, started_at_utc, ended_at_utc, trigger, target_paths, status,
                files_visited, findings_count, bytes_visited
         FROM scans WHERE id = ?1",
        [scan_id],
        row_to_summary,
    )
}

fn row_to_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScanSummary> {
    Ok(ScanSummary {
        id: row.get(0)?,
        started_at_utc: row.get(1)?,
        ended_at_utc: row.get(2)?,
        trigger: row.get(3)?,
        target_paths: row.get(4)?,
        status: row.get(5)?,
        files_visited: row.get(6)?,
        findings_count: row.get(7)?,
        bytes_visited: row.get(8)?,
    })
}

fn finding_to_view(f: findings::Finding) -> FindingView {
    FindingView {
        id: f.id,
        scan_id: f.scan_id,
        path: f.path,
        size_bytes: f.size_bytes,
        blake3_hex: f.blake3.map(hex::encode),
        sha256_hex: f.sha256.map(hex::encode),
        rule_id: f.rule_id,
        rule_source: f.rule_source,
        severity: f.severity,
        detected_at_utc: f.detected_at_utc,
        action_taken: f.action_taken.as_str().to_string(),
        evidence: f.evidence,
        notes: f.notes,
    }
}

fn report_to_wire(r: &mythkernel::quarantine::BatchReport) -> BatchOpReport {
    BatchOpReport {
        batch_id: r.batch_id,
        kind: r.kind.as_str().to_string(),
        items_total: r.items_total,
        items_done: r.items_done,
        bytes_total: r.bytes_total,
        bytes_done: r.bytes_done,
        errors: r
            .errors
            .iter()
            .map(|e| BatchItemErr {
                quarantine_id: e.quarantine_id,
                error: e.error.clone(),
            })
            .collect(),
    }
}

fn make_batch_callback(app: AppHandle) -> ProgressCallback {
    Arc::new(move |p: BatchProgress| {
        let payload = BatchProgressEvent {
            batch_id: p.batch_id,
            kind: p.kind.as_str().to_string(),
            items_done: p.items_done,
            items_total: p.items_total,
            bytes_done: p.bytes_done,
            bytes_total: p.bytes_total,
            last_error: p.last_error.map(|e| BatchItemErr {
                quarantine_id: e.quarantine_id,
                error: e.error,
            }),
        };
        if let Err(err) = app.emit("quarantine:batch_progress", &payload) {
            tracing::warn!(error = %err, "tauri emit (batch_progress) failed");
        }
    })
}

/// Build the engine's detection pipeline by scanning `<feeds_dir>` for
/// known `.bin` files. Missing files are silently skipped — first-run
/// users haven't downloaded any feeds yet, and that's fine. Per
/// `docs/prd.md` § 1.5.1 the engine ships with no bundled feeds.
pub fn build_pipeline_from_feeds(data_dir: &std::path::Path) -> DetectionPipeline {
    let feeds_dir = feeds_dir(data_dir);
    let mut detectors: Vec<Box<dyn mythkernel::detect::Detector>> = Vec::new();

    let nsrl_path = feeds_dir.join("nsrl_sha256.bin");
    if nsrl_path.exists() {
        match GoodwareAllowlistDetector::open(&nsrl_path) {
            Ok(d) => {
                tracing::info!(
                    feed = "nsrl",
                    path = %nsrl_path.display(),
                    count = d.loaded_count(),
                    "loaded NSRL goodware allowlist"
                );
                detectors.push(Box::new(d.with_hash_kind(HashKind::Sha256)));
            }
            Err(err) => {
                tracing::warn!(error = %err, path = %nsrl_path.display(), "NSRL load failed")
            }
        }
    }

    let abusech_path = feeds_dir.join("abusech_sha256.bin");
    if abusech_path.exists() {
        match HashBlacklistDetector::open(&abusech_path) {
            Ok(d) => {
                tracing::info!(
                    feed = "abusech",
                    path = %abusech_path.display(),
                    count = d.loaded_count(),
                    "loaded abuse.ch hash blacklist"
                );
                detectors.push(Box::new(d.with_hash_kind(HashKind::Sha256)));
            }
            Err(err) => {
                tracing::warn!(error = %err, path = %abusech_path.display(), "abuse.ch load failed")
            }
        }
    }

    DetectionPipeline::new(detectors)
}

/// Single-call helper to wire every Phase-3 command into a `tauri::Builder`.
/// The app uses this in `lib.rs::run` so we don't have to maintain two
/// lists.
#[macro_export]
macro_rules! invoke_handler {
    () => {
        ::tauri::generate_handler![
            $crate::commands::scan_start,
            $crate::commands::scan_status,
            $crate::commands::scan_cancel,
            $crate::commands::history_list,
            $crate::commands::history_get,
            $crate::commands::finding_list,
            $crate::commands::finding_action,
            $crate::commands::quarantine_list,
            $crate::commands::quarantine_restore,
            $crate::commands::quarantine_delete,
            $crate::commands::quarantine_restore_all,
            $crate::commands::quarantine_delete_all,
            $crate::commands::quarantine_restore_many,
            $crate::commands::quarantine_delete_many,
            $crate::commands::feed_status,
            $crate::commands::feed_update_now,
            $crate::commands::definition_count,
            $crate::commands::settings_get,
            $crate::commands::settings_update,
            $crate::commands::engine_version,
        ]
    };
}
