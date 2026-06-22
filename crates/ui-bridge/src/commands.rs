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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use mythkernel::{
    detect::{
        DetectionPipeline, HashKind, goodware_allowlist::GoodwareAllowlistDetector,
        hash_blacklist::HashBlacklistDetector, publisher,
    },
    engine::ScanEngine,
    exclusions::{self, ExclusionKind, ExclusionScope},
    findings::{self, FindingAction as KernelAction},
    quarantine::{BatchProgress, ProgressCallback, QuarantineVault},
    realtime::shields::{ShieldsActor, ShieldsBroker, ShieldsState},
    scan::{ScanOptions, ScanProgress, ScanTarget},
    updater::{
        channels::ChannelState,
        database::{DatabaseChannel, DatabaseUpdateProgress, DbProgressCallback},
        engine::{EngineChannel, EngineUpdateAvailable},
        nsrl::NsrlSource,
        nsrl::NsrlUpdater,
    },
};
use rusqlite::Connection;
use tauri::{AppHandle, Emitter, State};

use crate::types::*;

/// Path-validation result for [`validate_scan_target`] /
/// [`validate_restore_target`]. Distinct from a generic Result so the
/// caller can format human-grade error messages.
#[derive(Debug, thiserror::Error)]
pub enum PathPolicyError {
    #[error("path does not exist: {0}")]
    Missing(PathBuf),
    #[error("path is inside a system directory and is not scannable: {0}")]
    SystemDirectory(PathBuf),
    #[error("path canonicalization failed: {0}")]
    Canonicalize(String),
    #[error("path scheme not allowed: {0}")]
    BadScheme(String),
}

/// Roots that Mythodikal refuses to scan / restore into. Defense-in-depth
/// against a tampered SQLite row or a malicious frontend pointing
/// `scan_start` at an OS-managed location (security review C2 + C1+H1).
///
/// This is a **denylist**; we accept user data anywhere else. PRD § 2.5
/// promised canonicalization + scope checks — Phase 3 ships this minimal
/// denylist; a full per-platform allowlist with user-configurable
/// extensions is Phase 4 (FR-060/061 exclusions UX).
#[cfg(windows)]
const SYSTEM_PATH_DENYLIST: &[&str] = &[
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"\\?\GLOBALROOT",
];

#[cfg(unix)]
const SYSTEM_PATH_DENYLIST: &[&str] = &[
    "/etc", "/bin", "/sbin", "/usr", "/var", "/boot", "/sys", "/proc", "/lib", "/lib64", "/System",
    "/private",
];

/// Canonicalize `path` and confirm it isn't a system directory. Used by
/// `scan_start` (security review C2) and indirectly during restore
/// (security review C1).
pub fn validate_scan_target(path: &Path) -> Result<PathBuf, PathPolicyError> {
    let canonical = path.canonicalize().map_err(|err| match err.kind() {
        std::io::ErrorKind::NotFound => PathPolicyError::Missing(path.to_path_buf()),
        _ => PathPolicyError::Canonicalize(err.to_string()),
    })?;
    if path_is_system(&canonical) {
        return Err(PathPolicyError::SystemDirectory(canonical));
    }
    Ok(canonical)
}

/// Restore-time validation. Refuses paths that would write into a system
/// directory — defense against a tampered `quarantine.original_path`
/// (security review C1). Caller is responsible for the existing
/// refuses-to-overwrite check in `QuarantineVault::restore`.
pub fn validate_restore_target(path: &Path) -> Result<(), PathPolicyError> {
    let parent = path.parent().unwrap_or(path);
    // The path itself may not exist yet (that's the whole point of restore),
    // so canonicalize the parent and compose. If the parent is missing too,
    // accept — the engine will create it and restore-overwrite-check still
    // catches surprise files.
    let parent_canonical = match parent.canonicalize() {
        Ok(p) => p,
        Err(_) => return Ok(()),
    };
    if path_is_system(&parent_canonical) {
        return Err(PathPolicyError::SystemDirectory(parent_canonical));
    }
    Ok(())
}

fn path_is_system(canonical: &Path) -> bool {
    let s = canonical.to_string_lossy();
    // macOS: /var is a symlink to /private/var and user tempdirs live
    // under /private/var/folders/. Without an exemption the canonical
    // tempdir matches the /private denylist prefix and the user can't
    // even scan their own scratch space. The same applies to /private/tmp
    // (canonical form of /tmp). Both areas are user-writable by design.
    #[cfg(target_os = "macos")]
    {
        if s.starts_with("/private/var/folders/") || s.starts_with("/private/tmp/") {
            return false;
        }
    }
    let s_lower = s.to_lowercase();
    SYSTEM_PATH_DENYLIST.iter().any(|prefix| {
        let p = prefix.to_lowercase();
        s_lower == p
            || s_lower.starts_with(&format!("{p}\\"))
            || s_lower.starts_with(&format!("{p}/"))
    })
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn windows_system_paths_are_rejected() {
        assert!(path_is_system(Path::new(r"C:\Windows")));
        assert!(path_is_system(Path::new(r"C:\Windows\System32")));
        assert!(path_is_system(Path::new(r"C:\Program Files\app")));
        assert!(path_is_system(Path::new(r"C:\Program Files (x86)\app")));
        assert!(path_is_system(Path::new(
            r"\\?\GLOBALROOT\Device\HarddiskVolume1"
        )));
        // Mixed-case ProgramFiles must still trip the gate.
        assert!(path_is_system(Path::new(r"c:\program files\app")));
    }

    #[cfg(windows)]
    #[test]
    fn windows_user_paths_are_accepted() {
        assert!(!path_is_system(Path::new(r"C:\Users\me\Downloads")));
        assert!(!path_is_system(Path::new(r"D:\projects\src")));
        // A path whose substring contains "windows" but isn't a system
        // dir must not trip the denylist.
        assert!(!path_is_system(Path::new(r"C:\Users\me\Windows-Logos")));
    }

    #[cfg(unix)]
    #[test]
    fn unix_system_paths_are_rejected() {
        assert!(path_is_system(Path::new("/etc")));
        assert!(path_is_system(Path::new("/etc/passwd")));
        assert!(path_is_system(Path::new("/usr/bin/ls")));
        assert!(path_is_system(Path::new("/sys/kernel")));
        assert!(path_is_system(Path::new("/proc/self/mem")));
    }

    #[cfg(unix)]
    #[test]
    fn unix_user_paths_are_accepted() {
        assert!(!path_is_system(Path::new("/home/me/Downloads")));
        assert!(!path_is_system(Path::new("/tmp/scratch")));
        // /etcetera must not trip /etc.
        assert!(!path_is_system(Path::new("/etcetera/note")));
    }

    #[test]
    fn validate_scan_target_rejects_missing() {
        let nonexistent = std::env::temp_dir().join("mythodikal-validate-not-real-xyz123");
        let _ = std::fs::remove_file(&nonexistent);
        let err = validate_scan_target(&nonexistent).unwrap_err();
        assert!(matches!(err, PathPolicyError::Missing(_)));
    }

    #[test]
    fn validate_scan_target_canonicalizes_existing() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = validate_scan_target(dir.path()).unwrap();
        // Result must round-trip canonicalize (idempotent).
        assert_eq!(canonical, canonical.canonicalize().unwrap());
    }

    #[test]
    fn validate_restore_target_accepts_unknown_parent() {
        // Restore-to-new-dir is a valid case (engine will create the
        // parent). The policy check only refuses *system* parents.
        let target = std::env::temp_dir().join("mythodikal-restore-new-xyz123/file.bin");
        let _ = std::fs::remove_dir_all(target.parent().unwrap());
        validate_restore_target(&target).unwrap();
    }
}

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
    /// Shields master kill-switch (FR-160, TASK-156). Broker is cheap
    /// to clone; the frontend store subscribes via shields_get +
    /// shields:changed events.
    pub shields: ShieldsBroker,
    /// Live TOML config snapshot + path (TASK-041). The Mutex protects
    /// the in-memory copy; every `settings_update` mutates this and
    /// `config::save()`s atomically.
    pub config: Arc<Mutex<mythkernel::config::Config>>,
    pub config_path: PathBuf,
    /// Active scan pause flags (TASK-040). `scan_start` registers a
    /// flag; the forwarder removes it on the terminal event. `scan_pause`
    /// looks up by id and flips the flag — the worker observes it at
    /// the next iteration boundary (and mid-hash via the shared abort
    /// flag), persists the resume token, and exits.
    pub active_pause_flags: Arc<Mutex<HashMap<i64, Arc<AtomicBool>>>>,
    /// Active scan cancel flags. Sibling to `active_pause_flags`; set
    /// by `scan_cancel`. The worker exits without writing a resume
    /// token and marks the scans row as `cancelled`.
    pub active_cancel_flags: Arc<Mutex<HashMap<i64, Arc<AtomicBool>>>>,
    pub data_dir: PathBuf,
    pub engine_version: String,
    /// Engine self-update channel (TASK-130). Owns the persisted state
    /// for the `Settings → Updates → Engine` pane.
    pub updater_engine: Arc<EngineChannel>,
    /// Database / signature-feed update channel (TASK-131). The shared
    /// arc lets `updater_db_state` and `updater_db_check_now` both
    /// reach the same registry without re-registering feeds.
    pub updater_db: Arc<DatabaseChannel>,
}

/// Resolve the canonical feeds directory under `<data_dir>/feeds/`.
pub fn feeds_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("feeds")
}

// ============================================================================
// First-run flag (TASK-046 wave-3 follow-up)
// ============================================================================

/// On-disk path for the first-run-completed flag. Stored next to the
/// engine DB so it survives dev rebuilds (WebView2's profile dir is
/// ephemeral in dev mode, so localStorage alone resets every launch).
fn first_run_flag_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("first_run.json")
}

/// Read the first-run-completed flag. Returns `false` when the file
/// doesn't exist (fresh profile) or can't be parsed.
#[tauri::command]
pub async fn first_run_get(state: State<'_, AppState>) -> Result<bool, String> {
    let path = first_run_flag_path(&state.data_dir);
    if !path.exists() {
        return Ok(false);
    }
    let bytes = std::fs::read(&path).map_err(stringify)?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).map_err(stringify)?;
    Ok(v.get("completed")
        .and_then(|x| x.as_bool())
        .unwrap_or(false))
}

/// Persist the first-run-completed flag. Idempotent. Sec-review L1:
/// atomic write via tmp+rename so a crash mid-write doesn't leave a
/// zero-byte `first_run.json` that would re-trigger the welcome
/// wizard on next launch.
#[tauri::command]
pub async fn first_run_set(state: State<'_, AppState>, completed: bool) -> Result<(), String> {
    let path = first_run_flag_path(&state.data_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(stringify)?;
    }
    let body = serde_json::json!({ "completed": completed }).to_string();
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body).map_err(stringify)?;
    std::fs::rename(&tmp, &path).map_err(stringify)?;
    Ok(())
}

// ============================================================================
// Volumes (TASK-056) — Windows per-volume scan-target chooser
// ============================================================================

/// Enumerate every mounted volume on the host. On Windows this drives the
/// Scan page's per-volume target chooser (TASK-056); on other platforms
/// the command returns an empty `Vec` so the UI degrades cleanly to its
/// path-only chooser.
#[tauri::command]
pub async fn enumerate_volumes() -> Result<Vec<VolumeView>, String> {
    #[cfg(target_os = "windows")]
    {
        let raw = mythkernel::platform::win::volumes::enumerate_volumes().map_err(stringify)?;
        Ok(raw
            .into_iter()
            .map(|v| VolumeView {
                mount_path: v.mount_path.to_string_lossy().into_owned(),
                all_mount_paths: v
                    .all_mount_paths
                    .into_iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect(),
                fs_name: v.fs_name,
                serial: v.serial,
                is_ntfs: v.is_ntfs,
                is_removable: v.is_removable,
            })
            .collect())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(Vec::new())
    }
}

/// Canonical Quick Scan hotspot list — the directories where malware
/// most often first lands (drive-by downloads, droppers, persistence
/// installers, startup-shortcut payloads). Expanded from environment
/// variables at runtime so we follow the user's actual profile, not
/// hard-coded `C:\Users\<name>` paths.
///
/// Quick Scan also turns on registry + process phases via
/// `ScanOptions { include_registry: true, include_processes: true }`,
/// so this list covers only the *file* portion of the sweep.
#[tauri::command]
pub async fn quick_scan_paths() -> Result<Vec<String>, String> {
    let mut paths: Vec<String> = Vec::new();
    let mut push_env = |var: &str, suffix: Option<&str>| {
        if let Some(raw) = std::env::var_os(var) {
            let mut p = std::path::PathBuf::from(raw);
            if let Some(s) = suffix {
                p.push(s);
            }
            if p.exists() {
                paths.push(p.to_string_lossy().into_owned());
            }
        }
    };
    // Per-user transient + ephemeral install areas — the #1 dropper
    // target on modern Windows.
    push_env("TEMP", None);
    push_env("TMP", None);
    push_env("APPDATA", None);
    push_env("LOCALAPPDATA", None);
    push_env("USERPROFILE", Some("Downloads"));
    push_env("USERPROFILE", Some("Desktop"));
    // Persistence: startup folders.
    push_env(
        "APPDATA",
        Some("Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
    );
    // System-wide drop zones.
    push_env("ProgramData", None);
    push_env("PUBLIC", Some("Downloads"));
    push_env("SystemRoot", Some("Temp"));
    // De-dupe exact matches (TEMP and TMP commonly resolve to the
    // same folder).
    paths.sort();
    paths.dedup();

    // Descendant de-dupe — the user reported Quick Scan visited more
    // files than a full `C:\` scan because the producer walks every
    // root and many of the hotspots overlap:
    //   * `%TEMP%` often lives inside `%LOCALAPPDATA%\Temp`
    //   * `%APPDATA%\…\Startup` lives inside `%APPDATA%`
    //   * `%TMP%` is typically identical to `%TEMP%`
    // Each overlap got enumerated twice and `files_total_running`
    // doubled. Sort by length so the *shortest* path wins, then drop
    // any later path that has a kept path as a prefix (case-folded on
    // Windows because the FS is case-insensitive).
    paths.sort_by_key(|p| p.len());
    let mut kept: Vec<String> = Vec::with_capacity(paths.len());
    let case_fold = |s: &str| -> String {
        if cfg!(windows) {
            s.to_ascii_lowercase()
        } else {
            s.to_string()
        }
    };
    let sep = std::path::MAIN_SEPARATOR;
    'outer: for candidate in paths.into_iter() {
        let folded = case_fold(&candidate);
        for parent in &kept {
            let parent_folded = case_fold(parent);
            let parent_with_sep = if parent_folded.ends_with(sep) {
                parent_folded.clone()
            } else {
                format!("{parent_folded}{sep}")
            };
            if folded == parent_folded || folded.starts_with(&parent_with_sep) {
                continue 'outer;
            }
        }
        kept.push(candidate);
    }
    Ok(kept)
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
    // Path validation (security review C2): canonicalize and reject
    // system-managed directories before the engine ever sees the
    // target. The frontend's free-text target input is not trusted.
    //
    // TASK-056 + sec-review H2 (Phase 5 wave 3): when the user opted
    // into `all_volumes`, the MultiVolumeWalker ignores the target
    // path and discovers every mounted volume on its own. We
    // **discard** any caller-supplied `target_path` entirely (a
    // compromised renderer might pass `/etc` here and observe the
    // sentinel in History; dropping it on the IPC boundary keeps the
    // path-policy gate meaningful end-to-end) and feed a fixed
    // sentinel into the engine. The walker never touches the sentinel
    // because `MultiVolumeWalker::all_volumes(true)` resolves roots
    // through `enumerate_volumes()` before reading the requested
    // path.
    // Registry/Process-only sweep: no file target needed. We feed
    // the engine a sentinel target and rely on `files_disabled` to
    // skip the walker entirely.
    let target = if request.files_disabled {
        // Review M4 — surface a human-readable target string in
        // History instead of the raw sentinel. The engine still
        // skips the walker via `include_files=false`; the path
        // itself is never opened.
        let label = match (request.include_registry, request.include_processes) {
            (true, true) => "<registry + process sweep>",
            (true, false) => "<registry sweep>",
            (false, true) => "<process sweep>",
            (false, false) => "<system sweep>",
        };
        ScanTarget::Path(PathBuf::from(label))
    } else if request.all_volumes {
        ScanTarget::Path(PathBuf::from("<all-volumes>"))
    } else if !request.extra_paths.is_empty() {
        // Phase 6 Quick Scan path — every hotspot is validated, then
        // bundled into a multi-path target. We also include the
        // primary `target_path` if it was supplied (defensive against
        // a future caller that passes both).
        //
        // Sec-review SEC-H1: cap the number of extra paths the
        // renderer can submit in one scan_start call. Quick Scan
        // generates ~10 paths in practice; anything past 64 is either
        // a misconfiguration or a malicious renderer trying to stall
        // the canonicalize loop. Reject loudly instead of silently
        // truncating so a future legitimate use case (e.g. user
        // multi-select) surfaces a clear error to add a UI cap.
        const MAX_EXTRA_PATHS: usize = 64;
        if request.extra_paths.len() > MAX_EXTRA_PATHS {
            return Err(format!(
                "scan_start: extra_paths length {} exceeds cap {}",
                request.extra_paths.len(),
                MAX_EXTRA_PATHS
            ));
        }
        let mut paths: Vec<PathBuf> = Vec::with_capacity(request.extra_paths.len() + 1);
        if !request.target_path.as_os_str().is_empty() {
            let canonical = validate_scan_target(&request.target_path).map_err(stringify)?;
            paths.push(canonical);
        }
        for p in &request.extra_paths {
            let canonical = validate_scan_target(p).map_err(stringify)?;
            paths.push(canonical);
        }
        ScanTarget::Paths(paths)
    } else {
        let canonical_target = validate_scan_target(&request.target_path).map_err(stringify)?;
        ScanTarget::Path(canonical_target)
    };
    // CRC32 fast-screen gate (TASK / CRC32 pre-screen). When the
    // Mythodikal-side feed-builder has published a `crc32_blacklist.bin`
    // to the feeds dir, hand its path to the engine so the scan
    // worker can skip BLAKE3 + SHA-256 + the detection pipeline on
    // files whose CRC32 isn't in the malware set (~99.977% miss
    // rate at 1M-sample gates). Absent file → fall back to the
    // legacy "hash every file" path (None).
    let crc32_gate_path = {
        let p = feeds_dir(&state.data_dir).join("crc32_blacklist.bin");
        if p.exists() { Some(p) } else { None }
    };
    let opts = ScanOptions {
        compute_sha256: request.compute_sha256,
        follow_symlinks: request.follow_symlinks,
        // Sec-review/code-review blocker R-B1: the TASK-134 partial-hash
        // toggle flows through here. Without this wire-up the engine
        // never emits `scan:partial_hash` from the Tauri app.
        emit_partial_hash: request.emit_partial_hash,
        // TASK-053 / TASK-056: multi-volume fan-out is opt-in via the
        // Scan dashboard's "scan all volumes" checkbox.
        all_volumes: request.all_volumes,
        // Phase 6 — Quick Scan / advanced scan flags.
        include_registry: request.include_registry,
        include_processes: request.include_processes,
        include_archives: request.include_archives,
        include_files: !request.files_disabled,
        run_heuristics: request.run_heuristics,
        crc32_gate_path,
        ..ScanOptions::default()
    };
    let handle = state.engine.scan(target, opts).map_err(stringify)?;
    let scan_id = handle.scan_id;
    let pause_flag = handle.pause_flag.clone();
    let cancel_flag = handle.cancel_flag.clone();
    if let Ok(mut flags) = state.active_pause_flags.lock() {
        flags.insert(scan_id, pause_flag);
    }
    if let Ok(mut flags) = state.active_cancel_flags.lock() {
        flags.insert(scan_id, cancel_flag);
    }
    let mut rx = handle.progress;
    let app_for_task = app.clone();
    let db_for_task = state.db.clone();
    let pause_flags_for_task = state.active_pause_flags.clone();
    let cancel_flags_for_task = state.active_cancel_flags.clone();
    tauri::async_runtime::spawn(async move {
        run_scan_event_forwarder(app_for_task, db_for_task, scan_id, &mut rx).await;
        // Forwarder exited — the scan is in a terminal state. Drop
        // both flags so the maps don't accrete dead entries.
        if let Ok(mut flags) = pause_flags_for_task.lock() {
            flags.remove(&scan_id);
        }
        if let Ok(mut flags) = cancel_flags_for_task.lock() {
            flags.remove(&scan_id);
        }
    });
    Ok(scan_id)
}

/// Pause a running scan. In-place pause — the worker pool and producer
/// thread spin-wait on the pause flag without writing a resume token
/// or tearing down state, so `scan_resume` is just a flag-flip away.
/// The flag is observed within ~50 ms by every worker and within
/// ~20 ms by the hash-abort watcher (so any in-flight big-file mmap
/// hash bails fast).
#[tauri::command]
pub async fn scan_pause(state: State<'_, AppState>, scan_id: ScanId) -> Result<(), String> {
    let flag = {
        let flags = state
            .active_pause_flags
            .lock()
            .map_err(|_| "pause flag map poisoned".to_string())?;
        flags
            .get(&scan_id)
            .cloned()
            .ok_or_else(|| format!("scan {scan_id} is not running"))?
    };
    flag.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Resume a paused scan. In-place — just clears the pause flag; the
/// already-running workers wake up from their 50 ms spin-wait and
/// continue with the next item in the bounded channel. The scan_id
/// is unchanged.
#[tauri::command]
pub async fn scan_resume(
    _app: AppHandle,
    state: State<'_, AppState>,
    scan_id: ScanId,
) -> Result<ScanId, String> {
    let flag = {
        let flags = state
            .active_pause_flags
            .lock()
            .map_err(|_| "pause flag map poisoned".to_string())?;
        flags
            .get(&scan_id)
            .cloned()
            .ok_or_else(|| format!("scan {scan_id} has no live pause flag — cannot resume"))?
    };
    flag.store(false, std::sync::atomic::Ordering::Relaxed);
    Ok(scan_id)
}

/// Drains the scan's broadcast receiver and forwards events to the UI.
///
/// Three safety properties beyond a naive 1:1 forwarder
/// (BLOCKER fixes from the code review):
///
/// 1. **Throttle `scan:progress`** to ≤ 10 Hz per PRD § 4.2 / FR-085.
///    Per-file events arrive at kHz on a hot scan; emitting them 1:1
///    drowns the renderer in postMessage. We coalesce by retaining
///    the *last* File event in a window and emitting it on the next
///    tick.
/// 2. **Always emit a terminal event** (`scan:completed` /
///    `scan:failed`). The broadcast channel can drop messages on lag;
///    if the terminal event is among them, the UI's running-state
///    signal never clears. After receiving `Closed` we re-read the
///    scans row and synthesize a terminal event from the DB so the
///    UI always sees one.
/// 3. **Findings and errors pass through unthrottled.** They're
///    low-rate and time-sensitive (the user wants to see "you have
///    malware" the instant it's detected).
async fn run_scan_event_forwarder(
    app: AppHandle,
    db: Arc<Mutex<Connection>>,
    scan_id: ScanId,
    rx: &mut tokio::sync::broadcast::Receiver<ScanProgress>,
) {
    const THROTTLE_MS: u64 = 100;
    let mut last_file_emit =
        tokio::time::Instant::now() - tokio::time::Duration::from_millis(THROTTLE_MS);
    let mut pending_file: Option<ScanProgress> = None;
    let mut terminal_sent = false;

    loop {
        // Wake on either the channel or the throttle timer, whichever
        // fires first. This guarantees a pending File event eventually
        // surfaces even if the channel goes idle.
        let timeout = tokio::time::Duration::from_millis(THROTTLE_MS);
        let recv = tokio::time::timeout(timeout, rx.recv()).await;

        match recv {
            Ok(Ok(event)) => {
                let terminal = matches!(
                    &event,
                    ScanProgress::Completed { .. }
                        | ScanProgress::Failed { .. }
                        | ScanProgress::Paused { .. }
                        | ScanProgress::Cancelled { .. }
                );

                if matches!(&event, ScanProgress::File { .. }) {
                    pending_file = Some(event);
                    maybe_flush_file(&app, &mut pending_file, &mut last_file_emit, THROTTLE_MS);
                } else {
                    // Flush any pending File event before non-File so the
                    // UI never sees "Finding for path X" followed by "scan
                    // progress for path Y < X".
                    flush_file(&app, &mut pending_file, &mut last_file_emit);

                    let topic = match &event {
                        ScanProgress::Started { .. } => "scan:started",
                        ScanProgress::File { .. } => unreachable!(),
                        ScanProgress::Finding { .. } => "scan:finding",
                        ScanProgress::Error { .. } => "scan:error",
                        ScanProgress::Completed { .. } => "scan:completed",
                        ScanProgress::Failed { .. } => "scan:failed",
                        ScanProgress::Paused { .. } => "scan:paused",
                        ScanProgress::Cancelled { .. } => "scan:cancelled",
                        ScanProgress::PartialHash { .. } => "scan:partial_hash",
                        // TASK-137 — fires exactly once per scan when
                        // the producer locks Y; UI swaps from
                        // three-piece to X/Y presentation here.
                        ScanProgress::EnumerationComplete { .. } => "scan:enumeration_complete",
                        // Phase 6 — registry sweep events.
                        ScanProgress::RegistryPhaseStarted { .. } => "scan:registry_phase_started",
                        ScanProgress::RegistryProgress { .. } => "scan:registry_progress",
                        ScanProgress::RegistryPhaseComplete { .. } => {
                            "scan:registry_phase_complete"
                        }
                        // Phase 6 — process sweep events.
                        ScanProgress::ProcessPhaseStarted { .. } => "scan:process_phase_started",
                        ScanProgress::ProcessProgress { .. } => "scan:process_progress",
                        ScanProgress::ProcessPhaseComplete { .. } => "scan:process_phase_complete",
                        ScanProgress::ArchiveEntry { .. } => "scan:archive_entry",
                        ScanProgress::HeuristicPhaseStarted { .. } => {
                            "scan:heuristic_phase_started"
                        }
                        ScanProgress::HeuristicProgress { .. } => "scan:heuristic_progress",
                        ScanProgress::HeuristicPhaseComplete { .. } => {
                            "scan:heuristic_phase_complete"
                        }
                    };
                    if let Err(err) = app.emit(topic, &event) {
                        tracing::warn!(error = %err, "tauri emit failed");
                    }
                    if terminal {
                        terminal_sent = true;
                        break;
                    }
                }
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                tracing::warn!(
                    lagged_events = n,
                    "scan progress channel lagged; will reconcile on close"
                );
            }
            Err(_timeout) => {
                // No event this window — flush any pending File event so
                // the UI sees periodic motion.
                maybe_flush_file(&app, &mut pending_file, &mut last_file_emit, THROTTLE_MS);
            }
        }
    }

    if !terminal_sent {
        // Channel closed without a terminal event — possibly because
        // Completed/Failed was dropped on lag. Re-read the scan row and
        // synthesize whichever terminal event matches the DB's final
        // state so the UI never hangs in `running`.
        if let Ok(conn) = db.lock() {
            if let Ok((status, files_visited, files_hashed, bytes_visited, findings_count)) = conn
                .query_row(
                    "SELECT status, files_visited, files_hashed, bytes_visited,
                            findings_count FROM scans WHERE id = ?1",
                    [scan_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, i64>(4)?,
                        ))
                    },
                )
            {
                let synthetic = if status == "completed" {
                    ScanProgress::Completed {
                        scan_id,
                        files_visited,
                        files_hashed,
                        bytes_visited,
                        findings_count,
                        duration_ms: 0,
                    }
                } else {
                    ScanProgress::Failed {
                        scan_id,
                        message: format!(
                            "scan ended with status `{status}`; terminal progress event may have been dropped"
                        ),
                    }
                };
                let topic = match &synthetic {
                    ScanProgress::Completed { .. } => "scan:completed",
                    _ => "scan:failed",
                };
                let _ = app.emit(topic, &synthetic);
            }
        }
    }
}

fn maybe_flush_file(
    app: &AppHandle,
    pending: &mut Option<ScanProgress>,
    last_emit: &mut tokio::time::Instant,
    throttle_ms: u64,
) {
    if pending.is_none() {
        return;
    }
    let elapsed = tokio::time::Instant::now().duration_since(*last_emit);
    if elapsed >= tokio::time::Duration::from_millis(throttle_ms) {
        flush_file(app, pending, last_emit);
    }
}

fn flush_file(
    app: &AppHandle,
    pending: &mut Option<ScanProgress>,
    last_emit: &mut tokio::time::Instant,
) {
    if let Some(event) = pending.take() {
        if let Err(err) = app.emit("scan:progress", &event) {
            tracing::warn!(error = %err, "tauri emit failed (throttled file)");
        }
        *last_emit = tokio::time::Instant::now();
    }
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

/// Cancel a scan. Wave 2 (TASK-040): we use the same pause flag — the
/// worker exits cleanly on next iteration and the row is marked paused;
/// the caller then deletes the row to fully discard. A first-class
/// `cancelled` terminal state with full cleanup lands in a later wave;
/// for now `scan_pause` is the recommended graceful exit, and clients
/// can call `scan_pause` + ignore the resume token to achieve cancel.
#[tauri::command]
pub async fn scan_cancel(state: State<'_, AppState>, scan_id: ScanId) -> Result<(), String> {
    // Real cancel — distinct from pause. The worker observes the
    // cancel flag (also via the hasher's mid-chunk abort), marks the
    // scans row `cancelled`, and emits `ScanProgress::Cancelled`. No
    // resume token is persisted; the scan cannot be resumed.
    let flag = {
        let flags = state
            .active_cancel_flags
            .lock()
            .map_err(|_| "cancel flag map poisoned".to_string())?;
        flags
            .get(&scan_id)
            .cloned()
            .ok_or_else(|| format!("scan {scan_id} is not running"))?
    };
    flag.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

// ============================================================================
// History
// ============================================================================

/// Wipe every row from `findings` + `scans`. Used by the History
/// page's "Clear history" button. Doesn't touch the `quarantine`
/// vault — quarantined files stay quarantined; only the scan
/// metadata + finding rows disappear. Returns the number of scan
/// rows that were deleted so the UI can show a confirmation.
#[tauri::command]
pub async fn history_clear(state: State<'_, AppState>) -> Result<usize, String> {
    let conn = state
        .db
        .lock()
        .map_err(|_| "db lock poisoned".to_string())?;
    // Order matters: `findings.scan_id` references `scans.id`, so
    // findings rows must be deleted first to satisfy the FK
    // constraint. SQLite would otherwise error with FOREIGN KEY
    // failed.
    let _ = conn
        .execute("DELETE FROM findings", [])
        .map_err(stringify)?;
    let scans_deleted = conn.execute("DELETE FROM scans", []).map_err(stringify)?;
    // Sec-clean: also wipe the verdict_cache so the next scan does a
    // fresh hash + pipeline pass on every file (the user clearing
    // history typically wants a fully clean slate).
    let _ = conn.execute("DELETE FROM verdict_cache", []);
    Ok(scans_deleted)
}

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
            // Path-policy gate (security review H1): the row's `path`
            // was set by the engine from the walker, but a tampered
            // SQLite file could redirect the quarantine op. Validate
            // before invoking the vault.
            let finding = findings::get(&conn, finding_id).map_err(stringify)?;
            let path = std::path::PathBuf::from(&finding.path);
            validate_scan_target(&path).map_err(stringify)?;
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
                // Same path-policy gate as `quarantine_restore` —
                // the row's original_path is not trusted blindly.
                let entry = state.vault.get(&conn, qid).map_err(stringify)?;
                validate_restore_target(&entry.original_path).map_err(stringify)?;
                state.vault.restore(&mut conn, qid).map_err(stringify)?;
            }
        }
        (KernelAction::Delete, _) => {
            // If quarantined, shred the vault file too. Delete is safe
            // without a path gate — we're only unlinking from the vault
            // dir, not writing user-controlled paths.
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
    // Path-policy gate (security review C1): the row's `original_path`
    // is trusted only after passing this check. If the DB was tampered
    // with to redirect the restore at a system directory, refuse here
    // before the vault unbundles the XOR'd content.
    let entry = state.vault.get(&conn, id).map_err(stringify)?;
    validate_restore_target(&entry.original_path).map_err(stringify)?;
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

    // Repo-curated DB (2026-06-21): the raw abuse.ch upstream pull is
    // disabled. The curated blacklist is delivered as a verified `.bin` on
    // the GitHub release and refreshed by the database update channel
    // (Settings → Updates → Virus database / `updater_db_check_now`). A
    // legacy caller that still passes a key gets a clear, non-fatal
    // explanation here rather than a silent upstream fetch.
    if abusech_auth_key
        .as_deref()
        .map(|k| !k.trim().is_empty())
        .unwrap_or(false)
    {
        results.push(FeedUpdateResult {
            feed_id: "abusech".to_string(),
            parsed_count: 0,
            merged_count: 0,
            elapsed_ms: 0,
            error: Some(
                "abuse.ch upstream pull is disabled — the curated blacklist is delivered via the \
                 GitHub release; use Settings → Updates → Virus database to refresh it."
                    .to_string(),
            ),
        });
    }

    let nsrl_source = match (nsrl_local, nsrl_url) {
        (Some(p), _) => Some(NsrlSource::Local(p)),
        (_, Some(u)) => {
            // Security review L1: refuse non-HTTPS URLs. The renderer
            // can pass arbitrary strings through Tauri IPC; if a
            // future XSS or capability widening lets attacker control
            // this arg, http://attacker/ becomes an injection point
            // for the goodware allowlist (which would *suppress*
            // detection of every file in the attacker's payload).
            if !u.starts_with("https://") {
                return Err(format!(
                    "nsrl_url must be https:// (got `{}`). Per docs/prd.md § 1.5 NSRL fetches go through rustls — no plain HTTP.",
                    u
                ));
            }
            Some(NsrlSource::Url(u))
        }
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
/// TASK-132: extended to include per-feed last-updated timestamps so
/// the About page can render "Last updated 2 h ago" per source.
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
    let mtime_for = |name: &str| -> Option<i64> {
        let path = feeds_dir.join(name);
        if !path.exists() {
            return None;
        }
        std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
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
        abusech_last_updated_utc: mtime_for("abusech_sha256.bin"),
        nsrl_last_updated_utc: mtime_for("nsrl_sha256.bin"),
    }
}

#[tauri::command]
pub async fn settings_get(state: State<'_, AppState>) -> Result<SettingsSnapshot, String> {
    let definitions = compute_definition_count(&state.data_dir);
    let cfg = state
        .config
        .lock()
        .map_err(|_| "config lock poisoned".to_string())?
        .clone();
    Ok(SettingsSnapshot {
        general: GeneralSettings {
            // OS-state mirrors (FR-161 autostart, FR-162 tray) are not
            // owned by config.toml — they live in the OS (registry,
            // SMAppService, .desktop file). Phase 4 wave 1 surfaces a
            // safe default; TASK-157/158 will replace these with reads
            // from the actual OS state.
            start_with_os: false,
            show_tray_icon: true,
            close_action: cfg.general.close_action.clone(),
        },
        privacy: PrivacySettings {
            telemetry_enabled: cfg.telemetry.enabled,
        },
        scanning: ScanningSettings {
            archives_enabled: cfg.scanning.archives_enabled,
            follow_symlinks: cfg.scanning.follow_symlinks,
            skip_hidden: cfg.scanning.skip_hidden,
        },
        about: AboutInfo {
            engine_version: state.engine_version.clone(),
            definition_count: definitions,
        },
    })
}

/// Merge a partial patch into the live config and persist. Each section
/// is optional; within a section each field is optional. We never write
/// disk unless at least one field actually changed.
#[tauri::command]
pub async fn settings_update(
    state: State<'_, AppState>,
    patch: SettingsPatch,
) -> Result<(), String> {
    let path = state.config_path.clone();
    let mut guard = state
        .config
        .lock()
        .map_err(|_| "config lock poisoned".to_string())?;
    let before = guard.clone();
    if let Some(g) = patch.general {
        if let Some(action) = g.close_action {
            // Whitelist: only the two documented values reach config.
            // Anything else is rejected so a malicious frontend can't
            // store an arbitrary string here.
            match action.as_str() {
                "minimize_to_tray" | "quit" => guard.general.close_action = action,
                other => {
                    return Err(format!(
                        "invalid close_action: {other:?} (expected minimize_to_tray | quit)"
                    ));
                }
            }
        }
        // start_with_os and show_tray_icon are OS-state and are not
        // persisted to config.toml — TASK-157/158 will route them to
        // the Tauri autostart plugin + tray builder. Silently ignore
        // here so the frontend can send the full GeneralPatch shape.
    }
    if let Some(p) = patch.privacy
        && let Some(t) = p.telemetry_enabled
    {
        guard.telemetry.enabled = t;
    }
    if let Some(s) = patch.scanning {
        if let Some(v) = s.archives_enabled {
            guard.scanning.archives_enabled = v;
        }
        if let Some(v) = s.follow_symlinks {
            guard.scanning.follow_symlinks = v;
        }
        if let Some(v) = s.skip_hidden {
            guard.scanning.skip_hidden = v;
        }
    }
    let dirty = !configs_equal(&before, &guard);
    if !dirty {
        return Ok(());
    }
    let snapshot = guard.clone();
    drop(guard);
    mythkernel::config::save(&path, &snapshot).map_err(stringify)?;
    tracing::info!(
        "settings_update persisted to {}: {} field group(s) changed",
        path.display(),
        section_change_count(&before, &snapshot),
    );
    Ok(())
}

/// Tiny structural-equality helper. `Config` doesn't derive `PartialEq`
/// (its nested vecs/maps could grow), so we compare on the fields the
/// patch can actually touch.
fn configs_equal(a: &mythkernel::config::Config, b: &mythkernel::config::Config) -> bool {
    a.general.close_action == b.general.close_action
        && a.telemetry.enabled == b.telemetry.enabled
        && a.scanning.archives_enabled == b.scanning.archives_enabled
        && a.scanning.follow_symlinks == b.scanning.follow_symlinks
        && a.scanning.skip_hidden == b.scanning.skip_hidden
}

fn section_change_count(a: &mythkernel::config::Config, b: &mythkernel::config::Config) -> usize {
    let g = (a.general.close_action != b.general.close_action) as usize;
    let p = (a.telemetry.enabled != b.telemetry.enabled) as usize;
    let s = ((a.scanning.archives_enabled != b.scanning.archives_enabled) as usize)
        + ((a.scanning.follow_symlinks != b.scanning.follow_symlinks) as usize)
        + ((a.scanning.skip_hidden != b.scanning.skip_hidden) as usize);
    g + p + s
}

#[tauri::command]
pub async fn engine_version(state: State<'_, AppState>) -> Result<EngineVersionInfo, String> {
    Ok(EngineVersionInfo {
        version: state.engine_version.clone(),
    })
}

/// Read the most-recent scheduled-feed run summary (TASK-043). Returns
/// `None` when the scheduler has not yet completed a cycle (first run,
/// or no feeds configured).
#[tauri::command]
pub async fn updater_status(
    state: State<'_, AppState>,
) -> Result<Option<UpdaterStatusView>, String> {
    let feeds_dir = feeds_dir(&state.data_dir);
    Ok(
        mythkernel::updater::scheduler::read_last_run(&feeds_dir).map(|r| UpdaterStatusView {
            started_at_utc: r.started_at_utc,
            finished_at_utc: r.finished_at_utc,
            outcome: r.outcome,
            detail: r.detail,
            next_run_at_utc: r.next_run_at_utc,
        }),
    )
}

// ============================================================================
// Exclusions (FR-060/061/062/134, TASK-042)
// ============================================================================

#[tauri::command]
pub async fn exclusion_list(state: State<'_, AppState>) -> Result<Vec<ExclusionView>, String> {
    let conn = state
        .db
        .lock()
        .map_err(|_| "db lock poisoned".to_string())?;
    let rows = exclusions::list(&conn).map_err(stringify)?;
    Ok(rows.into_iter().map(to_exclusion_view).collect())
}

#[tauri::command]
pub async fn exclusion_add(
    state: State<'_, AppState>,
    request: ExclusionRequest,
) -> Result<ExclusionView, String> {
    let kind: ExclusionKind = request.kind.parse().map_err(stringify)?;
    let scope: ExclusionScope = request.scope.parse().map_err(stringify)?;
    let conn = state
        .db
        .lock()
        .map_err(|_| "db lock poisoned".to_string())?;
    let id = exclusions::add(
        &conn,
        kind,
        &request.value,
        scope,
        request.expires_at_utc,
        request.reason.as_deref(),
    )
    .map_err(stringify)?;
    let row = exclusions::get(&conn, id).map_err(stringify)?;
    Ok(to_exclusion_view(row))
}

#[tauri::command]
pub async fn exclusion_remove(state: State<'_, AppState>, id: i64) -> Result<(), String> {
    let conn = state
        .db
        .lock()
        .map_err(|_| "db lock poisoned".to_string())?;
    exclusions::remove(&conn, id).map_err(stringify)
}

fn to_exclusion_view(e: exclusions::Exclusion) -> ExclusionView {
    ExclusionView {
        id: e.id,
        kind: e.kind.as_str().to_string(),
        value: e.value,
        scope: e.scope.as_str().to_string(),
        expires_at_utc: e.expires_at_utc,
        created_at_utc: e.created_at_utc,
        reason: e.reason,
    }
}

// ============================================================================
// Updater channels (TASK-129/130/131/132/133)
// ============================================================================

/// Read the engine channel's persisted state (last check, last install,
/// auto-update toggle, channel name).
#[tauri::command]
pub async fn updater_engine_state(
    state: State<'_, AppState>,
) -> Result<UpdateChannelStateView, String> {
    let s = state.updater_engine.load_state();
    Ok(channel_state_to_view(&s, "engine"))
}

/// Trigger an HTTPS probe of the engine `latest.json` (TASK-130).
/// Returns `Some(...)` when a newer version is published, `None` when
/// up-to-date. Persisted state is updated inside
/// [`EngineChannel::check_for_updates`] — this fn is a thin wrapper.
#[tauri::command]
pub async fn updater_engine_check_now(
    state: State<'_, AppState>,
) -> Result<Option<EngineUpdateAvailableView>, String> {
    let channel = state.updater_engine.clone();
    channel
        .check_for_updates()
        .await
        .map(|opt| opt.map(engine_update_to_view))
        .map_err(stringify)
}

/// Toggle the engine channel's auto-update flag. Persisted to disk.
#[tauri::command]
pub async fn updater_engine_set_auto(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<(), String> {
    let channel = state.updater_engine.clone();
    let mut current = channel.load_state();
    current.auto_update_enabled = enabled;
    channel.save_state(&current).map_err(stringify)?;
    Ok(())
}

/// Read the database channel's persisted state including the per-feed
/// metadata map (TASK-131 / TASK-132).
#[tauri::command]
pub async fn updater_db_state(
    state: State<'_, AppState>,
) -> Result<DatabaseChannelStateView, String> {
    let s = state.updater_db.load_state();
    let mut feeds: Vec<FeedMetaView> = s
        .feeds
        .iter()
        .map(|(id, meta)| FeedMetaView {
            feed_id: id.clone(),
            last_check_at_utc: meta.last_check_at_utc,
            last_install_at_utc: meta.last_install_at_utc,
            entry_count: meta.entry_count,
            last_outcome: meta.last_outcome.clone(),
            last_error: meta.last_error.clone(),
        })
        .collect();
    feeds.sort_by(|a, b| a.feed_id.cmp(&b.feed_id));
    Ok(DatabaseChannelStateView {
        state: channel_state_to_view(&s.common, "database"),
        feeds,
    })
}

/// Run one cycle of the database channel. Emits
/// `db_update:progress` events along the way. Returns the post-cycle
/// state directly (code-review CR-I8: avoids the TOCTOU window between
/// `run_once` finishing and a follow-up `updater_db_state` read).
///
/// Per FR-156 there is no client-side rate limit — the user may invoke
/// this as often as they like.
#[tauri::command]
pub async fn updater_db_check_now(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<DatabaseChannelStateView, String> {
    let channel = state.updater_db.clone();
    let app_for_cb = app.clone();
    let progress: DbProgressCallback = Arc::new(move |p: DatabaseUpdateProgress| {
        let payload = DatabaseUpdateProgressEvent {
            feed_id: p.feed_id,
            phase: p.phase.as_str().to_string(),
            bytes_done: p.bytes_done,
            bytes_total: p.bytes_total,
            message: p.message,
        };
        if let Err(err) = app_for_cb.emit("db_update:progress", &payload) {
            tracing::warn!(error = %err, "tauri emit (db_update:progress) failed");
        }
    });
    let post = channel.run_once(progress).await;
    let mut feeds: Vec<FeedMetaView> = post
        .feeds
        .iter()
        .map(|(id, meta)| FeedMetaView {
            feed_id: id.clone(),
            last_check_at_utc: meta.last_check_at_utc,
            last_install_at_utc: meta.last_install_at_utc,
            entry_count: meta.entry_count,
            last_outcome: meta.last_outcome.clone(),
            last_error: meta.last_error.clone(),
        })
        .collect();
    feeds.sort_by(|a, b| a.feed_id.cmp(&b.feed_id));
    Ok(DatabaseChannelStateView {
        state: channel_state_to_view(&post.common, "database"),
        feeds,
    })
}

/// Toggle the database channel's auto-update flag. Persisted.
#[tauri::command]
pub async fn updater_db_set_auto(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    let channel = state.updater_db.clone();
    let mut current = channel.load_state();
    current.common.auto_update_enabled = enabled;
    channel.save_state(&current).map_err(stringify)?;
    Ok(())
}

fn channel_state_to_view(s: &ChannelState, kind: &str) -> UpdateChannelStateView {
    UpdateChannelStateView {
        kind: kind.to_string(),
        auto_update_enabled: s.auto_update_enabled,
        channel: s.channel.clone(),
        interval_hours: s.interval_hours,
        last_check_at_utc: s.last_check_at_utc,
        last_install_at_utc: s.last_install_at_utc,
        last_outcome: outcome_to_wire(s.last_outcome),
        last_error: s.last_error.clone(),
    }
}

fn outcome_to_wire(o: mythkernel::updater::channels::LastCheckOutcome) -> String {
    use mythkernel::updater::channels::LastCheckOutcome::*;
    match o {
        Never => "never",
        UpToDate => "up_to_date",
        UpdateAvailable => "update_available",
        Installed => "installed",
        Failed => "failed",
    }
    .to_string()
}

fn engine_update_to_view(u: EngineUpdateAvailable) -> EngineUpdateAvailableView {
    EngineUpdateAvailableView {
        current_version: u.current_version,
        latest_version: u.latest_version,
        release_url: u.release_url,
        release_notes: u.release_notes,
        published_at_utc: u.published_at_utc,
    }
}

// ============================================================================
// Publisher whitelist (FR-146 / TASK-136)
// ============================================================================

/// Extract the signer identity for a single file path. Used by the
/// Exclusions UI's "Add publisher exclusion from signed file" workflow.
/// The path is canonicalized + system-path-policy-checked before the
/// signer extractor shells out, matching `scan_start`'s gate.
///
/// Three-phase cache pattern (code-review CR-B2): hold the DB lock for
/// the cache lookup, release for the shell-out, re-acquire for the
/// cache store. This keeps `scan_status` polling responsive while a
/// "Probe signer" button is in flight.
#[tauri::command]
pub async fn publisher_signer_for_path(
    state: State<'_, AppState>,
    path: PathBuf,
) -> Result<PublisherView, String> {
    let canonical = validate_scan_target(&path).map_err(stringify)?;
    let probe = {
        let conn = state
            .db
            .lock()
            .map_err(|_| "db lock poisoned".to_string())?;
        publisher::cache_lookup(&conn, &canonical).map_err(stringify)?
    };
    let signer = match probe.cached.clone() {
        Some(s) => s,
        None => {
            let extracted = publisher::extract_io_unlocked(&canonical);
            let conn = state
                .db
                .lock()
                .map_err(|_| "db lock poisoned".to_string())?;
            publisher::cache_store(&conn, &probe, &extracted).map_err(stringify)?;
            extracted
        }
    };
    Ok(PublisherView {
        path: canonical.to_string_lossy().to_string(),
        identity: signer.identity,
        kind: signer.kind.as_str().to_string(),
    })
}

/// Manually trigger the publisher cache prune (TASK-136 / sec-review M5).
/// Returns the number of rows removed. Defaults are documented on
/// `publisher::DEFAULT_CACHE_PURGE_AGE_SECS` and
/// `DEFAULT_CACHE_PURGE_MAX_ROWS`.
#[tauri::command]
pub async fn publisher_prune_cache(state: State<'_, AppState>) -> Result<u64, String> {
    let conn = state
        .db
        .lock()
        .map_err(|_| "db lock poisoned".to_string())?;
    publisher::prune_cache(
        &conn,
        publisher::DEFAULT_CACHE_PURGE_AGE_SECS,
        publisher::DEFAULT_CACHE_PURGE_MAX_ROWS,
    )
    .map_err(stringify)
}

// ============================================================================
// Shields (FR-160 / TASK-156)
// ============================================================================

#[tauri::command]
pub async fn shields_get(state: State<'_, AppState>) -> Result<ShieldsState, String> {
    Ok(state.shields.get())
}

/// `enabled = true` clears any pause. `enabled = false` + pause_minutes
/// = None is the "until I turn it back on" form; Some(n) schedules an
/// auto-resume at now + n minutes. Emits `shields:changed` event.
#[tauri::command]
pub async fn shields_set(
    app: AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
    pause_minutes: Option<u32>,
) -> Result<ShieldsState, String> {
    let next = state
        .shields
        .set(enabled, pause_minutes, ShieldsActor::Ui)
        .map_err(stringify)?;
    if let Err(err) = app.emit("shields:changed", &next) {
        tracing::warn!(error = %err, "tauri emit (shields:changed) failed");
    }
    Ok(next)
}

// ============================================================================
// Helpers
// ============================================================================

pub(crate) fn stringify<E: std::fmt::Display>(e: E) -> String {
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
        kind: r.kind.into(),
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
            kind: p.kind.into(),
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

    // Built-in: EICAR test signature. Always loaded — no feed
    // download required. Verifies detection works end-to-end (drop
    // the canonical EICAR string into a `.txt` and scan).
    detectors.push(Box::new(mythkernel::detect::eicar::EicarDetector::new()));
    tracing::info!("loaded built-in EICAR test detector");

    // YARA rule pack (Phase 7 / commercial-friendly detection). Loads
    // every `.yar` / `.yara` file in `<feeds_dir>/yara_rules/` plus
    // one level of subdirs. Public packs like
    // Neo23x0/signature-base land here. Detector is registered only
    // when at least one rule compiled — skipping the registration
    // entirely when there are no rules avoids paying a fs::read +
    // scan cost per file for a no-op.
    let yara_dir = feeds_dir.join("yara_rules");
    if let Some(yara) = mythkernel::detect::yara_engine::YaraDetector::from_dir(&yara_dir) {
        tracing::info!(yara_rules = yara.rule_count(), "loaded YARA rule pack");
        detectors.push(Box::new(yara));
    }

    // TASK-183 — load the per-OS NSRL slice when present; fall back
    // to the union .bin when the per-OS variants aren't downloaded.
    // Multiple slices may be loaded as parallel detector instances
    // (host-OS slice + the cross-platform `_other` slice).
    for nsrl_path in mythkernel::detect::goodware_allowlist::resolve_nsrl_slice_paths(&feeds_dir) {
        match GoodwareAllowlistDetector::open(&nsrl_path) {
            Ok(d) => {
                tracing::info!(
                    feed = "nsrl",
                    path = %nsrl_path.display(),
                    count = d.loaded_count(),
                    "loaded NSRL goodware allowlist slice"
                );
                detectors.push(Box::new(d.with_hash_kind(HashKind::Sha256)));
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    path = %nsrl_path.display(),
                    "NSRL slice load failed"
                );
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

/// Single-call helper to wire every Phase-3 + Phase 8 command into a
/// `tauri::Builder`. The app uses this in `lib.rs::run` so we don't
/// have to maintain two lists.
///
/// **Tauri v2 quirk:** `.invoke_handler()` can only be called **once**
/// per builder — a second call replaces the first. App-level commands
/// (defined in `apps/mythodikal/src-tauri/src/lib.rs`) are passed in
/// as extra arguments so we land in one generate_handler! call.
///
/// Usage:
/// ```ignore
/// builder.invoke_handler(ui_bridge::invoke_handler!(
///     engine_install_update,
///     autostart_get,
///     /* …app-level commands… */
/// ));
/// ```
#[macro_export]
macro_rules! invoke_handler {
    ($($app_cmd:path),* $(,)?) => {
        ::tauri::generate_handler![
            $crate::commands::scan_start,
            $crate::commands::scan_status,
            $crate::commands::scan_cancel,
            $crate::commands::scan_pause,
            $crate::commands::scan_resume,
            $crate::commands::history_list,
            $crate::commands::history_get,
            $crate::commands::history_clear,
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
            $crate::commands::updater_status,
            $crate::commands::shields_get,
            $crate::commands::shields_set,
            $crate::commands::exclusion_list,
            $crate::commands::exclusion_add,
            $crate::commands::exclusion_remove,
            $crate::commands::updater_engine_state,
            $crate::commands::updater_engine_check_now,
            $crate::commands::updater_engine_set_auto,
            $crate::commands::updater_db_state,
            $crate::commands::updater_db_check_now,
            $crate::commands::updater_db_set_auto,
            $crate::commands::publisher_signer_for_path,
            $crate::commands::publisher_prune_cache,
            $crate::commands::enumerate_volumes,
            $crate::commands::quick_scan_paths,
            $crate::commands::first_run_get,
            $crate::commands::first_run_set,
            // Phase 8 Wave 2 — USB stack + per-mount toggle.
            $crate::commands_usb::usb_allowlist_list,
            $crate::commands_usb::usb_allowlist_add,
            $crate::commands_usb::usb_allowlist_remove,
            $crate::commands_usb::usb_power_only_list,
            $crate::commands_usb::usb_power_only_enable,
            $crate::commands_usb::usb_power_only_disable,
            $crate::commands_usb::usb_write_events,
            $crate::commands_usb::usb_devices,
            $crate::commands_mount::realtime_mounts_list,
            $crate::commands_mount::set_mount_enabled,
            $crate::commands_mount::wsl_list_distros,
            // Phase 9 — macOS surface (mode, exemptions, heartbeat).
            $crate::commands_mac::mac_realtime_mode,
            $crate::commands_mac::mac_exemption_list,
            $crate::commands_mac::mac_exemption_add,
            $crate::commands_mac::mac_exemption_remove,
            $crate::commands_mac::mac_heartbeat,
            $($app_cmd),*
        ]
    };
}
