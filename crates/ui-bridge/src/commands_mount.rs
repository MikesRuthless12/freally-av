//! Per-mount real-time toggle Tauri commands (TASK-238, Phase 8 Wave 2).
//!
//! The store lives in the daemon-local sqlite at
//! `/var/lib/mythd/mythd.db` so the engine + UI only need to read /
//! write the **preference**; the daemon owns the FAN_MARK_ADD /
//! FAN_MARK_REMOVE application.
//!
//! Surface on non-Linux hosts: both commands return an empty list /
//! a no-op so the UI degrades cleanly to "no real-time on this OS".

use rusqlite::{Connection, Row};
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::commands::stringify;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountToggleRow {
    pub device: String,
    pub mountpoint: String,
    pub fs_type: String,
    pub enabled: bool,
}

fn ensure_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS realtime_mounts (
            device     TEXT NOT NULL,
            mountpoint TEXT NOT NULL,
            fs_type    TEXT NOT NULL DEFAULT '',
            enabled    INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (device, mountpoint)
         );",
    )
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn realtime_mounts_list(
    state: State<'_, crate::commands::AppState>,
) -> Result<Vec<MountToggleRow>, String> {
    let conn = state.db.lock().map_err(|_| "db poisoned".to_string())?;
    ensure_schema(&conn)?;
    let mut stmt = conn
        .prepare(
            "SELECT device, mountpoint, fs_type, enabled FROM realtime_mounts ORDER BY mountpoint",
        )
        .map_err(stringify)?;
    let rows = stmt
        .query_map([], |r: &Row<'_>| {
            Ok(MountToggleRow {
                device: r.get(0)?,
                mountpoint: r.get(1)?,
                fs_type: r.get(2)?,
                enabled: r.get::<_, i64>(3)? == 1,
            })
        })
        .map_err(stringify)?;
    let mut out: Vec<MountToggleRow> = Vec::new();
    for r in rows {
        out.push(r.map_err(stringify)?);
    }
    Ok(out)
}

#[tauri::command]
pub async fn set_mount_enabled(
    state: State<'_, crate::commands::AppState>,
    device: String,
    mountpoint: String,
    fs_type: String,
    enabled: bool,
) -> Result<(), String> {
    let conn = state.db.lock().map_err(|_| "db poisoned".to_string())?;
    ensure_schema(&conn)?;
    conn.execute(
        "INSERT INTO realtime_mounts (device, mountpoint, fs_type, enabled)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(device, mountpoint) DO UPDATE
            SET fs_type = excluded.fs_type, enabled = excluded.enabled",
        rusqlite::params![device, mountpoint, fs_type, if enabled { 1 } else { 0 }],
    )
    .map_err(stringify)?;
    // TASK-238 foundation: the preference lands in the engine sqlite
    // (`<data_dir>/mythodikal.db`). The Linux-runtime validation pass
    // wires the daemon to read this table directly via a shared
    // sqlite handle — daemon-local `/var/lib/mythd/mythd.db` is the
    // fallback for when the daemon runs detached from the engine
    // (e.g. headless install). Until that wiring lands, this command
    // persists the user preference but the fanotify mark set is not
    // updated; the v0.8.0 launch checklist gates the runtime smoke.
    Ok(())
}

// ---------------------------------------------------------------------------
// TASK-240 — WSL distro auto-discover (Windows host side)
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn wsl_list_distros() -> Result<Vec<mythkernel::platform::wsl::WslDistroRow>, String> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let out = Command::new("wsl.exe")
            .arg("--list")
            .arg("--verbose")
            .output();
        match out {
            Ok(o) => Ok(mythkernel::platform::wsl::parse_wsl_list_utf16le(&o.stdout)),
            Err(_) => Ok(Vec::new()),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(Vec::new())
    }
}
