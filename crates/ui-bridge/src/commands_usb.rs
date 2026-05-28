//! USB-stack Tauri commands (TASK-242 + TASK-249 + TASK-250, Phase 8 Wave 2).
//!
//! Thin wrappers around `mythkernel::usb::{allowlist, write_log, device_history}`.
//! Each command takes a [`crate::commands::AppState`] for the engine
//! sqlite connection and returns a JSON-serializable view.

use mythkernel::usb::{
    allowlist::{self, UsbAllowEntry},
    device_history::{self, DeviceRow},
    power_only::{self, PowerOnlyEntry},
    write_log::{self, UsbWriteEvent},
};
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::commands::stringify;

// ---------------------------------------------------------------------------
// TASK-242 — VID:PID:Serial allowlist
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbAllowlistAddRequest {
    pub vid: String,
    pub pid: String,
    pub serial: String,
    pub label: String,
}

#[tauri::command]
pub async fn usb_allowlist_list(
    state: State<'_, crate::commands::AppState>,
) -> Result<Vec<UsbAllowEntry>, String> {
    let conn = state.db.lock().map_err(|_| "db poisoned".to_string())?;
    allowlist::ensure_schema(&conn).map_err(stringify)?;
    allowlist::list(&conn).map_err(stringify)
}

#[tauri::command]
pub async fn usb_allowlist_add(
    state: State<'_, crate::commands::AppState>,
    req: UsbAllowlistAddRequest,
) -> Result<(), String> {
    let conn = state.db.lock().map_err(|_| "db poisoned".to_string())?;
    allowlist::ensure_schema(&conn).map_err(stringify)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    allowlist::add(&conn, &req.vid, &req.pid, &req.serial, &req.label, now).map_err(stringify)
}

#[tauri::command]
pub async fn usb_allowlist_remove(
    state: State<'_, crate::commands::AppState>,
    vid: String,
    pid: String,
    serial: String,
) -> Result<usize, String> {
    let conn = state.db.lock().map_err(|_| "db poisoned".to_string())?;
    allowlist::ensure_schema(&conn).map_err(stringify)?;
    allowlist::remove(&conn, &vid, &pid, &serial).map_err(stringify)
}

// ---------------------------------------------------------------------------
// TASK-244 — power-only override (cross-platform store + lookup)
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn usb_power_only_list(
    state: State<'_, crate::commands::AppState>,
) -> Result<Vec<PowerOnlyEntry>, String> {
    let conn = state.db.lock().map_err(|_| "db poisoned".to_string())?;
    power_only::ensure_schema(&conn).map_err(stringify)?;
    power_only::list(&conn).map_err(stringify)
}

#[tauri::command]
pub async fn usb_power_only_enable(
    state: State<'_, crate::commands::AppState>,
    port_path: String,
    label: String,
) -> Result<(), String> {
    let conn = state.db.lock().map_err(|_| "db poisoned".to_string())?;
    power_only::ensure_schema(&conn).map_err(stringify)?;
    power_only::enable(&conn, &port_path, &label).map_err(stringify)
}

#[tauri::command]
pub async fn usb_power_only_disable(
    state: State<'_, crate::commands::AppState>,
    port_path: String,
) -> Result<(), String> {
    let conn = state.db.lock().map_err(|_| "db poisoned".to_string())?;
    power_only::ensure_schema(&conn).map_err(stringify)?;
    power_only::disable(&conn, &port_path).map_err(stringify)
}

// ---------------------------------------------------------------------------
// TASK-249 — write event log query
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn usb_write_events(
    state: State<'_, crate::commands::AppState>,
    serial: String,
    limit: Option<i64>,
) -> Result<Vec<UsbWriteEvent>, String> {
    let conn = state.db.lock().map_err(|_| "db poisoned".to_string())?;
    write_log::ensure_schema(&conn).map_err(stringify)?;
    let limit = limit.unwrap_or(500).min(10_000);
    write_log::query_by_serial(&conn, &serial, limit).map_err(stringify)
}

// ---------------------------------------------------------------------------
// TASK-250 — per-device scan history
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn usb_devices(
    state: State<'_, crate::commands::AppState>,
) -> Result<Vec<DeviceRow>, String> {
    let conn = state.db.lock().map_err(|_| "db poisoned".to_string())?;
    device_history::ensure_schema(&conn).map_err(stringify)?;
    device_history::list(&conn).map_err(stringify)
}
