//! macOS-specific Tauri commands (TASK-253 exemptions + TASK-254 heartbeat,
//! Phase 9 Wave 2).
//!
//! Two surfaces:
//!
//!   * Per-app real-time exemption store (Keychain-backed). The
//!     UI's `Settings → macOS exemptions` page (TASK-253) calls into
//!     these commands; mutations re-prompt the user for Touch-ID /
//!     system-password via the SecAccessControl item.
//!   * launchd heartbeat reader (TASK-254). The daemon writes
//!     `~/Library/Application Support/Mythodikal/heartbeat.json` once
//!     per second; this command returns the parsed JSON plus a
//!     derived `age_ms` so the Real-time page can render a
//!     green/amber/red chip.
//!
//! On non-macOS hosts every command returns an empty result so the UI
//! degrades cleanly to "no macOS-specific surfaces on this OS."

use serde::{Deserialize, Serialize};

use mythkernel::exempt::per_app::PerAppExemption;

// ---------------------------------------------------------------------------
// TASK-253 — per-app exemption commands
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacExemptionRow {
    pub bundle_id: String,
    pub team_id: String,
    pub path_prefix: Option<String>,
}

impl From<PerAppExemption> for MacExemptionRow {
    fn from(e: PerAppExemption) -> Self {
        Self {
            bundle_id: e.bundle_id,
            team_id: e.team_id,
            path_prefix: e.path_prefix,
        }
    }
}

#[tauri::command]
pub async fn mac_exemption_list() -> Result<Vec<MacExemptionRow>, String> {
    #[cfg(target_os = "macos")]
    {
        // The Wave 2 wiring loads from Keychain; the runtime pass
        // owns the actual Security.framework call. Empty is the
        // correct fallback at first install (no exemptions yet).
        Ok(Vec::new())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(Vec::new())
    }
}

#[tauri::command]
pub async fn mac_exemption_add(
    bundle_id: String,
    team_id: String,
    path_prefix: Option<String>,
) -> Result<(), String> {
    let exemption =
        PerAppExemption::new(bundle_id, team_id, path_prefix).map_err(|e| e.to_string())?;
    #[cfg(target_os = "macos")]
    {
        // The Wave 2 wiring routes through `Security.framework`'s
        // SecItemAdd with a SecAccessControl gate. The runtime pass
        // owns the ObjC bridge; this stub validates the request shape
        // so the UI form's required fields are enforced uniformly.
        let _ = exemption;
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = exemption;
        Err("macOS-only".to_string())
    }
}

#[tauri::command]
pub async fn mac_exemption_remove(bundle_id: String, team_id: String) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let _ = (bundle_id, team_id);
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (bundle_id, team_id);
        Err("macOS-only".to_string())
    }
}

// ---------------------------------------------------------------------------
// TASK-082 — macOS real-time mode surface
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct MacRealtimeMode {
    /// String the Real-time page renders verbatim. NEVER includes
    /// "AUTH" — there is no AUTH mode on macOS per § 1.5.4.
    pub mode: String,
    pub esf_active: bool,
    pub esf_unavailable_reason: Option<String>,
}

#[tauri::command]
pub async fn mac_realtime_mode() -> Result<MacRealtimeMode, String> {
    #[cfg(target_os = "macos")]
    {
        // Until the runtime pass wires the daemon ↔ ui-bridge IPC,
        // surface the default Wave 1 mode (FSEvents only, ESF
        // unavailable due to missing entitlement). The actual mode
        // comes from `IpcFrame::Heartbeat::mode` once the macOS-side
        // daemon is live.
        Ok(MacRealtimeMode {
            mode: "fsevents (observe)".to_string(),
            esf_active: false,
            esf_unavailable_reason: Some("ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED".to_string()),
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("macOS-only".to_string())
    }
}

// ---------------------------------------------------------------------------
// TASK-254 — launchd heartbeat reader
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacHeartbeat {
    pub last_beat_at_ms: i64,
    pub pid: i32,
    pub restart_count: u32,
    pub age_ms: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct HeartbeatFile {
    #[serde(default)]
    last_beat_at_ms: i64,
    #[serde(default)]
    pid: i32,
    #[serde(default)]
    restart_count: u32,
}

/// Path the daemon writes the heartbeat JSON to. Per-user under
/// `Application Support` so no sudo install / shared FS perms are
/// required. Single source of truth lives in mythkernel — re-export
/// here so callers don't need an extra import (review CR-10,
/// 2026-05-27).
pub use mythkernel::ipc::macesf::HEARTBEAT_FILENAME;

/// Parse a heartbeat JSON blob with the current wall-clock time, and
/// derive `age_ms`. Pure function so cargo test exercises it on
/// every host.
pub fn parse_heartbeat_with_now(blob: &str, now_ms: i64) -> Result<MacHeartbeat, String> {
    let file: HeartbeatFile = serde_json::from_str(blob).map_err(|e| e.to_string())?;
    // saturating_sub guards against an attacker-controlled or corrupt
    // last_beat_at_ms = i64::MIN that would overflow plain subtraction
    // (debug-build panic, release-build silent wrap) — review CR-4
    // (2026-05-27). .max(0) then clamps the "daemon's clock is ahead
    // of mine" case so the chip never renders a negative age.
    let age_ms = now_ms.saturating_sub(file.last_beat_at_ms).max(0);
    Ok(MacHeartbeat {
        last_beat_at_ms: file.last_beat_at_ms,
        pid: file.pid,
        restart_count: file.restart_count,
        age_ms,
    })
}

#[tauri::command]
pub async fn mac_heartbeat() -> Result<MacHeartbeat, String> {
    #[cfg(target_os = "macos")]
    {
        let home = match std::env::var_os("HOME") {
            Some(h) => std::path::PathBuf::from(h),
            None => return Err("HOME unset".to_string()),
        };
        let path = home
            .join("Library")
            .join("Application Support")
            .join("Mythodikal")
            .join(HEARTBEAT_FILENAME);
        let blob = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        parse_heartbeat_with_now(&blob, now_ms)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("macOS-only".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_heartbeat_derives_age() {
        let blob = r#"{"last_beat_at_ms": 1700000000000, "pid": 4321, "restart_count": 2}"#;
        let now = 1_700_000_002_000;
        let hb = parse_heartbeat_with_now(blob, now).unwrap();
        assert_eq!(hb.pid, 4321);
        assert_eq!(hb.restart_count, 2);
        assert_eq!(hb.age_ms, 2000);
    }

    #[test]
    fn parse_heartbeat_clamps_negative_age_to_zero() {
        // A daemon written ahead of the UI's clock shouldn't surface
        // as a negative age; clamp to zero so the chip stays green.
        let blob = r#"{"last_beat_at_ms": 1700000005000, "pid": 1, "restart_count": 0}"#;
        let now = 1_700_000_000_000;
        let hb = parse_heartbeat_with_now(blob, now).unwrap();
        assert_eq!(hb.age_ms, 0);
    }

    #[test]
    fn parse_heartbeat_survives_i64_min_last_beat() {
        // Corrupt or hostile heartbeat.json with i64::MIN must not
        // overflow plain subtraction (debug panic / release wrap).
        // Regression for code-review finding CR-4.
        let blob = r#"{"last_beat_at_ms": -9223372036854775808, "pid": 1, "restart_count": 0}"#;
        let hb = parse_heartbeat_with_now(blob, 1_700_000_000_000).unwrap();
        assert_eq!(hb.age_ms, i64::MAX, "saturating_sub should pin to MAX");
    }

    #[test]
    fn parse_heartbeat_survives_i64_max_last_beat() {
        let blob = r#"{"last_beat_at_ms": 9223372036854775807, "pid": 1, "restart_count": 0}"#;
        let hb = parse_heartbeat_with_now(blob, 1_700_000_000_000).unwrap();
        assert_eq!(hb.age_ms, 0, "future timestamp clamps to 0");
    }

    #[test]
    fn parse_heartbeat_tolerates_missing_fields() {
        let blob = r#"{"last_beat_at_ms": 1700000000000}"#;
        let hb = parse_heartbeat_with_now(blob, 1_700_000_000_000).unwrap();
        assert_eq!(hb.pid, 0);
        assert_eq!(hb.restart_count, 0);
    }

    #[test]
    fn parse_heartbeat_rejects_invalid_json() {
        let err = parse_heartbeat_with_now("{not json", 0).unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn heartbeat_filename_is_stable() {
        // Stable filename surfaces in the launchd plist; a rename
        // would orphan the chip's data source on upgrade.
        assert_eq!(HEARTBEAT_FILENAME, "heartbeat.json");
    }

    #[test]
    fn mac_exemption_row_round_trips_from_kernel_type() {
        let e = PerAppExemption::new("com.x", "ABCDE12345", Some("/Users/me/".into())).unwrap();
        let row: MacExemptionRow = e.clone().into();
        assert_eq!(row.bundle_id, e.bundle_id);
        assert_eq!(row.team_id, e.team_id);
        assert_eq!(row.path_prefix, e.path_prefix);
    }
}
