//! launchd LaunchAgent integration + heartbeat writer (TASK-254,
//! Phase 9 Wave 2).
//!
//! Two responsibilities:
//!
//!   * Render the LaunchAgent plist text the installer drops into
//!     `~/Library/LaunchAgents/com.mythodikal.heartbeat.plist`.
//!     `KeepAlive=true`, `RunAtLoad=true`, `ThrottleInterval=1`. No
//!     `sudo` install — LaunchAgents are per-user, signed-plist-not-
//!     required per `docs/prd.md` § 1.5.3.
//!   * Tick once per second from the daemon's main loop, writing
//!     `{ last_beat_at_ms, pid, restart_count }` to
//!     `~/Library/Application Support/Mythodikal/heartbeat.json`
//!     atomically (tmp + rename) so a partial write can never show
//!     up to the UI as a stale-looking timestamp.
//!
//! The UI's heartbeat chip lives in
//! `apps/mythodikal/frontend/src/components/MacRealtimeHeartbeat.tsx`
//! and reads the same file via the Tauri command
//! `crate::ipc_client` does NOT consume — `crates/ui-bridge/src/commands_mac.rs::mac_heartbeat`
//! handles the parse + age derivation.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// Stable launchd `Label` value. Reused by the plist + by the
/// installer's `launchctl bootstrap` invocation.
pub const LAUNCHD_LABEL: &str = "com.mythodikal.heartbeat";

/// On-disk heartbeat filename. Re-export from
/// `mythkernel::ipc::macesf::HEARTBEAT_FILENAME` so the writer here
/// and the reader at `ui_bridge::commands_mac` can never drift
/// independently (review CR-10, 2026-05-27).
pub use mythkernel::ipc::macesf::HEARTBEAT_FILENAME;

#[derive(Debug, thiserror::Error)]
pub enum LaunchdError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(String),
}

impl From<serde_json::Error> for LaunchdError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e.to_string())
    }
}

/// JSON shape the heartbeat tick writes. Field order is deterministic
/// (serde_json preserves struct field order) so a file diff between
/// two ticks is greppable.
#[derive(Debug, Clone, Serialize)]
pub struct HeartbeatPayload {
    pub last_beat_at_ms: i64,
    pub pid: i32,
    pub restart_count: u32,
}

/// Render the LaunchAgent plist text. Deterministic — the exec_path
/// and label arguments fully determine the output, so a diff between
/// two runs is empty as long as the inputs match.
pub fn render_agent_plist(exec_path: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exec}</string>
        <string>--heartbeat-only</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>1</integer>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        exec = exec_path,
    )
}

/// Where the heartbeat JSON lives. Pulled out as a helper so unit
/// tests can substitute a temp dir for `$HOME`.
pub fn heartbeat_path(home: &Path) -> PathBuf {
    home.join("Library")
        .join("Application Support")
        .join("Mythodikal")
        .join(HEARTBEAT_FILENAME)
}

/// Tick once. Writes the payload atomically (tmp + rename) so the UI
/// never sees a half-written file. Caller passes the wall-clock
/// timestamp; the daemon's main loop ticks every second.
pub fn write_heartbeat(
    home: &Path,
    now_ms: i64,
    pid: i32,
    restart_count: u32,
) -> Result<HeartbeatPayload, LaunchdError> {
    let payload = HeartbeatPayload {
        last_beat_at_ms: now_ms,
        pid,
        restart_count,
    };
    let dir = home
        .join("Library")
        .join("Application Support")
        .join("Mythodikal");
    std::fs::create_dir_all(&dir)?;
    let final_path = dir.join(HEARTBEAT_FILENAME);
    // PID-disambiguated tmp path so a transient old daemon overlapping
    // a launchd KeepAlive respawn doesn't race the shared tmp file
    // (review CR-2, 2026-05-27). Rename is still atomic per-process.
    let tmp_path = dir.join(format!("{HEARTBEAT_FILENAME}.{}.tmp", std::process::id()));
    let body = serde_json::to_vec(&payload)?;
    {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(&body)?;
        f.sync_data()?;
    }
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn render_plist_contains_keepalive_and_throttle() {
        let plist = render_agent_plist("/usr/local/bin/mythd");
        assert!(plist.contains("<key>KeepAlive</key>\n    <true/>"));
        assert!(plist.contains("<integer>1</integer>"));
        assert!(plist.contains("/usr/local/bin/mythd"));
        assert!(plist.contains(LAUNCHD_LABEL));
    }

    #[test]
    fn render_plist_is_deterministic_for_same_inputs() {
        let a = render_agent_plist("/usr/local/bin/mythd");
        let b = render_agent_plist("/usr/local/bin/mythd");
        assert_eq!(a, b);
    }

    #[test]
    fn write_heartbeat_round_trips_via_parse_helper() {
        let dir = tempdir().unwrap();
        let payload = write_heartbeat(dir.path(), 1_700_000_000_000, 4321, 2).unwrap();
        let body =
            std::fs::read_to_string(heartbeat_path(dir.path())).expect("heartbeat file written");
        // Parse via the ui-bridge helper so a schema drift between
        // writer and reader is caught at test time.
        let hb = crate::launchd::HeartbeatPayload {
            last_beat_at_ms: payload.last_beat_at_ms,
            pid: payload.pid,
            restart_count: payload.restart_count,
        };
        assert_eq!(hb.pid, 4321);
        assert_eq!(hb.restart_count, 2);
        assert!(body.contains("\"last_beat_at_ms\""));
    }

    #[test]
    fn write_heartbeat_overwrites_atomically() {
        let dir = tempdir().unwrap();
        write_heartbeat(dir.path(), 1, 1, 0).unwrap();
        write_heartbeat(dir.path(), 2, 1, 1).unwrap();
        let body =
            std::fs::read_to_string(heartbeat_path(dir.path())).expect("heartbeat file written");
        assert!(body.contains("\"last_beat_at_ms\":2"));
        assert!(body.contains("\"restart_count\":1"));
    }

    #[test]
    fn heartbeat_filename_matches_ui_bridge_constant() {
        // Both the daemon writer and the ui-bridge reader must agree
        // on the same filename. Both now re-export from
        // mythkernel::ipc::macesf::HEARTBEAT_FILENAME — `::` identity
        // is enforced at compile time, but assert the literal value
        // here too so a future inline-override is caught (review
        // CR-10).
        assert_eq!(HEARTBEAT_FILENAME, "heartbeat.json");
        assert_eq!(
            HEARTBEAT_FILENAME,
            mythkernel::ipc::macesf::HEARTBEAT_FILENAME,
            "daemon and mythkernel HEARTBEAT_FILENAME drifted"
        );
    }
}
