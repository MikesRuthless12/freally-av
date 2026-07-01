//! Updater channel abstraction (TASK-129, Phase 4 wave 3).
//!
//! Two completely independent update tracks per FR-151:
//!
//! * **Engine channel** — the app itself (binary + bundled assets). Self-updates
//!   ship as signed Tauri Updater bundles published to GitHub Releases. An
//!   engine update never invalidates feed files because the feeds live in
//!   `<data_dir>/feeds/`, outside the app bundle.
//!
//! * **Database channel** — the threat-intel feeds (abuse.ch hashes, NSRL
//!   allowlist, YARA-Forge rules, BYOVD blocklist, ...). Database updates are
//!   atomic .bin replacements; they never require an engine restart because the
//!   detectors mmap-reload on next scan (and detectors built per-scan can also
//!   pick up the change mid-uptime).
//!
//! Each channel persists its own state in `<data_dir>/updater/{engine,database}_state.json`
//! and exposes its own "Check now" / "Auto-update" knobs in the UI (FR-154,
//! TASK-133). The frontend never confuses one for the other — they're entirely
//! separate Settings → Updates panes.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Which channel a state file / event / command refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    Engine,
    Database,
}

impl ChannelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChannelKind::Engine => "engine",
            ChannelKind::Database => "database",
        }
    }

    /// Default state-file name for this channel under
    /// `<data_dir>/updater/`.
    pub fn state_file(self) -> &'static str {
        match self {
            ChannelKind::Engine => "engine_state.json",
            ChannelKind::Database => "database_state.json",
        }
    }
}

/// Outcome of one channel cycle. UI surfaces this as the "Last check"
/// summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LastCheckOutcome {
    /// No prior check has run yet.
    #[default]
    Never,
    /// Check succeeded; no update was available.
    UpToDate,
    /// Check succeeded; an update is available (and may or may not have
    /// been installed yet).
    UpdateAvailable,
    /// Check succeeded; update was installed.
    Installed,
    /// Check failed (network, parse, signature, etc.). UI shows the
    /// `last_error` string verbatim.
    Failed,
}

/// Common fields persisted by every channel. The engine/database channels
/// embed this and extend it with channel-specific state (latest_version,
/// per-feed ETags, etc.).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ChannelState {
    /// Auto-update enabled for this channel (FR-155). Default ON for the
    /// database channel; engine channel default depends on user opt-in
    /// during first-run (TASK-046 today defaults to ON for engine too,
    /// since the source-visible posture means users expect updates).
    pub auto_update_enabled: bool,
    /// Channel name: `"stable"` (default), `"beta"`, `"nightly"`. The
    /// engine channel uses this to filter GitHub Releases; the database
    /// channel ignores it (feeds are single-track).
    pub channel: String,
    /// Hours between automatic check cycles. `0` = "ASAP on app start
    /// only". Engine default: 24. Database default: 12.
    pub interval_hours: u32,
    /// Unix seconds of the most recent check (success or failure).
    pub last_check_at_utc: i64,
    /// Unix seconds of the most recent successful install.
    pub last_install_at_utc: i64,
    pub last_outcome: LastCheckOutcome,
    /// Free-text error message from the most recent failed check.
    /// Empty string when the most recent check succeeded.
    pub last_error: String,
}

impl ChannelState {
    /// Default state for a freshly-installed app.
    pub fn defaults_for(kind: ChannelKind) -> Self {
        Self {
            auto_update_enabled: true,
            channel: "stable".to_string(),
            interval_hours: match kind {
                ChannelKind::Engine => 24,
                ChannelKind::Database => 12,
            },
            ..Self::default()
        }
    }

    /// Stamp the current unix-seconds time onto `last_check_at_utc` and
    /// move the outcome forward.
    pub fn record_check(&mut self, outcome: LastCheckOutcome, error: Option<&str>) {
        self.last_check_at_utc = now_utc_secs();
        self.last_outcome = outcome;
        self.last_error = error.map(|s| s.to_string()).unwrap_or_default();
        if matches!(outcome, LastCheckOutcome::Installed) {
            self.last_install_at_utc = self.last_check_at_utc;
        }
    }
}

/// Load a channel state from `<data_dir>/updater/<kind>_state.json`.
/// Missing file → defaults for `kind`. Parse errors return defaults +
/// log a warning (never a hard fault — we'd rather force a fresh check
/// than refuse to boot).
pub fn load_state(updater_dir: &Path, kind: ChannelKind) -> ChannelState {
    let path = updater_dir.join(kind.state_file());
    match std::fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<ChannelState>(&bytes) {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    path = %path.display(),
                    channel = kind.as_str(),
                    "channel state parse failed; using defaults"
                );
                ChannelState::defaults_for(kind)
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => ChannelState::defaults_for(kind),
        Err(err) => {
            tracing::warn!(
                error = %err,
                path = %path.display(),
                channel = kind.as_str(),
                "channel state read failed; using defaults"
            );
            ChannelState::defaults_for(kind)
        }
    }
}

/// Persist `state` atomically: write to `path.tmp` then rename. The UI
/// always observes either the old file or the new one, never a torn
/// half-write.
pub fn save_state(
    updater_dir: &Path,
    kind: ChannelKind,
    state: &ChannelState,
) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(updater_dir)?;
    let path = updater_dir.join(kind.state_file());
    let json = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json)?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

/// Resolve the updater directory under `<data_dir>/updater/`. Caller
/// holds `<data_dir>` from `crate::db::default_data_dir()`.
pub fn updater_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("updater")
}

fn now_utc_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn defaults_are_channel_specific() {
        let engine = ChannelState::defaults_for(ChannelKind::Engine);
        let db = ChannelState::defaults_for(ChannelKind::Database);
        assert_eq!(engine.interval_hours, 24);
        assert_eq!(db.interval_hours, 12);
        assert!(engine.auto_update_enabled);
        assert!(db.auto_update_enabled);
    }

    #[test]
    fn missing_file_returns_defaults() {
        let dir = tempdir().unwrap();
        let s = load_state(dir.path(), ChannelKind::Engine);
        assert_eq!(s.channel, "stable");
        assert_eq!(s.interval_hours, 24);
    }

    #[test]
    fn round_trip_persists_values() {
        let dir = tempdir().unwrap();
        let updater_dir = dir.path().join("updater");
        let mut s = ChannelState::defaults_for(ChannelKind::Database);
        s.channel = "beta".into();
        s.interval_hours = 6;
        save_state(&updater_dir, ChannelKind::Database, &s).unwrap();
        let loaded = load_state(&updater_dir, ChannelKind::Database);
        assert_eq!(loaded.channel, "beta");
        assert_eq!(loaded.interval_hours, 6);
    }

    #[test]
    fn record_check_advances_timestamp_and_outcome() {
        let mut s = ChannelState::defaults_for(ChannelKind::Engine);
        let before = s.last_check_at_utc;
        std::thread::sleep(std::time::Duration::from_millis(50));
        s.record_check(LastCheckOutcome::Installed, None);
        assert!(s.last_check_at_utc >= before);
        assert!(s.last_install_at_utc >= before);
        assert!(matches!(s.last_outcome, LastCheckOutcome::Installed));
    }

    #[test]
    fn record_failure_stamps_error_message() {
        let mut s = ChannelState::defaults_for(ChannelKind::Database);
        s.record_check(LastCheckOutcome::Failed, Some("network: timeout"));
        assert!(matches!(s.last_outcome, LastCheckOutcome::Failed));
        assert_eq!(s.last_error, "network: timeout");
    }

    #[test]
    fn channel_kind_string_round_trips_via_state_file() {
        assert_eq!(ChannelKind::Engine.state_file(), "engine_state.json");
        assert_eq!(ChannelKind::Database.state_file(), "database_state.json");
    }

    #[test]
    fn corrupt_state_file_yields_defaults() {
        let dir = tempdir().unwrap();
        let updater_dir = dir.path().join("updater");
        std::fs::create_dir_all(&updater_dir).unwrap();
        std::fs::write(
            updater_dir.join(ChannelKind::Engine.state_file()),
            b"not json",
        )
        .unwrap();
        let s = load_state(&updater_dir, ChannelKind::Engine);
        // Defaults survived the bad file.
        assert_eq!(s.channel, "stable");
    }
}
