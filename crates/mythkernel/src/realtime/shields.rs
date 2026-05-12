//! Shields master kill-switch (TASK-156, Phase 4).
//!
//! Implements `docs/prd.md` FR-033 (promoted P0) + FR-160 — the
//! system-wide "Shields" state that every real-time platform component
//! (Linux fanotify daemon, macOS ESF NOTIFY listener, Windows ETW + AMSI
//! + WDAC user-mode service per § 1.5.4) MUST honor.
//!
//! Phase 4 ships the **architecture-only** version: state machine,
//! persistence, audit log, broadcast hook, Tauri command surface, and
//! CLI. The actual daemon-side respect of the state lands when each
//! platform daemon ships (Phases 8 / 9 / 12). Once Phase 4 is in,
//! every later phase's daemon code only needs to subscribe to
//! [`ShieldsBroker::subscribe`] and translate the state into its
//! platform's "ALLOW everything" mode when OFF.
//!
//! Per PRD § 6.3 FR-160:
//!
//!   1. Default: ON. Persists across app restart and OS reboot.
//!   2. OFF / paused: every daemon issues ALLOW; only the verdict
//!      policy changes, the daemon stays loaded.
//!   3. Timed pause: 15 min / 1 h / pause-until-restart / pause-until-
//!      explicit. Engine schedules an automatic resume tick.
//!   4. On-demand scans always run regardless of Shields state.
//!   5. Block-on-detected (FR-133) is honored even when Shields=OFF for
//!      paths with open `detected` findings — this is encoded by future
//!      daemon code, not here.
//!   6. Audit: every transition appended to `<data_dir>/shields.log`.
//!
//! Persistence: `<data_dir>/shields.json` written atomically (tmp +
//! rename) on every transition. fsync'd so a crash mid-write leaves the
//! previous-good state, not a half-written JSON.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

const SHIELDS_FILE: &str = "shields.json";
const AUDIT_FILE: &str = "shields.log";
const BROADCAST_CAPACITY: usize = 128;

#[derive(Debug, thiserror::Error)]
pub enum ShieldsError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("json: {0}")]
    Json(String),
    #[error("invalid pause duration: {0} minutes (must be > 0)")]
    InvalidPause(u32),
}

impl From<serde_json::Error> for ShieldsError {
    fn from(err: serde_json::Error) -> Self {
        ShieldsError::Json(err.to_string())
    }
}

/// What broadcast the state transition. Recorded in the audit log so
/// future incident response can correlate a Shields-OFF window to its
/// source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldsActor {
    Ui,
    Cli,
    Tray,
    AutoResume,
    Tauri,
    Engine,
}

impl ShieldsActor {
    pub fn as_str(self) -> &'static str {
        match self {
            ShieldsActor::Ui => "ui",
            ShieldsActor::Cli => "cli",
            ShieldsActor::Tray => "tray",
            ShieldsActor::AutoResume => "auto-resume",
            ShieldsActor::Tauri => "tauri",
            ShieldsActor::Engine => "engine",
        }
    }
}

/// The serialized state on disk + over IPC. Mirrors the TS
/// `ShieldsState` in `apps/mythodikal/frontend/src/ipc/types.ts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldsState {
    pub enabled: bool,
    /// When set + `enabled == false`, the engine schedules an auto-
    /// resume tick at this unix seconds. When `enabled == true` this
    /// is always None.
    pub pause_until_utc: Option<i64>,
}

impl Default for ShieldsState {
    fn default() -> Self {
        // Per FR-160.1 the default is ON.
        Self {
            enabled: true,
            pause_until_utc: None,
        }
    }
}

impl ShieldsState {
    /// Resolved view at `now_utc` — handles a pause whose expiry has
    /// already passed (returns the equivalent always-on state).
    pub fn resolved_at(&self, now_utc: i64) -> ShieldsState {
        match (self.enabled, self.pause_until_utc) {
            (false, Some(until)) if until <= now_utc => ShieldsState {
                enabled: true,
                pause_until_utc: None,
            },
            _ => *self,
        }
    }
}

/// Broker that owns the on-disk state, audit log, and broadcast
/// channel for `shields:changed` events. Cheap to clone (shares an
/// Arc<Mutex<...>>).
#[derive(Clone)]
pub struct ShieldsBroker {
    inner: Arc<std::sync::Mutex<Inner>>,
    tx: broadcast::Sender<ShieldsState>,
    data_dir: PathBuf,
}

struct Inner {
    state: ShieldsState,
}

impl ShieldsBroker {
    /// Open (or initialize) the broker against `<data_dir>`. Reads
    /// `shields.json` if it exists; otherwise writes the default state
    /// (ON) atomically and returns.
    pub fn open(data_dir: &Path) -> Result<Self, ShieldsError> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join(SHIELDS_FILE);
        let state = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str::<ShieldsState>(&text)?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                let initial = ShieldsState::default();
                write_atomic(&path, &initial)?;
                initial
            }
            Err(err) => return Err(err.into()),
        };
        let (tx, _rx) = broadcast::channel(BROADCAST_CAPACITY);
        Ok(Self {
            inner: Arc::new(std::sync::Mutex::new(Inner { state })),
            tx,
            data_dir: data_dir.to_path_buf(),
        })
    }

    /// Snapshot the current state, applying any expired-pause
    /// resolution so callers always see a consistent view.
    ///
    /// **Note (security review L1):** the auto-resume disk write only
    /// fires when `resolved != prior` so a UI badge that polls
    /// `shields_get` at 10 Hz does not rewrite `shields.json` repeatedly.
    pub fn get(&self) -> ShieldsState {
        let now = now_utc();
        let mut guard = self.inner.lock().expect("shields lock poisoned");
        let prior = guard.state;
        let resolved = prior.resolved_at(now);
        if resolved != prior {
            guard.state = resolved;
            // Persist the resolved (resumed) state. Audit preserves the
            // ORIGINAL `prior` (with the expired pause_until_utc intact)
            // so the trail reflects what actually expired.
            let _ = write_atomic(&self.data_dir.join(SHIELDS_FILE), &resolved);
            let _ = append_audit(
                &self.data_dir.join(AUDIT_FILE),
                ShieldsActor::AutoResume,
                prior,
                resolved,
                now,
            );
            let _ = self.tx.send(resolved);
        }
        resolved
    }

    /// Apply a transition. `enabled = true` clears any pause; setting
    /// `enabled = false` with `pause_minutes = None` is the "until I
    /// turn it back on" form; `Some(n)` schedules an auto-resume at
    /// `now + n` minutes.
    ///
    /// **Atomicity (security review H2):** the mutex is held across the
    /// disk write, audit append, and broadcast send so that concurrent
    /// callers can't observe an in-memory/disk/broadcast disagreement.
    /// Two racing `set()` calls now serialize cleanly.
    pub fn set(
        &self,
        enabled: bool,
        pause_minutes: Option<u32>,
        actor: ShieldsActor,
    ) -> Result<ShieldsState, ShieldsError> {
        if let Some(0) = pause_minutes {
            return Err(ShieldsError::InvalidPause(0));
        }
        let now = now_utc();
        let new_state = if enabled {
            ShieldsState {
                enabled: true,
                pause_until_utc: None,
            }
        } else {
            ShieldsState {
                enabled: false,
                pause_until_utc: pause_minutes.map(|m| now + (m as i64) * 60),
            }
        };
        let mut guard = self.inner.lock().expect("shields lock poisoned");
        let prior = guard.state;
        // Disk + audit + broadcast all happen under the lock so a racing
        // caller can't observe in-memory state ahead of (or behind) the
        // persisted state.
        write_atomic(&self.data_dir.join(SHIELDS_FILE), &new_state)?;
        append_audit(
            &self.data_dir.join(AUDIT_FILE),
            actor,
            prior,
            new_state,
            now,
        )?;
        guard.state = new_state;
        // Send under the lock — broadcast is a non-blocking channel
        // operation so this doesn't materially extend the critical
        // section, and ordering of `shields:changed` events now matches
        // the on-disk state machine exactly.
        let _ = self.tx.send(new_state);
        Ok(new_state)
    }

    /// Subscribe to `shields:changed` broadcasts. Daemons in Phases
    /// 8/9/12 will hold one of these and react to every transition.
    pub fn subscribe(&self) -> broadcast::Receiver<ShieldsState> {
        self.tx.subscribe()
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

fn write_atomic(path: &Path, state: &ShieldsState) -> Result<(), ShieldsError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = {
        let mut p = path.to_path_buf();
        let mut file_name = p
            .file_name()
            .map(|s| s.to_os_string())
            .unwrap_or_else(|| std::ffi::OsString::from("shields"));
        file_name.push(".tmp");
        p.set_file_name(file_name);
        p
    };
    {
        let mut f = File::create(&tmp)?;
        let body = serde_json::to_string_pretty(state)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn append_audit(
    path: &Path,
    actor: ShieldsActor,
    prior: ShieldsState,
    next: ShieldsState,
    now_utc_secs: i64,
) -> Result<(), ShieldsError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::json!({
        "ts_utc": now_utc_secs,
        "actor": actor.as_str(),
        "prior": prior,
        "next": next,
    });
    writeln!(f, "{}", line)?;
    Ok(())
}

fn now_utc() -> i64 {
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
    fn first_open_writes_default_on() {
        let dir = tempdir().unwrap();
        let broker = ShieldsBroker::open(dir.path()).unwrap();
        let state = broker.get();
        assert!(state.enabled);
        assert!(state.pause_until_utc.is_none());

        // The on-disk file must exist with the same default.
        let body = std::fs::read_to_string(dir.path().join(SHIELDS_FILE)).unwrap();
        let parsed: ShieldsState = serde_json::from_str(&body).unwrap();
        assert!(parsed.enabled);
    }

    #[test]
    fn reopen_preserves_state() {
        let dir = tempdir().unwrap();
        {
            let broker = ShieldsBroker::open(dir.path()).unwrap();
            broker.set(false, Some(15), ShieldsActor::Ui).unwrap();
        }
        let broker = ShieldsBroker::open(dir.path()).unwrap();
        let state = broker.get();
        assert!(!state.enabled);
        assert!(state.pause_until_utc.is_some());
    }

    #[test]
    fn set_off_with_no_pause_persists_indefinite() {
        let dir = tempdir().unwrap();
        let broker = ShieldsBroker::open(dir.path()).unwrap();
        let state = broker.set(false, None, ShieldsActor::Cli).unwrap();
        assert!(!state.enabled);
        assert!(state.pause_until_utc.is_none());
    }

    #[test]
    fn pause_zero_minutes_rejected() {
        let dir = tempdir().unwrap();
        let broker = ShieldsBroker::open(dir.path()).unwrap();
        let err = broker.set(false, Some(0), ShieldsActor::Ui).unwrap_err();
        assert!(matches!(err, ShieldsError::InvalidPause(0)));
    }

    #[test]
    fn resolved_at_clears_expired_pause() {
        let s = ShieldsState {
            enabled: false,
            pause_until_utc: Some(100),
        };
        let resolved = s.resolved_at(200);
        assert!(resolved.enabled);
        assert!(resolved.pause_until_utc.is_none());
    }

    #[test]
    fn resolved_at_preserves_active_pause() {
        let s = ShieldsState {
            enabled: false,
            pause_until_utc: Some(2_000_000_000),
        };
        let resolved = s.resolved_at(100);
        assert!(!resolved.enabled);
        assert_eq!(resolved.pause_until_utc, Some(2_000_000_000));
    }

    #[test]
    fn get_auto_resumes_an_expired_pause() {
        // Set a 1-minute pause with a back-dated expiry so the auto-
        // resume path fires on the next get().
        let dir = tempdir().unwrap();
        // Hand-write an expired pause directly to the file so get()
        // reads it on the next refresh.
        let expired = ShieldsState {
            enabled: false,
            pause_until_utc: Some(1), // unix epoch + 1s
        };
        write_atomic(&dir.path().join(SHIELDS_FILE), &expired).unwrap();
        // Open the broker — it should read the expired pause and resolve.
        let broker = ShieldsBroker::open(dir.path()).unwrap();
        let resolved = broker.get();
        assert!(
            resolved.enabled,
            "expired pause should auto-resume to ON; got {resolved:?}"
        );
    }

    #[test]
    fn audit_log_captures_every_transition() {
        let dir = tempdir().unwrap();
        let broker = ShieldsBroker::open(dir.path()).unwrap();
        broker.set(false, Some(15), ShieldsActor::Ui).unwrap();
        broker.set(false, None, ShieldsActor::Cli).unwrap();
        broker.set(true, None, ShieldsActor::Tray).unwrap();
        let body = std::fs::read_to_string(dir.path().join(AUDIT_FILE)).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("\"actor\":\"ui\""));
        assert!(lines[1].contains("\"actor\":\"cli\""));
        assert!(lines[2].contains("\"actor\":\"tray\""));
    }

    #[tokio::test]
    async fn subscribe_receives_transitions() {
        let dir = tempdir().unwrap();
        let broker = ShieldsBroker::open(dir.path()).unwrap();
        let mut rx = broker.subscribe();
        broker.set(false, Some(15), ShieldsActor::Ui).unwrap();
        let event = rx.recv().await.unwrap();
        assert!(!event.enabled);
        assert!(event.pause_until_utc.is_some());
    }
}
