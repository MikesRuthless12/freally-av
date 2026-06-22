//! Feed auto-updater scheduler (TASK-043, Phase 4 wave 2).
//!
//! Periodically refreshes the abuse.ch hash feed on a configurable
//! interval (default 24 h). Spawn one [`FeedScheduler`] at app start;
//! it owns a tokio task that wakes at the requested cadence, runs the
//! configured updaters in sequence, and persists a `last_run.json`
//! status file under `<feeds_dir>/` so the UI's About / Updates panel
//! can render the most recent run without re-fetching.
//!
//! The scheduler is **best-effort**: a transient network failure logs
//! a warning and falls back to a short retry interval (default 1 h);
//! it never panics the app. Hard errors (auth-key missing, malformed
//! config) surface in the status file so the user can act on them.
//!
//! **ed25519 signature checks**: the upstream abuse.ch + NSRL feeds
//! are unsigned plain-text downloads; the channel-split architecture
//! in TASK-129/130/131 adds a signed manifest + ed25519 verification.
//! For Phase 4 wave 2 we trust the upstream TLS certificate (rustls,
//! pinned at the root-store level via `rustls-platform-verifier`); the
//! signature hook below is a stub so the wave-3 work can plug in
//! without re-shaping the scheduler.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use crate::updater::abusech::AbuseChUpdater;
use crate::updater::curated::CuratedBlacklistUpdater;

/// Default interval between successful runs (24 hours).
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Retry interval after a failed run.
pub const FAILURE_RETRY_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// File the scheduler writes after each run.
pub const STATUS_FILE: &str = "last_run.json";

/// Persistent record of the most recent run. Stored next to the feed
/// binaries so the UI can read it without an IPC round-trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastRun {
    /// Unix seconds.
    pub started_at_utc: i64,
    /// Unix seconds.
    pub finished_at_utc: i64,
    /// "ok" | "error" | "skipped".
    pub outcome: String,
    /// Free-text detail (count merged, or the error message).
    pub detail: String,
    /// Next run scheduled at (unix seconds).
    pub next_run_at_utc: i64,
}

/// Trait the scheduler talks to. Tests can substitute a fake; production
/// installs [`AbuseChScheduledFeed`].
pub trait ScheduledFeed: Send + Sync {
    /// Run one update cycle. Async to fit into the existing reqwest
    /// flow; the scheduler `await`s this with a tokio `select!`.
    fn name(&self) -> &str;
    fn run<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + 'a>>;
}

/// Concrete adapter around [`AbuseChUpdater`]. Returns the merged-count
/// detail string on success.
pub struct AbuseChScheduledFeed {
    inner: AbuseChUpdater,
}

impl AbuseChScheduledFeed {
    pub fn new(inner: AbuseChUpdater) -> Self {
        Self { inner }
    }
}

impl ScheduledFeed for AbuseChScheduledFeed {
    fn name(&self) -> &str {
        "abusech"
    }
    fn run<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + 'a>>
    {
        Box::pin(async move {
            self.inner
                .update()
                .await
                .map(|r| {
                    format!(
                        "merged {} hashes in {:.1}s",
                        r.merged_count,
                        r.elapsed.as_secs_f64()
                    )
                })
                .map_err(|e| e.to_string())
        })
    }
}

/// Periodic adapter around [`CuratedBlacklistUpdater`] (repo-curated-DB
/// decision, 2026-06-21). Replaces [`AbuseChScheduledFeed`] on the auto-update
/// timer: each cycle downloads + verifies the curated `.bin` from the release
/// rather than pulling raw abuse.ch upstream. Reports under name `"abusech"`
/// for status-file continuity.
pub struct CuratedBlacklistScheduledFeed {
    inner: CuratedBlacklistUpdater,
}

impl CuratedBlacklistScheduledFeed {
    pub fn new(inner: CuratedBlacklistUpdater) -> Self {
        Self { inner }
    }
}

impl ScheduledFeed for CuratedBlacklistScheduledFeed {
    fn name(&self) -> &str {
        "abusech"
    }
    fn run<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + 'a>>
    {
        Box::pin(async move {
            // The periodic path doesn't surface byte-level progress (no UI
            // bar subscribes), so pass a no-op progress sink.
            let noop = |_done: u64, _total: u64| {};
            let report = self.inner.update(&noop).await.map_err(|e| e.to_string())?;
            if report.changed {
                Ok(format!(
                    "installed {} curated hashes in {:.1}s",
                    report.entry_count,
                    report.elapsed.as_secs_f64()
                ))
            } else {
                Ok("curated database already current".to_string())
            }
        })
    }
}

/// Handle for a running scheduler. Drop the handle to stop the task at
/// the next iteration boundary.
pub struct SchedulerHandle {
    /// Notifier that triggers an immediate run (e.g. user clicks the
    /// "Update now" button). The background task `select!`s on this
    /// against the regular interval timer.
    kick: Arc<Notify>,
    /// Notifier that asks the task to exit cleanly. Set on `Drop`.
    shutdown: Arc<Notify>,
    join: Option<SchedulerJoin>,
}

/// The scheduler can run on either an ambient tokio runtime (when the
/// caller already has one — tests, daemon shells, any future async
/// host) or on a dedicated thread it owns. The dedicated-thread mode
/// is what unblocks the Tauri shell startup, where `spawn()` is called
/// from outside the runtime context (Tauri's runtime hasn't started
/// yet when `setup` fires — calling raw `tokio::spawn` panics with
/// "no reactor running" and the MSI launch produces an invisible
/// crash because the panic has no console).
enum SchedulerJoin {
    Async(tokio::task::JoinHandle<()>),
    Owned(std::thread::JoinHandle<()>),
}

impl SchedulerHandle {
    /// Trigger an immediate update outside the regular interval.
    pub fn kick(&self) {
        self.kick.notify_one();
    }
}

impl Drop for SchedulerHandle {
    fn drop(&mut self) {
        self.shutdown.notify_one();
        if let Some(j) = self.join.take() {
            match j {
                SchedulerJoin::Async(h) => h.abort(),
                // Owned-runtime mode: the thread's `block_on` returns
                // when `shutdown_for_task.notified().await` resolves
                // (which happens via `self.shutdown.notify_one()` two
                // lines up). We deliberately don't `.join()` here so
                // app shutdown isn't gated on the scheduler finishing
                // a long-running feed download; the thread exits on
                // its own at the next iteration boundary.
                SchedulerJoin::Owned(_thread) => {}
            }
        }
    }
}

/// Spawn the scheduler. `feeds_dir` is where `last_run.json` lives;
/// pass the same `<data_dir>/feeds/` the engine reads.
///
/// When `feeds` is empty this returns a handle that does nothing —
/// useful in a first-run app that hasn't yet been configured with an
/// auth key.
///
/// Runtime-agnostic: detects an ambient tokio runtime via
/// `Handle::try_current()` and uses it; falls back to a dedicated
/// `mythkernel-scheduler` thread with its own current-thread runtime
/// when called from outside any runtime (the Tauri shell's startup
/// path).
pub fn spawn(
    feeds: Vec<Box<dyn ScheduledFeed>>,
    feeds_dir: PathBuf,
    interval: Duration,
) -> SchedulerHandle {
    let kick = Arc::new(Notify::new());
    let shutdown = Arc::new(Notify::new());
    let kick_for_task = kick.clone();
    let shutdown_for_task = shutdown.clone();
    let interval = if interval.is_zero() {
        DEFAULT_INTERVAL
    } else {
        interval
    };

    let work = async move {
        if feeds.is_empty() {
            tracing::info!("feed scheduler: no feeds configured, idling");
            shutdown_for_task.notified().await;
            return;
        }
        // First tick fires immediately after a small grace period so we
        // don't compete with engine startup for the network. Subsequent
        // ticks honor the configured interval; failures shorten the
        // next wait to FAILURE_RETRY_INTERVAL.
        let mut wait = Duration::from_secs(15);
        loop {
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = kick_for_task.notified() => {
                    tracing::info!("feed scheduler: kick received");
                }
                _ = shutdown_for_task.notified() => {
                    tracing::info!("feed scheduler: shutdown");
                    return;
                }
            }
            let any_failed = run_all_once(&feeds, &feeds_dir, interval).await;
            wait = if any_failed {
                FAILURE_RETRY_INTERVAL
            } else {
                interval
            };
        }
    };

    let join = if let Ok(handle) = tokio::runtime::Handle::try_current() {
        SchedulerJoin::Async(handle.spawn(work))
    } else {
        let thread = std::thread::Builder::new()
            .name("mythkernel-scheduler".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(err) => {
                        tracing::error!(
                            error = %err,
                            "feed scheduler: failed to build dedicated runtime"
                        );
                        return;
                    }
                };
                rt.block_on(work);
            })
            .expect("spawn mythkernel-scheduler thread");
        SchedulerJoin::Owned(thread)
    };

    SchedulerHandle {
        kick,
        shutdown,
        join: Some(join),
    }
}

/// Run every configured feed once, write a `last_run.json` summary.
/// Returns `true` if *any* feed failed (so the caller can shorten the
/// next wait interval).
async fn run_all_once(
    feeds: &[Box<dyn ScheduledFeed>],
    feeds_dir: &Path,
    interval: Duration,
) -> bool {
    let started_at_utc = now_utc();
    let mut any_failed = false;
    let mut details: Vec<String> = Vec::new();
    for feed in feeds {
        let name = feed.name().to_string();
        tracing::info!(feed = %name, "scheduled update starting");
        match feed.run().await {
            Ok(detail) => {
                tracing::info!(feed = %name, detail = %detail, "scheduled update ok");
                details.push(format!("{name}: ok — {detail}"));
            }
            Err(err) => {
                tracing::warn!(feed = %name, error = %err, "scheduled update failed");
                details.push(format!("{name}: error — {err}"));
                any_failed = true;
            }
        }
    }
    let finished_at_utc = now_utc();
    let next_interval = if any_failed {
        FAILURE_RETRY_INTERVAL
    } else {
        interval
    };
    let next_run_at_utc = finished_at_utc + next_interval.as_secs() as i64;
    let record = LastRun {
        started_at_utc,
        finished_at_utc,
        outcome: if any_failed {
            "error".into()
        } else {
            "ok".into()
        },
        detail: details.join("\n"),
        next_run_at_utc,
    };
    if let Err(e) = write_status_file(feeds_dir, &record) {
        tracing::warn!(error = %e, "failed to write feed last_run.json");
    }
    any_failed
}

fn write_status_file(feeds_dir: &Path, record: &LastRun) -> std::io::Result<()> {
    std::fs::create_dir_all(feeds_dir)?;
    let json = serde_json::to_vec_pretty(record).map_err(std::io::Error::other)?;
    let tmp = feeds_dir.join("last_run.json.tmp");
    std::fs::write(&tmp, &json)?;
    std::fs::rename(tmp, feeds_dir.join(STATUS_FILE))?;
    Ok(())
}

/// Read the persisted last-run record, if any. The UI uses this on
/// startup to render "Last updated: …" without spinning up the
/// scheduler.
pub fn read_last_run(feeds_dir: &Path) -> Option<LastRun> {
    let path = feeds_dir.join(STATUS_FILE);
    let bytes = std::fs::read(&path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn now_utc() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::tempdir;

    /// Test feed that increments a counter on each call.
    struct CountingFeed {
        name: &'static str,
        counter: Arc<AtomicUsize>,
        fail: bool,
    }
    impl ScheduledFeed for CountingFeed {
        fn name(&self) -> &str {
            self.name
        }
        fn run<'a>(
            &'a self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + 'a>>
        {
            let counter = self.counter.clone();
            let fail = self.fail;
            Box::pin(async move {
                let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
                if fail {
                    Err(format!("forced failure #{n}"))
                } else {
                    Ok(format!("run #{n}"))
                }
            })
        }
    }

    #[tokio::test]
    async fn writes_status_file_after_run() {
        let dir = tempdir().unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let feeds: Vec<Box<dyn ScheduledFeed>> = vec![Box::new(CountingFeed {
            name: "ok",
            counter: counter.clone(),
            fail: false,
        })];
        let any_failed = run_all_once(&feeds, dir.path(), Duration::from_secs(60)).await;
        assert!(!any_failed);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        let lr = read_last_run(dir.path()).expect("status file written");
        assert_eq!(lr.outcome, "ok");
        assert!(lr.detail.contains("ok"));
    }

    #[tokio::test]
    async fn failure_records_error_outcome() {
        let dir = tempdir().unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let feeds: Vec<Box<dyn ScheduledFeed>> = vec![Box::new(CountingFeed {
            name: "boom",
            counter,
            fail: true,
        })];
        let any_failed = run_all_once(&feeds, dir.path(), Duration::from_secs(60)).await;
        assert!(any_failed);
        let lr = read_last_run(dir.path()).expect("status file written");
        assert_eq!(lr.outcome, "error");
        assert!(lr.detail.contains("forced failure"));
    }

    #[tokio::test]
    async fn kick_triggers_immediate_run() {
        let dir = tempdir().unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let feeds: Vec<Box<dyn ScheduledFeed>> = vec![Box::new(CountingFeed {
            name: "kicked",
            counter: counter.clone(),
            fail: false,
        })];
        // Set an interval far beyond the test window so the only way
        // the run happens is via `kick`.
        let handle = spawn(feeds, dir.path().to_path_buf(), Duration::from_secs(3600));
        // The initial 15s grace prevents the first tick from racing
        // the kick — kick is still serviced by `select!`.
        handle.kick();
        // Give the spawned task a moment to react. We need a real
        // sleep here; the runtime returns immediately for `yield_now`.
        tokio::time::sleep(Duration::from_millis(300)).await;
        // Wait until either the counter advances or we time out.
        let start = std::time::Instant::now();
        while counter.load(Ordering::Relaxed) == 0 && start.elapsed() < Duration::from_secs(2) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            counter.load(Ordering::Relaxed) >= 1,
            "kick should have triggered at least one run"
        );
        drop(handle);
    }

    #[test]
    fn missing_status_file_is_none() {
        let dir = tempdir().unwrap();
        assert!(read_last_run(dir.path()).is_none());
    }
}
