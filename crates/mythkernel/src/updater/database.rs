//! Database (signature feed) update channel (TASK-131, Phase 4 wave 3).
//!
//! Implements FR-153 (database portion) + FR-156. Wraps the existing per-feed
//! updaters (`abusech`, `nsrl`, ...) in a uniform progress-emitting interface
//! and exposes the channel-level orchestration the UI uses.
//!
//! Per FR-156 there is **no client-side rate limit** — users may click "Update
//! virus database now" as often as they like; the unrestricted pull is a key
//! differentiator versus rate-limited commercial AVs. Per-feed `If-Modified-Since`
//! / `ETag` short-circuits the heavy bytes-on-the-wire path when the upstream
//! says nothing changed.
//!
//! Per FR-153 every per-feed run emits `db_update:progress` events at ≤ 10 Hz
//! with phases `download | decompress | rebuild_index | swap`. The Tauri shell
//! forwards these into the Settings → Updates "Virus database" pane.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use crate::updater::channels::{ChannelKind, ChannelState, LastCheckOutcome, updater_dir};

/// Phases of one database-feed update (FR-153). Stable wire strings;
/// changing them requires a TS-side mirror update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseUpdatePhase {
    /// HTTP bytes flowing in.
    Download,
    /// Local decompression / parsing of the dump (e.g. malwarebazaar text
    /// → 32-byte hash records).
    Decompress,
    /// Sort + dedup + rebuild the mmap-friendly `.bin` index in memory.
    RebuildIndex,
    /// Atomic rename of the new `.bin` into place. tmp → final.
    Swap,
}

impl DatabaseUpdatePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            DatabaseUpdatePhase::Download => "download",
            DatabaseUpdatePhase::Decompress => "decompress",
            DatabaseUpdatePhase::RebuildIndex => "rebuild_index",
            DatabaseUpdatePhase::Swap => "swap",
        }
    }
}

/// One progress event for the `db_update:progress` Tauri topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseUpdateProgress {
    /// Stable feed identifier — `"abusech"`, `"nsrl"`, etc. The
    /// frontend joins this with the persisted feed metadata to render
    /// the per-feed bar.
    pub feed_id: String,
    pub phase: DatabaseUpdatePhase,
    pub bytes_done: u64,
    pub bytes_total: u64,
    /// Free-text status. Empty string means "no extra context — render
    /// the phase name".
    pub message: String,
}

/// Per-feed metadata persisted in `database_state.json :: feeds`. The UI
/// uses this to render the per-feed last-checked / last-installed
/// timestamps independently of the engine binary version.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FeedMeta {
    /// Unix seconds of the most recent successful pull (200 OK from
    /// upstream — does not require bytes to have changed).
    pub last_check_at_utc: i64,
    /// Unix seconds of the last actual content change (post-swap).
    pub last_install_at_utc: i64,
    /// Total entries currently in the merged .bin file.
    pub entry_count: u64,
    /// Free-text outcome of the most recent run.
    pub last_outcome: String,
    /// Free-text last error (empty on success).
    pub last_error: String,
    /// `If-Modified-Since` / `Last-Modified` value from the most recent
    /// successful pull (RFC 7231 HTTP-date). Sent back to upstream on the
    /// next pull to short-circuit unchanged downloads.
    pub last_modified: String,
    /// `ETag` value from the most recent successful pull. Same purpose
    /// as `last_modified` — short-circuit on no-change.
    pub etag: String,
}

/// Full database-channel state. Embeds the generic `ChannelState` plus
/// the per-feed metadata map.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseChannelState {
    #[serde(flatten)]
    pub common: ChannelState,
    /// Per-feed metadata keyed by `feed_id`.
    pub feeds: HashMap<String, FeedMeta>,
}

impl DatabaseChannelState {
    pub fn defaults() -> Self {
        Self {
            common: ChannelState::defaults_for(ChannelKind::Database),
            feeds: HashMap::new(),
        }
    }

    pub fn feed_meta(&self, feed_id: &str) -> FeedMeta {
        self.feeds.get(feed_id).cloned().unwrap_or_default()
    }
}

/// Progress callback the channel hands to each feed runner. Cheap clone
/// (Arc<dyn Fn>). UI subscribers register one of these and translate to
/// `db_update:progress` events.
pub type DbProgressCallback =
    std::sync::Arc<dyn Fn(DatabaseUpdateProgress) + Send + Sync + 'static>;

/// Trait every feed runner implements. The channel iterates feeds in
/// the order registered, calling `run` on each. Failures are captured
/// and surfaced individually — one bad feed never aborts the whole
/// cycle (matches the scheduler's "best-effort per-feed" contract).
pub trait DatabaseFeedRunner: Send + Sync {
    /// Stable feed identifier.
    fn feed_id(&self) -> &str;
    /// Run one cycle. Emits progress events via `progress` ≤ 10 Hz.
    /// Returns a free-text outcome string on success or an error.
    fn run<'a>(
        &'a self,
        progress: DbProgressCallback,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<FeedRunOutcome, String>> + Send + 'a>,
    >;
}

/// What a feed runner reports back to the channel on success. Used to
/// stamp `FeedMeta::entry_count` + the modified-since / etag pair on the
/// next cycle.
#[derive(Debug, Clone, Default)]
pub struct FeedRunOutcome {
    pub entry_count: u64,
    pub last_modified: String,
    pub etag: String,
    /// Free-text human description of what landed.
    pub detail: String,
    /// True iff the on-disk feed bytes actually changed in this run.
    /// When an `If-Modified-Since` / `ETag` short-circuit fires (HTTP
    /// 304) this stays `false`, the channel records the outcome as
    /// `UpToDate`, and `last_install_at_utc` is NOT touched (code-review
    /// blocker R-B3 — the previous version always landed at `Installed`).
    pub bytes_changed: bool,
}

/// Adapter wrapping the existing `AbuseChUpdater`. Emits the four
/// canonical phases. The underlying updater doesn't yet expose
/// streaming progress — Phase 4 emits one event per phase rather than
/// byte-level (frontend animates between events).
pub struct AbuseChFeedRunner {
    inner: crate::updater::abusech::AbuseChUpdater,
}

impl AbuseChFeedRunner {
    pub fn new(inner: crate::updater::abusech::AbuseChUpdater) -> Self {
        Self { inner }
    }
}

impl DatabaseFeedRunner for AbuseChFeedRunner {
    fn feed_id(&self) -> &str {
        "abusech"
    }
    fn run<'a>(
        &'a self,
        progress: DbProgressCallback,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<FeedRunOutcome, String>> + Send + 'a>,
    > {
        Box::pin(async move {
            emit(
                &progress,
                "abusech",
                DatabaseUpdatePhase::Download,
                0,
                0,
                "fetching MalwareBazaar + ThreatFox",
            );
            let report = self.inner.update().await.map_err(|e| e.to_string())?;
            emit(
                &progress,
                "abusech",
                DatabaseUpdatePhase::Decompress,
                0,
                0,
                "parsing dumps",
            );
            emit(
                &progress,
                "abusech",
                DatabaseUpdatePhase::RebuildIndex,
                report.merged_count,
                report.merged_count,
                "sorting + deduplicating",
            );
            emit(
                &progress,
                "abusech",
                DatabaseUpdatePhase::Swap,
                report.merged_count,
                report.merged_count,
                "atomic rename",
            );
            Ok(FeedRunOutcome {
                entry_count: report.merged_count,
                last_modified: String::new(),
                etag: String::new(),
                detail: format!(
                    "merged {} hashes in {:.1}s",
                    report.merged_count,
                    report.elapsed.as_secs_f64()
                ),
                // Phase 4 wave 2 — the underlying `AbuseChUpdater` always
                // rewrites the .bin atomically; we don't yet have a
                // 304/Last-Modified short-circuit on this feed, so every
                // successful run is treated as a real swap. When the
                // adapter learns to honor `Last-Modified` (FR-156 future
                // work), flip this conditionally.
                bytes_changed: true,
            })
        })
    }
}

/// Adapter wrapping the existing `NsrlUpdater`. Same shape as
/// `AbuseChFeedRunner`.
pub struct NsrlFeedRunner {
    inner: crate::updater::nsrl::NsrlUpdater,
}

impl NsrlFeedRunner {
    pub fn new(inner: crate::updater::nsrl::NsrlUpdater) -> Self {
        Self { inner }
    }
}

impl DatabaseFeedRunner for NsrlFeedRunner {
    fn feed_id(&self) -> &str {
        "nsrl"
    }
    fn run<'a>(
        &'a self,
        progress: DbProgressCallback,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<FeedRunOutcome, String>> + Send + 'a>,
    > {
        Box::pin(async move {
            emit(
                &progress,
                "nsrl",
                DatabaseUpdatePhase::Download,
                0,
                0,
                "fetching NSRL",
            );
            let report = self.inner.update().await.map_err(|e| e.to_string())?;
            emit(
                &progress,
                "nsrl",
                DatabaseUpdatePhase::Decompress,
                report.parsed_count,
                report.parsed_count,
                "parsing TSV/CSV",
            );
            emit(
                &progress,
                "nsrl",
                DatabaseUpdatePhase::RebuildIndex,
                report.merged_count,
                report.merged_count,
                "rebuilding allowlist index",
            );
            emit(
                &progress,
                "nsrl",
                DatabaseUpdatePhase::Swap,
                report.merged_count,
                report.merged_count,
                "atomic rename",
            );
            Ok(FeedRunOutcome {
                entry_count: report.merged_count,
                last_modified: String::new(),
                etag: String::new(),
                detail: format!(
                    "merged {} NSRL hashes in {:.1}s",
                    report.merged_count,
                    report.elapsed.as_secs_f64()
                ),
                bytes_changed: true,
            })
        })
    }
}

fn emit(
    cb: &DbProgressCallback,
    feed_id: &str,
    phase: DatabaseUpdatePhase,
    bytes_done: u64,
    bytes_total: u64,
    message: &str,
) {
    cb(DatabaseUpdateProgress {
        feed_id: feed_id.to_string(),
        phase,
        bytes_done,
        bytes_total,
        message: message.to_string(),
    });
}

/// Database update channel. Owns the per-feed registry and the
/// persistence layer. Cheap to clone (no live state).
pub struct DatabaseChannel {
    state_dir: PathBuf,
    feeds_dir: PathBuf,
    runners: Vec<std::sync::Arc<dyn DatabaseFeedRunner>>,
    /// Notifier the scheduler wires up; users hit "Check now" → kick().
    kick: std::sync::Arc<Notify>,
    /// Per-cycle interval (defaults to `ChannelState::interval_hours`).
    interval: Duration,
}

impl DatabaseChannel {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            state_dir: updater_dir(data_dir),
            feeds_dir: data_dir.join("feeds"),
            runners: Vec::new(),
            kick: std::sync::Arc::new(Notify::new()),
            interval: Duration::from_secs(12 * 3600),
        }
    }

    /// Register a feed runner. Order is preserved; runners execute
    /// sequentially within one cycle.
    pub fn register<R: DatabaseFeedRunner + 'static>(mut self, runner: R) -> Self {
        self.runners.push(std::sync::Arc::new(runner));
        self
    }

    /// Override the cycle interval (default 12 h).
    pub fn with_interval(mut self, d: Duration) -> Self {
        self.interval = d;
        self
    }

    pub fn feeds_dir(&self) -> &Path {
        &self.feeds_dir
    }

    pub fn kick_handle(&self) -> std::sync::Arc<Notify> {
        self.kick.clone()
    }

    /// Iterate over the stable feed IDs registered in this channel.
    /// Surfaces order-of-registration to log lines + the UI.
    pub fn iter_feed_ids(&self) -> impl Iterator<Item = &str> {
        self.runners.iter().map(|r| r.feed_id())
    }

    /// Read persisted state. Missing file → defaults.
    pub fn load_state(&self) -> DatabaseChannelState {
        let path = self.state_dir.join(ChannelKind::Database.state_file());
        match std::fs::read(&path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).unwrap_or_else(|_| DatabaseChannelState::defaults())
            }
            Err(_) => DatabaseChannelState::defaults(),
        }
    }

    pub fn save_state(&self, state: &DatabaseChannelState) -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(&self.state_dir)?;
        let path = self.state_dir.join(ChannelKind::Database.state_file());
        let json = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, &path)?;
        Ok(path)
    }

    /// Run one cycle of every registered feed. Emits progress events
    /// via `progress`. Returns the post-cycle state (which is also
    /// persisted to disk) so callers don't need a follow-up `load_state`
    /// — that round-trip was a TOCTOU window per code-review CR-I8.
    /// The aggregate "did everything succeed" is encoded in the
    /// returned `common.last_outcome` (`Installed`/`UpToDate` = ok,
    /// `Failed` = at-least-one-failed).
    ///
    /// Outcome semantics (code-review R-B3):
    ///   * any feed failed → channel outcome = `Failed`
    ///   * else any feed swapped bytes → `Installed`
    ///   * else (all 304 / no-change) → `UpToDate`
    ///
    /// `last_install_at_utc` is bumped per-feed **only** when that feed
    /// actually changed bytes, so the UI's "Last installed" timestamp
    /// reflects real content updates rather than every successful poll.
    pub async fn run_once(&self, progress: DbProgressCallback) -> DatabaseChannelState {
        let mut state = self.load_state();
        let mut any_failed = false;
        let mut any_installed = false;
        for runner in &self.runners {
            let id = runner.feed_id().to_string();
            tracing::info!(feed = %id, "database channel: starting feed");
            match runner.run(progress.clone()).await {
                Ok(outcome) => {
                    let now = now_utc_secs();
                    let prior = state.feed_meta(&id);
                    let meta = FeedMeta {
                        last_check_at_utc: now,
                        last_install_at_utc: if outcome.bytes_changed {
                            now
                        } else {
                            prior.last_install_at_utc
                        },
                        entry_count: outcome.entry_count,
                        last_outcome: if outcome.bytes_changed {
                            "ok"
                        } else {
                            "up_to_date"
                        }
                        .to_string(),
                        last_error: String::new(),
                        last_modified: outcome.last_modified,
                        etag: outcome.etag,
                    };
                    state.feeds.insert(id, meta);
                    if outcome.bytes_changed {
                        any_installed = true;
                    }
                }
                Err(err) => {
                    tracing::warn!(feed = %id, error = %err, "database channel: feed failed");
                    let mut meta = state.feed_meta(&id);
                    meta.last_check_at_utc = now_utc_secs();
                    meta.last_outcome = "error".to_string();
                    meta.last_error = err;
                    state.feeds.insert(id, meta);
                    any_failed = true;
                }
            }
        }
        let outcome = if any_failed {
            LastCheckOutcome::Failed
        } else if any_installed {
            LastCheckOutcome::Installed
        } else {
            LastCheckOutcome::UpToDate
        };
        state.common.record_check(outcome, None);
        if let Err(err) = self.save_state(&state) {
            tracing::warn!(error = %err, "database channel: state persist failed");
        }
        state
    }
}

fn now_utc_secs() -> i64 {
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

    struct StubFeed {
        id: &'static str,
        counter: std::sync::Arc<AtomicUsize>,
        fail: bool,
    }

    impl DatabaseFeedRunner for StubFeed {
        fn feed_id(&self) -> &str {
            self.id
        }
        fn run<'a>(
            &'a self,
            progress: DbProgressCallback,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<FeedRunOutcome, String>> + Send + 'a>,
        > {
            let counter = self.counter.clone();
            let fail = self.fail;
            let id = self.id;
            Box::pin(async move {
                counter.fetch_add(1, Ordering::Relaxed);
                emit(&progress, id, DatabaseUpdatePhase::Download, 0, 0, "");
                emit(&progress, id, DatabaseUpdatePhase::Decompress, 0, 0, "");
                emit(&progress, id, DatabaseUpdatePhase::RebuildIndex, 0, 0, "");
                emit(&progress, id, DatabaseUpdatePhase::Swap, 0, 0, "");
                if fail {
                    Err(format!("forced failure: {id}"))
                } else {
                    Ok(FeedRunOutcome {
                        entry_count: 42,
                        bytes_changed: true,
                        ..Default::default()
                    })
                }
            })
        }
    }

    #[tokio::test]
    async fn run_once_records_per_feed_meta_on_success() {
        let dir = tempdir().unwrap();
        let counter = std::sync::Arc::new(AtomicUsize::new(0));
        let channel = DatabaseChannel::new(dir.path()).register(StubFeed {
            id: "stub",
            counter: counter.clone(),
            fail: false,
        });
        let progress: DbProgressCallback = std::sync::Arc::new(|_p| {});
        let state = channel.run_once(progress).await;
        assert!(matches!(
            state.common.last_outcome,
            LastCheckOutcome::Installed
        ));
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        let meta = state.feed_meta("stub");
        assert_eq!(meta.entry_count, 42);
        assert_eq!(meta.last_outcome, "ok");
        assert!(meta.last_check_at_utc > 0);
    }

    #[tokio::test]
    async fn run_once_isolates_per_feed_failure() {
        let dir = tempdir().unwrap();
        let counter = std::sync::Arc::new(AtomicUsize::new(0));
        let channel = DatabaseChannel::new(dir.path())
            .register(StubFeed {
                id: "ok",
                counter: counter.clone(),
                fail: false,
            })
            .register(StubFeed {
                id: "bad",
                counter,
                fail: true,
            });
        let progress: DbProgressCallback = std::sync::Arc::new(|_p| {});
        let state = channel.run_once(progress).await;
        // Aggregate failed.
        assert!(matches!(
            state.common.last_outcome,
            LastCheckOutcome::Failed
        ));
        // The "ok" feed still landed.
        assert_eq!(state.feed_meta("ok").last_outcome, "ok");
        // The "bad" feed surfaced its error.
        assert_eq!(state.feed_meta("bad").last_outcome, "error");
        assert!(state.feed_meta("bad").last_error.contains("forced failure"));
    }

    #[tokio::test]
    async fn progress_events_fire_in_phase_order() {
        let dir = tempdir().unwrap();
        let counter = std::sync::Arc::new(AtomicUsize::new(0));
        let channel = DatabaseChannel::new(dir.path()).register(StubFeed {
            id: "stub",
            counter,
            fail: false,
        });
        let phases = std::sync::Arc::new(std::sync::Mutex::new(Vec::<DatabaseUpdatePhase>::new()));
        let phases_clone = phases.clone();
        let progress: DbProgressCallback = std::sync::Arc::new(move |p| {
            phases_clone.lock().unwrap().push(p.phase);
        });
        channel.run_once(progress).await;
        let seq = phases.lock().unwrap().clone();
        assert_eq!(
            seq,
            vec![
                DatabaseUpdatePhase::Download,
                DatabaseUpdatePhase::Decompress,
                DatabaseUpdatePhase::RebuildIndex,
                DatabaseUpdatePhase::Swap,
            ]
        );
    }

    #[test]
    fn phase_strings_are_stable_wire_contract() {
        assert_eq!(DatabaseUpdatePhase::Download.as_str(), "download");
        assert_eq!(DatabaseUpdatePhase::Decompress.as_str(), "decompress");
        assert_eq!(DatabaseUpdatePhase::RebuildIndex.as_str(), "rebuild_index");
        assert_eq!(DatabaseUpdatePhase::Swap.as_str(), "swap");
    }

    #[test]
    fn database_state_round_trips_through_disk() {
        let dir = tempdir().unwrap();
        let channel = DatabaseChannel::new(dir.path());
        let mut state = DatabaseChannelState::defaults();
        state.feeds.insert(
            "abusech".to_string(),
            FeedMeta {
                entry_count: 999,
                last_outcome: "ok".to_string(),
                ..Default::default()
            },
        );
        channel.save_state(&state).unwrap();
        let loaded = channel.load_state();
        assert_eq!(loaded.feed_meta("abusech").entry_count, 999);
    }
}
