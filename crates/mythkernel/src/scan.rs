//! Scan handle, progress events, and scan-level value types.
//!
//! TASK-012 (Phase 1) ships the engine-internal scan types. Mid-flight pause /
//! resume across reboot is TASK-040 (Phase 4), MFT/USN per-volume parallelism
//! is TASK-053 (Phase 5), and the locked-Y two-phase counter is TASK-137.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::history::ScanTrigger;

/// Cap on the number of completed paths we persist into a single
/// resume_token. Beyond this we let resume re-do the duplicate work —
/// findings persist DB-side, so the worst case is a couple extra
/// hash passes (cheap) rather than a giant token (slow to read/write).
pub const RESUME_TOKEN_PATH_CAP: usize = 100_000;

/// What the user asked us to scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanTarget {
    /// One path (file or directory).
    Path(PathBuf),
    /// Multiple paths (treated as one logical scan).
    Paths(Vec<PathBuf>),
}

impl ScanTarget {
    /// Iterator over the root paths in this target.
    pub fn paths(&self) -> impl Iterator<Item = &PathBuf> {
        let v: Vec<&PathBuf> = match self {
            ScanTarget::Path(p) => vec![p],
            ScanTarget::Paths(ps) => ps.iter().collect(),
        };
        v.into_iter()
    }

    /// JSON-serialized representation, written into the `scans.target_paths`
    /// column when the scan record is created.
    pub fn to_paths_json(&self) -> String {
        match self {
            ScanTarget::Path(p) => serde_json::to_string(&[p]).unwrap_or_else(|_| "[]".into()),
            ScanTarget::Paths(ps) => serde_json::to_string(ps).unwrap_or_else(|_| "[]".into()),
        }
    }

    /// Categorical label for the `scans.target_kind` column.
    pub fn kind(&self) -> &'static str {
        match self {
            ScanTarget::Path(_) => "path",
            ScanTarget::Paths(_) => "paths",
        }
    }
}

/// Per-scan options. Phase 1 keeps it small; later phases extend with
/// throttle (FR-012), exclusions snapshot (FR-062), and archive depth
/// (FR-017). TASK-040 (Phase 4 wave 2) added `Clone` so the worker can
/// stash the options into a resume token.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub trigger: ScanTrigger,
    pub follow_symlinks: bool,
    pub skip_hidden: bool,
    pub max_depth: Option<usize>,
    pub compute_sha256: bool,
    /// Emit `ScanProgress::PartialHash` events at ≤ 10 Hz while hashing
    /// each file (TASK-134, FR-136). Off by default; the Scan dashboard's
    /// operator-mode toggle flips this on per-scan.
    pub emit_partial_hash: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            trigger: ScanTrigger::Manual,
            follow_symlinks: false,
            skip_hidden: false,
            max_depth: None,
            compute_sha256: false,
            emit_partial_hash: false,
        }
    }
}

/// Resume token persisted on pause (TASK-040). The token is JSON-
/// serialized into `scans.resume_token` so a fresh process can pick the
/// scan up by reading the DB. We re-walk the original target paths on
/// resume and skip any path in `processed_paths`; counters carry over.
///
/// `schema_version` lets us evolve the layout without a migration; a
/// resume token from an older version is silently discarded (rerun
/// from scratch) rather than risk a botched continuation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeToken {
    pub schema_version: u32,
    pub target_paths: Vec<PathBuf>,
    pub target_kind: String,
    pub follow_symlinks: bool,
    pub skip_hidden: bool,
    pub compute_sha256: bool,
    /// TASK-134 / sec-review R-B2: persist the operator-mode partial-hash
    /// toggle so a resumed scan emits events with the same cadence the
    /// user originally requested. `#[serde(default)]` keeps old (schema
    /// v1) tokens loading cleanly.
    #[serde(default)]
    pub emit_partial_hash: bool,
    /// Files we've already hashed + processed. On resume we skip these.
    /// Capped at [`RESUME_TOKEN_PATH_CAP`]; if the original scan exceeded
    /// the cap the engine just re-scans the overage (cheap correctness
    /// vs. an unbounded blob).
    pub processed_paths: BTreeSet<String>,
    pub files_visited: i64,
    pub files_hashed: i64,
    pub bytes_visited: i64,
    pub findings_count: i64,
}

impl ResumeToken {
    /// Bumped to 2 when `emit_partial_hash` was added (TASK-134). Older
    /// tokens (schema 1) still load via `#[serde(default)]` — engine
    /// resume re-runs them with the field defaulted to `false`.
    pub const CURRENT_SCHEMA: u32 = 2;
}

/// One progress event emitted by a running scan.
///
/// Subscribers consume this stream via [`ScanHandle::progress`]. The engine
/// emits at most a few thousand events per second; UI subscribers should
/// throttle their own re-render rate (≤ 10 Hz per FR-085 / FR-136).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScanProgress {
    Started {
        scan_id: i64,
        started_at_utc: i64,
    },
    File {
        path: PathBuf,
        blake3: String,
        size: u64,
        /// Calibrated ETA in seconds, post-3%-baseline-clamp per FR-085 /
        /// TASK-038. `None` while the estimator is still warming up (first
        /// sample, or before file/byte totals are known). UI formats as
        /// `Hh Mm Ss` counting down (see frontend `formatEta`).
        #[serde(default)]
        eta_secs: Option<f64>,
    },
    /// Live mid-flight BLAKE3 partial of the file currently being hashed.
    /// Throttled at ≤ 10 Hz by the engine (TASK-134 / FR-136). Optional —
    /// off by default; the engine emits this variant only when the scan
    /// was started with `ScanOptions::emit_partial_hash = true`.
    PartialHash {
        scan_id: i64,
        path: PathBuf,
        /// Hex BLAKE3 of the bytes hashed so far.
        blake3_partial: String,
        bytes_done: u64,
    },
    /// A detector matched the file. Carries the persisted `findings.id` so
    /// the UI can request follow-up actions (quarantine, ignore) without
    /// a second round-trip.
    Finding {
        scan_id: i64,
        finding_id: i64,
        path: PathBuf,
        rule_id: String,
        rule_source: String,
        severity: String,
    },
    Error {
        path: PathBuf,
        message: String,
    },
    Completed {
        scan_id: i64,
        files_visited: i64,
        files_hashed: i64,
        bytes_visited: i64,
        findings_count: i64,
        duration_ms: u64,
    },
    /// Worker observed a pause request, persisted a resume token, and
    /// exited cleanly. The scan can be resumed by `engine.resume(id)`.
    Paused {
        scan_id: i64,
        files_visited: i64,
        files_hashed: i64,
        bytes_visited: i64,
        findings_count: i64,
    },
    Failed {
        scan_id: i64,
        message: String,
    },
}

/// Handle returned by [`crate::engine::ScanEngine::scan`]. Drop the handle to
/// detach (the scan keeps running in the background); call [`ScanHandle::join`]
/// to wait for completion.
pub struct ScanHandle {
    pub scan_id: i64,
    pub progress: broadcast::Receiver<ScanProgress>,
    pub worker: tokio::task::JoinHandle<()>,
    /// Pause flag (TASK-040). The worker checks this between each file;
    /// when `true` it persists a resume token, emits `ScanProgress::Paused`,
    /// and exits. Cloning is cheap (`Arc::clone`).
    pub pause_flag: Arc<AtomicBool>,
}

impl ScanHandle {
    /// Wait for the scan worker to finish. Use `progress` if you also want
    /// per-file events.
    pub async fn join(self) -> Result<(), tokio::task::JoinError> {
        self.worker.await
    }

    /// Signal the worker to pause at the next iteration boundary. The
    /// worker writes a resume token and emits `ScanProgress::Paused`
    /// before exiting; callers should `join()` to observe that exit.
    pub fn request_pause(&self) {
        self.pause_flag
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}
