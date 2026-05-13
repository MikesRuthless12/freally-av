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
    /// TASK-053 / TASK-056 — when set, ignore the target path and fan
    /// out across every detected volume on the host. Windows-only
    /// (`MultiVolumeWalker` discovery returns the requested root on
    /// other platforms). Off by default.
    pub all_volumes: bool,
    /// Phase 5 wave 3 follow-up — when `true`, the adaptive throttle's
    /// per-file `std::thread::sleep` is skipped so the scan runs at
    /// the consumer pool's natural rate. The throttle was designed
    /// for background daemon scans (Phase 8+) that need to yield to
    /// interactive work; for user-initiated foreground scans the user
    /// is actively staring at the progress bar and wants flat-out
    /// throughput. Default `true` since the GUI + CLI are both
    /// foreground entry points.
    pub foreground: bool,
    /// Phase 6 — run the Windows registry persistence-key sweep before
    /// the file walk. Quick Scan turns this on. Custom Scan defaults
    /// off so the file workflow stays unchanged.
    pub include_registry: bool,
    /// Phase 6 — enumerate running processes and hash each main exe
    /// before the file walk. Quick Scan turns this on.
    pub include_processes: bool,
    /// Phase 6 — run the per-file walker + worker pool. Defaults on
    /// (every existing scan path expects it). Quick Scan can leave it
    /// on (with a `target` of the canonical hotspot paths) or, for a
    /// "registry + processes only" sweep, turn it off.
    pub include_files: bool,
    /// Phase 6 — recurse into archive containers (.zip / .zipx) and
    /// hash each entry through the same detection pipeline. The
    /// archive itself counts as one file in `files_visited`; entries
    /// scanned inside accumulate into a separate `archive_entries`
    /// counter. Off by default (per-archive open + per-entry hash
    /// costs add real latency on big backup folders).
    pub include_archives: bool,
    /// Phase 6 — run heuristic pattern matchers after the file/
    /// registry/process phases complete. Flags `.exe` / `.dll` /
    /// `.scr` / etc. in known dropper-staging dirs (`%TEMP%`,
    /// `%APPDATA%`, Downloads, ProgramData/Temp). Off by default.
    pub run_heuristics: bool,
    /// Optional path to a `crc32_blacklist.bin` (the fast-screen
    /// artifact emitted by `tools/feed-builder`). When provided,
    /// the hasher computes CRC32 first; files whose CRC32 isn't in
    /// the set skip BLAKE3 + SHA-256 + the entire detection pipeline.
    /// ~1 in 4,300 false-positive rate at the gate stage; those
    /// fall through to the normal hashing path and BLAKE3 confirms.
    /// `None` (the default) preserves the legacy "hash every file"
    /// behavior — existing callers are unaffected.
    pub crc32_gate_path: Option<std::path::PathBuf>,
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
            all_volumes: false,
            foreground: true,
            include_registry: false,
            include_processes: false,
            include_files: true,
            include_archives: false,
            run_heuristics: false,
            crc32_gate_path: None,
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
    /// TASK-053 / TASK-056 — persist the multi-volume fan-out toggle so
    /// a resumed scan continues across the same volume set. `#[serde(default)]`
    /// keeps older tokens loading cleanly (defaults to `false` = single root).
    #[serde(default)]
    pub all_volumes: bool,
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
        /// TASK-040 / wave-3 follow-up — when this start is actually
        /// a resume from a paused scan, these fields carry the prior
        /// run's counters so the UI's running totals don't visually
        /// reset to zero before the worker's first `File` event lands
        /// with the real numbers. `0` for fresh starts.
        #[serde(default)]
        resumed_files_visited: i64,
        #[serde(default)]
        resumed_files_hashed: i64,
        #[serde(default)]
        resumed_bytes_visited: i64,
        #[serde(default)]
        resumed_findings_count: i64,
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
        /// FR-135 / TASK-137 — running enumeration count, **unlocked**.
        /// Tracks the moving denominator while the producer is still
        /// discovering files. `None` after `EnumerationComplete` fires
        /// (UI switches to `files_total_locked`).
        #[serde(default)]
        files_total_running: Option<u64>,
        /// FR-135 / TASK-137 — locked total after the producer finished
        /// enumeration. `None` until the producer emits
        /// `EnumerationComplete`; from that event onward this carries
        /// the canonical Y in the "X/Y" UI presentation.
        #[serde(default)]
        files_total_locked: Option<u64>,
        /// Cumulative counters at the moment this event was emitted.
        /// The Tauri forwarder throttles File events to ≤ 10 Hz, so a
        /// per-event `+1` on the UI side underflows on fast scans.
        /// The frontend SETs to these values instead, which stays
        /// correct under arbitrary event drop / coalesce.
        #[serde(default)]
        files_visited_total: u64,
        #[serde(default)]
        files_hashed_total: u64,
        #[serde(default)]
        bytes_visited_total: u64,
        #[serde(default)]
        findings_count_total: u64,
    },
    /// FR-135 / TASK-137 — fires exactly once per scan, when the
    /// producer finishes walking every requested root. After this event
    /// the UI swaps from `X scanned · Y enumerated · counting…` to
    /// `X/Y`. Files surfaced after this point (e.g. mid-scan tree
    /// mutations) accrue against the `+N discovered after lock` /
    /// `Y − D not found` scan-summary footnotes; the locked Y here does
    /// not change.
    EnumerationComplete {
        scan_id: i64,
        files_total_locked: u64,
        bytes_total_locked: u64,
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
    /// Worker observed a cancel request, marked the scan row as
    /// `cancelled`, and exited. **No resume token is written** — the
    /// scan cannot be resumed. Counters reflect work done before the
    /// cancellation point.
    Cancelled {
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
    /// Phase 6 — Registry phase started. UI switches the active counter
    /// tile to "Registry items scanned". `expected_items` is the
    /// total value count across every persistence key, pre-counted so
    /// the UI's progress bar has a denominator from tick one (rather
    /// than re-walking "counting…").
    RegistryPhaseStarted {
        scan_id: i64,
        #[serde(default)]
        expected_items: u64,
    },
    /// Registry phase progress. `items_total` is the running cumulative
    /// count of value entries inspected so far across all persistence
    /// keys. `current_key` is the key the engine is currently iterating.
    RegistryProgress {
        scan_id: i64,
        items_scanned_total: u64,
        current_key: String,
    },
    /// Registry phase finished. `items_total` is the final count.
    RegistryPhaseComplete {
        scan_id: i64,
        items_total: u64,
    },
    /// Phase 6 — Process phase started. `expected_processes` is the
    /// total PID count from the initial `sysinfo::System::refresh` so
    /// the UI shows X/Y from tick one.
    ProcessPhaseStarted {
        scan_id: i64,
        #[serde(default)]
        expected_processes: u64,
    },
    /// One process inspected. `processes_total` is the running cumulative
    /// count of PIDs visited; `name` is the process name; `exe_path` is
    /// the resolved exe path (None if unresolvable / kernel pseudo).
    ProcessProgress {
        scan_id: i64,
        processes_scanned_total: u64,
        pid: u32,
        name: String,
        #[serde(default)]
        exe_path: Option<PathBuf>,
    },
    /// Process phase finished.
    ProcessPhaseComplete {
        scan_id: i64,
        processes_total: u64,
    },
    /// Phase 6 — Engine processed one entry inside an archive
    /// container. UI shows "Inside <archive>: <entry>" in the
    /// current-path line and increments the archive-entries counter.
    ArchiveEntry {
        scan_id: i64,
        archive_path: PathBuf,
        entry_name: String,
        archive_entries_scanned_total: u64,
    },
    /// Phase 6 — Heuristic post-pass started. UI swaps the active
    /// tile to "Heuristics" and shows the items scanned counter.
    HeuristicPhaseStarted {
        scan_id: i64,
        #[serde(default)]
        expected_items: u64,
    },
    /// One heuristic item examined. `current_path` is the file/
    /// registry value currently being checked.
    HeuristicProgress {
        scan_id: i64,
        items_scanned_total: u64,
        current_path: String,
    },
    /// Heuristic post-pass finished. `items_total` is the count of
    /// items examined; `flagged_total` is the count of items that
    /// matched a heuristic rule and were recorded as findings.
    HeuristicPhaseComplete {
        scan_id: i64,
        items_total: u64,
        flagged_total: u64,
    },
}

/// Handle returned by [`crate::engine::ScanEngine::scan`]. Drop the handle to
/// detach (the scan keeps running in the background); call [`ScanHandle::join`]
/// to wait for completion.
pub struct ScanHandle {
    pub scan_id: i64,
    pub progress: broadcast::Receiver<ScanProgress>,
    pub worker: tokio::task::JoinHandle<()>,
    /// Pause flag (TASK-040). The worker checks this between each file
    /// AND between hash chunks (mid-hash cooperative cancellation via
    /// [`crate::hasher::Hasher::with_abort_flag`]); when `true` it
    /// persists a resume token, emits `ScanProgress::Paused`, and
    /// exits. Cloning is cheap (`Arc::clone`).
    pub pause_flag: Arc<AtomicBool>,
    /// Cancel flag — sibling to `pause_flag`. Set by `scan_cancel`;
    /// the worker exits without writing a resume token and marks the
    /// scan row as `cancelled`. Cancellation is **not** resumable.
    pub cancel_flag: Arc<AtomicBool>,
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
