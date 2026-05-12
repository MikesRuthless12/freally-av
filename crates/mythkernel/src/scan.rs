//! Scan handle, progress events, and scan-level value types.
//!
//! TASK-012 (Phase 1) ships the engine-internal scan types. Mid-flight pause /
//! resume across reboot is TASK-040 (Phase 4), MFT/USN per-volume parallelism
//! is TASK-053 (Phase 5), and the locked-Y two-phase counter is TASK-137.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::history::ScanTrigger;

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
/// pause/resume tokens (FR-011), throttle (FR-012), exclusions snapshot
/// (FR-062), and archive depth (FR-017).
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub trigger: ScanTrigger,
    pub follow_symlinks: bool,
    pub skip_hidden: bool,
    pub max_depth: Option<usize>,
    pub compute_sha256: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            trigger: ScanTrigger::Manual,
            follow_symlinks: false,
            skip_hidden: false,
            max_depth: None,
            compute_sha256: false,
        }
    }
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
}

impl ScanHandle {
    /// Wait for the scan worker to finish. Use `progress` if you also want
    /// per-file events.
    pub async fn join(self) -> Result<(), tokio::task::JoinError> {
        self.worker.await
    }
}
