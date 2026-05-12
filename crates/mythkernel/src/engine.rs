//! Top-level scan engine.
//!
//! TASK-012 (Phase 1) ships [`ScanEngine`], the entry point the CLI
//! (`mythctl scan` — TASK-017) and Tauri bridge (`scan_start` — TASK-028)
//! both invoke. Each call to [`ScanEngine::scan`] returns a
//! [`crate::scan::ScanHandle`] with a broadcast receiver of
//! [`crate::scan::ScanProgress`] events.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use rusqlite::Connection;
use tokio::sync::broadcast;

use crate::detect::{DetectionPipeline, FileCtx, PipelineOutcome, blake3_hex_to_bytes};
use crate::error::EngineError;
use crate::hasher::Hasher;
use crate::history::{self, ScanStatus};
use crate::scan::{ScanHandle, ScanOptions, ScanProgress, ScanTarget};
use crate::walker::{FileWalker, PosixWalker, WalkEvent, WalkOpts};

/// The default progress-channel capacity. Subscribers that lag past this
/// buffer drop oldest events (broadcast channel semantics) — that's intended
/// since UI surfaces only need recent events for rendering.
const PROGRESS_CHANNEL_CAPACITY: usize = 4096;

/// The engine's persistent + in-memory state. Cheap to clone via the inner
/// `Arc`. Hold one per process; dispatch many concurrent scans through it.
#[derive(Clone)]
pub struct ScanEngine {
    db: Arc<Mutex<Connection>>,
    pipeline: Arc<DetectionPipeline>,
    engine_version: &'static str,
}

impl ScanEngine {
    pub fn new(db: Connection) -> Self {
        Self {
            db: Arc::new(Mutex::new(db)),
            pipeline: Arc::new(DetectionPipeline::new(Vec::new())),
            engine_version: env!("CARGO_PKG_VERSION"),
        }
    }

    /// Install a detection pipeline. The engine evaluates it against every
    /// successfully-hashed file and records `findings` rows + emits
    /// `ScanProgress::Finding` events on Detected outcomes. Allowlist
    /// (`SkipFile`) outcomes are silently honored — no event, no row.
    ///
    /// The default engine ships with an empty pipeline (no detectors); the
    /// Tauri bridge in TASK-028 builds a populated one from `<feeds_dir>`
    /// at startup.
    pub fn with_detection_pipeline(mut self, pipeline: DetectionPipeline) -> Self {
        self.pipeline = Arc::new(pipeline);
        self
    }

    /// Begin a scan. Inserts the row in `scans` synchronously (so the caller
    /// gets an id immediately), then spawns the worker that walks + hashes +
    /// finalizes.
    pub fn scan(&self, target: ScanTarget, opts: ScanOptions) -> Result<ScanHandle, EngineError> {
        let started_at_utc = now_utc();
        let started_at_instant = Instant::now();
        let target_paths_json = target.to_paths_json();
        let target_kind = target.kind();
        let trigger = opts.trigger;

        let scan_id = {
            let conn = self
                .db
                .lock()
                .map_err(|_| EngineError::Db(crate::db::DbError::Poisoned.to_string()))?;
            history::create_scan(
                &conn,
                started_at_utc,
                trigger,
                target_kind,
                &target_paths_json,
                "[]",
                self.engine_version,
                "{}",
            )
            .map_err(|e| EngineError::Db(e.to_string()))?
        };

        let (tx, rx) = broadcast::channel(PROGRESS_CHANNEL_CAPACITY);
        let _ = tx.send(ScanProgress::Started {
            scan_id,
            started_at_utc,
        });

        let db = self.db.clone();
        let pipeline = self.pipeline.clone();
        let tx_for_worker = tx.clone();
        let hasher = Hasher::new().with_sha256(opts.compute_sha256);
        let walk_opts = WalkOpts {
            follow_symlinks: opts.follow_symlinks,
            skip_hidden: opts.skip_hidden,
            max_depth: opts.max_depth,
        };
        let target_for_worker = target;

        // The walker uses rayon internally and the hash step is CPU-bound, so
        // this work belongs on the blocking pool, not the tokio reactor.
        let worker = tokio::task::spawn_blocking(move || {
            let walker = PosixWalker::new();

            let mut files_visited: i64 = 0;
            let mut files_hashed: i64 = 0;
            let mut bytes_visited: i64 = 0;
            let mut findings_count: i64 = 0;

            for root in target_for_worker.paths() {
                let event_rx = walker.walk(root, walk_opts.clone());
                for event in event_rx.iter() {
                    match event {
                        WalkEvent::File { path, size, .. } => {
                            files_visited += 1;
                            bytes_visited += size as i64;
                            match hasher.hash_file(&path) {
                                Ok(result) => {
                                    files_hashed += 1;
                                    let _ = tx_for_worker.send(ScanProgress::File {
                                        path: path.clone(),
                                        blake3: result.blake3.clone(),
                                        size: result.size,
                                    });

                                    // Run the detection pipeline. Empty pipeline
                                    // short-circuits without touching FileCtx,
                                    // so the zero-detector default case has no
                                    // per-file overhead.
                                    if !pipeline.is_empty() {
                                        evaluate_pipeline(
                                            &pipeline,
                                            &db,
                                            &tx_for_worker,
                                            scan_id,
                                            &path,
                                            size,
                                            &result,
                                            &mut findings_count,
                                        );
                                    }
                                }
                                Err(err) => {
                                    let _ = tx_for_worker.send(ScanProgress::Error {
                                        path: path.clone(),
                                        message: err.to_string(),
                                    });
                                }
                            }
                        }
                        WalkEvent::Error { path, message } => {
                            let _ = tx_for_worker.send(ScanProgress::Error { path, message });
                        }
                        WalkEvent::Skipped { .. } => {}
                    }
                }
            }

            let ended_at_utc = now_utc();
            let duration_ms = started_at_instant.elapsed().as_millis() as u64;

            let finalize_status = match db.lock() {
                Ok(conn) => history::finalize_scan(
                    &conn,
                    scan_id,
                    ended_at_utc,
                    ScanStatus::Completed,
                    files_visited,
                    files_hashed,
                    0,
                    0,
                    bytes_visited,
                    findings_count,
                ),
                Err(_) => Err(crate::db::DbError::Poisoned),
            };

            match finalize_status {
                Ok(()) => {
                    let _ = tx_for_worker.send(ScanProgress::Completed {
                        scan_id,
                        files_visited,
                        files_hashed,
                        bytes_visited,
                        findings_count,
                        duration_ms,
                    });
                }
                Err(err) => {
                    let _ = tx_for_worker.send(ScanProgress::Failed {
                        scan_id,
                        message: err.to_string(),
                    });
                }
            }
        });

        Ok(ScanHandle {
            scan_id,
            progress: rx,
            worker,
        })
    }

    /// Subscribe a fresh receiver to a running scan. Useful for UI that joins
    /// late and wants to watch progress without re-running. Phase 1 returns
    /// `None` because the engine doesn't yet keep per-scan senders alive after
    /// the worker exits; TASK-040 (pause/resume) will introduce a registry.
    pub fn subscribe(&self, _scan_id: i64) -> Option<broadcast::Receiver<ScanProgress>> {
        None
    }
}

fn now_utc() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Build a [`FileCtx`] from the hasher's hex output and evaluate the
/// pipeline. On `Detected` we record a `findings` row and emit a
/// `ScanProgress::Finding` event; on `SkippedByAllowlist` we silently
/// honor the verdict; on `Clean` we do nothing. Hash-decode failures are
/// surfaced as `ScanProgress::Error` (engine programmer error, not a
/// user-facing issue, but worth logging).
#[allow(clippy::too_many_arguments)]
fn evaluate_pipeline(
    pipeline: &DetectionPipeline,
    db: &Arc<Mutex<Connection>>,
    tx: &broadcast::Sender<ScanProgress>,
    scan_id: i64,
    path: &std::path::Path,
    size: u64,
    hash: &crate::hasher::HashResult,
    findings_count: &mut i64,
) {
    let Some(blake3_bytes) = blake3_hex_to_bytes(&hash.blake3) else {
        let _ = tx.send(ScanProgress::Error {
            path: path.to_path_buf(),
            message: "blake3 hex decode failed".to_string(),
        });
        return;
    };
    let sha256_bytes: Option<[u8; 32]> = hash.sha256.as_deref().and_then(decode_sha256);

    let ctx = FileCtx {
        path,
        size_bytes: size,
        blake3: &blake3_bytes,
        sha256: sha256_bytes.as_ref(),
    };
    let outcome = pipeline.evaluate(&ctx);
    match outcome {
        PipelineOutcome::Clean | PipelineOutcome::SkippedByAllowlist { .. } => {}
        PipelineOutcome::Detected {
            rule_id,
            rule_source,
            severity,
            evidence: _,
            detector_id: _,
        } => {
            let detected_at_utc = now_utc();
            let finding_id = match db.lock() {
                Ok(conn) => history::record_finding(
                    &conn,
                    scan_id,
                    path.to_string_lossy().as_ref(),
                    Some(size as i64),
                    Some(&blake3_bytes),
                    sha256_bytes.as_ref().map(|s| s.as_slice()),
                    &rule_id,
                    &rule_source,
                    severity.as_str(),
                    detected_at_utc,
                )
                .ok(),
                Err(_) => None,
            };
            if let Some(id) = finding_id {
                *findings_count += 1;
                let _ = tx.send(ScanProgress::Finding {
                    scan_id,
                    finding_id: id,
                    path: path.to_path_buf(),
                    rule_id,
                    rule_source,
                    severity: severity.as_str().to_string(),
                });
            }
        }
    }
}

fn decode_sha256(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use std::fs;
    use tempfile::tempdir;

    #[tokio::test]
    async fn scans_a_directory_and_records_completion() {
        let conn = db::open_in_memory().unwrap();
        let engine = ScanEngine::new(conn);

        let dir = tempdir().unwrap();
        for i in 0..5 {
            fs::write(
                dir.path().join(format!("f_{i}.txt")),
                format!("payload {i}"),
            )
            .unwrap();
        }

        let handle = engine
            .scan(
                ScanTarget::Path(dir.path().to_path_buf()),
                ScanOptions::default(),
            )
            .unwrap();
        let scan_id = handle.scan_id;
        let mut rx = handle.progress;
        let worker = handle.worker;
        worker.await.unwrap();

        let mut got_started = false;
        let mut got_completed = false;
        let mut files = 0;
        while let Ok(event) = rx.try_recv() {
            match event {
                ScanProgress::Started { .. } => got_started = true,
                ScanProgress::File { .. } => files += 1,
                ScanProgress::Completed {
                    files_visited,
                    files_hashed,
                    ..
                } => {
                    got_completed = true;
                    assert_eq!(files_visited, 5);
                    assert_eq!(files_hashed, 5);
                }
                _ => {}
            }
        }

        assert!(got_started, "should have emitted Started");
        assert!(got_completed, "should have emitted Completed");
        assert_eq!(files, 5);

        // Verify DB state matches.
        let db = engine.db.lock().unwrap();
        let (status, fv): (String, i64) = db
            .query_row(
                "SELECT status, files_visited FROM scans WHERE id = ?1",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, "completed");
        assert_eq!(fv, 5);
    }

    #[tokio::test]
    async fn pipeline_emits_finding_and_records_row_when_detector_matches() {
        // Build a feed containing the SHA-256 of a known payload, attach
        // a blacklist detector to the engine, scan the dir, and assert
        // that ScanProgress::Finding fires AND a findings row landed.
        // This is the gap both reviewers flagged: previously the e2e test
        // bypassed ScanEngine::scan entirely.
        use crate::detect::{
            DetectionPipeline, HashKind, hash_blacklist::HashBlacklistDetector,
            hash_set_file::write_sorted,
        };

        let dir = tempdir().unwrap();
        let target = dir.path().join("sample.bin");
        let payload: Vec<u8> = (0..256u32).map(|i| (i & 0xff) as u8).collect();
        fs::write(&target, &payload).unwrap();

        // Compute SHA-256 of the payload so we can build a 1-entry feed.
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&payload);
        let sha256: [u8; 32] = hasher.finalize().into();

        let feed_path = dir.path().join("feed.bin");
        write_sorted(&feed_path, [sha256]).unwrap();
        let detector = HashBlacklistDetector::open(&feed_path)
            .unwrap()
            .with_hash_kind(HashKind::Sha256);
        let pipeline = DetectionPipeline::new(vec![Box::new(detector)]);

        let conn = db::open_in_memory().unwrap();
        let engine = ScanEngine::new(conn).with_detection_pipeline(pipeline);

        let handle = engine
            .scan(
                ScanTarget::Path(dir.path().to_path_buf()),
                ScanOptions {
                    compute_sha256: true,
                    ..ScanOptions::default()
                },
            )
            .unwrap();
        let scan_id = handle.scan_id;
        let mut rx = handle.progress;
        let worker = handle.worker;
        worker.await.unwrap();

        let mut got_finding = false;
        let mut completed_findings_count: i64 = -1;
        while let Ok(event) = rx.try_recv() {
            match event {
                ScanProgress::Finding {
                    rule_source,
                    severity,
                    ..
                } => {
                    got_finding = true;
                    assert_eq!(rule_source, "abusech");
                    assert_eq!(severity, "high");
                }
                ScanProgress::Completed { findings_count, .. } => {
                    completed_findings_count = findings_count;
                }
                _ => {}
            }
        }
        assert!(got_finding, "expected ScanProgress::Finding for known-bad");
        assert_eq!(completed_findings_count, 1);

        // The findings row must have landed on disk.
        let db = engine.db.lock().unwrap();
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM findings WHERE scan_id = ?1",
                [scan_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        // And the scans row's findings_count is updated.
        let scan_findings_count: i64 = db
            .query_row(
                "SELECT findings_count FROM scans WHERE id = ?1",
                [scan_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(scan_findings_count, 1);
    }

    #[tokio::test]
    async fn empty_directory_completes_with_zero_files() {
        let conn = db::open_in_memory().unwrap();
        let engine = ScanEngine::new(conn);
        let dir = tempdir().unwrap();

        let handle = engine
            .scan(
                ScanTarget::Path(dir.path().to_path_buf()),
                ScanOptions::default(),
            )
            .unwrap();
        let scan_id = handle.scan_id;
        let worker = handle.worker;
        worker.await.unwrap();

        let db = engine.db.lock().unwrap();
        let (fv, fh): (i64, i64) = db
            .query_row(
                "SELECT files_visited, files_hashed FROM scans WHERE id = ?1",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(fv, 0);
        assert_eq!(fh, 0);
    }
}
