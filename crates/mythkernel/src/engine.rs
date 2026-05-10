//! Top-level scan engine.
//!
//! TASK-012 (Phase 1) ships [`ScanEngine`], the entry point the CLI
//! (`mythctl scan` — TASK-017) and Tauri bridge (`scan_start` — TASK-028)
//! both invoke. Each call to [`ScanEngine::scan`] returns a
//! [`crate::scan::ScanHandle`] with a broadcast receiver of
//! [`crate::scan::ScanProgress`] events.

use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use tokio::sync::broadcast;

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
    engine_version: &'static str,
}

impl ScanEngine {
    pub fn new(db: Connection) -> Self {
        Self {
            db: Arc::new(Mutex::new(db)),
            engine_version: env!("CARGO_PKG_VERSION"),
        }
    }

    /// Begin a scan. Inserts the row in `scans` synchronously (so the caller
    /// gets an id immediately), then spawns the worker that walks + hashes +
    /// finalizes.
    pub fn scan(&self, target: ScanTarget, opts: ScanOptions) -> Result<ScanHandle, EngineError> {
        let started_at_utc = now_utc();
        let target_paths_json = target.to_paths_json();
        let target_kind = target.kind();
        let trigger = opts.trigger;

        let scan_id = {
            let conn = self.db.lock().expect("scan db poisoned");
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
                                        blake3: result.blake3,
                                        size: result.size,
                                    });
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
            let duration_ms =
                ((ended_at_utc.saturating_sub(started_at_utc)) as u64).saturating_mul(1000);

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
                    0,
                ),
                Err(_) => Err(crate::db::DbError::Sqlite(
                    rusqlite::Error::ExecuteReturnedResults,
                )),
            };

            match finalize_status {
                Ok(()) => {
                    let _ = tx_for_worker.send(ScanProgress::Completed {
                        scan_id,
                        files_visited,
                        files_hashed,
                        bytes_visited,
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
