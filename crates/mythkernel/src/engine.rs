//! Top-level scan engine.
//!
//! TASK-012 (Phase 1) ships [`ScanEngine`], the entry point the CLI
//! (`mythctl scan` — TASK-017) and Tauri bridge (`scan_start` — TASK-028)
//! both invoke. Each call to [`ScanEngine::scan`] returns a
//! [`crate::scan::ScanHandle`] with a broadcast receiver of
//! [`crate::scan::ScanProgress`] events.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rusqlite::Connection;
use tokio::sync::broadcast;

use crate::detect::publisher;
use crate::detect::{DetectionPipeline, FileCtx, PipelineOutcome, blake3_hex_to_bytes};
use crate::error::EngineError;
use crate::eta::{EtaEstimator, Progress as EtaSample};
use crate::exclusions::{self, ExclusionKind, MatchCtx, MatchScope};
use crate::hasher::{HashResult, Hasher, StreamingHasher};
use crate::history::{self, ScanStatus};
use crate::scan::{
    RESUME_TOKEN_PATH_CAP, ResumeToken, ScanHandle, ScanOptions, ScanProgress, ScanTarget,
};
use crate::throttle::{AdaptiveThrottle, Throttle};
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
        self.scan_internal(target, opts, None)
    }

    /// Resume a previously paused scan. Reads the row's resume_token,
    /// re-walks the target paths, skips already-processed files, and
    /// continues from the persisted counters. The token's schema must
    /// match `ResumeToken::CURRENT_SCHEMA`; older versions return an
    /// error so the caller can re-run the scan from scratch rather than
    /// risk a corrupted continuation.
    pub fn resume(&self, scan_id: i64) -> Result<ScanHandle, EngineError> {
        let token_bytes = {
            let conn = self
                .db
                .lock()
                .map_err(|_| EngineError::Db(crate::db::DbError::Poisoned.to_string()))?;
            history::read_resume_token(&conn, scan_id)
                .map_err(|e| EngineError::Db(e.to_string()))?
                .ok_or_else(|| EngineError::Config(format!("scan {scan_id} has no resume token")))?
        };
        let token: ResumeToken = serde_json::from_slice(&token_bytes)
            .map_err(|e| EngineError::Config(format!("resume token decode: {e}")))?;
        if token.schema_version != ResumeToken::CURRENT_SCHEMA {
            return Err(EngineError::Config(format!(
                "resume token schema {} unsupported (current {})",
                token.schema_version,
                ResumeToken::CURRENT_SCHEMA
            )));
        }
        let target = if token.target_paths.len() == 1 && token.target_kind == "path" {
            ScanTarget::Path(token.target_paths[0].clone())
        } else {
            ScanTarget::Paths(token.target_paths.clone())
        };
        let opts = ScanOptions {
            follow_symlinks: token.follow_symlinks,
            skip_hidden: token.skip_hidden,
            compute_sha256: token.compute_sha256,
            // Code-review R-B2: restore the user's TASK-134 partial-hash
            // preference so a resumed scan keeps emitting the same event
            // stream the original scan was emitting before pause.
            emit_partial_hash: token.emit_partial_hash,
            ..ScanOptions::default()
        };
        self.scan_internal(target, opts, Some((scan_id, token)))
    }

    fn scan_internal(
        &self,
        target: ScanTarget,
        opts: ScanOptions,
        resume_from: Option<(i64, ResumeToken)>,
    ) -> Result<ScanHandle, EngineError> {
        let started_at_utc = now_utc();
        let started_at_instant = Instant::now();
        let target_paths_json = target.to_paths_json();
        let target_kind = target.kind();
        let trigger = opts.trigger;
        let resume_carry = resume_from.as_ref().map(|(_, t)| t.clone());

        let (scan_id, exclusions_snap) = if let Some((existing_id, _)) = resume_from.as_ref() {
            // Resume: keep the same scan_id; clear the resume_token so
            // a follow-up pause writes a fresh one, and flip the row
            // back to `running`.
            let conn = self
                .db
                .lock()
                .map_err(|_| EngineError::Db(crate::db::DbError::Poisoned.to_string()))?;
            history::set_resume_token(&conn, *existing_id, &[])
                .map_err(|e| EngineError::Db(e.to_string()))?;
            conn.execute(
                "UPDATE scans SET status = 'running' WHERE id = ?1",
                rusqlite::params![*existing_id],
            )
            .map_err(|e| EngineError::Db(e.to_string()))?;
            (*existing_id, String::from("[]"))
        } else {
            let conn = self
                .db
                .lock()
                .map_err(|_| EngineError::Db(crate::db::DbError::Poisoned.to_string()))?;
            // FR-062: snapshot the rule set in force at this moment into
            // `scans.exclusions_snap` so rerunning the scan later uses these
            // rules, not whatever the user has configured then.
            let snap = exclusions::snapshot_active_json(&conn)
                .map_err(|e| EngineError::Db(e.to_string()))?;
            let id = history::create_scan(
                &conn,
                started_at_utc,
                trigger,
                target_kind,
                &target_paths_json,
                &snap,
                self.engine_version,
                "{}",
            )
            .map_err(|e| EngineError::Db(e.to_string()))?;
            (id, snap)
        };
        let _ = exclusions_snap; // reserved for future per-scan matcher

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
        let pause_flag = Arc::new(AtomicBool::new(false));
        let pause_flag_for_worker = pause_flag.clone();
        let target_for_worker = target;
        let opts_for_token = opts.clone();
        let emit_partial = opts.emit_partial_hash;

        // The walker uses rayon internally and the hash step is CPU-bound, so
        // this work belongs on the blocking pool, not the tokio reactor.
        let target_paths_for_token: Vec<std::path::PathBuf> =
            target_for_worker.paths().cloned().collect();
        let target_kind_for_token = target_kind.to_string();
        // TASK-136 — short-circuit publisher extraction when the user has
        // no active publisher exclusions. Per-file shell-out is expensive
        // (~100 ms cold, sub-ms cached); skipping the extraction entirely
        // when no rule could ever fire is the standard "pay for what you
        // use" approach. The check happens once per scan, not per-file.
        let has_publisher_excl = match db.lock() {
            Ok(conn) => exclusions::list_active(&conn, now_utc())
                .map(|rules| {
                    rules
                        .iter()
                        .any(|r| matches!(r.kind, ExclusionKind::Publisher))
                })
                .unwrap_or(false),
            Err(_) => false,
        };
        let worker = tokio::task::spawn_blocking(move || {
            let walker = PosixWalker::new();
            // TASK-040 — resume context. When `resume_carry` is Some,
            // pre-load counters and the set of already-completed paths so
            // we skip them in the hash loop.
            let mut processed_paths: BTreeSet<String> = resume_carry
                .as_ref()
                .map(|t| t.processed_paths.clone())
                .unwrap_or_default();
            let mut files_visited: i64 =
                resume_carry.as_ref().map(|t| t.files_visited).unwrap_or(0);
            let mut files_hashed: i64 = resume_carry.as_ref().map(|t| t.files_hashed).unwrap_or(0);
            let mut bytes_visited: i64 =
                resume_carry.as_ref().map(|t| t.bytes_visited).unwrap_or(0);
            let mut findings_count: i64 =
                resume_carry.as_ref().map(|t| t.findings_count).unwrap_or(0);

            // Phase A — enumeration pass (TASK-038 ETA + early TASK-137).
            let mut files_total: u64 = 0;
            let mut bytes_total: u64 = 0;
            let mut worklist: Vec<(std::path::PathBuf, u64)> = Vec::new();
            for root in target_for_worker.paths() {
                let event_rx = walker.walk(root, walk_opts.clone());
                for event in event_rx.iter() {
                    match event {
                        WalkEvent::File { path, size, .. } => {
                            files_total += 1;
                            bytes_total = bytes_total.saturating_add(size);
                            worklist.push((path, size));
                        }
                        WalkEvent::Error { path, message } => {
                            let _ = tx_for_worker.send(ScanProgress::Error { path, message });
                        }
                        WalkEvent::Skipped { .. } => {}
                    }
                }
            }

            // Phase B — hash + detect pass with live ETA + adaptive throttle.
            let mut estimator = EtaEstimator::new();
            let throttle_base = Throttle::default();
            let mut throttle = AdaptiveThrottle::new(throttle_base);
            let mut paused_mid_run = false;

            for (path, size) in worklist {
                // TASK-040 — pause check at the top of every iteration.
                // We persist a resume token and exit cleanly so the
                // caller can pick this scan up later via `engine.resume`.
                if pause_flag_for_worker.load(Ordering::Relaxed) {
                    paused_mid_run = true;
                    break;
                }

                let path_str_owned = path.to_string_lossy().into_owned();

                // Skip files we already processed in a prior run that
                // got paused. Counters carry over from the resume_carry.
                if processed_paths.contains(&path_str_owned) {
                    continue;
                }

                files_visited += 1;
                bytes_visited += size as i64;

                // Path/glob/publisher exclusion check first — if hit,
                // skip this file entirely (don't hash, don't detect).
                //
                // TASK-136 + code-review CR-B1: when at least one
                // publisher-kind exclusion exists, extract the signer
                // identity in three phases:
                //   1. cache lookup (lock held briefly)
                //   2. shell-out to platform signer extractor (NO lock)
                //   3. cache store on miss (lock held briefly)
                // The 100 ms+ shell-out never blocks other Tauri
                // commands that share the Arc<Mutex<Connection>>.
                let signer_identity: Option<String> = if has_publisher_excl {
                    let probe = match db.lock() {
                        Ok(conn) => publisher::cache_lookup(&conn, &path).ok(),
                        Err(_) => None,
                    };
                    match probe {
                        Some(probe) => {
                            let identity = match probe.cached.clone() {
                                Some(c) => c,
                                None => {
                                    let extracted = publisher::extract_io_unlocked(&path);
                                    if let Ok(conn) = db.lock() {
                                        let _ = publisher::cache_store(&conn, &probe, &extracted);
                                    }
                                    extracted
                                }
                            };
                            if identity.is_signed() {
                                Some(identity.identity)
                            } else {
                                None
                            }
                        }
                        None => None,
                    }
                } else {
                    None
                };
                let path_excluded = match db.lock() {
                    Ok(conn) => exclusions::matches(
                        &conn,
                        &MatchCtx {
                            path: path_str_owned.as_str(),
                            blake3_hex: None,
                            sha256_hex: None,
                            publisher: signer_identity.as_deref(),
                            scope: MatchScope::Scan,
                        },
                    )
                    .ok()
                    .flatten(),
                    Err(_) => None,
                };
                if path_excluded.is_some() {
                    // Pre-hash skip — count it as processed so a resume
                    // doesn't re-evaluate the rule for the same path.
                    if processed_paths.len() < RESUME_TOKEN_PATH_CAP {
                        processed_paths.insert(path_str_owned.clone());
                    }
                    continue;
                }

                // Adaptive yield per TASK-039.
                yield_per_throttle(&mut throttle);

                let hash_outcome = if emit_partial {
                    hash_file_with_partial_events(
                        &path,
                        opts_for_token.compute_sha256,
                        scan_id,
                        &tx_for_worker,
                    )
                } else {
                    hasher.hash_file(&path)
                };

                match hash_outcome {
                    Ok(result) => {
                        files_hashed += 1;
                        let sample = EtaSample {
                            files_done: files_visited as u64,
                            files_total: Some(files_total),
                            bytes_done: bytes_visited as u64,
                            bytes_total: Some(bytes_total),
                            now: Instant::now(),
                        };
                        let eta_secs = estimator.observe(sample);
                        let _ = tx_for_worker.send(ScanProgress::File {
                            path: path.clone(),
                            blake3: result.blake3.clone(),
                            size: result.size,
                            eta_secs,
                        });

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

                        // Record the path as done so a follow-up resume
                        // skips it. Cap protects the token from
                        // unbounded growth on giant scans.
                        if processed_paths.len() < RESUME_TOKEN_PATH_CAP {
                            processed_paths.insert(path_str_owned);
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

            let ended_at_utc = now_utc();
            let duration_ms = started_at_instant.elapsed().as_millis() as u64;

            if paused_mid_run {
                // Persist the resume token, flip the row status, fire the
                // Paused event, and exit. The DB row keeps its
                // `files_visited` etc. up to date for the History page.
                let token = ResumeToken {
                    schema_version: ResumeToken::CURRENT_SCHEMA,
                    target_paths: target_paths_for_token,
                    target_kind: target_kind_for_token,
                    follow_symlinks: opts_for_token.follow_symlinks,
                    skip_hidden: opts_for_token.skip_hidden,
                    compute_sha256: opts_for_token.compute_sha256,
                    emit_partial_hash: opts_for_token.emit_partial_hash,
                    processed_paths,
                    files_visited,
                    files_hashed,
                    bytes_visited,
                    findings_count,
                };
                let encoded = serde_json::to_vec(&token).unwrap_or_else(|_| b"{}".to_vec());
                if let Ok(conn) = db.lock() {
                    let _ = history::set_resume_token(&conn, scan_id, &encoded);
                    let _ = history::finalize_scan(
                        &conn,
                        scan_id,
                        ended_at_utc,
                        ScanStatus::Paused,
                        files_visited,
                        files_hashed,
                        0,
                        0,
                        bytes_visited,
                        findings_count,
                    );
                }
                let _ = tx_for_worker.send(ScanProgress::Paused {
                    scan_id,
                    files_visited,
                    files_hashed,
                    bytes_visited,
                    findings_count,
                });
                return;
            }

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
            pause_flag,
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

/// Map the AdaptiveThrottle's "current workers" reading to a per-file
/// sleep that lets the user's foreground apps stay responsive. At full
/// throttle we don't sleep; at 1 worker (high external load) we sleep
/// 50 ms between files.
fn yield_per_throttle(throttle: &mut AdaptiveThrottle) {
    let max = throttle.base().max_workers as i64;
    let now_workers = throttle.current_workers() as i64;
    if now_workers >= max {
        return;
    }
    // Linear ramp: full throttle → 0 ms, 1 worker → ~50 ms.
    let denom = (max - 1).max(1);
    let scale = ((max - now_workers) * 50) / denom;
    if scale > 0 {
        std::thread::sleep(std::time::Duration::from_millis(scale as u64));
    }
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

/// Stream-hash `path` and emit `ScanProgress::PartialHash` events at
/// ≤ 10 Hz (TASK-134 / FR-136). Identical contract to `Hasher::hash_file`
/// except for the per-chunk progress events. Used only when the scan was
/// started with `ScanOptions::emit_partial_hash = true`.
fn hash_file_with_partial_events(
    path: &std::path::Path,
    compute_sha256: bool,
    scan_id: i64,
    tx: &tokio::sync::broadcast::Sender<ScanProgress>,
) -> std::io::Result<HashResult> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut streaming = StreamingHasher::new(compute_sha256);
    let mut buf = vec![0u8; crate::hasher::DEFAULT_CHUNK_SIZE];
    let mut last_emit = std::time::Instant::now();
    let throttle = std::time::Duration::from_millis(100);
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        streaming.update(&buf[..n]);
        if last_emit.elapsed() >= throttle {
            let _ = tx.send(ScanProgress::PartialHash {
                scan_id,
                path: path.to_path_buf(),
                blake3_partial: streaming.partial(),
                bytes_done: streaming.bytes_seen(),
            });
            last_emit = std::time::Instant::now();
        }
    }
    Ok(streaming.finalize())
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
    async fn pause_then_resume_completes_all_files() {
        // Build a tree with 10 files, kick off a scan, pause it after
        // the first File event, then resume the same scan and assert
        // the totals match a clean scan of the same tree.
        let conn = db::open_in_memory().unwrap();
        let engine = ScanEngine::new(conn);
        let dir = tempdir().unwrap();
        for i in 0..10 {
            fs::write(dir.path().join(format!("f_{i}.txt")), format!("p{i}")).unwrap();
        }

        let handle = engine
            .scan(
                ScanTarget::Path(dir.path().to_path_buf()),
                ScanOptions::default(),
            )
            .unwrap();
        let scan_id = handle.scan_id;
        let pause_flag = handle.pause_flag.clone();
        let mut rx = handle.progress;
        let worker = handle.worker;

        // Wait for the first File event, then request a pause.
        let mut got_paused = false;
        let mut paused_files: i64 = 0;
        loop {
            match rx.recv().await {
                Ok(ScanProgress::File { .. }) => {
                    pause_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                Ok(ScanProgress::Paused { files_visited, .. }) => {
                    got_paused = true;
                    paused_files = files_visited;
                    break;
                }
                Ok(ScanProgress::Completed { .. }) => {
                    // Scan finished before our pause flag landed — fine on
                    // a very small tree.
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        worker.await.unwrap();

        // The row should reflect either paused or completed.
        let (status, files_after_pause): (String, i64) = {
            let db = engine.db.lock().unwrap();
            db.query_row(
                "SELECT status, files_visited FROM scans WHERE id = ?1",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
        };

        if got_paused {
            assert_eq!(status, "paused");
            assert!(
                (1..10).contains(&files_after_pause),
                "should have paused mid-scan, got {files_after_pause}"
            );
            assert!(paused_files >= 1);

            // Resume and let it complete.
            let resumed = engine.resume(scan_id).unwrap();
            assert_eq!(resumed.scan_id, scan_id);
            resumed.worker.await.unwrap();

            let (status, files_after_resume): (String, i64) = {
                let db = engine.db.lock().unwrap();
                db.query_row(
                    "SELECT status, files_visited FROM scans WHERE id = ?1",
                    [scan_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap()
            };
            assert_eq!(status, "completed");
            assert_eq!(files_after_resume, 10);
        }
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
