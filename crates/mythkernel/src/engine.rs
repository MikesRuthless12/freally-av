//! Top-level scan engine.
//!
//! TASK-012 (Phase 1) ships [`ScanEngine`], the entry point the CLI
//! (`mythctl scan` — TASK-017) and Tauri bridge (`scan_start` — TASK-028)
//! both invoke. Each call to [`ScanEngine::scan`] returns a
//! [`crate::scan::ScanHandle`] with a broadcast receiver of
//! [`crate::scan::ScanProgress`] events.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rusqlite::Connection;
use tokio::sync::broadcast;

use crate::detect::file_mutation::FileBaseline;
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
use crate::walker::{FileWalker, MultiVolumeWalker, WalkEvent, WalkOpts};

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
            // TASK-053 / TASK-056: restore the multi-volume fan-out
            // toggle so resume continues across the same volume set.
            all_volumes: token.all_volumes,
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
        let (
            resumed_files_visited,
            resumed_files_hashed,
            resumed_bytes_visited,
            resumed_findings_count,
        ) = match &resume_from {
            Some((_, token)) => (
                token.files_visited,
                token.files_hashed,
                token.bytes_visited,
                token.findings_count,
            ),
            None => (0, 0, 0, 0),
        };
        let _ = tx.send(ScanProgress::Started {
            scan_id,
            started_at_utc,
            resumed_files_visited,
            resumed_files_hashed,
            resumed_bytes_visited,
            resumed_findings_count,
        });

        let db = self.db.clone();
        // `pipeline` is cloned later as `pipeline_for_workers` for the
        // worker pool — the original single-thread design had it scoped
        // at this level.
        let tx_for_worker = tx.clone();
        let pause_flag = Arc::new(AtomicBool::new(false));
        let cancel_flag = Arc::new(AtomicBool::new(false));
        // Composite "abort" flag handed to the hasher — fires on
        // pause OR cancel so a mid-flight 1.5 GiB hash exits within
        // one chunk (~1 ms on NVMe) when the user clicks either
        // control. Pause vs cancel post-mortem happens after the
        // hasher returns Err(Interrupted) — the worker reads the two
        // source flags to pick the right exit path.
        let abort_flag = Arc::new(AtomicBool::new(false));
        let abort_flag_for_hasher = abort_flag.clone();
        // SHA-256 is ~5× slower than BLAKE3 — only compute it when at
        // least one registered detector actually needs the SHA-256
        // digest (abuse.ch hash blacklist with SHA-256 key, NSRL
        // allowlist, BYOVD loldrivers). When the pipeline is empty or
        // every detector is BLAKE3-keyed, SHA-256 is wasted work and
        // we skip it regardless of the caller's `compute_sha256`
        // request. The user toggle in the UI has been retired — if a
        // future detector ever needs SHA-256, it overrides
        // `Detector::requires_sha256` and gets it automatically.
        let need_sha256 = self.pipeline.requires_sha256();
        // Optional CRC32 fast-screen gate. When the caller provides
        // a `crc32_blacklist.bin` path, the hasher routes through
        // a CRC32-first pre-pass and skips BLAKE3 + SHA-256 on miss.
        // Load failures (missing/malformed file) degrade gracefully
        // — the scan falls back to "hash everything", which is
        // what existing code already does.
        let crc32_gate: Option<std::sync::Arc<crate::detect::crc32_set_file::Crc32SetFile>> =
            opts.crc32_gate_path.as_deref().and_then(|p| {
                match crate::detect::crc32_set_file::Crc32SetFile::open(p) {
                    Ok(set) => {
                        tracing::info!(
                            path = %p.display(),
                            count = set.len(),
                            "crc32 fast-screen gate loaded"
                        );
                        Some(std::sync::Arc::new(set))
                    }
                    Err(err) => {
                        tracing::warn!(
                            path = %p.display(),
                            error = %err,
                            "crc32 gate failed to load; scan will hash every file"
                        );
                        None
                    }
                }
            });
        let mut hasher = Hasher::new()
            .with_sha256(need_sha256)
            .with_abort_flag(abort_flag_for_hasher);
        if let Some(gate) = crc32_gate.clone() {
            hasher = hasher.with_crc32_gate(gate);
        }
        let has_crc32_gate = crc32_gate.is_some();
        let walk_opts = WalkOpts {
            follow_symlinks: opts.follow_symlinks,
            skip_hidden: opts.skip_hidden,
            max_depth: opts.max_depth,
        };
        let pause_flag_for_worker = pause_flag.clone();
        let cancel_flag_for_worker = cancel_flag.clone();
        let abort_flag_for_worker = abort_flag.clone();
        let target_for_worker = target;
        let emit_partial = opts.emit_partial_hash;

        // The walker uses rayon internally and the hash step is CPU-bound, so
        // this work belongs on the blocking pool, not the tokio reactor.
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
        // TASK-138 — per-scan file-mutation baseline. The actual
        // `FileBaseline` instance is constructed inside the worker
        // closure below as `file_baseline_shared` so the perf-phase-1
        // worker pool can share it through `Arc` (the original
        // single-thread design had it as a local).
        // TASK-053 + TASK-056: every scan goes through `MultiVolumeWalker`.
        // Single-root behavior passes through to `NtfsWalker` (the platform
        // fast walker — NTFS MFT on Windows, raw `getdents64` on Linux,
        // FSEvents-driven recursive walk on macOS — with `PosixWalker`
        // fallback when the per-OS fast path can't open the volume).
        // `all_volumes(true)` fans out across every host volume on Windows.
        let all_volumes = opts.all_volumes;

        // TASK-137 — concurrent producer/consumer. The walker thread
        // streams `(PathBuf, u64)` into a **bounded** crossbeam channel
        // (sec-review H2 / wave 3 follow-up — an unbounded queue would
        // accrete ~300 MB resident on a 5M-file NTFS walk because the
        // MFT producer's 100K files/s outruns the hash consumer's ~MB/s).
        // The bound back-pressures the producer at ~32K queued items
        // (≈ 2 MB of PathBuf+u64 tuples) — enough buffer that the
        // consumer keeps the CPU saturated, small enough that the
        // resident-set budget stays predictable.
        // The hash+detect consumer drains the channel as items arrive
        // so scanning starts on the first enumerated file. The running
        // totals live in shared atomics so the consumer can include
        // them in every File event without locking. The producer fires
        // `EnumerationComplete` once it has walked every root, then
        // drops the work sender — the consumer's `recv()` returns
        // `Err` once the channel drains and the loop exits cleanly.
        //
        // Unbounded by design: a bounded channel back-pressures the
        // walker (good for memory) but also stalls the per-file
        // enumeration counter at the channel capacity, because the
        // producer increments `files_running` and then blocks on
        // `send` for the same file. The UI then shows e.g.
        // "170 / 35,016 · 0%" frozen for the entire duration of
        // hashing a slow batch — even though the walker is ready to
        // enumerate millions more. Trade-off: memory grows with
        // pending-file count. At ~200 B per `(PathBuf, u64, i64)`,
        // 1 M files ≈ 200 MB; tolerable for a desktop AV scanner.
        let (work_tx, work_rx) =
            crossbeam_channel::unbounded::<(std::path::PathBuf, u64, i64)>();
        let files_running = Arc::new(AtomicU64::new(0));
        let bytes_running = Arc::new(AtomicU64::new(0));
        let enum_complete = Arc::new(AtomicBool::new(false));

        let files_running_p = files_running.clone();
        let bytes_running_p = bytes_running.clone();
        let enum_complete_p = enum_complete.clone();
        let target_for_producer = target_for_worker.clone();
        let walk_opts_p = walk_opts.clone();
        let tx_for_producer = tx_for_worker.clone();
        let pause_flag_for_producer = pause_flag.clone();
        let cancel_flag_for_producer = cancel_flag.clone();
        // RAII guard: every exit path from the producer body — clean
        // completion, pause, consumer-dropped, panic — flips
        // `enum_complete` and emits `EnumerationComplete` exactly once
        // (sec-review H3 + code-review H3). Without this the UI would
        // stay stuck on "counting…" when Cancel races the walker.
        struct ProducerCompletionGuard {
            files_running: Arc<AtomicU64>,
            bytes_running: Arc<AtomicU64>,
            enum_complete: Arc<AtomicBool>,
            tx: broadcast::Sender<ScanProgress>,
            scan_id: i64,
            armed: bool,
        }
        impl Drop for ProducerCompletionGuard {
            fn drop(&mut self) {
                if !self.armed {
                    return;
                }
                let files_total_locked = self.files_running.load(Ordering::Relaxed);
                let bytes_total_locked = self.bytes_running.load(Ordering::Relaxed);
                self.enum_complete.store(true, Ordering::Relaxed);
                let _ = self.tx.send(ScanProgress::EnumerationComplete {
                    scan_id: self.scan_id,
                    files_total_locked,
                    bytes_total_locked,
                });
            }
        }

        // Phase-6 sequencing gate: when the scan has registry or
        // process phases enabled, the file producer waits here until
        // the spawn_blocking coordinator finishes those phases and
        // flips `phases_ready` to true. With include_files-only
        // (default), the flag starts true and the producer walks
        // immediately. Also short-circuits if include_files is false.
        let phases_ready = Arc::new(AtomicBool::new(
            !(opts.include_registry || opts.include_processes),
        ));
        let phases_ready_for_producer = phases_ready.clone();
        let phases_ready_for_blocking = phases_ready.clone();
        let include_files = opts.include_files;
        let include_files_for_producer = include_files;
        let include_registry = opts.include_registry;
        let include_processes = opts.include_processes;
        let cancel_flag_for_phases = cancel_flag.clone();
        let tx_for_phases = tx_for_worker.clone();

        let producer_spawn = std::thread::Builder::new()
            .name("mythkernel/scan-producer".into())
            .spawn(move || {
                let mut guard = ProducerCompletionGuard {
                    files_running: files_running_p.clone(),
                    bytes_running: bytes_running_p.clone(),
                    enum_complete: enum_complete_p.clone(),
                    tx: tx_for_producer.clone(),
                    scan_id,
                    armed: true,
                };
                // Phase 6 — wait until registry + process phases
                // finish before walking. Lets the UI render the three
                // phases sequentially. The flag starts `true` when no
                // pre-phases are enabled, so the legacy file-only
                // scan path takes no extra latency.
                while !phases_ready_for_producer.load(Ordering::Relaxed) {
                    if cancel_flag_for_producer.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                // include_files=false → registry/process-only sweep.
                // Skip the walker entirely; guard's Drop still fires
                // EnumerationComplete so the UI moves to the file
                // phase's "completed" state.
                if !include_files_for_producer {
                    return;
                }
                let walker = MultiVolumeWalker::new().all_volumes(all_volumes);
                'outer: for root in target_for_producer.paths() {
                    let event_rx = walker.walk(root, walk_opts_p.clone());
                    // Cancel-aware recv: a blocking `event_rx.iter()`
                    // would park the producer indefinitely on a slow
                    // walker, leaving the cancel flag unobserved and
                    // the walker still pinning rayon. Poll with a 50 ms
                    // timeout so cancel propagates within one tick.
                    //
                    // Walker-stall guard: if we've seen at least one
                    // event but haven't received another in
                    // WALKER_STALL_TIMEOUT, assume the walker is wedged
                    // on a slow `read_dir` (typical on a USB-detached
                    // share, a quarantined drive, or a deeply
                    // permission-denied tree). Break out of the inner
                    // loop — dropping `event_rx` aborts the walker via
                    // `take_while` in `PosixWalker`. The
                    // `EnumerationComplete` guard's Drop still fires so
                    // the UI's ETA can lock and the user sees a final
                    // X/Y. Walker tasks then clean up and free rayon.
                    const WALKER_STALL_TIMEOUT: std::time::Duration =
                        std::time::Duration::from_secs(15);
                    let mut last_event_at = std::time::Instant::now();
                    let mut have_seen_event = false;
                    loop {
                        if cancel_flag_for_producer.load(Ordering::Relaxed) {
                            break 'outer;
                        }
                        // Pause-aware stall timer (review H1): time spent
                        // parked in the pause loop should NOT count
                        // toward the 15 s stall window — a 10-minute
                        // pause would otherwise trip a false stall the
                        // moment the user resumes. Refresh the timer
                        // after every pause exit so the heuristic
                        // measures only walker-actual time.
                        if pause_flag_for_producer.load(Ordering::Relaxed) {
                            while pause_flag_for_producer.load(Ordering::Relaxed) {
                                if cancel_flag_for_producer.load(Ordering::Relaxed) {
                                    break 'outer;
                                }
                                std::thread::sleep(std::time::Duration::from_millis(50));
                            }
                            last_event_at = std::time::Instant::now();
                        }
                        let event = match event_rx
                            .recv_timeout(std::time::Duration::from_millis(50))
                        {
                            Ok(e) => {
                                last_event_at = std::time::Instant::now();
                                have_seen_event = true;
                                e
                            }
                            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                                if have_seen_event
                                    && last_event_at.elapsed() >= WALKER_STALL_TIMEOUT
                                {
                                    tracing::warn!(
                                        stalled_for_secs = last_event_at.elapsed().as_secs(),
                                        files_enumerated =
                                            files_running_p.load(Ordering::Relaxed),
                                        "walker stalled — finalizing enumeration"
                                    );
                                    break;
                                }
                                continue;
                            }
                            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                        };
                        match event {
                            WalkEvent::File { path, size, mtime } => {
                                files_running_p.fetch_add(1, Ordering::Relaxed);
                                bytes_running_p.fetch_add(size, Ordering::Relaxed);
                                // `work_tx` is unbounded — send is
                                // non-blocking, so `files_running` ticks
                                // independently of worker throughput.
                                // The only failure mode is Disconnected
                                // (the worker pool finalized first); the
                                // guard's Drop still emits
                                // EnumerationComplete on the way out.
                                if work_tx.send((path, size, mtime)).is_err() {
                                    return;
                                }
                            }
                            WalkEvent::Error { path, message } => {
                                let _ = tx_for_producer.send(ScanProgress::Error { path, message });
                            }
                            WalkEvent::Skipped { .. } => {}
                        }
                    }
                }
                // Clean exit → guard's Drop fires EnumerationComplete.
                let _ = &mut guard;
                // `work_tx` drops at end of scope → channel closes.
            });

        // Sec-review M6: a thread-spawn failure (EAGAIN under RLIMIT_NPROC)
        // is recoverable — surface it as an EngineError so the caller
        // can finalize the scan row as failed rather than panicking the
        // tokio runtime.
        if let Err(err) = producer_spawn {
            let conn = self
                .db
                .lock()
                .map_err(|_| EngineError::Db(crate::db::DbError::Poisoned.to_string()))?;
            let _ = history::finalize_scan(
                &conn,
                scan_id,
                now_utc(),
                ScanStatus::Failed,
                0,
                0,
                0,
                0,
                0,
                0,
            );
            return Err(EngineError::Config(format!(
                "failed to spawn scan producer thread: {err}"
            )));
        }
        let _producer_handle = producer_spawn.expect("checked Ok above");

        // Mirror pause/cancel into the shared abort flag so the hasher
        // sees the request mid-chunk. A lightweight watcher thread
        // polls the two source flags at 50 Hz and OR's them into the
        // hasher-visible abort flag; cheap (one atomic load + maybe
        // one store every 20 ms) and avoids weaving a 3-way flag check
        // into every chunk of `hash_file`. With in-place pause we need
        // the watcher to keep mirroring across pause→resume cycles
        // (abort flips on then *back off* when the user clicks
        // Resume) — so the only terminal exits are cancel (workers
        // are exiting) or the coordinator flipping `scan_alive` off
        // at finalize.
        let scan_alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let pause_for_watcher = pause_flag.clone();
        let cancel_for_watcher = cancel_flag.clone();
        let abort_for_watcher = abort_flag.clone();
        let scan_alive_for_watcher = scan_alive.clone();
        std::thread::Builder::new()
            .name("mythkernel/scan-abort-watcher".into())
            .spawn(move || {
                loop {
                    let p = pause_for_watcher.load(Ordering::Relaxed);
                    let c = cancel_for_watcher.load(Ordering::Relaxed);
                    abort_for_watcher.store(p || c, Ordering::Relaxed);
                    if c || !scan_alive_for_watcher.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            })
            .expect("spawn scan-abort-watcher");

        // Perf phase 1 — wrap mutable counters + dedup set into Arcs
        // so a worker pool can share them lock-free (counters) or
        // briefly-locked (processed_paths Mutex). Pre-seed with
        // resume carry so a resumed scan continues from where it
        // paused.
        let processed_paths_set: BTreeSet<String> = resume_carry
            .as_ref()
            .map(|t| t.processed_paths.clone())
            .unwrap_or_default();
        let processed_paths_shared = Arc::new(Mutex::new(processed_paths_set));
        let files_visited_atom = Arc::new(std::sync::atomic::AtomicI64::new(
            resume_carry.as_ref().map(|t| t.files_visited).unwrap_or(0),
        ));
        let files_hashed_atom = Arc::new(std::sync::atomic::AtomicI64::new(
            resume_carry.as_ref().map(|t| t.files_hashed).unwrap_or(0),
        ));
        let bytes_visited_atom = Arc::new(std::sync::atomic::AtomicI64::new(
            resume_carry.as_ref().map(|t| t.bytes_visited).unwrap_or(0),
        ));
        let findings_count_atom = Arc::new(std::sync::atomic::AtomicI64::new(
            resume_carry.as_ref().map(|t| t.findings_count).unwrap_or(0),
        ));
        let estimator_shared = Arc::new(Mutex::new(EtaEstimator::new()));
        let throttle_shared = Arc::new(Mutex::new(AdaptiveThrottle::new(Throttle::default())));
        let file_baseline_shared = Arc::new(FileBaseline::from_platform());

        // Heartbeat tracer — every 5 s, log the live counters so we
        // can tell from logs alone whether workers are making progress
        // or genuinely stalled. Retires when `scan_alive` flips to
        // false at coordinator-finalize time.
        //
        // Off by default in release builds — set `MYTHODIKAL_HEARTBEAT=1`
        // to re-enable for diagnosing a stuck scan. Spinning a thread
        // that logs once every 5 s isn't expensive, but the WARN-level
        // logs on a healthy big-file scan (where workers legitimately
        // sit on a slow hash for >5 s) are noise in production logs.
        let heartbeat_enabled = cfg!(debug_assertions)
            || std::env::var_os("MYTHODIKAL_HEARTBEAT").is_some();
        let heartbeat_visited = files_visited_atom.clone();
        let heartbeat_hashed = files_hashed_atom.clone();
        let heartbeat_running = files_running.clone();
        let heartbeat_alive = scan_alive.clone();
        if heartbeat_enabled {
        std::thread::Builder::new()
            .name("mythkernel/scan-heartbeat".into())
            .spawn(move || {
                let mut prev_visited = 0i64;
                let mut prev_hashed = 0i64;
                let mut stall_ticks = 0u32;
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    if !heartbeat_alive.load(Ordering::Relaxed) {
                        return;
                    }
                    let v = heartbeat_visited.load(Ordering::Relaxed);
                    let h = heartbeat_hashed.load(Ordering::Relaxed);
                    let r = heartbeat_running.load(Ordering::Relaxed);
                    let dv = v - prev_visited;
                    let dh = h - prev_hashed;
                    if dv == 0 && dh == 0 {
                        stall_ticks += 1;
                        tracing::warn!(
                            files_visited = v,
                            files_hashed = h,
                            files_enumerated = r,
                            stall_ticks,
                            "scan heartbeat: NO PROGRESS in last 5 s"
                        );
                    } else {
                        stall_ticks = 0;
                        tracing::info!(
                            files_visited = v,
                            files_hashed = h,
                            files_enumerated = r,
                            delta_visited = dv,
                            delta_hashed = dh,
                            "scan heartbeat"
                        );
                    }
                    prev_visited = v;
                    prev_hashed = h;
                }
            })
            .expect("spawn scan-heartbeat");
        } // end heartbeat_enabled gate
        let foreground = opts.foreground;
        let compute_sha256 = opts.compute_sha256;
        let include_archives = opts.include_archives;
        let run_heuristics = opts.run_heuristics;
        let archive_entries_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let pipeline_for_workers = self.pipeline.clone();
        let hasher_for_workers = hasher;

        // Clones the coordinator captures for finalization (after
        // workers join).
        let files_visited_for_finalize = files_visited_atom.clone();
        let files_hashed_for_finalize = files_hashed_atom.clone();
        let bytes_visited_for_finalize = bytes_visited_atom.clone();
        let findings_count_for_finalize = findings_count_atom.clone();
        let file_baseline_for_finalize = file_baseline_shared.clone();
        let cancel_flag_for_finalize = cancel_flag.clone();
        let scan_alive_for_finalize = scan_alive.clone();

        let worker = tokio::task::spawn_blocking(move || {
            // Phase 6 — registry sweep runs first. Cheap (~hundreds
            // of values) compared to a file scan, so a sequential
            // pre-pass is fine. Skipped when include_registry is off.
            if include_registry && !cancel_flag_for_phases.load(Ordering::Relaxed) {
                crate::registry_scan::scan_registry(
                    scan_id,
                    &tx_for_phases,
                    &cancel_flag_for_phases,
                );
            }
            // Phase 6 — process sweep runs after registry. Enumerates
            // every PID, streams one event per process, hashes the
            // main exe via the existing hasher pipeline (Phase 7
            // wave). Skipped when include_processes is off.
            if include_processes && !cancel_flag_for_phases.load(Ordering::Relaxed) {
                crate::process_scan::scan_processes(
                    scan_id,
                    &tx_for_phases,
                    &cancel_flag_for_phases,
                );
            }
            // Release the file producer — it's been waiting on this
            // flag while the pre-phases ran.
            phases_ready_for_blocking.store(true, Ordering::Relaxed);

            // Phase 6 (review M3) — Reg-only / Process-only sweeps
            // turn off `include_files`; in that mode the producer
            // never enqueues anything into `work_rx`, so skip the
            // worker pool entirely and finalize once registry +
            // process phases have completed. Saves ~80 ms of thread
            // spawn / teardown on a 32-core box and avoids the
            // sleeping-worker noise in the scheduler.
            if !include_files {
                // Drop work_tx so any future producer cycle's
                // workers (which there aren't) would see Disconnected
                // immediately. Actually work_tx is held by the
                // producer thread; nothing to do here.
                let files_visited = files_visited_for_finalize.load(Ordering::Relaxed);
                let files_hashed = files_hashed_for_finalize.load(Ordering::Relaxed);
                let bytes_visited = bytes_visited_for_finalize.load(Ordering::Relaxed);
                let findings_count = findings_count_for_finalize.load(Ordering::Relaxed);
                scan_alive_for_finalize.store(false, Ordering::Relaxed);
                let _ = file_baseline_for_finalize.flush_pending(&db);
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
                    Ok(_) => {
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
                return;
            }

            // Perf phase 1 — spawn N worker threads each draining
            // the same MPMC `work_rx`. N defaults to the host's
            // logical core count; on an 8-core machine this gets
            // us roughly 8× the per-file throughput of the prior
            // single-consumer design.
            let n_workers = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4);
            tracing::info!(workers = n_workers, "scan worker pool spawning");
            let mut handles: Vec<std::thread::JoinHandle<()>> = Vec::with_capacity(n_workers);
            for worker_idx in 0..n_workers {
                let work_rx = work_rx.clone();
                let pause_flag = pause_flag_for_worker.clone();
                let cancel_flag = cancel_flag_for_worker.clone();
                let abort_flag = abort_flag_for_worker.clone();
                let processed_paths = processed_paths_shared.clone();
                let files_visited = files_visited_atom.clone();
                let files_hashed = files_hashed_atom.clone();
                let bytes_visited = bytes_visited_atom.clone();
                let findings_count = findings_count_atom.clone();
                let estimator = estimator_shared.clone();
                let throttle = throttle_shared.clone();
                let pipeline = pipeline_for_workers.clone();
                let hasher = hasher_for_workers.clone();
                let db = db.clone();
                let file_baseline = file_baseline_shared.clone();
                let files_running = files_running.clone();
                let bytes_running = bytes_running.clone();
                let enum_complete = enum_complete.clone();
                let tx = tx_for_worker.clone();
                let archive_entries_counter = archive_entries_counter.clone();
                let handle = std::thread::Builder::new()
                    .name(format!("mythkernel/scan-worker-{worker_idx}"))
                    .spawn(move || {
                        let ctx = WorkerCtx {
                            work_rx,
                            pause_flag,
                            cancel_flag,
                            abort_flag,
                            processed_paths,
                            files_visited,
                            files_hashed,
                            bytes_visited,
                            findings_count,
                            estimator,
                            throttle,
                            pipeline,
                            hasher,
                            db,
                            file_baseline,
                            scan_id,
                            has_publisher_excl,
                            foreground,
                            emit_partial,
                            compute_sha256,
                            files_running,
                            bytes_running,
                            enum_complete,
                            tx,
                            include_archives,
                            archive_entries_counter,
                            has_crc32_gate,
                        };
                        run_worker_loop(&ctx);
                    })
                    .expect("spawn worker thread");
                handles.push(handle);
            }
            for h in handles {
                let _ = h.join();
            }

            // Perf phase 5 — single batch flush of file_mutation
            // baseline rows. Removes the per-file IMMEDIATE
            // transaction overhead from the hot path.
            let flushed = file_baseline_for_finalize.flush_pending(&db);
            if flushed > 0 {
                tracing::info!(rows = flushed, "file_mutation baseline batch flushed");
            }

            // Phase 6 — heuristic post-pass (preview). Runs after
            // the file phase finishes; reads `verdict_cache` rows
            // from this run and flags executables in dropper-
            // staging directories.
            if run_heuristics && !cancel_flag_for_finalize.load(Ordering::Relaxed) {
                let (items, flagged) = crate::heuristics_scan::scan_heuristics(
                    scan_id,
                    &db,
                    &tx_for_worker,
                    &cancel_flag_for_finalize,
                );
                if flagged > 0 {
                    findings_count_for_finalize
                        .fetch_add(flagged as i64, Ordering::Relaxed);
                }
                tracing::info!(items, flagged, "heuristics post-pass done");
            }

            // Workers only exit on cancel or natural drain — pause is
            // in-place now, so there's no `paused_mid_run` finalize
            // branch. Tell the abort-watcher the scan is done so it
            // can retire cleanly even if pause never fired.
            scan_alive_for_finalize.store(false, Ordering::Relaxed);

            // Snapshot the shared counters for finalization. All
            // workers are joined at this point so loads are
            // race-free.
            let files_visited = files_visited_for_finalize.load(Ordering::Relaxed);
            let files_hashed = files_hashed_for_finalize.load(Ordering::Relaxed);
            let bytes_visited = bytes_visited_for_finalize.load(Ordering::Relaxed);
            let findings_count = findings_count_for_finalize.load(Ordering::Relaxed);

            let cancelled_mid_run = cancel_flag_for_finalize.load(Ordering::Relaxed);

            let ended_at_utc = now_utc();
            let duration_ms = started_at_instant.elapsed().as_millis() as u64;

            if cancelled_mid_run {
                // No resume token — cancellation is final. Update the
                // scan row to `cancelled` so History reflects the user's
                // intent. Counters carry the work actually done.
                if let Ok(conn) = db.lock() {
                    let _ = history::set_resume_token(&conn, scan_id, &[]);
                    let _ = history::finalize_scan(
                        &conn,
                        scan_id,
                        ended_at_utc,
                        ScanStatus::Cancelled,
                        files_visited,
                        files_hashed,
                        0,
                        0,
                        bytes_visited,
                        findings_count,
                    );
                }
                let _ = tx_for_worker.send(ScanProgress::Cancelled {
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
            cancel_flag,
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

/// Shared state for one worker in the per-scan worker pool. Every
/// worker pulls work items from the same `work_rx` MPMC channel and
/// applies the same per-file pipeline, but all mutable counters and
/// the dedup set are behind `Arc<AtomicI64>` / `Arc<Mutex<...>>` so
/// concurrent workers don't trample each other's writes.
struct WorkerCtx {
    work_rx: crossbeam_channel::Receiver<(std::path::PathBuf, u64, i64)>,
    pause_flag: Arc<std::sync::atomic::AtomicBool>,
    cancel_flag: Arc<std::sync::atomic::AtomicBool>,
    abort_flag: Arc<std::sync::atomic::AtomicBool>,
    processed_paths: Arc<Mutex<BTreeSet<String>>>,
    files_visited: Arc<std::sync::atomic::AtomicI64>,
    files_hashed: Arc<std::sync::atomic::AtomicI64>,
    bytes_visited: Arc<std::sync::atomic::AtomicI64>,
    findings_count: Arc<std::sync::atomic::AtomicI64>,
    estimator: Arc<Mutex<EtaEstimator>>,
    throttle: Arc<Mutex<AdaptiveThrottle>>,
    pipeline: Arc<DetectionPipeline>,
    hasher: Hasher,
    db: Arc<Mutex<Connection>>,
    file_baseline: Arc<crate::detect::file_mutation::FileBaseline>,
    scan_id: i64,
    has_publisher_excl: bool,
    foreground: bool,
    emit_partial: bool,
    compute_sha256: bool,
    files_running: Arc<std::sync::atomic::AtomicU64>,
    bytes_running: Arc<std::sync::atomic::AtomicU64>,
    enum_complete: Arc<std::sync::atomic::AtomicBool>,
    tx: broadcast::Sender<ScanProgress>,
    /// Phase 6 — when true, recurse into .zip/.zipx files and emit
    /// `ArchiveEntry` events for each entry. Default false.
    include_archives: bool,
    /// Phase 6 — running total of archive entries scanned across all
    /// archives in this scan. Shared across workers.
    archive_entries_counter: Arc<std::sync::atomic::AtomicU64>,
    /// CRC32 fast-screen gate is configured. When true, the worker
    /// routes hashing through the gated entry-point and skips
    /// BLAKE3 (+ pipeline) for files whose CRC32 isn't in the set.
    has_crc32_gate: bool,
}

/// One scan worker's body. Loops on `work_rx` until cancel fires or
/// the channel disconnects. Each iteration handles a single file
/// through the full pipeline (verdict cache → MS-signed fast-path →
/// exclusions → hash → detect → cache store → file_mutation enqueue).
///
/// Pause is in-place: the loop parks on `pause_flag` at the top of
/// each iteration and resumes from the exact same point in the queue
/// when the flag clears. Cancel still exits the worker permanently.
fn run_worker_loop(ctx: &WorkerCtx) {
    loop {
        if ctx.cancel_flag.load(Ordering::Relaxed) {
            return;
        }
        // In-place pause loop. The hash-abort watcher mirrors
        // `pause_flag` into the hasher's abort flag, so any in-flight
        // hash bails fast and the worker re-enters this wait on the
        // next iteration. Cancel takes precedence and exits.
        while ctx.pause_flag.load(Ordering::Relaxed) {
            if ctx.cancel_flag.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let (path, size, mtime) = match ctx
            .work_rx
            .recv_timeout(std::time::Duration::from_millis(100))
        {
            Ok(item) => item,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => return,
        };
        // Interrupted mid-hash → re-loop. The pause-wait above will
        // catch a pause; a cancel will exit on the next iteration's
        // top check. The Interrupted arm in `process_one_file` rolled
        // back the visited counters so the partial file isn't counted.
        process_one_file(ctx, path, size, mtime);
    }
}

/// Single-file pipeline run. All of the per-file work — verdict
/// cache lookup, MS-signed fast-path, exclusions, hash, pipeline
/// evaluation, file_mutation enqueue, processed_paths bookkeeping —
/// happens here. Returns whether the caller should stop the worker.
fn process_one_file(
    ctx: &WorkerCtx,
    path: std::path::PathBuf,
    size: u64,
    mtime: i64,
) {
    let path_str_owned = path.to_string_lossy().into_owned();

    // 1. Skip already-processed (resume carry or another worker
    //    finished this path between recv and us).
    if let Ok(paths) = ctx.processed_paths.lock()
        && paths.contains(&path_str_owned)
    {
        return;
    }

    // Bump the visited counters before any work — matches the
    // prior single-threaded semantics where "visited" tracked
    // every file the loop saw, even ones it later skipped via
    // exclusions.
    ctx.files_visited.fetch_add(1, Ordering::Relaxed);
    ctx.bytes_visited.fetch_add(size as i64, Ordering::Relaxed);

    // 2. Signer extraction. Each extraction shells out to
    //    PowerShell (~200-500 ms cold) and the MS-signed fast-path
    //    only pays off inside `C:\Windows`. For arbitrary scan
    //    targets (D:\, user folders, backup dirs) the long tail of
    //    non-MS-signed `.dll` files makes the shell-out a net loss.
    //    We therefore only extract when:
    //      a) the user has a publisher exclusion (correctness
    //         requirement — we must check signers), OR
    //      b) the file is under the OS install dir (typical
    //         MS-signed payoff), OR
    //      c) on macOS, the file is a Mach-O candidate (cheap
    //         `codesign --display` shell-out — different cost
    //         profile from Windows PowerShell).
    let signer_identity_full: Option<crate::detect::publisher::SignerIdentity> = {
        let needs_signer = ctx.has_publisher_excl
            || (cfg!(target_os = "windows")
                && may_be_executable(&path)
                && is_under_windows_system_dir(&path))
            || (cfg!(target_os = "macos") && may_be_executable(&path));
        if needs_signer {
            Some(extract_signer_cached(&ctx.db, &path))
        } else {
            None
        }
    };
    let signer_identity_str: Option<String> = signer_identity_full
        .as_ref()
        .filter(|s| s.is_signed())
        .map(|s| s.identity.clone());

    // 3. Path/glob/publisher exclusion check.
    let path_excluded = match ctx.db.lock() {
        Ok(conn) => exclusions::matches(
            &conn,
            &MatchCtx {
                path: path_str_owned.as_str(),
                blake3_hex: None,
                sha256_hex: None,
                publisher: signer_identity_str.as_deref(),
                scope: MatchScope::Scan,
            },
        )
        .ok()
        .flatten(),
        Err(_) => None,
    };
    if path_excluded.is_some() {
        mark_processed(&ctx.processed_paths, &path_str_owned);
        return;
    }

    // 4. Perf phase 4 — Microsoft-signed system file fast-path.
    //    Skip hash + pipeline when the binary is signed by
    //    Microsoft Windows / Corporation. Caches the Clean verdict
    //    so the next scan short-circuits via verdict_cache too
    //    (without re-extracting the signer).
    if let Some(ref s) = signer_identity_full
        && crate::detect::publisher::is_microsoft_signer(&s.identity)
    {
        ctx.files_hashed.fetch_add(1, Ordering::Relaxed);
        // Sec-review M1: use a sentinel rather than an empty hash so
        // downstream consumers (history detail, findings UI) don't
        // mis-key on `""` and so the cache row is greppable.
        const MS_SIGNED_SENTINEL: &str = "<microsoft-signed>";
        emit_file_event(ctx, &path, MS_SIGNED_SENTINEL, size);
        if let Ok(conn) = ctx.db.lock() {
            crate::detect::verdict_cache::store(
                &conn,
                &path,
                mtime,
                size,
                MS_SIGNED_SENTINEL,
                None,
                &crate::detect::verdict_cache::CachedOutcome::Clean,
                now_utc(),
            );
        }
        mark_processed(&ctx.processed_paths, &path_str_owned);
        return;
    }

    // 5. Perf phase 3 — verdict cache lookup. Skip hash + pipeline
    //    when (path, mtime, size) is unchanged since last scan.
    if let Ok(conn) = ctx.db.lock()
        && let Some(cached) = crate::detect::verdict_cache::lookup(&conn, &path, mtime, size)
    {
        drop(conn);
        ctx.files_hashed.fetch_add(1, Ordering::Relaxed);
        emit_file_event(ctx, &path, &cached.blake3_hex, size);
        if let crate::detect::verdict_cache::CachedOutcome::Detected {
            rule_id,
            rule_source,
            severity,
            evidence,
        } = &cached.outcome
        {
            // Sec-review H1: re-record the findings row for THIS
            // scan_id so History → scan-detail shows the verdict,
            // even though the original detection was cached. Without
            // this re-record, `findings_count` on the new scan row
            // would be inflated relative to actual `findings`
            // entries for `scan_id = ?`, breaking the detail panel.
            // The user can delete the prior scan's finding row
            // without making subsequent scans go silent on
            // recurring detections.
            let blake3_bytes = crate::detect::blake3_hex_to_bytes(&cached.blake3_hex);
            let sha256_bytes = cached.sha256_hex.as_deref().and_then(decode_sha256);
            let detected_at_utc = now_utc();
            let finding_id = match ctx.db.lock() {
                Ok(conn) => history::record_finding(
                    &conn,
                    ctx.scan_id,
                    path.to_string_lossy().as_ref(),
                    Some(size as i64),
                    blake3_bytes.as_ref().map(|b| b.as_slice()),
                    sha256_bytes.as_ref().map(|s| s.as_slice()),
                    rule_id,
                    rule_source,
                    severity.as_str(),
                    detected_at_utc,
                )
                .ok(),
                Err(_) => None,
            };
            if let Some(id) = finding_id {
                ctx.findings_count.fetch_add(1, Ordering::Relaxed);
                let _ = ctx.tx.send(ScanProgress::Finding {
                    scan_id: ctx.scan_id,
                    finding_id: id,
                    path: path.clone(),
                    rule_id: rule_id.clone(),
                    rule_source: rule_source.clone(),
                    severity: severity.as_str().to_string(),
                });
            }
            let _ = evidence; // currently unused — evidence flows via the new findings row's `evidence` column when re-record lands in a follow-up
        }
        // Phase 6 — archive scan still runs on cache hits. The
        // archive's bytes are unchanged but the user expects the
        // "archive entries scanned" counter to tick up every scan,
        // not just the first one. Re-iterating a cached zip is the
        // same cost as the original scan; for big archives this is
        // worth re-thinking later (cache the entry count too) but
        // for now correctness > re-scan latency.
        if ctx.include_archives && crate::archive_scan::is_archive(&path) {
            crate::archive_scan::scan_archive(
                ctx.scan_id,
                &path,
                &ctx.tx,
                &ctx.cancel_flag,
                &ctx.pause_flag,
                &ctx.archive_entries_counter,
                &ctx.files_hashed,
            );
        }
        mark_processed(&ctx.processed_paths, &path_str_owned);
        return;
    }

    // 6. Perf phase 2 — skip per-file throttle sleep on foreground
    //    scans. Background daemon scans (Phase 8+) keep the
    //    throttle to yield to interactive load.
    if !ctx.foreground
        && let Ok(mut t) = ctx.throttle.lock()
    {
        yield_per_throttle(&mut t);
    }

    // 7. Hash the file (mid-chunk abort-flag aware).
    //
    // When a CRC32 fast-screen gate is configured (`has_crc32_gate`)
    // and we're not in partial-hash UI mode, route through the gated
    // entry-point. On a CRC32 miss the file is "hash-clean" (no
    // malware blacklist entry could possibly match) so we short-
    // circuit: bump per-file counters, mark the path processed,
    // and return without computing BLAKE3 / SHA-256 / running the
    // detection pipeline. The 1-in-4300 false-positive rate at the
    // gate stage falls through to the normal hashing path, where
    // BLAKE3 confirms or rejects.
    let hash_outcome = if ctx.has_crc32_gate && !ctx.emit_partial {
        use crate::hasher::MaybeHashResult;
        match ctx.hasher.hash_file_with_crc32_gate(&path) {
            Ok(MaybeHashResult::GatedMiss { size, .. }) => {
                // Review fix: do NOT double-bump visited counters
                // (already incremented at the top of this function at
                // L1058-1059). DO bump files_hashed so the
                // X-scanned tile + ETA estimator stay meaningful, and
                // emit a `File` event with a sentinel so the UI
                // progress totals advance (matching the MS-signed
                // fast-path pattern above).
                ctx.files_hashed.fetch_add(1, Ordering::Relaxed);
                const CRC32_SKIP_SENTINEL: &str = "<crc32-skip>";
                emit_file_event(ctx, &path, CRC32_SKIP_SENTINEL, size);
                mark_processed(&ctx.processed_paths, &path_str_owned);
                return;
            }
            Ok(MaybeHashResult::Hashed { result, .. }) => Ok(result),
            Err(e) => Err(e),
        }
    } else if ctx.emit_partial {
        hash_file_with_partial_events(
            &path,
            ctx.compute_sha256,
            ctx.scan_id,
            &ctx.tx,
            &ctx.abort_flag,
        )
    } else {
        ctx.hasher.hash_file(&path)
    };

    match hash_outcome {
        Ok(result) => {
            ctx.files_hashed.fetch_add(1, Ordering::Relaxed);

            // 7.5. Archive recursion (Phase 6 follow-up). Hash the
            // archive itself first (above), then if the user enabled
            // `include_archives` and the extension is a known zip
            // container, iterate every entry inside and emit one
            // `ArchiveEntry` event per entry.
            if ctx.include_archives && crate::archive_scan::is_archive(&path) {
                crate::archive_scan::scan_archive(
                    ctx.scan_id,
                    &path,
                    &ctx.tx,
                    &ctx.cancel_flag,
                    &ctx.pause_flag,
                    &ctx.archive_entries_counter,
                    &ctx.files_hashed,
                );
            }

            // 8. ETA sample (brief lock).
            let eta_secs = {
                let locked = ctx.enum_complete.load(Ordering::Relaxed);
                let files_total_now = ctx.files_running.load(Ordering::Relaxed);
                let bytes_total_now = ctx.bytes_running.load(Ordering::Relaxed);
                let sample = EtaSample {
                    files_done: ctx.files_visited.load(Ordering::Relaxed) as u64,
                    files_total: Some(files_total_now),
                    bytes_done: ctx.bytes_visited.load(Ordering::Relaxed) as u64,
                    bytes_total: Some(bytes_total_now),
                    now: Instant::now(),
                };
                let eta = ctx
                    .estimator
                    .lock()
                    .ok()
                    .and_then(|mut e| e.observe(sample));
                emit_file_event_full(
                    ctx,
                    &path,
                    &result.blake3,
                    result.size,
                    eta,
                    locked,
                    files_total_now,
                );
                eta
            };
            let _ = eta_secs; // already emitted above

            // 9. Detection pipeline.
            let outcome = if !ctx.pipeline.is_empty() {
                evaluate_pipeline_with_outcome(
                    &ctx.pipeline,
                    &ctx.db,
                    &ctx.tx,
                    ctx.scan_id,
                    &path,
                    size,
                    &result,
                    &ctx.findings_count,
                )
            } else {
                PipelineOutcome::Clean
            };

            // 10. Perf phase 3 — cache the verdict for next scan.
            if let Ok(conn) = ctx.db.lock() {
                let cached =
                    crate::detect::verdict_cache::CachedOutcome::from_pipeline_outcome(&outcome);
                crate::detect::verdict_cache::store(
                    &conn,
                    &path,
                    mtime,
                    size,
                    &result.blake3,
                    result.sha256.as_deref(),
                    &cached,
                    now_utc(),
                );
            }

            // 11. Perf phase 5 — enqueue file_mutation baseline row.
            //     Single batch flush at scan end (in coordinator).
            if ctx.file_baseline.is_enabled() {
                run_file_mutation_hook(
                    &ctx.file_baseline,
                    &ctx.db,
                    &ctx.tx,
                    ctx.scan_id,
                    &path,
                    size,
                    &result,
                    signer_identity_str.as_deref(),
                    &ctx.findings_count,
                );
            }

            mark_processed(&ctx.processed_paths, &path_str_owned);
        }
        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
            // Pause-triggered hash abort. Roll back the visited
            // counters so the partial file isn't double-counted and
            // re-loop — the worker's top-of-loop pause-wait will park
            // the thread until Resume.
            ctx.files_visited.fetch_sub(1, Ordering::Relaxed);
            ctx.bytes_visited.fetch_sub(size as i64, Ordering::Relaxed);
        }
        Err(err) => {
            let _ = ctx.tx.send(ScanProgress::Error {
                path: path.clone(),
                message: err.to_string(),
            });
        }
    }
}

/// Extract the signer identity for `path`, going through the
/// three-phase publisher cache (lookup → unlocked I/O → store)
/// from TASK-136. The shell-out to the platform signer extractor
/// never holds the DB lock so other workers can keep using it.
fn extract_signer_cached(
    db: &Arc<Mutex<Connection>>,
    path: &std::path::Path,
) -> crate::detect::publisher::SignerIdentity {
    let probe = match db.lock() {
        Ok(conn) => publisher::cache_lookup(&conn, path).ok(),
        Err(_) => None,
    };
    let probe = match probe {
        Some(p) => p,
        None => return crate::detect::publisher::SignerIdentity::unsigned(),
    };
    match probe.cached.clone() {
        Some(c) => c,
        None => {
            let extracted = publisher::extract_io_unlocked(path);
            if let Ok(conn) = db.lock() {
                let _ = publisher::cache_store(&conn, &probe, &extracted);
            }
            extracted
        }
    }
}

/// Quick check: does the file path's extension suggest it could be
/// an executable that's worth checking for an Authenticode / codesign
/// signature? Used by the MS-signed fast-path to avoid extracting
/// signers from .txt/.png/.mp4 etc.
fn may_be_executable(path: &std::path::Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "exe" | "dll" | "sys" | "ocx" | "cpl" | "drv" | "msi" | "mui" | "node" | "scr"
    )
}

/// On Windows, is `path` under the OS install directory (typically
/// `C:\Windows`)? Used to gate signer extraction: the MS-signed
/// fast-path is hugely valuable inside `C:\Windows` (skips hashing on
/// ~30% of system files) but the per-file `Get-AuthenticodeSignature`
/// shell-out is brutal for scans of `D:\`, user folders, or backup
/// directories where almost nothing is MS-signed. Extracting only
/// when inside the OS dir avoids paying that cost on the long tail.
///
/// Reads `%SystemRoot%` (set on every modern Windows install) and
/// falls back to `C:\Windows` if the env var is missing. A `None`
/// SystemRoot returns false (be conservative — don't shell out).
#[cfg(target_os = "windows")]
fn is_under_windows_system_dir(path: &std::path::Path) -> bool {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let root_path = std::path::PathBuf::from(root);
    path.starts_with(&root_path)
        || path
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains("\\windows\\")
}
#[cfg(not(target_os = "windows"))]
fn is_under_windows_system_dir(_path: &std::path::Path) -> bool {
    false
}

/// Append a path to the `processed_paths` dedup set, respecting the
/// per-scan cap so a giant scan doesn't grow the resume token
/// unbounded.
fn mark_processed(processed_paths: &Mutex<BTreeSet<String>>, path_str: &str) {
    if let Ok(mut paths) = processed_paths.lock()
        && paths.len() < RESUME_TOKEN_PATH_CAP
    {
        paths.insert(path_str.to_string());
    }
}

/// Emit a `ScanProgress::File` event with no ETA / total info.
/// Used by the fast-path branches (MS-signed, verdict cache hit)
/// where we skipped the hash so there's nothing to feed the ETA
/// estimator. The UI's throughput chart already smooths over
/// per-event jitter; we don't need an ETA sample per skip.
fn emit_file_event(ctx: &WorkerCtx, path: &std::path::Path, blake3: &str, size: u64) {
    let locked = ctx.enum_complete.load(Ordering::Relaxed);
    let files_total_now = ctx.files_running.load(Ordering::Relaxed);
    emit_file_event_full(ctx, path, blake3, size, None, locked, files_total_now);
}

/// Emit a `ScanProgress::File` event with explicit ETA + totals.
/// Centralizes the running-vs-locked payload picking so the
/// fast-path and full-hash branches share one definition.
fn emit_file_event_full(
    ctx: &WorkerCtx,
    path: &std::path::Path,
    blake3: &str,
    size: u64,
    eta_secs: Option<f64>,
    locked: bool,
    files_total_now: u64,
) {
    let _ = ctx.tx.send(ScanProgress::File {
        path: path.to_path_buf(),
        blake3: blake3.to_string(),
        size,
        eta_secs,
        files_total_running: if locked { None } else { Some(files_total_now) },
        files_total_locked: if locked { Some(files_total_now) } else { None },
        // Cumulative snapshots — UI uses these as authoritative
        // counters because the forwarder coalesces File events to
        // ≤ 10 Hz, which would otherwise undercount a +1-per-event
        // UI by orders of magnitude on a fast scan.
        files_visited_total: ctx.files_visited.load(Ordering::Relaxed).max(0) as u64,
        files_hashed_total: ctx.files_hashed.load(Ordering::Relaxed).max(0) as u64,
        bytes_visited_total: ctx.bytes_visited.load(Ordering::Relaxed).max(0) as u64,
        findings_count_total: ctx.findings_count.load(Ordering::Relaxed).max(0) as u64,
    });
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
/// pipeline. Returns the [`PipelineOutcome`] for the verdict cache
/// (Perf phase 3). On `Detected` we record a `findings` row and emit
/// a `ScanProgress::Finding` event; on `SkippedByAllowlist` we
/// silently honor the verdict; on `Clean` we do nothing.
///
/// Perf phase 1: takes the findings counter as `&AtomicI64` so
/// concurrent workers can increment it lock-free.
#[allow(clippy::too_many_arguments)]
fn evaluate_pipeline_with_outcome(
    pipeline: &DetectionPipeline,
    db: &Arc<Mutex<Connection>>,
    tx: &broadcast::Sender<ScanProgress>,
    scan_id: i64,
    path: &std::path::Path,
    size: u64,
    hash: &crate::hasher::HashResult,
    findings_count: &std::sync::atomic::AtomicI64,
) -> PipelineOutcome {
    let Some(blake3_bytes) = blake3_hex_to_bytes(&hash.blake3) else {
        let _ = tx.send(ScanProgress::Error {
            path: path.to_path_buf(),
            message: "blake3 hex decode failed".to_string(),
        });
        return PipelineOutcome::Clean;
    };
    let sha256_bytes: Option<[u8; 32]> = hash.sha256.as_deref().and_then(decode_sha256);

    let ctx = FileCtx {
        path,
        size_bytes: size,
        blake3: &blake3_bytes,
        sha256: sha256_bytes.as_ref(),
    };
    let outcome = pipeline.evaluate(&ctx);
    if let PipelineOutcome::Detected {
        rule_id,
        rule_source,
        severity,
        evidence: _,
        detector_id: _,
    } = &outcome
    {
        let detected_at_utc = now_utc();
        let finding_id = match db.lock() {
            Ok(conn) => history::record_finding(
                &conn,
                scan_id,
                path.to_string_lossy().as_ref(),
                Some(size as i64),
                Some(&blake3_bytes),
                sha256_bytes.as_ref().map(|s| s.as_slice()),
                rule_id,
                rule_source,
                severity.as_str(),
                detected_at_utc,
            )
            .ok(),
            Err(_) => None,
        };
        if let Some(id) = finding_id {
            findings_count.fetch_add(1, Ordering::Relaxed);
            let _ = tx.send(ScanProgress::Finding {
                scan_id,
                finding_id: id,
                path: path.to_path_buf(),
                rule_id: rule_id.clone(),
                rule_source: rule_source.clone(),
                severity: severity.as_str().to_string(),
            });
        }
    }
    outcome
}

fn decode_sha256(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// TASK-138 — bridge between the engine's per-file loop and
/// [`FileBaseline`]. Records the new baseline row for autostart /
/// `$PATH` / script files and, when the diff fires the
/// "previously signed-or-known → now mutated" rule, persists a
/// `findings` row + emits `ScanProgress::Finding`.
///
/// `nsrl_known` is hard-wired to `false` for now — the live pipeline
/// already short-circuits NSRL allowlist hits before this hook fires,
/// so we have no signal that "this file would have been
/// allowlisted" without an extra DB lookup. Phase 5 wave 3 ships the
/// hash-drift half of FR-131; the NSRL-known half lands when
/// goodware_allowlist exposes a "would-this-have-skipped?" probe
/// (TASK-138 follow-up tracked in the comment block at the top of
/// `detect/file_mutation.rs`).
///
/// Code-review M7: the `signer_kind` is derived from the host OS so
/// the baseline row's `signer_kind` column carries the right
/// platform tag (`authenticode` on Windows, `codesign` on macOS,
/// `gpg` on Linux) rather than always reporting `authenticode`.
#[allow(clippy::too_many_arguments)]
fn run_file_mutation_hook(
    baseline: &FileBaseline,
    db: &Arc<Mutex<Connection>>,
    tx: &broadcast::Sender<ScanProgress>,
    scan_id: i64,
    path: &std::path::Path,
    size: u64,
    hash: &HashResult,
    signer_identity: Option<&str>,
    findings_count: &std::sync::atomic::AtomicI64,
) {
    let signer = match signer_identity {
        Some(s) if !s.is_empty() => {
            #[cfg(target_os = "windows")]
            let kind = crate::detect::publisher::SignerKind::Authenticode;
            #[cfg(target_os = "macos")]
            let kind = crate::detect::publisher::SignerKind::Codesign;
            #[cfg(target_os = "linux")]
            let kind = crate::detect::publisher::SignerKind::Gpg;
            #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
            let kind = crate::detect::publisher::SignerKind::Unsigned;
            crate::detect::publisher::SignerIdentity {
                identity: s.to_string(),
                kind,
            }
            .truncated()
        }
        _ => crate::detect::publisher::SignerIdentity::unsigned(),
    };
    let finding = baseline.check_and_enqueue(
        db,
        scan_id,
        path,
        &hash.blake3,
        hash.sha256.as_deref(),
        size,
        &signer,
        false,
    );
    let Some(finding) = finding else {
        return;
    };
    // Persist the finding row + emit the event so the UI surfaces it.
    let blake3_bytes = blake3_hex_to_bytes(&hash.blake3);
    let sha256_bytes = hash.sha256.as_deref().and_then(decode_sha256);
    let detected_at_utc = now_utc();
    let finding_id = match db.lock() {
        Ok(conn) => history::record_finding(
            &conn,
            scan_id,
            path.to_string_lossy().as_ref(),
            Some(size as i64),
            blake3_bytes.as_ref().map(|b| b.as_slice()),
            sha256_bytes.as_ref().map(|s| s.as_slice()),
            &finding.rule_id,
            "file_mutation",
            finding.severity.as_str(),
            detected_at_utc,
        )
        .ok(),
        Err(_) => None,
    };
    if let Some(id) = finding_id {
        findings_count.fetch_add(1, Ordering::Relaxed);
        let _ = tx.send(ScanProgress::Finding {
            scan_id,
            finding_id: id,
            path: path.to_path_buf(),
            rule_id: finding.rule_id,
            rule_source: "file_mutation".to_string(),
            severity: finding.severity.as_str().to_string(),
        });
    }
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
    abort_flag: &Arc<AtomicBool>,
) -> std::io::Result<HashResult> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut streaming = StreamingHasher::new(compute_sha256);
    let mut buf = vec![0u8; crate::hasher::DEFAULT_CHUNK_SIZE];
    let mut last_emit = std::time::Instant::now();
    let throttle = std::time::Duration::from_millis(100);
    loop {
        // Mid-hash cooperative cancellation. Mirrors the abort poll
        // baked into `Hasher::hash_file` so operator-mode + non-
        // operator-mode share the same responsiveness contract.
        if abort_flag.load(Ordering::Relaxed) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "scan aborted mid-hash",
            ));
        }
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
        // In-place pause: setting `pause_flag = true` parks the
        // worker pool and the producer in their respective spin-wait
        // loops; flipping it back to false lets them resume from
        // exactly where they were. There's no `Paused` event and no
        // resume-from-token round trip — the same `ScanHandle` carries
        // through the whole pause/resume cycle.
        const FILES: usize = 200;
        let conn = db::open_in_memory().unwrap();
        let engine = ScanEngine::new(conn);
        let dir = tempdir().unwrap();
        for i in 0..FILES {
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

        // Wait for the first File event, then assert pause-then-resume
        // doesn't drop files. We don't strictly need to *observe* a
        // paused state from the engine (there's no Paused event in the
        // in-place model); we just need to prove that toggling the
        // flag on then off doesn't break the scan.
        let pause_clear = pause_flag.clone();
        let raise = tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ScanProgress::File { .. }) => {
                        pause_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                        // Give the workers time to actually enter the
                        // pause wait (50ms tick × small slack).
                        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                        pause_clear.store(false, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                    Ok(ScanProgress::Completed { .. }) => break, // very small tree raced past us
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
        worker.await.unwrap();
        let _ = raise.await;

        let (status, files_after, findings_count): (String, i64, i64) = {
            let db = engine.db.lock().unwrap();
            db.query_row(
                "SELECT status, files_visited, findings_count FROM scans WHERE id = ?1",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap()
        };
        assert_eq!(status, "completed");
        assert_eq!(files_after, FILES as i64);
        assert_eq!(findings_count, 0);
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
