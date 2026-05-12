//! `mythctl scan` — TASK-017.
//!
//! Streams progress to stderr (text or NDJSON), summary to stdout. Uses an
//! in-memory SQLite for now; the persistent DB lands when `mythctl history`
//! arrives in Phase 2.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, anyhow};
use mythkernel::{
    db,
    engine::ScanEngine,
    scan::{ScanOptions, ScanProgress, ScanTarget},
};

use crate::Format;

pub async fn run(
    path: PathBuf,
    format: Format,
    compute_sha256: bool,
    follow_symlinks: bool,
) -> anyhow::Result<()> {
    if !path.exists() {
        return Err(anyhow!("path does not exist: {}", path.display()));
    }

    let conn = db::open_in_memory().context("open in-memory engine db")?;
    let engine = ScanEngine::new(conn);

    let opts = ScanOptions {
        compute_sha256,
        follow_symlinks,
        ..ScanOptions::default()
    };

    let handle = engine
        .scan(ScanTarget::Path(path.clone()), opts)
        .map_err(|e| anyhow!("scan: {e}"))?;
    let scan_id = handle.scan_id;
    let mut rx = handle.progress;
    let worker = handle.worker;

    let stderr = std::io::stderr();
    let mut stderr = stderr.lock();
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();

    let mut files = 0u64;
    let mut errors = 0u64;
    let mut bytes = 0u64;
    let mut last_completed: Option<ScanProgress> = None;

    loop {
        match rx.recv().await {
            Ok(event) => match &event {
                ScanProgress::Started { .. } => {
                    // In Text mode the start banner is informational and goes
                    // to stderr; in JSON mode every event including Started
                    // belongs on stdout so the full stream is one valid NDJSON
                    // document.
                    match format {
                        Format::Text => {
                            writeln!(stderr, "scanning {}", path.display())?;
                        }
                        Format::Json => {
                            writeln!(stdout, "{}", serde_json::to_string(&event)?)?;
                        }
                    }
                }
                ScanProgress::File { size, .. } => {
                    files += 1;
                    bytes += *size;
                    if matches!(format, Format::Json) {
                        writeln!(stdout, "{}", serde_json::to_string(&event)?)?;
                    }
                }
                ScanProgress::Finding {
                    path,
                    rule_id,
                    severity,
                    ..
                } => match format {
                    Format::Text => {
                        writeln!(
                            stderr,
                            "  ! finding {} [{severity}] {rule_id}",
                            path.display()
                        )?;
                    }
                    Format::Json => writeln!(stdout, "{}", serde_json::to_string(&event)?)?,
                },
                ScanProgress::Error { path, message } => {
                    errors += 1;
                    match format {
                        Format::Text => {
                            writeln!(stderr, "  ! error {}: {message}", path.display())?
                        }
                        Format::Json => writeln!(stdout, "{}", serde_json::to_string(&event)?)?,
                    }
                }
                ScanProgress::PartialHash { .. } => {
                    // CLI ignores live partial-hash events (TASK-134) — the
                    // text-mode line would flicker too fast and the JSON
                    // mode user can opt into them by piping through
                    // `--format json`.
                    if matches!(format, Format::Json) {
                        writeln!(stdout, "{}", serde_json::to_string(&event)?)?;
                    }
                }
                ScanProgress::Completed { .. }
                | ScanProgress::Failed { .. }
                | ScanProgress::Paused { .. } => {
                    last_completed = Some(event);
                    break;
                }
            },
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                writeln!(stderr, "  ! progress lagged by {n} events")?;
            }
        }
    }

    let _ = worker.await;

    match (format, last_completed) {
        (
            Format::Text,
            Some(ScanProgress::Completed {
                files_visited,
                files_hashed,
                bytes_visited,
                duration_ms,
                ..
            }),
        ) => {
            // Prefer the engine's authoritative counters from the Completed
            // payload over our local accumulators (which only count files the
            // hasher succeeded on, missing the WalkEvent::Error contributors).
            writeln!(
                stdout,
                "scan {scan_id}: {files_visited} files visited, {files_hashed} hashed, \
                 {bytes_visited} bytes, {errors} errors, {duration_ms} ms"
            )?;
        }
        (Format::Text, Some(ScanProgress::Failed { message, .. })) => {
            writeln!(stderr, "scan {scan_id} failed: {message}")?;
        }
        (Format::Json, Some(ev)) => {
            writeln!(stdout, "{}", serde_json::to_string(&ev)?)?;
        }
        _ => {
            // Walked-no-completion fallback: report what we observed locally.
            writeln!(
                stderr,
                "scan {scan_id}: ended without completion event \
                 ({files} files, {bytes} bytes, {errors} errors)"
            )?;
        }
    }

    Ok(())
}
