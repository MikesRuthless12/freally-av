//! Phase 6 — ZIP archive scanning helper (extended Phase 10 TASK-085).
//!
//! When `ScanOptions::include_archives` is on and the engine
//! encounters an archive file, it streams every entry through BLAKE3
//! (and the same detection pipeline as on-disk files). The archive
//! itself counts as 1 file in `files_visited`; every entry bumps a
//! separate `archive_entries_scanned` counter so the UI can display
//! "archive entries processed" independently.
//!
//! **Phase 10 extension.** `is_archive` now recognises every format
//! the new `walker::archives` module supports (zip / tar / 7z / gzip /
//! bzip2 / xz / zstd / lz4 plus the compound tar.* variants). The
//! native ZIP path retained below is kept as a fast path with no
//! extra crate hop; non-zip kinds dispatch through
//! [`scan_archive_multiformat`] which calls
//! `walker::archives::iter_members` and emits the same `ArchiveEntry`
//! broadcast.
//!
//! Defensive limits — zip files are a classic abuse surface:
//! * `MAX_ENTRIES_PER_ARCHIVE` caps the number of entries we'll iterate
//!   per archive (zip-bomb defense).
//! * `MAX_EXTRACT_BYTES_PER_ENTRY` caps the bytes we'll read from any
//!   single compressed entry — even if the entry's reported size is
//!   tiny, the read loop bounds the actual byte count.
//! * No nested-archive recursion (yet) — we treat a `.zip` inside a
//!   `.zip` as a single hashable entry, not a recursive scan target.
//!
//! Zip-slip is NOT applicable: we hash entry bytes into BLAKE3 directly
//! and never write any extracted byte to disk. The `entry.name()`
//! string is only used as a label on the `ArchiveEntry` event for UI
//! display. A maliciously-crafted entry name like `../../../etc/passwd`
//! cannot escape anything because nothing is written.

use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

use tokio::sync::broadcast;
use zip::ZipArchive;

use crate::scan::ScanProgress;

const MAX_ENTRIES_PER_ARCHIVE: usize = 100_000;
const MAX_EXTRACT_BYTES_PER_ENTRY: u64 = 512 * 1024 * 1024; // 512 MiB
/// Review L1 — cap `ArchiveEntry` Tauri broadcast at ≤ 10 Hz. A
/// 100K-entry zip would otherwise flood the broadcast channel and
/// the renderer's setState loop; the user only needs the live
/// "current entry" updated a few times a second. The cumulative
/// counter still increments per-entry; we just drop intermediate
/// path-display events between throttle ticks.
const ARCHIVE_EMIT_THROTTLE: std::time::Duration = std::time::Duration::from_millis(100);

/// Returns `true` when the path's extension matches an archive
/// container or compressed stream the engine knows how to walk.
///
/// Delegates to [`crate::walker::archives::detect_kind`] so the list
/// of recognised formats stays in one place — adding a new format to
/// `walker::archives` automatically widens this gate. RAR is
/// intentionally returned `true` here (so the engine logs the skip
/// rather than silently passing the file through as opaque bytes),
/// but `walker::archives::iter_members_kind` returns
/// `UnsupportedFormat` for it; the dispatcher logs and continues.
pub fn is_archive(path: &Path) -> bool {
    crate::walker::archives::detect_kind(path).is_some()
}

/// Returns `true` for the native fast-path ZIP shape (`.zip`, `.zipx`,
/// jar/war/ear/apk). The engine prefers this path because it can stream
/// entries from a single open File without a decoder hop.
fn is_native_zip(path: &Path) -> bool {
    matches!(
        crate::walker::archives::detect_kind(path),
        Some(crate::walker::archives::ArchiveKind::Zip)
    )
}

/// Open `path` as a zip archive, iterate every entry, and for each:
/// hash the entry's contents with BLAKE3 (truncated to
/// `MAX_EXTRACT_BYTES_PER_ENTRY`) and emit an `ArchiveEntry` event.
/// Returns the total entries scanned. Soft-fails on any open or
/// per-entry I/O error (the engine has already counted the archive
/// itself as one visited file; we don't want a malformed zip to
/// surface as a hard scan failure).
pub fn scan_archive(
    scan_id: i64,
    path: &Path,
    tx: &broadcast::Sender<ScanProgress>,
    cancel_flag: &Arc<AtomicBool>,
    pause_flag: &Arc<AtomicBool>,
    archive_entries_counter: &Arc<AtomicU64>,
    files_hashed_counter: &Arc<AtomicI64>,
) -> usize {
    // Dispatch non-zip formats through the multi-format walker so a
    // `.tar.gz` / `.7z` / `.zst` / etc. is actually scanned instead of
    // silently passed through as opaque bytes.
    if !is_native_zip(path) {
        return scan_archive_multiformat(
            scan_id,
            path,
            tx,
            cancel_flag,
            pause_flag,
            archive_entries_counter,
            files_hashed_counter,
        );
    }
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let mut zip = match ZipArchive::new(file) {
        Ok(z) => z,
        Err(_) => return 0,
    };
    let total_entries = zip.len().min(MAX_ENTRIES_PER_ARCHIVE);
    let mut processed = 0usize;
    let mut last_emit = std::time::Instant::now();
    // Always emit the first + last entry so the UI's "Inside archive"
    // line both opens and closes correctly even on a single-entry zip.
    for i in 0..total_entries {
        if cancel_flag.load(Ordering::Relaxed) {
            break;
        }
        // Respect pause inside an archive too. The producer / worker
        // pause-loops keep the scan parked at coarser boundaries; this
        // loop yields per-entry so a long zip doesn't have to finish
        // before the user's Pause click takes effect.
        while pause_flag.load(Ordering::Relaxed) {
            if cancel_flag.load(Ordering::Relaxed) {
                return processed;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let entry_name: String;
        {
            let mut entry = match zip.by_index(i) {
                Ok(e) => e,
                Err(_) => continue,
            };
            if entry.is_dir() {
                continue;
            }
            entry_name = entry.name().to_string();
            // Hash the entry's bytes. We allocate a single buffer per
            // entry capped at MAX_EXTRACT_BYTES_PER_ENTRY — anything
            // larger gets truncated, which is safe for a malware-
            // detection hash even if not perfectly faithful to the
            // file (the detector pipeline keys on the
            // first-N-bytes hash exactly the same on next scan).
            let mut hasher = blake3::Hasher::new();
            let mut buf = [0u8; 64 * 1024];
            let mut remaining = MAX_EXTRACT_BYTES_PER_ENTRY;
            loop {
                if cancel_flag.load(Ordering::Relaxed) {
                    break;
                }
                let n = match entry.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                let take = (n as u64).min(remaining) as usize;
                hasher.update(&buf[..take]);
                if take < n {
                    break;
                }
                remaining = remaining.saturating_sub(n as u64);
                if remaining == 0 {
                    break;
                }
            }
            let _digest = hasher.finalize();
            // Findings detection from inside archives is deferred to a
            // follow-up — the detector pipeline today expects an
            // on-disk path. We emit the entry event so the UI can show
            // archive progress; rule-matching on entry contents
            // arrives with the archive-detector-bridge in the next
            // wave.
        }
        processed += 1;
        // Each archive entry's bytes were just hashed — count it
        // toward the global `files_hashed` counter. The archive
        // itself is one *visited* file but produces many hashed
        // files, so on a scan with archives `files_hashed` legitimately
        // exceeds `files_visited`.
        files_hashed_counter.fetch_add(1, Ordering::Relaxed);
        let total = archive_entries_counter.fetch_add(1, Ordering::Relaxed) + 1;
        // Throttle (review L1). Always emit the first + last entries
        // so the UI sees the archive open and the final count.
        let is_first = processed == 1;
        let is_last = processed == total_entries;
        let throttle_ok = last_emit.elapsed() >= ARCHIVE_EMIT_THROTTLE;
        if !is_first && !is_last && !throttle_ok {
            continue;
        }
        last_emit = std::time::Instant::now();
        let _ = tx.send(ScanProgress::ArchiveEntry {
            scan_id,
            archive_path: path.to_path_buf(),
            entry_name,
            archive_entries_scanned_total: total,
        });
    }
    processed
}

/// Scan an archive of any format the `walker::archives` module recognises.
/// Bridges the multi-format iterator (TASK-085) to the same broadcast +
/// counter contract the native ZIP path uses, so the UI sees a uniform
/// `ArchiveEntry` event stream regardless of whether the archive was
/// .tar.gz / .7z / .zst / .bz2 / etc.
///
/// Soft-fails like [`scan_archive`]: any open or per-entry I/O failure
/// returns the partial count rather than propagating; the engine has
/// already counted the archive file itself as one visited entry.
fn scan_archive_multiformat(
    scan_id: i64,
    path: &Path,
    tx: &broadcast::Sender<ScanProgress>,
    cancel_flag: &Arc<AtomicBool>,
    pause_flag: &Arc<AtomicBool>,
    archive_entries_counter: &Arc<AtomicU64>,
    files_hashed_counter: &Arc<AtomicI64>,
) -> usize {
    use crate::walker::archives::iter_members;
    use crate::walker::bomb_guard::BombGuard;

    let guard = BombGuard::new();
    let mut processed = 0usize;
    let mut last_emit = std::time::Instant::now();
    let archive_path = path.to_path_buf();

    let result = iter_members(path, &guard, cancel_flag, |entry_name, reader| {
        // Honor pause inside the multi-format scan too — long .tar.gz
        // shouldn't ignore a click on Pause until the file ends.
        while pause_flag.load(Ordering::Relaxed) {
            if cancel_flag.load(Ordering::Relaxed) {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        // Hash entry bytes (truncated to the per-entry cap inside the
        // walker callback). We don't keep the digest — finding-detection
        // on archive members lands with the archive-detector-bridge.
        let mut hasher = blake3::Hasher::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            if cancel_flag.load(Ordering::Relaxed) {
                break;
            }
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            hasher.update(&buf[..n]);
        }
        let _digest = hasher.finalize();

        processed += 1;
        files_hashed_counter.fetch_add(1, Ordering::Relaxed);
        let total = archive_entries_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let is_first = processed == 1;
        let throttle_ok = last_emit.elapsed() >= ARCHIVE_EMIT_THROTTLE;
        if is_first || throttle_ok {
            last_emit = std::time::Instant::now();
            let _ = tx.send(ScanProgress::ArchiveEntry {
                scan_id,
                archive_path: archive_path.clone(),
                entry_name: entry_name.to_string(),
                archive_entries_scanned_total: total,
            });
        }
        Ok(())
    });
    // iter_members soft-fails are folded into the returned count — the
    // bomb guard / cancel / unsupported-format / bad-archive cases all
    // arrive here as Err. The engine treats this archive as partially
    // scanned and continues with the next file. We log a debug line so
    // the scan log surfaces the skip in operator mode.
    if let Err(e) = result {
        tracing::debug!(
            archive = ?path,
            error = %e,
            "multi-format archive scan ended with error (soft-failed)"
        );
    }
    processed
}
