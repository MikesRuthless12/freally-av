//! TASK-202 — Differential rescan since last clean.
//!
//! Caches a 4-tuple `(mtime, size, ctime, inode)` per file that emitted
//! a clean outcome from a previous scan. When the walker re-encounters
//! that path, [`should_emit`] compares the live stat against the cached
//! tuple. A match returns `false`: the engine short-circuits the hash +
//! detect pipeline and credits the file as clean via `source=diff-
//! cache`. Any tuple change returns `true` and the file flows through
//! the normal scan path.
//!
//! Distinct from `crate::detect::verdict_cache` (caches every verdict,
//! keyed on `(path, mtime, size)`): this table caches CLEAN files only,
//! uses the wider 4-tuple so a backup-restored file (mtime preserved,
//! inode + ctime changed) still gets re-hashed, and is wiped on every
//! feed-epoch advance so a new blocklist invalidates yesterday's clean
//! verdicts.

use std::fs::Metadata;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use crate::db::DbError;

/// Live filesystem stat captured before the diff-cache lookup. Fields
/// the platform can't expose default to 0 — the comparison still works,
/// it just becomes a 2- or 3-tuple instead of the full 4-tuple on those
/// volumes (mainly Windows FATFS / network mounts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveStat {
    pub size: u64,
    pub mtime: i64,
    pub ctime: i64,
    pub inode: u64,
}

impl LiveStat {
    /// Build a LiveStat from a `std::fs::Metadata`. Per-platform shims
    /// pull ctime + inode via the OS extension traits; absent data
    /// degrades to 0.
    pub fn from_metadata(meta: &Metadata) -> Self {
        let size = meta.len();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let (ctime, inode) = platform_ctime_inode(meta);
        Self {
            size,
            mtime,
            ctime,
            inode,
        }
    }
}

#[cfg(unix)]
fn platform_ctime_inode(meta: &Metadata) -> (i64, u64) {
    use std::os::unix::fs::MetadataExt;
    (meta.ctime(), meta.ino())
}

#[cfg(windows)]
fn platform_ctime_inode(meta: &Metadata) -> (i64, u64) {
    use std::os::windows::fs::MetadataExt;
    // FILETIME is 100-ns intervals since 1601-01-01; convert to unix
    // seconds for parity with the unix path.
    const FT_TO_UNIX_EPOCH_NS: u64 = 11_644_473_600 * 10_000_000;
    let creation_ft = meta.creation_time();
    let ctime = if creation_ft >= FT_TO_UNIX_EPOCH_NS {
        ((creation_ft - FT_TO_UNIX_EPOCH_NS) / 10_000_000) as i64
    } else {
        0
    };
    // `Metadata::file_index()` is nightly-only (windows_by_handle). The
    // 3-tuple (size, mtime, ctime) is sufficient to detect every change
    // a benign edit produces; we'd only lose discrimination against an
    // inode swap that preserves the other three, which is vanishingly
    // rare on Windows. Set inode = 0 so the comparison stays uniform
    // across platforms; if a future stable API exposes the NTFS file
    // index, swap it in here.
    let inode = 0u64;
    (ctime, inode)
}

#[cfg(not(any(unix, windows)))]
fn platform_ctime_inode(_meta: &Metadata) -> (i64, u64) {
    (0, 0)
}

/// Cached clean-state row for a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileState {
    pub path: String,
    pub size: u64,
    pub mtime: i64,
    pub ctime: i64,
    pub inode: u64,
    pub last_clean_scan_id: i64,
}

/// Returns `true` when the file should be emitted to the hash + detect
/// pipeline (cache miss OR tuple changed). Returns `false` when the
/// cache is hit and the live stat matches — in that case the caller
/// short-circuits with a `source=diff-cache` clean shortcut.
pub fn should_emit(conn: &Connection, path: &Path, live: &LiveStat) -> bool {
    match lookup(conn, path) {
        Ok(Some(cached)) => {
            cached.size != live.size
                || cached.mtime != live.mtime
                || cached.ctime != live.ctime
                || cached.inode != live.inode
        }
        // Miss or DB error → emit (correctness over perf).
        _ => true,
    }
}

/// Read the cached row for `path`, if any. Returns `Ok(None)` on
/// cache miss.
pub fn lookup(conn: &Connection, path: &Path) -> Result<Option<FileState>, DbError> {
    let path_str = path.to_string_lossy();
    let row = conn
        .query_row(
            "SELECT path, size, mtime, ctime, inode, last_clean_scan_id
             FROM file_state
             WHERE path = ?1",
            [path_str.as_ref()],
            |row| {
                Ok(FileState {
                    path: row.get(0)?,
                    size: row.get::<_, i64>(1)? as u64,
                    mtime: row.get(2)?,
                    ctime: row.get(3)?,
                    inode: row.get::<_, i64>(4)? as u64,
                    last_clean_scan_id: row.get(5)?,
                })
            },
        )
        .optional()?;
    Ok(row)
}

/// Record this path as clean as of `scan_id`. INSERT-OR-REPLACE on
/// `path` PK so a subsequent clean run overwrites the prior row.
/// Callers must ONLY call this when the pipeline produced no
/// non-clean outcome for the file (the prompt's "clean rows only"
/// constraint).
pub fn record_clean(
    conn: &Connection,
    path: &Path,
    live: &LiveStat,
    scan_id: i64,
) -> Result<(), DbError> {
    let path_str = path.to_string_lossy();
    conn.execute(
        "INSERT INTO file_state (path, size, mtime, ctime, inode, last_clean_scan_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(path) DO UPDATE SET
             size                = excluded.size,
             mtime               = excluded.mtime,
             ctime               = excluded.ctime,
             inode               = excluded.inode,
             last_clean_scan_id  = excluded.last_clean_scan_id",
        params![
            path_str.as_ref(),
            live.size as i64,
            live.mtime,
            live.ctime,
            live.inode as i64,
            scan_id,
        ],
    )?;
    Ok(())
}

/// Invalidate the entire diff cache when the feed_epoch advances. The
/// caller passes the current feed_epoch; the table tracks the epoch
/// last used by `record_clean`. Mismatch → wipe `file_state` and
/// update the tracker. Returns the number of rows deleted.
pub fn invalidate_on_epoch_change(conn: &Connection, current_epoch: i64) -> Result<usize, DbError> {
    let stored: Option<i64> = conn
        .query_row(
            "SELECT current_epoch FROM feed_epoch_state WHERE rowid = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match stored {
        Some(e) if e == current_epoch => Ok(0),
        _ => {
            let deleted = conn.execute("DELETE FROM file_state", [])?;
            conn.execute(
                "INSERT INTO feed_epoch_state (rowid, current_epoch) VALUES (1, ?1)
                 ON CONFLICT(rowid) DO UPDATE SET current_epoch = excluded.current_epoch",
                [current_epoch],
            )?;
            Ok(deleted)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::history::{ScanTrigger, create_scan};
    use std::path::PathBuf;

    fn dummy_scan(conn: &Connection) -> i64 {
        create_scan(
            conn,
            1_700_000_000,
            ScanTrigger::Manual,
            "path",
            "[\"/tmp\"]",
            "[]",
            "0.0.0-test",
            "{}",
        )
        .unwrap()
    }

    fn ls(size: u64, mtime: i64, ctime: i64, inode: u64) -> LiveStat {
        LiveStat {
            size,
            mtime,
            ctime,
            inode,
        }
    }

    #[test]
    fn miss_emits_true() {
        let conn = open_in_memory().unwrap();
        let p = PathBuf::from("/tmp/x");
        assert!(should_emit(&conn, &p, &ls(10, 100, 50, 7)));
    }

    #[test]
    fn matching_tuple_short_circuits() {
        let conn = open_in_memory().unwrap();
        let sid = dummy_scan(&conn);
        let p = PathBuf::from("/tmp/x");
        let live = ls(10, 100, 50, 7);
        record_clean(&conn, &p, &live, sid).unwrap();
        assert!(!should_emit(&conn, &p, &live));
    }

    #[test]
    fn any_field_change_re_emits() {
        let conn = open_in_memory().unwrap();
        let sid = dummy_scan(&conn);
        let p = PathBuf::from("/tmp/x");
        let cached = ls(10, 100, 50, 7);
        record_clean(&conn, &p, &cached, sid).unwrap();
        // Each field independently flipped should re-emit.
        assert!(should_emit(&conn, &p, &ls(11, 100, 50, 7)));
        assert!(should_emit(&conn, &p, &ls(10, 101, 50, 7)));
        assert!(should_emit(&conn, &p, &ls(10, 100, 51, 7)));
        assert!(should_emit(&conn, &p, &ls(10, 100, 50, 8)));
    }

    #[test]
    fn record_clean_upserts() {
        let conn = open_in_memory().unwrap();
        let sid = dummy_scan(&conn);
        let p = PathBuf::from("/tmp/x");
        record_clean(&conn, &p, &ls(10, 100, 50, 7), sid).unwrap();
        record_clean(&conn, &p, &ls(20, 200, 60, 8), sid).unwrap();
        let cached = lookup(&conn, &p).unwrap().unwrap();
        assert_eq!(cached.size, 20);
        assert_eq!(cached.mtime, 200);
        assert_eq!(cached.ctime, 60);
        assert_eq!(cached.inode, 8);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM file_state", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn epoch_advance_wipes_cache() {
        let conn = open_in_memory().unwrap();
        let sid = dummy_scan(&conn);
        for i in 0..5 {
            let p = PathBuf::from(format!("/tmp/f{i}"));
            record_clean(&conn, &p, &ls(1, 1, 1, i), sid).unwrap();
        }
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM file_state", [], |row| row.get(0))
            .unwrap();
        assert_eq!(n, 5);
        // First epoch sets the marker without deleting.
        let deleted = invalidate_on_epoch_change(&conn, 100).unwrap();
        assert_eq!(deleted, 5, "wipe on first epoch set (no prior marker)");
        // Re-populate then re-check: same epoch → no wipe.
        for i in 0..3 {
            let p = PathBuf::from(format!("/tmp/g{i}"));
            record_clean(&conn, &p, &ls(1, 1, 1, i), sid).unwrap();
        }
        assert_eq!(invalidate_on_epoch_change(&conn, 100).unwrap(), 0);
        // New epoch → wipe.
        assert_eq!(invalidate_on_epoch_change(&conn, 101).unwrap(), 3);
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM file_state", [], |row| row.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn live_stat_from_metadata_uses_platform_extensions() {
        // Smoke: a temp file's LiveStat should expose non-zero size +
        // mtime; ctime + inode are platform-conditional but at least
        // size + mtime must be populated.
        let td = tempfile::tempdir().unwrap();
        let p = td.path().join("a.txt");
        std::fs::write(&p, b"hello").unwrap();
        let meta = std::fs::metadata(&p).unwrap();
        let live = LiveStat::from_metadata(&meta);
        assert_eq!(live.size, 5);
        assert!(live.mtime > 1_000_000_000, "expected post-epoch mtime");
    }
}
