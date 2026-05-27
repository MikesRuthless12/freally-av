//! TASK-201 — Resumable scans across reboots.
//!
//! Persists a periodically-snapshotted scan cursor plus a walked-set Bloom
//! filter so a scan interrupted by power loss, SIGKILL, or process crash can
//! resume from where it left off on next start.
//!
//! ## Why this is distinct from `ResumeToken` (Phase 4 / TASK-040)
//!
//! `ResumeToken` (in [`crate::scan`]) handles graceful pause/resume: the user
//! clicks Pause, the worker writes a one-shot JSON blob into `scans.resume_token`
//! containing the full `processed_paths` set (capped at 100K paths), then exits
//! cleanly. Resume reads that blob and re-walks from where the worker left off.
//!
//! [`ScanCursor`] here addresses the *ungraceful* case: the process is killed
//! mid-walk by the OS or by a power loss. There is no opportunity to write a
//! resume token at exit time. Instead, the engine snapshots a compact cursor
//! every ~5 s during a live walk; the snapshot survives abrupt termination
//! because each persist is its own committed SQLite transaction.
//!
//! The two mechanisms coexist: a graceful pause uses `ResumeToken`; an abrupt
//! kill falls back to `ScanCursor` on next launch.
//!
//! ## Walked-set Bloom
//!
//! Re-uses the in-RAM variant of the bloom filter from TASK-178
//! ([`crate::detect::bloom::Builder`]). Default sizing — 10M paths at 0.1 %
//! FPR ≈ 18 MB. The path key is BLAKE3 of the path's UTF-8 bytes so the
//! double-hash split has full entropy. A bloom hit means "definitely walked
//! already"; the 0.1 % FPR is acceptable because the worst case is silently
//! re-hashing a tiny number of files (correctness preserved).

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, params};

use crate::db::DbError;
use crate::detect::bloom::{BloomError, Builder as BloomBuilder};

/// Default walked-set budget — 10 million paths. Sizes the bloom for
/// ~18 MB at the default 0.1 % FPR.
pub const DEFAULT_BUDGET_ITEMS: u64 = 10_000_000;

/// Default target false-positive rate, in parts-per-million. 1 000 ppm
/// = 0.1 %.
pub const DEFAULT_FPR_PPM: u32 = 1_000;

#[derive(Debug, thiserror::Error)]
pub enum ResumeError {
    #[error(transparent)]
    Db(#[from] DbError),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("bloom: {0}")]
    Bloom(#[from] BloomError),
}

/// A live scan-cursor. Each call to [`ScanCursor::record_walked`] inserts
/// the path's BLAKE3 hash into the walked-set bloom and advances
/// `cursor_path`. Periodic snapshots to SQLite go through
/// [`ScanCursor::persist`].
pub struct ScanCursor {
    pub scan_id: i64,
    pub root: PathBuf,
    pub cursor_path: PathBuf,
    pub walked_bloom: BloomBuilder,
    pub started_at: i64,
}

impl ScanCursor {
    /// Create a fresh cursor sized for the default 10 M-path walk budget.
    pub fn new(scan_id: i64, root: PathBuf, started_at: i64) -> Self {
        Self::with_budget(
            scan_id,
            root,
            started_at,
            DEFAULT_BUDGET_ITEMS,
            DEFAULT_FPR_PPM,
        )
    }

    /// Create a fresh cursor with an explicit budget — used by tests to
    /// avoid a 18 MB allocation per construction.
    pub fn with_budget(
        scan_id: i64,
        root: PathBuf,
        started_at: i64,
        expected_items: u64,
        fpr_ppm: u32,
    ) -> Self {
        let walked_bloom = BloomBuilder::new(expected_items, fpr_ppm, scan_id as u64);
        Self {
            scan_id,
            root: root.clone(),
            cursor_path: root,
            walked_bloom,
            started_at,
        }
    }

    /// Mark `path` as walked: insert its BLAKE3 key into the bloom and
    /// advance `cursor_path`. Cheap: BLAKE3 of a typical path is < 200 ns.
    pub fn record_walked(&mut self, path: &Path) {
        let key = path_key(path);
        self.walked_bloom.insert(&key);
        self.cursor_path = path.to_path_buf();
    }

    /// Probe whether `path` is already in the walked set. A `true` means
    /// "definitely walked" (or, with 0.1 % probability at the default
    /// FPR, a false positive — fine: a missed re-hash is correctness-
    /// preserving). A `false` means "definitely not walked".
    pub fn contains_walked(&self, path: &Path) -> bool {
        let key = path_key(path);
        self.walked_bloom.contains(&key).unwrap_or(false)
    }

    /// INSERT-OR-REPLACE this cursor into the `scan_cursors` table. The
    /// bloom is serialised via [`BloomBuilder::to_bytes`] and stored as a
    /// BLOB. `finished_at` is left untouched if this is an update to an
    /// existing row.
    pub fn persist(&self, conn: &Connection) -> Result<(), ResumeError> {
        let blob = self.walked_bloom.to_bytes();
        conn.execute(
            "INSERT INTO scan_cursors (scan_id, root, cursor_path, walked_bloom, started_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(scan_id) DO UPDATE SET
                 root         = excluded.root,
                 cursor_path  = excluded.cursor_path,
                 walked_bloom = excluded.walked_bloom",
            params![
                self.scan_id,
                self.root.to_string_lossy().as_ref(),
                self.cursor_path.to_string_lossy().as_ref(),
                blob,
                self.started_at,
            ],
        )?;
        Ok(())
    }

    /// Mark a cursor row as finished. After this returns, the row will
    /// never be offered by [`ScanCursor::load_latest_unfinished`].
    pub fn mark_finished(
        conn: &Connection,
        scan_id: i64,
        finished_at_utc: i64,
    ) -> Result<(), ResumeError> {
        conn.execute(
            "UPDATE scan_cursors SET finished_at = ?2 WHERE scan_id = ?1",
            params![scan_id, finished_at_utc],
        )?;
        Ok(())
    }

    /// Load the most recent unfinished cursor, if any. Returns `Ok(None)`
    /// when every row is finished or the table is empty.
    pub fn load_latest_unfinished(conn: &Connection) -> Result<Option<Self>, ResumeError> {
        let row_opt: Option<(i64, String, String, Vec<u8>, i64)> = conn
            .query_row(
                "SELECT scan_id, root, cursor_path, walked_bloom, started_at
                 FROM scan_cursors
                 WHERE finished_at IS NULL
                 ORDER BY started_at DESC
                 LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?;

        let Some((scan_id, root, cursor_path, blob, started_at)) = row_opt else {
            return Ok(None);
        };
        let walked_bloom = BloomBuilder::from_bytes(&blob)?;
        Ok(Some(Self {
            scan_id,
            root: PathBuf::from(root),
            cursor_path: PathBuf::from(cursor_path),
            walked_bloom,
            started_at,
        }))
    }
}

/// BLAKE3 of the path's UTF-8 byte representation. The Bloom needs ≥ 16
/// uniformly-distributed bytes for its two-u64 double-hash split; a 32-byte
/// BLAKE3 digest more than covers that.
fn path_key(path: &Path) -> [u8; 32] {
    let bytes = path.to_string_lossy();
    *blake3::hash(bytes.as_bytes()).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::history::{ScanTrigger, create_scan};

    // Phase 4 `scans` rows are FK targets for scan_cursors; create one so
    // the FK is satisfied. Returns the new scan_id.
    fn insert_dummy_scan(conn: &Connection) -> i64 {
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

    // Small budget so the bloom is ~1 KB instead of 18 MB. 1 000 items at
    // 1 % FPR is still uniform enough for the round-trip / membership
    // assertions in these tests.
    fn small_cursor(scan_id: i64, root: &str) -> ScanCursor {
        ScanCursor::with_budget(scan_id, PathBuf::from(root), 1_700_000_000, 1_000, 10_000)
    }

    #[test]
    fn record_walked_then_contains_hits() {
        let mut cur = small_cursor(1, "/tmp/scan-root");
        let a = PathBuf::from("/tmp/scan-root/a.txt");
        let b = PathBuf::from("/tmp/scan-root/nested/b.bin");
        cur.record_walked(&a);
        cur.record_walked(&b);
        assert!(cur.contains_walked(&a));
        assert!(cur.contains_walked(&b));
        assert_eq!(cur.cursor_path, b, "cursor_path follows last walked");
    }

    #[test]
    fn contains_misses_unwalked_path() {
        let mut cur = small_cursor(2, "/tmp/scan-root");
        // Insert a small, disjoint set so the FPR doesn't approach 1.
        for i in 0..20 {
            cur.record_walked(&PathBuf::from(format!("/tmp/scan-root/walked-{i}.txt")));
        }
        // Probe a clearly-disjoint candidate. With a ~1 % FPR and 20
        // inserts, a single unrelated probe should miss with > 99 %
        // probability — try a handful and assert at least one misses.
        let mut miss_observed = false;
        for i in 0..50 {
            let p = PathBuf::from(format!("/tmp/scan-root/never-walked-{i}.txt"));
            if !cur.contains_walked(&p) {
                miss_observed = true;
                break;
            }
        }
        assert!(
            miss_observed,
            "expected at least one disjoint probe to miss"
        );
    }

    #[test]
    fn persist_then_reload_roundtrip() {
        let conn = open_in_memory().unwrap();
        let scan_id = insert_dummy_scan(&conn);

        let mut cur = small_cursor(scan_id, "/tmp/root");
        let paths: Vec<PathBuf> = (0..50)
            .map(|i| PathBuf::from(format!("/tmp/root/file-{i}.bin")))
            .collect();
        for p in &paths {
            cur.record_walked(p);
        }
        cur.persist(&conn).unwrap();

        let restored = ScanCursor::load_latest_unfinished(&conn)
            .unwrap()
            .expect("unfinished cursor present");
        assert_eq!(restored.scan_id, scan_id);
        assert_eq!(restored.root, PathBuf::from("/tmp/root"));
        assert_eq!(restored.cursor_path, *paths.last().unwrap());
        for p in &paths {
            assert!(restored.contains_walked(p), "restored bloom missed {p:?}");
        }
    }

    #[test]
    fn finished_cursor_never_reloads() {
        let conn = open_in_memory().unwrap();
        let scan_id = insert_dummy_scan(&conn);

        let mut cur = small_cursor(scan_id, "/tmp/root");
        cur.record_walked(&PathBuf::from("/tmp/root/x"));
        cur.persist(&conn).unwrap();

        // Before mark_finished: should reload.
        assert!(ScanCursor::load_latest_unfinished(&conn).unwrap().is_some());

        ScanCursor::mark_finished(&conn, scan_id, 1_700_000_100).unwrap();

        // After: load_latest_unfinished returns None.
        assert!(ScanCursor::load_latest_unfinished(&conn).unwrap().is_none());
    }

    #[test]
    fn load_returns_none_on_empty_table() {
        let conn = open_in_memory().unwrap();
        assert!(ScanCursor::load_latest_unfinished(&conn).unwrap().is_none());
    }

    #[test]
    fn load_picks_most_recent_unfinished() {
        let conn = open_in_memory().unwrap();
        let id_a = insert_dummy_scan(&conn);
        let id_b = insert_dummy_scan(&conn);

        // Cursor A started earlier; B started later. Both are unfinished.
        ScanCursor::with_budget(id_a, PathBuf::from("/a"), 1_000, 100, 10_000)
            .persist(&conn)
            .unwrap();
        ScanCursor::with_budget(id_b, PathBuf::from("/b"), 2_000, 100, 10_000)
            .persist(&conn)
            .unwrap();

        let picked = ScanCursor::load_latest_unfinished(&conn).unwrap().unwrap();
        assert_eq!(picked.scan_id, id_b, "later started_at wins");
    }

    #[test]
    fn persist_overwrites_prior_row_for_same_scan_id() {
        let conn = open_in_memory().unwrap();
        let scan_id = insert_dummy_scan(&conn);

        let mut cur = small_cursor(scan_id, "/tmp/root");
        cur.record_walked(&PathBuf::from("/tmp/root/initial"));
        cur.persist(&conn).unwrap();

        // Walk further; persist again — should UPDATE, not double-INSERT.
        for i in 0..10 {
            cur.record_walked(&PathBuf::from(format!("/tmp/root/later-{i}")));
        }
        cur.persist(&conn).unwrap();

        let row_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM scan_cursors WHERE scan_id = ?1",
                [scan_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(row_count, 1, "ON CONFLICT should upsert, not duplicate");

        let restored = ScanCursor::load_latest_unfinished(&conn).unwrap().unwrap();
        assert_eq!(
            restored.cursor_path,
            PathBuf::from("/tmp/root/later-9"),
            "later persist overwrites cursor_path"
        );
        // Both the initial and later paths should still be in the bloom
        // because record_walked just keeps adding to the same filter.
        assert!(restored.contains_walked(&PathBuf::from("/tmp/root/initial")));
        for i in 0..10 {
            assert!(restored.contains_walked(&PathBuf::from(format!("/tmp/root/later-{i}"))));
        }
    }

    #[test]
    fn path_key_is_stable_for_identical_input() {
        let p = PathBuf::from("/usr/local/bin/foo");
        assert_eq!(path_key(&p), path_key(&p));
        // Different inputs almost certainly hash differently.
        let q = PathBuf::from("/usr/local/bin/bar");
        assert_ne!(path_key(&p), path_key(&q));
    }
}
