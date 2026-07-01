//! Scan diffing (TASK-149, FR-150, Phase 10).
//!
//! Surfaces what changed between two points in time. The first concrete
//! use today is **persistence diff**: list every autostart entry that
//! arrived since a reference timestamp + every entry that disappeared.
//! UI's Diff modal renders the result.
//!
//! ## Design
//!
//! Persistence entries in `persistence_entries` carry `first_seen_at`
//! and `last_seen_at` columns (TASK-144's migration `0011`). The diff
//! is computed from those columns directly — no per-scan snapshot
//! table is needed:
//!
//!   * **Added between T_prev and T_now**: rows where
//!     `first_seen_at >= T_prev`. (First-seen times monotonically
//!     advance, so anything first-seen-after-T_prev is "new since the
//!     previous reference.")
//!   * **Removed between T_prev and T_now**: rows where
//!     `last_seen_at < T_now - GRACE` AND `last_seen_at >= T_prev`.
//!     The upper bound (`< T_now - GRACE`) prevents an in-progress
//!     scan (which hasn't bumped `last_seen_at` on every row yet)
//!     from falsely flagging persistent entries as removed. The lower
//!     bound (`>= T_prev`) prevents the rolling history of every-row-
//!     ever-deleted from polluting today's diff — without it, a
//!     LaunchAgent uninstalled five years ago would appear on every
//!     diff call forever.
//!
//! The grace window is the engine's persistence-scan interval. Two
//! minutes is more than the typical < 30 s persistence walk, leaving
//! room for kernel-paged-out scans without false-positives.
//!
//! ## Future extension surfaces
//!
//! The same shape will host scan-to-scan diff for findings (TASK-085c
//! follow-up: file-level diff inside archives), browser-extension
//! diffs (Phase 10 wave 2), and the persistence diff per autostart
//! kind.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::detect::persistence::{PersistenceEntry, PersistenceKind};

/// Default grace window (seconds) before a missing `last_seen_at`
/// counts as a removal. Two minutes — see module doc comment.
pub const DEFAULT_REMOVAL_GRACE_SECS: i64 = 120;

/// What changed between two reference timestamps `previous_unix` (the
/// time of the prior diff / scan) and `current_unix` (now).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistenceDiff {
    /// Entries whose `first_seen_at >= previous_unix`.
    pub added: Vec<PersistenceEntry>,
    /// Entries whose `last_seen_at` falls in
    /// `[previous_unix, current_unix - grace)`. Sorted by
    /// `last_seen_at DESC` so the most-recently-disappeared shows
    /// first — matches the UI's "what just changed" expectation.
    pub removed: Vec<PersistenceEntry>,
    /// Count of entries that existed before `previous_unix` and have
    /// been re-stamped since. Drives the "unchanged" pill in the Diff
    /// modal.
    pub unchanged_count: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum DiffError {
    #[error("db: {0}")]
    Db(#[from] rusqlite::Error),
}

/// Compute the persistence diff between two reference timestamps.
///
/// `previous_unix` is typically the start time of the prior scan (the
/// engine queries `scans.started_at` for the previous scan id and
/// passes that here); `current_unix` is "now" — typically the start
/// time of the scan whose diff this is. `removal_grace_secs` is the
/// per-call leeway for an in-flight scan that hasn't bumped
/// `last_seen_at` on every row yet.
pub fn diff_persistence_between(
    conn: &Connection,
    previous_unix: i64,
    current_unix: i64,
    removal_grace_secs: i64,
) -> Result<PersistenceDiff, DiffError> {
    let removed_cutoff = current_unix.saturating_sub(removal_grace_secs);
    let added = query_persistence(
        conn,
        "WHERE first_seen_at >= ?1 ORDER BY first_seen_at DESC",
        &[&previous_unix],
    )?;
    let removed = query_persistence(
        conn,
        "WHERE last_seen_at < ?1 AND last_seen_at >= ?2 ORDER BY last_seen_at DESC",
        &[&removed_cutoff, &previous_unix],
    )?;
    let unchanged_count = conn.query_row::<i64, _, _>(
        "SELECT COUNT(*) FROM persistence_entries
         WHERE first_seen_at < ?1 AND last_seen_at >= ?2",
        rusqlite::params![previous_unix, previous_unix],
        |row| row.get(0),
    )? as usize;
    Ok(PersistenceDiff {
        added,
        removed,
        unchanged_count,
    })
}

fn query_persistence(
    conn: &Connection,
    where_clause: &str,
    bind: &[&dyn rusqlite::ToSql],
) -> Result<Vec<PersistenceEntry>, DiffError> {
    let sql = format!(
        "SELECT id, kind, identifier, target_path, display_name, signer,
                first_seen_at, last_seen_at
         FROM persistence_entries
         {where_clause}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(bind, |row| {
            let kind_str: String = row.get("kind")?;
            let kind = PersistenceKind::parse(&kind_str).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::other(format!(
                        "unknown persistence kind '{kind_str}'"
                    ))),
                )
            })?;
            Ok(PersistenceEntry {
                id: Some(row.get("id")?),
                kind,
                identifier: row.get("identifier")?,
                target_path: row
                    .get::<_, Option<String>>("target_path")?
                    .map(std::path::PathBuf::from),
                display_name: row.get("display_name")?,
                signer: row.get("signer")?,
                first_seen_at: row.get("first_seen_at")?,
                last_seen_at: row.get("last_seen_at")?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    fn open_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../migrations/0011_persistence_entries.sql"))
            .unwrap();
        conn
    }

    fn insert_row(conn: &Connection, kind: &str, id: &str, first: i64, last: i64) {
        conn.execute(
            "INSERT INTO persistence_entries
             (kind, identifier, first_seen_at, last_seen_at)
             VALUES (?, ?, ?, ?)",
            params![kind, id, first, last],
        )
        .unwrap();
    }

    #[test]
    fn added_only_when_first_seen_after_previous() {
        let conn = open_test_db();
        insert_row(&conn, "launch_agent", "/old", 100, 200);
        insert_row(&conn, "launch_agent", "/new", 1000, 1000);
        let d = diff_persistence_between(&conn, 500, 1500, 0).unwrap();
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].identifier, "/new");
    }

    #[test]
    fn removed_only_when_last_seen_in_window() {
        let conn = open_test_db();
        // Row last seen at 100 with grace 10 — outside removal window
        // because last_seen_at (100) < previous_unix (200). This is
        // the regression case: without the lower bound, every row ever
        // deleted appeared in every diff forever.
        insert_row(&conn, "crontab", "/ancient", 50, 100);
        // Row last seen at 220 — inside [previous_unix=200, current-grace=290).
        // Wait: current=300, grace=10 → cutoff=290. last_seen 220 < 290 → removed.
        insert_row(&conn, "crontab", "/gone", 50, 220);
        // Row last seen at 295 — within grace, NOT removed.
        insert_row(&conn, "crontab", "/keep", 50, 295);
        let d = diff_persistence_between(&conn, 200, 300, 10).unwrap();
        let removed_ids: Vec<&str> = d.removed.iter().map(|e| e.identifier.as_str()).collect();
        assert_eq!(removed_ids, vec!["/gone"]);
    }

    #[test]
    fn ancient_deletions_excluded_from_diff() {
        // Regression: a row deleted long before the diff window must NOT
        // appear in `removed`. Without the lower bound on last_seen_at,
        // this row would pollute every diff forever.
        let conn = open_test_db();
        insert_row(&conn, "launch_agent", "/uninstalled_5y_ago", 10, 20);
        let d = diff_persistence_between(&conn, 1_000_000, 2_000_000, 60).unwrap();
        assert!(d.removed.is_empty());
    }

    #[test]
    fn unchanged_count_picks_up_pre_existing_re_stamped_rows() {
        let conn = open_test_db();
        // Two pre-existing rows; one was re-stamped after `previous`,
        // the other before. Only the re-stamped one counts as unchanged.
        insert_row(&conn, "launch_agent", "/a", 50, 250);
        insert_row(&conn, "launch_agent", "/b", 50, 150);
        let d = diff_persistence_between(&conn, 200, 300, 0).unwrap();
        assert_eq!(d.unchanged_count, 1);
    }

    #[test]
    fn empty_db_yields_empty_diff() {
        let conn = open_test_db();
        let d = diff_persistence_between(&conn, 1000, 2000, 60).unwrap();
        assert!(d.added.is_empty());
        assert!(d.removed.is_empty());
        assert_eq!(d.unchanged_count, 0);
    }

    #[test]
    fn added_ordered_first_seen_desc() {
        let conn = open_test_db();
        insert_row(&conn, "launch_agent", "/earlier", 600, 600);
        insert_row(&conn, "launch_agent", "/later", 900, 900);
        let d = diff_persistence_between(&conn, 500, 1000, 0).unwrap();
        assert_eq!(d.added[0].identifier, "/later");
        assert_eq!(d.added[1].identifier, "/earlier");
    }
}
