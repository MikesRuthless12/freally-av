//! Active-findings index (TASK-140, Phase 8).
//!
//! Backs the **block-on-detected** policy (FR-133): while a file path
//! has an open `detected` finding (i.e. `action_taken = 'detected'`),
//! the platform real-time daemon must DENY any open against it.
//!
//! The engine writes the index; each daemon pulls it via
//! [`crate::ipc::linfan::IpcFrame::ActiveFindingsPush`] (Linux today;
//! macOS via the matching `macesf` frame in Phase 9; Windows via
//! `winflt` in Phase 12). The push delivers the **full** path set so
//! the daemon can replace its in-memory cache atomically.
//!
//! Per § 1.5.4 the block decision lives on the daemon side — the
//! engine just keeps the index fresh. This module is the
//! single source of truth for "which paths are currently denylisted
//! because of an open detection?" and it survives Shields=OFF (FR-160
//! point 5): block-on-detected is honored regardless of Shields state.

use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension};

use crate::db::DbError;

/// One snapshot of the active-findings path set. Sorted + de-duplicated
/// so the daemon can binary-search or hash-set it without re-sorting.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ActivePathsSnapshot {
    pub paths: Vec<String>,
    /// Unix seconds when the snapshot was produced. The daemon stamps
    /// this into its log line so an operator can correlate a DENY to
    /// the engine push that planted the path.
    pub generated_at_utc: i64,
}

impl ActivePathsSnapshot {
    /// Returns true when `path` is in the snapshot. The internal
    /// representation is sorted, so this is a single binary search;
    /// the daemon hot path can use this directly without converting
    /// to a `HashSet`.
    pub fn contains(&self, path: &str) -> bool {
        self.paths
            .binary_search_by(|p| p.as_str().cmp(path))
            .is_ok()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }
}

/// Query the engine DB for every finding currently in the `detected`
/// state. The result is the path set the daemon will install as its
/// "DENY on open" denylist.
///
/// `findings.action_taken` is a TEXT column whose canonical values
/// match `FindingState::as_str()` — `'detected'` here is the initial
/// row state before the user has Trusted / Quarantined / Restored.
pub fn snapshot_active(conn: &Connection, now_utc: i64) -> Result<ActivePathsSnapshot, DbError> {
    let mut stmt = conn.prepare(
        "SELECT path FROM findings
         WHERE action_taken = 'detected'
         ORDER BY path ASC",
    )?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    // De-dupe — the same path can have multiple open findings (e.g. a
    // YARA hit plus a hash-blacklist hit on the same file). For the
    // DENY list we only care that the path is listed once.
    let mut set = BTreeSet::new();
    for row in rows {
        set.insert(row?);
    }
    Ok(ActivePathsSnapshot {
        paths: set.into_iter().collect(),
        generated_at_utc: now_utc,
    })
}

/// Returns true iff at least one open `detected` finding currently
/// names `path`. Useful for ad-hoc queries from the UI explainer
/// ("why was this open denied?"). The hot path on the daemon side
/// uses [`ActivePathsSnapshot::contains`] instead — the snapshot is
/// pushed once per change rather than per-event.
pub fn is_active(conn: &Connection, path: &str) -> Result<bool, DbError> {
    let row: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM findings WHERE path = ?1 AND action_taken = 'detected' LIMIT 1",
            [path],
            |r| r.get(0),
        )
        .optional()?;
    Ok(row.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn build_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE scans (id INTEGER PRIMARY KEY);
             INSERT INTO scans (id) VALUES (1);
             CREATE TABLE findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                path TEXT NOT NULL,
                size_bytes INTEGER,
                blake3 BLOB,
                sha256 BLOB,
                rule_id TEXT NOT NULL,
                rule_source TEXT NOT NULL,
                severity TEXT NOT NULL,
                detected_at_utc INTEGER NOT NULL,
                action_taken TEXT NOT NULL DEFAULT 'detected',
                evidence TEXT,
                notes TEXT
             );",
        )
        .unwrap();
        conn
    }

    fn add(conn: &Connection, path: &str, action: &str) {
        conn.execute(
            "INSERT INTO findings (scan_id, path, rule_id, rule_source, severity,
                                   detected_at_utc, action_taken)
             VALUES (1, ?1, 'r', 'test', 'high', 0, ?2)",
            [path, action],
        )
        .unwrap();
    }

    #[test]
    fn snapshot_lists_only_detected_rows_unique_and_sorted() {
        let conn = build_db();
        add(&conn, "/b", "detected");
        add(&conn, "/a", "detected");
        add(&conn, "/c", "quarantined");
        add(&conn, "/a", "detected"); // duplicate
        let snap = snapshot_active(&conn, 42).unwrap();
        assert_eq!(snap.paths, vec!["/a".to_string(), "/b".to_string()]);
        assert_eq!(snap.generated_at_utc, 42);
        assert!(snap.contains("/a"));
        assert!(snap.contains("/b"));
        assert!(!snap.contains("/c"));
    }

    #[test]
    fn is_active_reflects_state_transitions() {
        let conn = build_db();
        add(&conn, "/foo", "detected");
        assert!(is_active(&conn, "/foo").unwrap());
        // Transition to quarantined — should no longer be active.
        conn.execute(
            "UPDATE findings SET action_taken='quarantined' WHERE path='/foo'",
            [],
        )
        .unwrap();
        assert!(!is_active(&conn, "/foo").unwrap());
    }

    #[test]
    fn empty_db_returns_empty_snapshot() {
        let conn = build_db();
        let snap = snapshot_active(&conn, 7).unwrap();
        assert!(snap.is_empty());
        assert_eq!(snap.len(), 0);
    }
}
