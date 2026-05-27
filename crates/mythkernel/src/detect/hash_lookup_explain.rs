//! Per-hash query helpers shared by the History page (TASK-198 —
//! lateral hash search) and the new Hash Lookup page (TASK-197 —
//! reverse lookup).
//!
//! Both queries are pure read-only joins over the engine's
//! `findings` table; neither touches the filesystem. Wiring to
//! Tauri commands lives in `crates/ui-bridge` (follow-up — for
//! v0.7.x these helpers compile as a library surface so UI code
//! can land in stages).

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum HashLookupError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("hash must be 8-64 hex characters (got {0} chars)")]
    BadShape(usize),
}

/// SR-H1 fix — validate the caller-supplied hash *before* it goes
/// into a `LIKE '%hash%'` clause. Without this, an empty string or
/// a `%`/`_` wildcard would dump arbitrary findings rows. Minimum
/// length 8 hex chars (32 bits) collapses the substring-match
/// false-positive rate to ≪ 0.01%.
fn validate_hash_hex(hash_hex: &str) -> Result<(), HashLookupError> {
    if hash_hex.len() < 8 || hash_hex.len() > 64 {
        return Err(HashLookupError::BadShape(hash_hex.len()));
    }
    if !hash_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(HashLookupError::BadShape(hash_hex.len()));
    }
    Ok(())
}

/// One row of "this hash was observed in scan N at path P at time T".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashObservation {
    pub scan_id: i64,
    pub path: String,
    pub observed_at_utc: i64,
    pub severity: String,
    pub rule_source: String,
    pub rule_id: String,
}

/// TASK-198 — Find every prior scan that observed `hash_hex` at any
/// path. Sorted newest-first.
///
/// Note: the runtime `findings` table stores `evidence` strings of
/// the form `"sha256=<hex>"` or `"blake3=<hex>"` rather than
/// dedicated hash columns. We do a string match into that field;
/// brittle but workable until a schema migration lifts the hash
/// onto its own column.
pub fn lateral_hash_search(
    conn: &Connection,
    hash_hex: &str,
) -> Result<Vec<HashObservation>, HashLookupError> {
    validate_hash_hex(hash_hex)?;
    let needle = format!("%{}%", hash_hex.to_ascii_lowercase());
    let mut stmt = conn.prepare(
        "SELECT f.scan_id, f.path, f.detected_at_utc, f.severity,
                f.rule_source, f.rule_id
           FROM findings f
          WHERE LOWER(COALESCE(f.evidence, '')) LIKE ?1
          ORDER BY f.detected_at_utc DESC",
    )?;
    let rows = stmt.query_map(params![needle], |r| {
        Ok(HashObservation {
            scan_id: r.get(0)?,
            path: r.get(1)?,
            observed_at_utc: r.get(2)?,
            severity: r.get(3)?,
            rule_source: r.get(4)?,
            rule_id: r.get(5)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// TASK-197 — Verdict tree for a pasted hash. Combines:
///   * Every prior observation in `findings` (via lateral search).
///   * Lifetime + 30-day observation counts.
///
/// Future extensions (deferred): blacklist + whitelist + provenance
/// lookups against the consolidated `myth-blacklist.sqlite` /
/// `myth-whitelist.sqlite` artifacts. Those land when the engine
/// reads the consolidated SQLite directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashVerdictTree {
    pub hash_hex: String,
    pub total_observations: i64,
    pub observations_last_30d: i64,
    pub recent_observations: Vec<HashObservation>,
}

pub fn hash_verdict_tree(
    conn: &Connection,
    hash_hex: &str,
    recent_limit: usize,
    now_unix: i64,
) -> Result<HashVerdictTree, HashLookupError> {
    validate_hash_hex(hash_hex)?;
    let needle = format!("%{}%", hash_hex.to_ascii_lowercase());
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE LOWER(COALESCE(evidence, '')) LIKE ?1",
        params![needle],
        |r| r.get(0),
    )?;
    let cutoff = now_unix - 30 * 24 * 60 * 60;
    let last_30d: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings
          WHERE LOWER(COALESCE(evidence, '')) LIKE ?1
            AND detected_at_utc >= ?2",
        params![needle, cutoff],
        |r| r.get(0),
    )?;
    let mut stmt = conn.prepare(
        "SELECT scan_id, path, detected_at_utc, severity, rule_source, rule_id
           FROM findings
          WHERE LOWER(COALESCE(evidence, '')) LIKE ?1
          ORDER BY detected_at_utc DESC
          LIMIT ?2",
    )?;
    let rows: Vec<HashObservation> = stmt
        .query_map(params![needle, recent_limit as i64], |r| {
            Ok(HashObservation {
                scan_id: r.get(0)?,
                path: r.get(1)?,
                observed_at_utc: r.get(2)?,
                severity: r.get(3)?,
                rule_source: r.get(4)?,
                rule_id: r.get(5)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(HashVerdictTree {
        hash_hex: hash_hex.to_ascii_lowercase(),
        total_observations: total,
        observations_last_30d: last_30d,
        recent_observations: rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn seed_findings(conn: &Connection) {
        conn.execute_batch(
            "INSERT INTO scans (id, started_at_utc, trigger, target_kind, target_paths,
                                exclusions_snap, engine_version, feed_versions, status) VALUES
                (1, 1700, 'manual', 'path', '/home', '[]', '0.7', '{}', 'completed'),
                (2, 1800, 'manual', 'path', '/usr',  '[]', '0.7', '{}', 'completed');",
        )
        .unwrap();
        conn.execute_batch(
            "INSERT INTO findings (scan_id, path, severity, rule_id, rule_source, evidence, detected_at_utc) VALUES
                (1, '/home/me/bad.exe', 'high', 'abusech:hash:01', 'abusech', 'sha256=deadbeef', 1700),
                (1, '/home/me/other.exe', 'high', 'abusech:hash:02', 'abusech', 'sha256=cafebabe', 1700),
                (2, '/usr/bin/bad-again.exe', 'high', 'abusech:hash:01', 'abusech', 'sha256=deadbeef', 1800);",
        )
        .unwrap();
    }

    #[test]
    fn lateral_search_returns_all_paths_for_hash() {
        let conn = db::open_in_memory().unwrap();
        seed_findings(&conn);
        let obs = lateral_hash_search(&conn, "deadbeef").unwrap();
        assert_eq!(obs.len(), 2);
        assert_eq!(obs[0].scan_id, 2);
        assert_eq!(obs[1].scan_id, 1);
        assert_eq!(obs[0].path, "/usr/bin/bad-again.exe");
    }

    #[test]
    fn lateral_search_misses_unknown_hash() {
        let conn = db::open_in_memory().unwrap();
        seed_findings(&conn);
        let obs = lateral_hash_search(&conn, "00000000").unwrap();
        assert!(obs.is_empty());
    }

    #[test]
    fn verdict_tree_counts_and_recent() {
        let conn = db::open_in_memory().unwrap();
        seed_findings(&conn);
        let tree = hash_verdict_tree(&conn, "DEADBEEF", 10, 1850).unwrap();
        assert_eq!(tree.total_observations, 2);
        assert_eq!(tree.observations_last_30d, 2);
        assert_eq!(tree.recent_observations.len(), 2);
        assert_eq!(tree.hash_hex, "deadbeef");
    }

    #[test]
    fn rejects_sql_wildcards_and_empty_hash() {
        let conn = db::open_in_memory().unwrap();
        seed_findings(&conn);
        // SR-H1 — wildcard chars and short input rejected.
        assert!(matches!(
            lateral_hash_search(&conn, ""),
            Err(HashLookupError::BadShape(_))
        ));
        assert!(matches!(
            lateral_hash_search(&conn, "%"),
            Err(HashLookupError::BadShape(_))
        ));
        assert!(matches!(
            lateral_hash_search(&conn, "_"),
            Err(HashLookupError::BadShape(_))
        ));
        // Non-hex but right length still rejected.
        assert!(matches!(
            lateral_hash_search(&conn, "GGGGGGGG"),
            Err(HashLookupError::BadShape(_))
        ));
        // 8 hex chars OK.
        lateral_hash_search(&conn, "deadbeef").unwrap();
    }

    #[test]
    fn verdict_tree_respects_recent_limit() {
        let conn = db::open_in_memory().unwrap();
        seed_findings(&conn);
        let tree = hash_verdict_tree(&conn, "deadbeef", 1, 1850).unwrap();
        assert_eq!(tree.recent_observations.len(), 1);
        assert_eq!(tree.recent_observations[0].scan_id, 2);
    }
}
