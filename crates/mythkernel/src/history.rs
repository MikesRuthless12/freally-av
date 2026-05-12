//! Typed CRUD over the scan-history tables (`scans`, `findings`).
//!
//! Phase 1 (TASK-011) ships the engine-side writers needed by [`crate::scan`]
//! (TASK-012): start a scan, end a scan, record a finding. The Tauri-facing
//! history queries (`history_list`, `history_detail`) land in TASK-028 (Phase 3).

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use crate::db::DbError;

/// What triggered the scan.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanTrigger {
    Manual,
    Scheduled,
    Realtime,
    Incremental,
}

impl ScanTrigger {
    fn as_str(self) -> &'static str {
        match self {
            ScanTrigger::Manual => "manual",
            ScanTrigger::Scheduled => "scheduled",
            ScanTrigger::Realtime => "realtime",
            ScanTrigger::Incremental => "incremental",
        }
    }
}

/// Categorical state of a scan record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Running,
    Completed,
    Paused,
    Cancelled,
    Failed,
}

impl ScanStatus {
    fn as_str(self) -> &'static str {
        match self {
            ScanStatus::Running => "running",
            ScanStatus::Completed => "completed",
            ScanStatus::Paused => "paused",
            ScanStatus::Cancelled => "cancelled",
            ScanStatus::Failed => "failed",
        }
    }
}

/// Insert a new `scans` row with status = `running`. Returns the row id.
#[allow(clippy::too_many_arguments)]
pub fn create_scan(
    conn: &Connection,
    started_at_utc: i64,
    trigger: ScanTrigger,
    target_kind: &str,
    target_paths_json: &str,
    exclusions_snapshot_json: &str,
    engine_version: &str,
    feed_versions_json: &str,
) -> Result<i64, DbError> {
    conn.execute(
        "INSERT INTO scans (
            started_at_utc, trigger, target_kind, target_paths,
            exclusions_snap, engine_version, feed_versions, status
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'running')",
        params![
            started_at_utc,
            trigger.as_str(),
            target_kind,
            target_paths_json,
            exclusions_snapshot_json,
            engine_version,
            feed_versions_json,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Mark a scan as finished, capture final counters.
#[allow(clippy::too_many_arguments)]
pub fn finalize_scan(
    conn: &Connection,
    scan_id: i64,
    ended_at_utc: i64,
    status: ScanStatus,
    files_visited: i64,
    files_hashed: i64,
    files_yara: i64,
    archive_members_visited: i64,
    bytes_visited: i64,
    findings_count: i64,
) -> Result<(), DbError> {
    conn.execute(
        "UPDATE scans SET
            ended_at_utc = ?2,
            status = ?3,
            files_visited = ?4,
            files_hashed = ?5,
            files_yara = ?6,
            archive_members_visited = ?7,
            bytes_visited = ?8,
            findings_count = ?9
         WHERE id = ?1",
        params![
            scan_id,
            ended_at_utc,
            status.as_str(),
            files_visited,
            files_hashed,
            files_yara,
            archive_members_visited,
            bytes_visited,
            findings_count,
        ],
    )?;
    Ok(())
}

/// Persist a serialized resume token onto a scan row (TASK-040).
/// The blob is opaque to the DB layer — the engine encodes
/// `crate::scan::ResumeToken` as JSON. Callers should also set the
/// status to `paused` via `finalize_scan` so the row signals to a
/// subsequent process that it can be picked up.
pub fn set_resume_token(conn: &Connection, scan_id: i64, token: &[u8]) -> Result<(), DbError> {
    conn.execute(
        "UPDATE scans SET resume_token = ?2 WHERE id = ?1",
        params![scan_id, token],
    )?;
    Ok(())
}

/// Read the resume token blob (if any) for a scan row.
pub fn read_resume_token(conn: &Connection, scan_id: i64) -> Result<Option<Vec<u8>>, DbError> {
    let blob: Option<Vec<u8>> = conn
        .query_row(
            "SELECT resume_token FROM scans WHERE id = ?1",
            [scan_id],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .map_err(DbError::from)?;
    Ok(blob)
}

/// Append a `findings` row tied to a running scan.
#[allow(clippy::too_many_arguments)]
pub fn record_finding(
    conn: &Connection,
    scan_id: i64,
    path: &str,
    size_bytes: Option<i64>,
    blake3: Option<&[u8]>,
    sha256: Option<&[u8]>,
    rule_id: &str,
    rule_source: &str,
    severity: &str,
    detected_at_utc: i64,
) -> Result<i64, DbError> {
    conn.execute(
        "INSERT INTO findings (
            scan_id, path, size_bytes, blake3, sha256,
            rule_id, rule_source, severity, detected_at_utc, action_taken
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'none')",
        params![
            scan_id,
            path,
            size_bytes,
            blake3,
            sha256,
            rule_id,
            rule_source,
            severity,
            detected_at_utc,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    #[test]
    fn create_and_finalize_scan() {
        let conn = open_in_memory().unwrap();
        let scan_id = create_scan(
            &conn,
            1_700_000_000,
            ScanTrigger::Manual,
            "path",
            "[\"/home/user\"]",
            "[]",
            "0.1.0",
            "{}",
        )
        .unwrap();
        assert!(scan_id > 0);

        finalize_scan(
            &conn,
            scan_id,
            1_700_000_300,
            ScanStatus::Completed,
            42,
            42,
            0,
            0,
            123_456,
            0,
        )
        .unwrap();

        let (status, files): (String, i64) = conn
            .query_row(
                "SELECT status, files_visited FROM scans WHERE id = ?1",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, "completed");
        assert_eq!(files, 42);
    }

    #[test]
    fn record_finding_attaches_to_scan() {
        let conn = open_in_memory().unwrap();
        let scan_id = create_scan(
            &conn,
            1_700_000_000,
            ScanTrigger::Manual,
            "file",
            "[\"/tmp/eicar.com\"]",
            "[]",
            "0.1.0",
            "{}",
        )
        .unwrap();

        let fid = record_finding(
            &conn,
            scan_id,
            "/tmp/eicar.com",
            Some(68),
            Some(&[0u8; 32]),
            None,
            "abusech:hash:eicar",
            "abusech",
            "high",
            1_700_000_100,
        )
        .unwrap();
        assert!(fid > 0);

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM findings WHERE scan_id = ?1",
                [scan_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }
}
