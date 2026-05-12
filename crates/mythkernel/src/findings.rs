//! Findings CRUD + action state machine (TASK-025, Phase 2).
//!
//! Layered above the `findings` row writer from [`crate::history`] (the
//! insertion path is owned by the scan engine in Phase 1). This module
//! adds:
//!
//! - typed read access to one or many findings
//! - filtering by scan, severity, and current state
//! - the [`FindingState`] state machine that governs allowed
//!   `action_taken` transitions
//! - [`apply_action`] — single entry-point for changing a finding's
//!   state from the UI or CLI (TASK-026)
//!
//! The state machine is intentionally narrow:
//!
//! ```text
//!                +-------------+
//!                |  Detected   |  ← initial state when a finding is
//!                +------+------+    first recorded by the engine
//!                       |
//!         +-------------+----------------+
//!         |             |                |
//!         v             v                v
//!  +-------------+ +----------+    +-----------+
//!  | Quarantined | | Ignored  |    | Deleted   |   (direct shred of a
//!  +------+------+ +----------+    +-----------+    detected file, no
//!         |                                          quarantine round-trip)
//!         |
//!         +-------------+----------------+
//!         |             |                |
//!         v             v                v
//!  +-------------+ +----------+    +-----------+
//!  |  Restored   | | Deleted  |    | Ignored   |
//!  +-------------+ +----------+    +-----------+
//! ```
//!
//! Transitions outside this graph return
//! [`FindingsError::InvalidTransition`]. The engine code that does the
//! actual filesystem work (move to vault, restore, etc.) is layered
//! *above* this module — apply_action is a pure DB state update; the
//! orchestrator in TASK-026 / Phase 3 wires it to [`crate::quarantine`].

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::db::DbError;

#[derive(Debug, thiserror::Error)]
pub enum FindingsError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("db: {0}")]
    Db(#[from] DbError),
    #[error("finding {0} not found")]
    NotFound(i64),
    #[error("invalid transition from {from} via {action}")]
    InvalidTransition { from: String, action: String },
    #[error("unknown action_taken value in DB row: {0}")]
    UnknownState(String),
}

/// One row from the `findings` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: i64,
    pub scan_id: i64,
    pub path: String,
    pub size_bytes: Option<i64>,
    pub blake3: Option<Vec<u8>>,
    pub sha256: Option<Vec<u8>>,
    pub rule_id: String,
    pub rule_source: String,
    pub severity: String,
    pub detected_at_utc: i64,
    pub action_taken: FindingState,
    pub evidence: Option<String>,
    pub notes: Option<String>,
}

/// Persisted state of a finding — the `action_taken` column. The wire
/// representation matches the column's TEXT value exactly so existing rows
/// roundtrip through this enum without translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingState {
    /// Just detected; engine has taken no action yet. Matches the
    /// schema's default `'none'`.
    Detected,
    Quarantined,
    Restored,
    Deleted,
    Ignored,
}

impl FindingState {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingState::Detected => "none",
            FindingState::Quarantined => "quarantined",
            FindingState::Restored => "restored",
            FindingState::Deleted => "deleted",
            FindingState::Ignored => "ignored",
        }
    }
}

impl std::str::FromStr for FindingState {
    type Err = FindingsError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "none" => FindingState::Detected,
            "quarantined" => FindingState::Quarantined,
            "restored" => FindingState::Restored,
            "deleted" => FindingState::Deleted,
            "ignored" => FindingState::Ignored,
            other => return Err(FindingsError::UnknownState(other.to_string())),
        })
    }
}

/// Action the user / CLI is taking against a finding. Translates to a
/// state transition via [`next_state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingAction {
    /// Move the file into the quarantine vault. Allowed from `Detected`.
    Quarantine,
    /// Restore a vaulted file to its original path. Allowed from
    /// `Quarantined`.
    Restore,
    /// Permanently shred the file. Allowed from `Detected` (skip-vault
    /// fast delete) and from `Quarantined`.
    Delete,
    /// Trust the file; engine no longer surfaces it. Allowed from any
    /// non-terminal state (Detected / Quarantined).
    Ignore,
}

impl FindingAction {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingAction::Quarantine => "quarantine",
            FindingAction::Restore => "restore",
            FindingAction::Delete => "delete",
            FindingAction::Ignore => "ignore",
        }
    }
}

/// Resolve the next state for `(current, action)` per the state diagram
/// at the top of the module. Returns
/// [`FindingsError::InvalidTransition`] for forbidden edges.
pub fn next_state(
    current: FindingState,
    action: FindingAction,
) -> Result<FindingState, FindingsError> {
    use FindingAction as A;
    use FindingState as S;
    match (current, action) {
        (S::Detected, A::Quarantine) => Ok(S::Quarantined),
        (S::Detected, A::Delete) => Ok(S::Deleted),
        (S::Detected, A::Ignore) => Ok(S::Ignored),
        (S::Quarantined, A::Restore) => Ok(S::Restored),
        (S::Quarantined, A::Delete) => Ok(S::Deleted),
        (S::Quarantined, A::Ignore) => Ok(S::Ignored),
        // All other edges are forbidden.
        (from, act) => Err(FindingsError::InvalidTransition {
            from: from.as_str().to_string(),
            action: act.as_str().to_string(),
        }),
    }
}

/// Fetch one finding by id.
pub fn get(conn: &Connection, id: i64) -> Result<Finding, FindingsError> {
    let row = conn
        .query_row(
            "SELECT id, scan_id, path, size_bytes, blake3, sha256,
                    rule_id, rule_source, severity, detected_at_utc,
                    action_taken, evidence, notes
             FROM findings WHERE id = ?1",
            params![id],
            row_to_finding,
        )
        .optional()?;
    row.transpose()?.ok_or(FindingsError::NotFound(id))
}

/// All findings for one scan, ordered most-recent first (then by id DESC).
pub fn list_by_scan(conn: &Connection, scan_id: i64) -> Result<Vec<Finding>, FindingsError> {
    list_query(
        conn,
        "SELECT id, scan_id, path, size_bytes, blake3, sha256,
                rule_id, rule_source, severity, detected_at_utc,
                action_taken, evidence, notes
         FROM findings WHERE scan_id = ?1
         ORDER BY detected_at_utc DESC, id DESC",
        params![scan_id],
    )
}

/// All findings currently in the given state.
pub fn list_by_state(
    conn: &Connection,
    state: FindingState,
) -> Result<Vec<Finding>, FindingsError> {
    list_query(
        conn,
        "SELECT id, scan_id, path, size_bytes, blake3, sha256,
                rule_id, rule_source, severity, detected_at_utc,
                action_taken, evidence, notes
         FROM findings WHERE action_taken = ?1
         ORDER BY detected_at_utc DESC, id DESC",
        params![state.as_str()],
    )
}

/// All findings in `state` with severity at least `min_severity`. Severity
/// ordering is the string ordering of the values written by
/// [`crate::detect::Severity::as_str`]; we filter via a small enum-to-rank
/// mapping rather than relying on TEXT ordering.
pub fn list_by_state_and_min_severity(
    conn: &Connection,
    state: FindingState,
    min_severity: crate::detect::Severity,
) -> Result<Vec<Finding>, FindingsError> {
    let acceptable: Vec<&'static str> = severities_at_or_above(min_severity);
    // Build a placeholder list (?2, ?3, ...) sized to acceptable.len().
    let placeholders: Vec<String> = (0..acceptable.len())
        .map(|i| format!("?{}", i + 2))
        .collect();
    let sql = format!(
        "SELECT id, scan_id, path, size_bytes, blake3, sha256,
                rule_id, rule_source, severity, detected_at_utc,
                action_taken, evidence, notes
         FROM findings WHERE action_taken = ?1 AND severity IN ({})
         ORDER BY detected_at_utc DESC, id DESC",
        placeholders.join(", ")
    );
    let mut stmt = conn.prepare(&sql)?;
    // Bind: ?1 = state, then each severity string. We need a backing
    // `String` for the state because rusqlite's ToSql impl borrows.
    let state_str = state.as_str();
    let mut params: Vec<&dyn rusqlite::ToSql> = vec![&state_str as &dyn rusqlite::ToSql];
    let severities_as_sql: Vec<&dyn rusqlite::ToSql> = acceptable
        .iter()
        .map(|s| s as &dyn rusqlite::ToSql)
        .collect();
    params.extend(severities_as_sql);
    let mut rows = stmt.query(params.as_slice())?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row_to_finding(row)??);
    }
    Ok(out)
}

fn severities_at_or_above(min: crate::detect::Severity) -> Vec<&'static str> {
    use crate::detect::Severity as S;
    let all = [S::Info, S::Low, S::Medium, S::High, S::Critical];
    all.iter()
        .filter(|s| **s >= min)
        .map(|s| s.as_str())
        .collect()
}

fn list_query<P: rusqlite::Params>(
    conn: &Connection,
    sql: &str,
    params: P,
) -> Result<Vec<Finding>, FindingsError> {
    let mut stmt = conn.prepare(sql)?;
    let mut out = Vec::new();
    let mut rows = stmt.query(params)?;
    while let Some(row) = rows.next()? {
        out.push(row_to_finding(row)??);
    }
    Ok(out)
}

/// Apply an action to a finding, transitioning its state. Returns the new
/// state on success. Forbidden transitions return
/// [`FindingsError::InvalidTransition`] and leave the row untouched.
///
/// This is a pure DB state update — the orchestrator that calls this
/// (TASK-026 / mythctl / ui-bridge) is responsible for any filesystem
/// work (e.g. moving the file to the vault via
/// [`crate::quarantine::QuarantineVault`]) and for sequencing the vault
/// op before / after the state change as appropriate.
pub fn apply_action(
    conn: &Connection,
    finding_id: i64,
    action: FindingAction,
) -> Result<FindingState, FindingsError> {
    let current = current_state(conn, finding_id)?;
    let next = next_state(current, action)?;
    let updated = conn.execute(
        "UPDATE findings SET action_taken = ?2 WHERE id = ?1",
        params![finding_id, next.as_str()],
    )?;
    if updated == 0 {
        // Concurrent delete between current_state() and this UPDATE.
        return Err(FindingsError::NotFound(finding_id));
    }
    Ok(next)
}

/// Read the current state of a finding without loading the whole row.
pub fn current_state(conn: &Connection, finding_id: i64) -> Result<FindingState, FindingsError> {
    let state_str: Option<String> = conn
        .query_row(
            "SELECT action_taken FROM findings WHERE id = ?1",
            params![finding_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let state_str = state_str.ok_or(FindingsError::NotFound(finding_id))?;
    state_str.parse::<FindingState>()
}

/// Replace the `notes` field on a finding. Pass `None` to clear.
pub fn set_notes(
    conn: &Connection,
    finding_id: i64,
    notes: Option<&str>,
) -> Result<(), FindingsError> {
    let updated = conn.execute(
        "UPDATE findings SET notes = ?2 WHERE id = ?1",
        params![finding_id, notes],
    )?;
    if updated == 0 {
        return Err(FindingsError::NotFound(finding_id));
    }
    Ok(())
}

/// Replace the `evidence` JSON blob on a finding. Pass `None` to clear.
pub fn set_evidence(
    conn: &Connection,
    finding_id: i64,
    evidence: Option<&str>,
) -> Result<(), FindingsError> {
    let updated = conn.execute(
        "UPDATE findings SET evidence = ?2 WHERE id = ?1",
        params![finding_id, evidence],
    )?;
    if updated == 0 {
        return Err(FindingsError::NotFound(finding_id));
    }
    Ok(())
}

fn row_to_finding(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Finding, FindingsError>> {
    let state_str: String = row.get(10)?;
    let action_taken = match state_str.parse::<FindingState>() {
        Ok(s) => s,
        Err(err) => return Ok(Err(err)),
    };
    Ok(Ok(Finding {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        path: row.get(2)?,
        size_bytes: row.get(3)?,
        blake3: row.get(4)?,
        sha256: row.get(5)?,
        rule_id: row.get(6)?,
        rule_source: row.get(7)?,
        severity: row.get(8)?,
        detected_at_utc: row.get(9)?,
        action_taken,
        evidence: row.get(11)?,
        notes: row.get(12)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::history::{ScanTrigger, create_scan, record_finding};

    fn seed_scan(conn: &Connection) -> i64 {
        create_scan(
            conn,
            1_700_000_000,
            ScanTrigger::Manual,
            "path",
            "[\"/tmp\"]",
            "[]",
            "0.2.0",
            "{}",
        )
        .unwrap()
    }

    fn seed_finding(conn: &Connection, scan_id: i64, severity: &str) -> i64 {
        record_finding(
            conn,
            scan_id,
            "/tmp/sample.exe",
            Some(1024),
            Some(&[0u8; 32]),
            Some(&[1u8; 32]),
            "abusech:hash:sample",
            "abusech",
            severity,
            1_700_000_100,
        )
        .unwrap()
    }

    #[test]
    fn state_string_roundtrip() {
        for s in [
            FindingState::Detected,
            FindingState::Quarantined,
            FindingState::Restored,
            FindingState::Deleted,
            FindingState::Ignored,
        ] {
            assert_eq!(s.as_str().parse::<FindingState>().unwrap(), s);
        }
    }

    #[test]
    fn state_string_rejects_unknown() {
        match "nonsense".parse::<FindingState>().unwrap_err() {
            FindingsError::UnknownState(v) => assert_eq!(v, "nonsense"),
            other => panic!("expected UnknownState, got {other:?}"),
        }
    }

    #[test]
    fn next_state_happy_paths() {
        assert_eq!(
            next_state(FindingState::Detected, FindingAction::Quarantine).unwrap(),
            FindingState::Quarantined
        );
        assert_eq!(
            next_state(FindingState::Detected, FindingAction::Ignore).unwrap(),
            FindingState::Ignored
        );
        assert_eq!(
            next_state(FindingState::Detected, FindingAction::Delete).unwrap(),
            FindingState::Deleted
        );
        assert_eq!(
            next_state(FindingState::Quarantined, FindingAction::Restore).unwrap(),
            FindingState::Restored
        );
        assert_eq!(
            next_state(FindingState::Quarantined, FindingAction::Delete).unwrap(),
            FindingState::Deleted
        );
        assert_eq!(
            next_state(FindingState::Quarantined, FindingAction::Ignore).unwrap(),
            FindingState::Ignored
        );
    }

    #[test]
    fn next_state_forbidden_transitions_error_clearly() {
        // Terminal-state transitions all forbidden.
        for from in [
            FindingState::Restored,
            FindingState::Deleted,
            FindingState::Ignored,
        ] {
            for act in [
                FindingAction::Quarantine,
                FindingAction::Restore,
                FindingAction::Delete,
                FindingAction::Ignore,
            ] {
                match next_state(from, act) {
                    Err(FindingsError::InvalidTransition { from: f, action: a }) => {
                        assert_eq!(f, from.as_str());
                        assert_eq!(a, act.as_str());
                    }
                    Ok(_) => panic!("transition from {from:?} via {act:?} should be forbidden"),
                    Err(other) => panic!("expected InvalidTransition, got {other:?}"),
                }
            }
        }
        // Detected -> Restore is also forbidden (you must Quarantine first).
        assert!(next_state(FindingState::Detected, FindingAction::Restore).is_err());
    }

    #[test]
    fn get_returns_finding_with_default_state() {
        let conn = open_in_memory().unwrap();
        let scan_id = seed_scan(&conn);
        let fid = seed_finding(&conn, scan_id, "high");
        let finding = get(&conn, fid).unwrap();
        assert_eq!(finding.id, fid);
        assert_eq!(finding.scan_id, scan_id);
        assert_eq!(finding.action_taken, FindingState::Detected);
        assert_eq!(finding.severity, "high");
    }

    #[test]
    fn get_missing_finding_returns_not_found() {
        let conn = open_in_memory().unwrap();
        match get(&conn, 999).unwrap_err() {
            FindingsError::NotFound(999) => {}
            other => panic!("expected NotFound(999), got {other:?}"),
        }
    }

    #[test]
    fn apply_action_walks_detected_to_quarantined_to_restored() {
        let conn = open_in_memory().unwrap();
        let scan_id = seed_scan(&conn);
        let fid = seed_finding(&conn, scan_id, "high");

        let s1 = apply_action(&conn, fid, FindingAction::Quarantine).unwrap();
        assert_eq!(s1, FindingState::Quarantined);
        assert_eq!(
            current_state(&conn, fid).unwrap(),
            FindingState::Quarantined
        );

        let s2 = apply_action(&conn, fid, FindingAction::Restore).unwrap();
        assert_eq!(s2, FindingState::Restored);
        // Restored is terminal.
        match apply_action(&conn, fid, FindingAction::Quarantine).unwrap_err() {
            FindingsError::InvalidTransition { .. } => {}
            other => panic!("expected InvalidTransition, got {other:?}"),
        }
    }

    #[test]
    fn apply_action_invalid_transition_leaves_row_unchanged() {
        let conn = open_in_memory().unwrap();
        let scan_id = seed_scan(&conn);
        let fid = seed_finding(&conn, scan_id, "high");
        // Detected -> Restore is forbidden.
        let err = apply_action(&conn, fid, FindingAction::Restore).unwrap_err();
        match err {
            FindingsError::InvalidTransition { .. } => {}
            other => panic!("expected InvalidTransition, got {other:?}"),
        }
        assert_eq!(current_state(&conn, fid).unwrap(), FindingState::Detected);
    }

    #[test]
    fn list_by_scan_returns_only_that_scans_findings() {
        let conn = open_in_memory().unwrap();
        let s1 = seed_scan(&conn);
        let s2 = seed_scan(&conn);
        let f1 = seed_finding(&conn, s1, "high");
        let _ = seed_finding(&conn, s2, "medium");
        let list = list_by_scan(&conn, s1).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, f1);
    }

    #[test]
    fn list_by_state_filters_correctly() {
        let conn = open_in_memory().unwrap();
        let s = seed_scan(&conn);
        let a = seed_finding(&conn, s, "high");
        let b = seed_finding(&conn, s, "medium");
        apply_action(&conn, a, FindingAction::Quarantine).unwrap();
        let detected = list_by_state(&conn, FindingState::Detected).unwrap();
        let quarantined = list_by_state(&conn, FindingState::Quarantined).unwrap();
        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].id, b);
        assert_eq!(quarantined.len(), 1);
        assert_eq!(quarantined[0].id, a);
    }

    #[test]
    fn list_by_state_and_min_severity_filters_severity_correctly() {
        let conn = open_in_memory().unwrap();
        let s = seed_scan(&conn);
        let _info = seed_finding(&conn, s, "info");
        let _low = seed_finding(&conn, s, "low");
        let med = seed_finding(&conn, s, "medium");
        let high = seed_finding(&conn, s, "high");
        let crit = seed_finding(&conn, s, "critical");

        let high_plus = list_by_state_and_min_severity(
            &conn,
            FindingState::Detected,
            crate::detect::Severity::High,
        )
        .unwrap();
        let ids: Vec<i64> = high_plus.iter().map(|f| f.id).collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&high));
        assert!(ids.contains(&crit));
        assert!(!ids.contains(&med));
    }

    #[test]
    fn set_notes_and_evidence_round_trip() {
        let conn = open_in_memory().unwrap();
        let s = seed_scan(&conn);
        let fid = seed_finding(&conn, s, "high");
        set_notes(&conn, fid, Some("user marked false positive")).unwrap();
        set_evidence(&conn, fid, Some("{\"matched\":\"EICAR\"}")).unwrap();
        let f = get(&conn, fid).unwrap();
        assert_eq!(f.notes.as_deref(), Some("user marked false positive"));
        assert_eq!(f.evidence.as_deref(), Some("{\"matched\":\"EICAR\"}"));
        set_notes(&conn, fid, None).unwrap();
        let f = get(&conn, fid).unwrap();
        assert!(f.notes.is_none());
    }

    #[test]
    fn set_notes_missing_finding_returns_not_found() {
        let conn = open_in_memory().unwrap();
        match set_notes(&conn, 999, Some("x")).unwrap_err() {
            FindingsError::NotFound(999) => {}
            other => panic!("expected NotFound(999), got {other:?}"),
        }
    }
}
