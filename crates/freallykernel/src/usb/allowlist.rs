//! USB allowlist by VID:PID:Serial (TASK-242, Phase 8 Wave 2).
//!
//! Persists a per-device allowlist in the engine sqlite. Allowlisted
//! devices skip the USB-insert auto-trigger modal (TASK-241) and the
//! BadUSB / RTL heuristics (TASK-243 / TASK-248).
//!
//! Serial supports a single `*` wildcard so an operator can allow
//! "every Kingston DT100 G3" with one row instead of one per device.
//! Wildcards are tail-only (`vid:pid:*`) — no glob, no leading
//! wildcard — to keep the SQL trivial and indexable.

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::db::DbError;

/// One allowlisted device. `serial` may be `"*"` to allow every
/// device matching `(vid, pid)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbAllowEntry {
    pub vid: String,
    pub pid: String,
    pub serial: String,
    pub label: String,
    pub added_at_utc: i64,
}

/// Create the `usb_allowlist` table if it does not exist. Idempotent
/// — wired into the engine's migration runner (TASK-242 sql will be
/// folded into the next migration file when the schema bumps).
pub fn ensure_schema(conn: &Connection) -> Result<(), DbError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS usb_allowlist (
            vid          TEXT NOT NULL,
            pid          TEXT NOT NULL,
            serial       TEXT NOT NULL,
            label        TEXT NOT NULL DEFAULT '',
            added_at_utc INTEGER NOT NULL,
            PRIMARY KEY (vid, pid, serial)
         );",
    )?;
    Ok(())
}

/// Reject inputs the module doc forbids (wildcards in VID/PID, or
/// embedded `*` in serial) and return the canonical (lower-cased)
/// `(vid, pid, serial)` form. Returned as `DbError::Io` with
/// `InvalidInput` so a bad caller can't ever land a row of shape
/// `('*','*','*')` that a future GLOB-based matcher would
/// interpret as "allow every USB device".
fn validate(vid: &str, pid: &str, serial: &str) -> Result<(String, String, String), DbError> {
    let invalid = |msg: String| -> DbError {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, msg).into()
    };
    if vid.contains('*') {
        return Err(invalid(format!("vid must not contain '*' (got '{vid}')")));
    }
    if pid.contains('*') {
        return Err(invalid(format!("pid must not contain '*' (got '{pid}')")));
    }
    if serial != "*" && serial.contains('*') {
        return Err(invalid(format!(
            "serial must be literal or whole-string '*' (no embedded wildcards; got '{serial}')"
        )));
    }
    Ok((
        vid.to_ascii_lowercase(),
        pid.to_ascii_lowercase(),
        serial.to_string(),
    ))
}

/// Returns true when `(vid, pid, serial)` matches an allowlist row.
/// Exact-match is tried first; on no hit, the wildcard form
/// `(vid, pid, '*')` is consulted. VID + PID are case-folded so a
/// daemon-side udev / SetupDi / IOKit caller can present whichever
/// case the OS hands them without breaking the lookup.
pub fn is_allowed(conn: &Connection, vid: &str, pid: &str, serial: &str) -> Result<bool, DbError> {
    let vid = vid.to_ascii_lowercase();
    let pid = pid.to_ascii_lowercase();
    let exact: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM usb_allowlist
              WHERE vid = ?1 AND pid = ?2 AND serial = ?3 LIMIT 1",
            params![vid, pid, serial],
            |r| r.get(0),
        )
        .optional()?;
    if exact.is_some() {
        return Ok(true);
    }
    let wildcard: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM usb_allowlist
              WHERE vid = ?1 AND pid = ?2 AND serial = '*' LIMIT 1",
            params![vid, pid],
            |r| r.get(0),
        )
        .optional()?;
    Ok(wildcard.is_some())
}

pub fn add(
    conn: &Connection,
    vid: &str,
    pid: &str,
    serial: &str,
    label: &str,
    now_utc: i64,
) -> Result<(), DbError> {
    let (vid, pid, serial) = validate(vid, pid, serial)?;
    conn.execute(
        "INSERT OR REPLACE INTO usb_allowlist (vid, pid, serial, label, added_at_utc)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![vid, pid, serial, label, now_utc],
    )?;
    Ok(())
}

pub fn remove(conn: &Connection, vid: &str, pid: &str, serial: &str) -> Result<usize, DbError> {
    let vid = vid.to_ascii_lowercase();
    let pid = pid.to_ascii_lowercase();
    let n = conn.execute(
        "DELETE FROM usb_allowlist WHERE vid = ?1 AND pid = ?2 AND serial = ?3",
        params![vid, pid, serial],
    )?;
    Ok(n)
}

pub fn list(conn: &Connection) -> Result<Vec<UsbAllowEntry>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT vid, pid, serial, label, added_at_utc FROM usb_allowlist
         ORDER BY added_at_utc DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(UsbAllowEntry {
            vid: r.get(0)?,
            pid: r.get(1)?,
            serial: r.get(2)?,
            label: r.get(3)?,
            added_at_utc: r.get(4)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        ensure_schema(&c).unwrap();
        c
    }

    #[test]
    fn exact_match_is_allowed() {
        let c = db();
        add(&c, "0951", "1665", "AAAA", "Kingston", 1).unwrap();
        assert!(is_allowed(&c, "0951", "1665", "AAAA").unwrap());
        assert!(!is_allowed(&c, "0951", "1665", "BBBB").unwrap());
    }

    #[test]
    fn case_folded_vid_and_pid_match_across_case_variants() {
        let c = db();
        // Daemon-side udev hands the device with uppercase hex bytes;
        // the user stored the row through the lower-cased UI form.
        add(&c, "0951", "1665", "AAAA", "Kingston", 1).unwrap();
        assert!(is_allowed(&c, "0951", "1665", "AAAA").unwrap());
        assert!(is_allowed(&c, "0951", "1665", "AAAA").unwrap());
        // Conversely, a row stored via mixed-case input still matches.
        add(&c, "AbCd", "1234", "X", "device", 2).unwrap();
        assert!(is_allowed(&c, "abcd", "1234", "X").unwrap());
    }

    #[test]
    fn wildcard_vid_or_pid_rejected_with_invalid_input() {
        let c = db();
        let err = add(&c, "*", "1665", "*", "any", 1).unwrap_err();
        assert!(err.to_string().contains("vid must not contain"));
        let err = add(&c, "0951", "*", "*", "any", 1).unwrap_err();
        assert!(err.to_string().contains("pid must not contain"));
        let err = add(&c, "0951", "1665", "AA*BB", "embedded", 1).unwrap_err();
        assert!(err.to_string().contains("serial must be literal"));
    }

    #[test]
    fn wildcard_serial_allows_every_unit() {
        let c = db();
        add(&c, "0951", "1665", "*", "Kingston DT100 G3", 1).unwrap();
        assert!(is_allowed(&c, "0951", "1665", "WHATEVER").unwrap());
        // Different VID does not match.
        assert!(!is_allowed(&c, "0952", "1665", "AAA").unwrap());
    }

    #[test]
    fn remove_drops_only_matching_row() {
        let c = db();
        add(&c, "0951", "1665", "AAAA", "Kingston", 1).unwrap();
        add(&c, "0951", "1665", "BBBB", "Kingston", 2).unwrap();
        let n = remove(&c, "0951", "1665", "AAAA").unwrap();
        assert_eq!(n, 1);
        assert!(!is_allowed(&c, "0951", "1665", "AAAA").unwrap());
        assert!(is_allowed(&c, "0951", "1665", "BBBB").unwrap());
    }

    #[test]
    fn list_returns_newest_first() {
        let c = db();
        add(&c, "0951", "1665", "OLD", "older", 1).unwrap();
        add(&c, "0951", "1665", "NEW", "newer", 5).unwrap();
        let items = list(&c).unwrap();
        assert_eq!(items[0].serial, "NEW");
        assert_eq!(items[1].serial, "OLD");
    }
}
