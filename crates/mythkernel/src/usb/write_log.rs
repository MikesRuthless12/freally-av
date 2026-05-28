//! USB write event log (TASK-249, Phase 8 Wave 2).
//!
//! Read-only audit trail of every write to a removable volume.
//! Populated per-OS:
//!   * Linux — fanotify `FAN_MODIFY | FAN_CLOSE_WRITE` on removable
//!     mountpoints.
//!   * macOS — FSEvents stream rooted at `/Volumes/*`.
//!   * Windows — ETW `Microsoft-Windows-Kernel-File` filtered by
//!     `DRIVE_REMOVABLE` from `GetDriveTypeW`.
//!
//! No enforcement. The table is ring-buffered at a soft cap so the
//! user's "pin this device's history" toggle prevents eviction.

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::db::DbError;

/// Default soft cap. Rows past this are evicted oldest-first when
/// the next [`record`] runs (so a one-shot bulk write does not bypass
/// the cap by completing within a single transaction).
pub const DEFAULT_RING_CAP: i64 = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbWriteEvent {
    pub id: Option<i64>,
    pub ts_utc: i64,
    pub device_vid: String,
    pub device_pid: String,
    pub device_serial: String,
    pub pid: Option<i32>,
    pub exe_path: Option<String>,
    pub target_path: String,
    pub bytes: i64,
}

pub fn ensure_schema(conn: &Connection) -> Result<(), DbError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS usb_write_events (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_utc        INTEGER NOT NULL,
            device_vid    TEXT NOT NULL,
            device_pid    TEXT NOT NULL,
            device_serial TEXT NOT NULL,
            pid           INTEGER,
            exe_path      TEXT,
            target_path   TEXT NOT NULL,
            bytes         INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_usb_write_serial_ts
            ON usb_write_events (device_serial, ts_utc DESC);
         CREATE TABLE IF NOT EXISTS usb_write_pinned (
            device_vid    TEXT NOT NULL,
            device_pid    TEXT NOT NULL,
            device_serial TEXT NOT NULL,
            PRIMARY KEY (device_vid, device_pid, device_serial)
         );",
    )?;
    Ok(())
}

pub fn record(conn: &Connection, event: &UsbWriteEvent, ring_cap: i64) -> Result<i64, DbError> {
    let id = {
        conn.execute(
            "INSERT INTO usb_write_events (ts_utc, device_vid, device_pid, device_serial,
                                            pid, exe_path, target_path, bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                event.ts_utc,
                event.device_vid,
                event.device_pid,
                event.device_serial,
                event.pid,
                event.exe_path,
                event.target_path,
                event.bytes
            ],
        )?;
        conn.last_insert_rowid()
    };
    enforce_ring_cap(conn, ring_cap)?;
    Ok(id)
}

/// Drop oldest rows past `ring_cap`, excluding rows whose
/// `(vid, pid, serial)` is pinned via [`pin_device`].
fn enforce_ring_cap(conn: &Connection, ring_cap: i64) -> Result<(), DbError> {
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM usb_write_events", [], |r| r.get(0))?;
    if total <= ring_cap {
        return Ok(());
    }
    let to_evict = total - ring_cap;
    conn.execute(
        "DELETE FROM usb_write_events
          WHERE id IN (
            SELECT e.id
              FROM usb_write_events e
              LEFT JOIN usb_write_pinned p
                ON e.device_vid = p.device_vid
               AND e.device_pid = p.device_pid
               AND e.device_serial = p.device_serial
             WHERE p.device_vid IS NULL
             ORDER BY e.ts_utc ASC
             LIMIT ?1
          )",
        [to_evict],
    )?;
    Ok(())
}

pub fn query_by_serial(
    conn: &Connection,
    serial: &str,
    limit: i64,
) -> Result<Vec<UsbWriteEvent>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT id, ts_utc, device_vid, device_pid, device_serial, pid, exe_path,
                target_path, bytes
           FROM usb_write_events
          WHERE device_serial = ?1
          ORDER BY ts_utc DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![serial, limit], |r| {
        Ok(UsbWriteEvent {
            id: r.get(0)?,
            ts_utc: r.get(1)?,
            device_vid: r.get(2)?,
            device_pid: r.get(3)?,
            device_serial: r.get(4)?,
            pid: r.get(5)?,
            exe_path: r.get(6)?,
            target_path: r.get(7)?,
            bytes: r.get(8)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn pin_device(conn: &Connection, vid: &str, pid: &str, serial: &str) -> Result<(), DbError> {
    conn.execute(
        "INSERT OR IGNORE INTO usb_write_pinned (device_vid, device_pid, device_serial)
         VALUES (?1, ?2, ?3)",
        params![vid, pid, serial],
    )?;
    Ok(())
}

pub fn is_pinned(conn: &Connection, vid: &str, pid: &str, serial: &str) -> Result<bool, DbError> {
    let row: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM usb_write_pinned
              WHERE device_vid = ?1 AND device_pid = ?2 AND device_serial = ?3",
            params![vid, pid, serial],
            |r| r.get(0),
        )
        .optional()?;
    Ok(row.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        ensure_schema(&c).unwrap();
        c
    }

    fn ev(serial: &str, ts: i64) -> UsbWriteEvent {
        UsbWriteEvent {
            id: None,
            ts_utc: ts,
            device_vid: "0951".into(),
            device_pid: "1665".into(),
            device_serial: serial.into(),
            pid: Some(1234),
            exe_path: Some("/usr/bin/cp".into()),
            target_path: format!("/mnt/usb/{ts}.bin"),
            bytes: 1_000_000,
        }
    }

    #[test]
    fn record_and_query() {
        let c = db();
        record(&c, &ev("A", 1), DEFAULT_RING_CAP).unwrap();
        record(&c, &ev("A", 2), DEFAULT_RING_CAP).unwrap();
        record(&c, &ev("B", 3), DEFAULT_RING_CAP).unwrap();
        let rows = query_by_serial(&c, "A", 10).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].ts_utc, 2);
    }

    #[test]
    fn ring_cap_evicts_oldest_unpinned() {
        let c = db();
        // Insert 5 rows, cap at 3 → expect 3 newest survive.
        for ts in 1..=5 {
            record(&c, &ev("A", ts), 3).unwrap();
        }
        let rows = query_by_serial(&c, "A", 100).unwrap();
        assert_eq!(rows.len(), 3);
        // Newest ts should be 5, oldest of survivors 3.
        assert_eq!(rows[0].ts_utc, 5);
        assert_eq!(rows[2].ts_utc, 3);
    }

    #[test]
    fn pinned_device_survives_eviction() {
        let c = db();
        pin_device(&c, "0951", "1665", "A").unwrap();
        assert!(is_pinned(&c, "0951", "1665", "A").unwrap());
        for ts in 1..=10 {
            record(&c, &ev("A", ts), 3).unwrap();
        }
        // Cap is 3 — but A is pinned, so all 10 rows survive.
        let rows = query_by_serial(&c, "A", 100).unwrap();
        assert_eq!(rows.len(), 10);
    }
}
