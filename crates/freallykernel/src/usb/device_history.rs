//! Per-device USB scan history (TASK-250, Phase 8 Wave 2).
//!
//! Persists first-/last-seen timestamps, scan counts, and per-file
//! quick-hash records so re-insertion of the same USB drive can
//! short-circuit re-hashing on unchanged files.
//!
//! `is_unchanged(device, path, quick_hash)` returns true when the
//! prior recorded quick-hash matches; the engine then skips re-hashing
//! and reuses the prior verdict. Quick-hash is BLAKE3 over the first
//! 64 KiB + file size (computed in [`quick_hash_bytes`]).
//!
//! Per § 1.5.2 the history is local — no telemetry, never sent.

use std::io::Read;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::db::DbError;

/// Quick-hash sniffs the first N bytes plus file size. 64 KiB is the
/// roadmap default — small enough to be cheap on a USB stick, large
/// enough that two different binaries are extremely unlikely to
/// collide.
pub const QUICK_HASH_PREFIX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRow {
    pub vid: String,
    pub pid: String,
    pub serial: String,
    pub first_seen_utc: i64,
    pub last_seen_utc: i64,
    pub scan_count: i64,
    pub last_verdict: String,
}

pub fn ensure_schema(conn: &Connection) -> Result<(), DbError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS usb_device_history (
            vid             TEXT NOT NULL,
            pid             TEXT NOT NULL,
            serial          TEXT NOT NULL,
            first_seen_utc  INTEGER NOT NULL,
            last_seen_utc   INTEGER NOT NULL,
            scan_count      INTEGER NOT NULL DEFAULT 0,
            last_verdict    TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (vid, pid, serial)
         );
         CREATE TABLE IF NOT EXISTS usb_device_files (
            vid                TEXT NOT NULL,
            pid                TEXT NOT NULL,
            serial             TEXT NOT NULL,
            path               TEXT NOT NULL,
            quick_hash_hex     TEXT NOT NULL,
            size_bytes         INTEGER NOT NULL,
            last_scanned_utc   INTEGER NOT NULL,
            last_verdict       TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (vid, pid, serial, path)
         );",
    )?;
    Ok(())
}

/// Update first/last-seen + bump scan_count for a device. Called on
/// every insert event (TASK-241 path).
pub fn on_insert(
    conn: &Connection,
    vid: &str,
    pid: &str,
    serial: &str,
    now_utc: i64,
) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO usb_device_history (vid, pid, serial, first_seen_utc, last_seen_utc, scan_count, last_verdict)
         VALUES (?1, ?2, ?3, ?4, ?4, 1, '')
         ON CONFLICT(vid, pid, serial) DO UPDATE
            SET last_seen_utc = excluded.last_seen_utc,
                scan_count    = usb_device_history.scan_count + 1",
        params![vid, pid, serial, now_utc],
    )?;
    Ok(())
}

pub fn set_verdict(
    conn: &Connection,
    vid: &str,
    pid: &str,
    serial: &str,
    verdict: &str,
) -> Result<(), DbError> {
    conn.execute(
        "UPDATE usb_device_history SET last_verdict = ?4
          WHERE vid = ?1 AND pid = ?2 AND serial = ?3",
        params![vid, pid, serial, verdict],
    )?;
    Ok(())
}

pub fn get(
    conn: &Connection,
    vid: &str,
    pid: &str,
    serial: &str,
) -> Result<Option<DeviceRow>, DbError> {
    let row = conn
        .query_row(
            "SELECT vid, pid, serial, first_seen_utc, last_seen_utc, scan_count, last_verdict
               FROM usb_device_history
              WHERE vid = ?1 AND pid = ?2 AND serial = ?3",
            params![vid, pid, serial],
            |r| {
                Ok(DeviceRow {
                    vid: r.get(0)?,
                    pid: r.get(1)?,
                    serial: r.get(2)?,
                    first_seen_utc: r.get(3)?,
                    last_seen_utc: r.get(4)?,
                    scan_count: r.get(5)?,
                    last_verdict: r.get(6)?,
                })
            },
        )
        .optional()?;
    Ok(row)
}

pub fn list(conn: &Connection) -> Result<Vec<DeviceRow>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT vid, pid, serial, first_seen_utc, last_seen_utc, scan_count, last_verdict
           FROM usb_device_history
           ORDER BY last_seen_utc DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(DeviceRow {
            vid: r.get(0)?,
            pid: r.get(1)?,
            serial: r.get(2)?,
            first_seen_utc: r.get(3)?,
            last_seen_utc: r.get(4)?,
            scan_count: r.get(5)?,
            last_verdict: r.get(6)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Per-file scan record. Bundled into a struct (rather than nine positional
/// args) so the call site stays readable and the function fits the
/// 7-argument clippy budget.
#[derive(Debug, Clone)]
pub struct FileScanRecord<'a> {
    pub vid: &'a str,
    pub pid: &'a str,
    pub serial: &'a str,
    pub path: &'a str,
    pub quick_hash_hex: &'a str,
    pub size_bytes: i64,
    pub now_utc: i64,
    pub verdict: &'a str,
}

/// Record a per-file scan outcome. Used by the engine's insert-scan
/// path so the next insert can short-circuit re-hashing.
pub fn record_file(conn: &Connection, rec: &FileScanRecord<'_>) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO usb_device_files (vid, pid, serial, path, quick_hash_hex, size_bytes,
                                        last_scanned_utc, last_verdict)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(vid, pid, serial, path) DO UPDATE
            SET quick_hash_hex   = excluded.quick_hash_hex,
                size_bytes       = excluded.size_bytes,
                last_scanned_utc = excluded.last_scanned_utc,
                last_verdict     = excluded.last_verdict",
        params![
            rec.vid,
            rec.pid,
            rec.serial,
            rec.path,
            rec.quick_hash_hex,
            rec.size_bytes,
            rec.now_utc,
            rec.verdict
        ],
    )?;
    Ok(())
}

/// True when `(vid, pid, serial, path)` already exists in the history
/// with an identical `(quick_hash_hex, size_bytes)`. The engine uses
/// this as a short-circuit before computing the full BLAKE3.
pub fn is_unchanged(
    conn: &Connection,
    vid: &str,
    pid: &str,
    serial: &str,
    path: &str,
    quick_hash_hex: &str,
    size_bytes: i64,
) -> Result<bool, DbError> {
    let row: Option<(String, i64)> = conn
        .query_row(
            "SELECT quick_hash_hex, size_bytes FROM usb_device_files
              WHERE vid = ?1 AND pid = ?2 AND serial = ?3 AND path = ?4",
            params![vid, pid, serial, path],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
        )
        .optional()?;
    Ok(row.is_some_and(|(h, s)| h == quick_hash_hex && s == size_bytes))
}

/// Compute the quick-hash for a path: BLAKE3 over the first
/// [`QUICK_HASH_PREFIX_BYTES`] (or less if the file is smaller).
/// Caller is expected to record the file size alongside.
pub fn quick_hash_path(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; QUICK_HASH_PREFIX_BYTES];
    let mut read = 0;
    while read < buf.len() {
        match f.read(&mut buf[read..])? {
            0 => break,
            n => read += n,
        }
    }
    buf.truncate(read);
    Ok(quick_hash_bytes(&buf))
}

/// Pure helper for tests + the path variant. BLAKE3 of the slice.
pub fn quick_hash_bytes(bytes: &[u8]) -> String {
    let h = blake3::hash(bytes);
    hex::encode(h.as_bytes())
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
    fn on_insert_creates_then_bumps_scan_count() {
        let c = db();
        on_insert(&c, "0951", "1665", "AA", 100).unwrap();
        let row = get(&c, "0951", "1665", "AA").unwrap().unwrap();
        assert_eq!(row.scan_count, 1);
        on_insert(&c, "0951", "1665", "AA", 200).unwrap();
        let row = get(&c, "0951", "1665", "AA").unwrap().unwrap();
        assert_eq!(row.scan_count, 2);
        assert_eq!(row.last_seen_utc, 200);
        // first_seen_utc stays at 100.
        assert_eq!(row.first_seen_utc, 100);
    }

    #[test]
    fn is_unchanged_true_on_identical_hash_and_size() {
        let c = db();
        let h = quick_hash_bytes(b"hello world");
        record_file(
            &c,
            &FileScanRecord {
                vid: "0951",
                pid: "1665",
                serial: "AA",
                path: "/x/foo",
                quick_hash_hex: &h,
                size_bytes: 11,
                now_utc: 1,
                verdict: "clean",
            },
        )
        .unwrap();
        assert!(is_unchanged(&c, "0951", "1665", "AA", "/x/foo", &h, 11).unwrap());
        // Size differs → not unchanged.
        assert!(!is_unchanged(&c, "0951", "1665", "AA", "/x/foo", &h, 12).unwrap());
        // Hash differs → not unchanged.
        let other = quick_hash_bytes(b"different");
        assert!(!is_unchanged(&c, "0951", "1665", "AA", "/x/foo", &other, 11).unwrap());
    }

    #[test]
    fn list_orders_by_last_seen_desc() {
        let c = db();
        on_insert(&c, "0951", "1665", "A", 100).unwrap();
        on_insert(&c, "0951", "1665", "B", 200).unwrap();
        let items = list(&c).unwrap();
        assert_eq!(items[0].serial, "B");
        assert_eq!(items[1].serial, "A");
    }
}
