//! USB power-only override (TASK-244, Phase 8 Wave 2).
//!
//! Per-port toggle that suppresses storage mounting on a flagged port.
//! Linux: writes `0` to `/sys/bus/usb/devices/<port>/bConfigurationValue`
//! to unbind interfaces. macOS: `IOServiceClose` on the mass-storage
//! interface user-client. Windows: **never auto-applies** — surfaces a
//! hint card pointing to Device Manager. All per § 1.5.4
//! (no kernel driver, no filter driver).
//!
//! The toggle name "power-only" matches the user mental model; the UI
//! tooltip is explicit that this does NOT physically limit power
//! delivery — it only suppresses mounting.
//!
//! This module owns the **store** and the **policy lookup**. Each
//! per-OS daemon owns the actual unbind/diskutil/devmgmt step.

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::db::DbError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerOnlyEntry {
    pub port_path: String,
    pub label: String,
    pub enabled: bool,
}

pub fn ensure_schema(conn: &Connection) -> Result<(), DbError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS usb_power_only (
            port_path TEXT PRIMARY KEY,
            label     TEXT NOT NULL DEFAULT '',
            enabled   INTEGER NOT NULL DEFAULT 1
         );",
    )?;
    Ok(())
}

/// True iff `port_path` is currently set to power-only.
pub fn is_power_only(conn: &Connection, port_path: &str) -> Result<bool, DbError> {
    let row: Option<i64> = conn
        .query_row(
            "SELECT enabled FROM usb_power_only WHERE port_path = ?1",
            [port_path],
            |r| r.get(0),
        )
        .optional()?;
    Ok(matches!(row, Some(1)))
}

pub fn enable(conn: &Connection, port_path: &str, label: &str) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO usb_power_only (port_path, label, enabled) VALUES (?1, ?2, 1)
         ON CONFLICT(port_path) DO UPDATE SET label=excluded.label, enabled=1",
        params![port_path, label],
    )?;
    Ok(())
}

pub fn disable(conn: &Connection, port_path: &str) -> Result<(), DbError> {
    conn.execute(
        "UPDATE usb_power_only SET enabled=0 WHERE port_path=?1",
        [port_path],
    )?;
    Ok(())
}

pub fn list(conn: &Connection) -> Result<Vec<PowerOnlyEntry>, DbError> {
    let mut stmt = conn
        .prepare("SELECT port_path, label, enabled FROM usb_power_only ORDER BY port_path ASC")?;
    let rows = stmt.query_map([], |r| {
        Ok(PowerOnlyEntry {
            port_path: r.get(0)?,
            label: r.get(1)?,
            enabled: r.get::<_, i64>(2)? == 1,
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
    fn enable_marks_port_power_only() {
        let c = db();
        enable(&c, "1-3.2", "front-left").unwrap();
        assert!(is_power_only(&c, "1-3.2").unwrap());
        assert!(!is_power_only(&c, "1-3.3").unwrap());
    }

    #[test]
    fn disable_keeps_row_but_clears_flag() {
        let c = db();
        enable(&c, "1-3.2", "front-left").unwrap();
        disable(&c, "1-3.2").unwrap();
        assert!(!is_power_only(&c, "1-3.2").unwrap());
        let items = list(&c).unwrap();
        assert_eq!(items.len(), 1);
        assert!(!items[0].enabled);
    }
}
