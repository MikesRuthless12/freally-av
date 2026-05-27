//! TASK-226 — Per-machine baseline table.
//!
//! Schema:
//! ```sql
//! CREATE TABLE IF NOT EXISTS baseline (
//!   cell_key  TEXT PRIMARY KEY,
//!   count     INTEGER NOT NULL
//! );
//! ```
//!
//! `cell_key` is the deterministic string encoding of
//! `(extension, size_decile, entropy_bucket, hardening_score)` —
//! produced by [`CellKey::encode`]. Plain string lets us use one
//! `UPSERT` to fold a row's contribution into the prior:
//!
//! ```sql
//! INSERT INTO baseline(cell_key, count) VALUES(?, 1)
//!   ON CONFLICT(cell_key) DO UPDATE SET count = count + 1;
//! ```
//!
//! Storing rows here rather than in the in-memory `Anomaly` lets
//! the prior survive process restarts. The aging job from TASK-181
//! decays old buckets every N days; we don't enforce decay here.

use rusqlite::{Connection, OptionalExtension, Result, params};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CellKey {
    pub extension: String,
    pub size_decile: u8,
    pub entropy_bucket: u8,
    pub hardening_score: u8,
}

impl CellKey {
    /// Pack into a deterministic string of the form
    /// `"{ext}|{size}|{entropy}|{hard}"`. The extension is
    /// lowercased so case-insensitive fs matches don't double-bucket.
    pub fn encode(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.extension.to_ascii_lowercase(),
            self.size_decile,
            self.entropy_bucket,
            self.hardening_score
        )
    }

    /// Inverse of [`Self::encode`]. Returns `None` on malformed input.
    pub fn decode(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.splitn(4, '|').collect();
        if parts.len() != 4 {
            return None;
        }
        Some(Self {
            extension: parts[0].to_string(),
            size_decile: parts[1].parse().ok()?,
            entropy_bucket: parts[2].parse().ok()?,
            hardening_score: parts[3].parse().ok()?,
        })
    }
}

/// Create the `baseline` table if missing.
pub fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS baseline (
            cell_key  TEXT PRIMARY KEY,
            count     INTEGER NOT NULL
        )",
        [],
    )?;
    Ok(())
}

/// Fold one observation into the prior.
pub fn bump(conn: &Connection, key: &CellKey) -> Result<()> {
    conn.execute(
        "INSERT INTO baseline(cell_key, count) VALUES(?1, 1)
         ON CONFLICT(cell_key) DO UPDATE SET count = count + 1",
        params![key.encode()],
    )?;
    Ok(())
}

/// Fold a batch of observations atomically.
pub fn bump_batch(conn: &mut Connection, keys: &[CellKey]) -> Result<()> {
    let tx = conn.transaction()?;
    for k in keys {
        tx.execute(
            "INSERT INTO baseline(cell_key, count) VALUES(?1, 1)
             ON CONFLICT(cell_key) DO UPDATE SET count = count + 1",
            params![k.encode()],
        )?;
    }
    tx.commit()
}

/// Look up the current count for a key, or 0 if absent.
pub fn count_for(conn: &Connection, key: &CellKey) -> Result<u64> {
    let n: Option<i64> = conn
        .query_row(
            "SELECT count FROM baseline WHERE cell_key = ?1",
            params![key.encode()],
            |row| row.get(0),
        )
        .optional()?;
    Ok(n.unwrap_or(0).max(0) as u64)
}

/// Total number of distinct cells (rows in the table).
pub fn cell_count(conn: &Connection) -> Result<u64> {
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM baseline", [], |row| row.get(0))?;
    Ok(n.max(0) as u64)
}

/// Drop every row. Used by tests + the user-initiated "rebuild
/// baseline" flow.
pub fn clear(conn: &Connection) -> Result<()> {
    conn.execute("DELETE FROM baseline", [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(ext: &str, size: u8, entropy: u8, hard: u8) -> CellKey {
        CellKey {
            extension: ext.into(),
            size_decile: size,
            entropy_bucket: entropy,
            hardening_score: hard,
        }
    }

    fn fresh_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn encode_decode_round_trips() {
        let k = key("EXE", 3, 5, 2);
        let s = k.encode();
        let k2 = CellKey::decode(&s).unwrap();
        // Lowercase normalisation: extension comes back lowercase.
        assert_eq!(k2.extension, "exe");
        assert_eq!(k2.size_decile, 3);
        assert_eq!(k2.entropy_bucket, 5);
        assert_eq!(k2.hardening_score, 2);
    }

    #[test]
    fn decode_rejects_malformed_input() {
        assert!(CellKey::decode("exe|3|5").is_none());
        assert!(CellKey::decode("exe|x|5|2").is_none());
    }

    #[test]
    fn bump_starts_at_one_then_increments() {
        let conn = fresh_conn();
        let k = key("exe", 3, 5, 2);
        bump(&conn, &k).unwrap();
        assert_eq!(count_for(&conn, &k).unwrap(), 1);
        bump(&conn, &k).unwrap();
        assert_eq!(count_for(&conn, &k).unwrap(), 2);
    }

    #[test]
    fn distinct_cells_independent() {
        let conn = fresh_conn();
        bump(&conn, &key("exe", 3, 5, 2)).unwrap();
        bump(&conn, &key("dll", 4, 5, 2)).unwrap();
        bump(&conn, &key("dll", 4, 5, 2)).unwrap();
        assert_eq!(count_for(&conn, &key("exe", 3, 5, 2)).unwrap(), 1);
        assert_eq!(count_for(&conn, &key("dll", 4, 5, 2)).unwrap(), 2);
    }

    #[test]
    fn case_insensitive_extension_buckets_correctly() {
        let conn = fresh_conn();
        bump(&conn, &key("EXE", 3, 5, 2)).unwrap();
        bump(&conn, &key("exe", 3, 5, 2)).unwrap();
        // Same bucket — count is 2, not two distinct rows.
        assert_eq!(count_for(&conn, &key("exe", 3, 5, 2)).unwrap(), 2);
        assert_eq!(cell_count(&conn).unwrap(), 1);
    }

    #[test]
    fn count_for_absent_key_returns_zero() {
        let conn = fresh_conn();
        assert_eq!(count_for(&conn, &key("never_seen", 1, 1, 1)).unwrap(), 0);
    }

    #[test]
    fn clear_resets_table() {
        let conn = fresh_conn();
        for _ in 0..5 {
            bump(&conn, &key("exe", 3, 5, 2)).unwrap();
        }
        clear(&conn).unwrap();
        assert_eq!(cell_count(&conn).unwrap(), 0);
    }

    #[test]
    fn bump_batch_atomic_count() {
        let mut conn = fresh_conn();
        let keys = vec![
            key("exe", 1, 1, 1),
            key("exe", 1, 1, 1),
            key("dll", 2, 2, 2),
        ];
        bump_batch(&mut conn, &keys).unwrap();
        assert_eq!(count_for(&conn, &key("exe", 1, 1, 1)).unwrap(), 2);
        assert_eq!(count_for(&conn, &key("dll", 2, 2, 2)).unwrap(), 1);
    }

    #[test]
    fn ensure_schema_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        ensure_schema(&conn).unwrap(); // no panic
    }
}
