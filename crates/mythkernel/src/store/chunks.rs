//! TASK-231 — Chunk store for FastCDC selective rehash.
//!
//! Schema:
//! ```sql
//! CREATE TABLE IF NOT EXISTS chunks (
//!   file_id        INTEGER NOT NULL,
//!   chunk_index    INTEGER NOT NULL,
//!   chunk_offset   INTEGER NOT NULL,
//!   chunk_len      INTEGER NOT NULL,
//!   chunk_blake3   BLOB    NOT NULL,
//!   PRIMARY KEY (file_id, chunk_index)
//! );
//! ```
//!
//! Insert paths use `INSERT OR REPLACE` so a rescan that changes a
//! chunk index's blake3 overwrites the previous row deterministically.
//! `lookup_prior_chunks(file_id)` returns the chunks in
//! `chunk_index` ascending order so the engine can do an O(n) zip
//! against the new chunk list to find changed chunks.

use rusqlite::{Connection, Result, params};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRow {
    pub file_id: i64,
    pub chunk_index: u32,
    pub chunk_offset: u64,
    pub chunk_len: u32,
    pub chunk_blake3: [u8; 32],
}

pub fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS chunks (
            file_id        INTEGER NOT NULL,
            chunk_index    INTEGER NOT NULL,
            chunk_offset   INTEGER NOT NULL,
            chunk_len      INTEGER NOT NULL,
            chunk_blake3   BLOB    NOT NULL,
            PRIMARY KEY (file_id, chunk_index)
        )",
        [],
    )?;
    Ok(())
}

pub fn put_chunk(conn: &Connection, row: &ChunkRow) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO chunks (file_id, chunk_index, chunk_offset, chunk_len, chunk_blake3)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            row.file_id,
            row.chunk_index as i64,
            row.chunk_offset as i64,
            row.chunk_len as i64,
            &row.chunk_blake3 as &[u8],
        ],
    )?;
    Ok(())
}

pub fn put_chunks(conn: &mut Connection, rows: &[ChunkRow]) -> Result<()> {
    let tx = conn.transaction()?;
    for row in rows {
        tx.execute(
            "INSERT OR REPLACE INTO chunks (file_id, chunk_index, chunk_offset, chunk_len, chunk_blake3)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                row.file_id,
                row.chunk_index as i64,
                row.chunk_offset as i64,
                row.chunk_len as i64,
                &row.chunk_blake3 as &[u8],
            ],
        )?;
    }
    tx.commit()
}

pub fn lookup_prior_chunks(conn: &Connection, file_id: i64) -> Result<Vec<ChunkRow>> {
    let mut stmt = conn.prepare(
        "SELECT chunk_index, chunk_offset, chunk_len, chunk_blake3
         FROM chunks WHERE file_id = ?1 ORDER BY chunk_index",
    )?;
    let rows = stmt.query_map(params![file_id], |row| {
        let chunk_index: i64 = row.get(0)?;
        let chunk_offset: i64 = row.get(1)?;
        let chunk_len: i64 = row.get(2)?;
        let blob: Vec<u8> = row.get(3)?;
        let mut blake3 = [0u8; 32];
        let copy_len = blob.len().min(32);
        blake3[..copy_len].copy_from_slice(&blob[..copy_len]);
        Ok(ChunkRow {
            file_id,
            chunk_index: chunk_index as u32,
            chunk_offset: chunk_offset as u64,
            chunk_len: chunk_len as u32,
            chunk_blake3: blake3,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn clear_file(conn: &Connection, file_id: i64) -> Result<()> {
    conn.execute("DELETE FROM chunks WHERE file_id = ?1", params![file_id])?;
    Ok(())
}

pub fn clear_all(conn: &Connection) -> Result<()> {
    conn.execute("DELETE FROM chunks", [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        conn
    }

    fn row(file_id: i64, idx: u32, offset: u64, len: u32, byte: u8) -> ChunkRow {
        ChunkRow {
            file_id,
            chunk_index: idx,
            chunk_offset: offset,
            chunk_len: len,
            chunk_blake3: [byte; 32],
        }
    }

    #[test]
    fn put_and_lookup_round_trip() {
        let conn = fresh_conn();
        put_chunk(&conn, &row(1, 0, 0, 1024, 0xAB)).unwrap();
        let chunks = lookup_prior_chunks(&conn, 1).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].chunk_blake3, [0xAB; 32]);
        assert_eq!(chunks[0].chunk_len, 1024);
    }

    #[test]
    fn put_replaces_existing_chunk_index() {
        let conn = fresh_conn();
        put_chunk(&conn, &row(1, 5, 0, 100, 0x11)).unwrap();
        put_chunk(&conn, &row(1, 5, 0, 100, 0x22)).unwrap();
        let chunks = lookup_prior_chunks(&conn, 1).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].chunk_blake3[0], 0x22);
    }

    #[test]
    fn lookup_orders_by_chunk_index() {
        let conn = fresh_conn();
        put_chunk(&conn, &row(1, 2, 200, 100, 0xCC)).unwrap();
        put_chunk(&conn, &row(1, 0, 0, 100, 0xAA)).unwrap();
        put_chunk(&conn, &row(1, 1, 100, 100, 0xBB)).unwrap();
        let chunks = lookup_prior_chunks(&conn, 1).unwrap();
        let indices: Vec<u32> = chunks.iter().map(|c| c.chunk_index).collect();
        assert_eq!(indices, vec![0, 1, 2]);
    }

    #[test]
    fn lookup_filters_by_file_id() {
        let conn = fresh_conn();
        put_chunk(&conn, &row(1, 0, 0, 100, 0xAA)).unwrap();
        put_chunk(&conn, &row(2, 0, 0, 100, 0xBB)).unwrap();
        let chunks = lookup_prior_chunks(&conn, 1).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].chunk_blake3[0], 0xAA);
    }

    #[test]
    fn put_chunks_batch_commits() {
        let mut conn = fresh_conn();
        let rows = vec![
            row(7, 0, 0, 100, 0xAA),
            row(7, 1, 100, 100, 0xBB),
            row(7, 2, 200, 100, 0xCC),
        ];
        put_chunks(&mut conn, &rows).unwrap();
        let chunks = lookup_prior_chunks(&conn, 7).unwrap();
        assert_eq!(chunks.len(), 3);
    }

    #[test]
    fn clear_file_only_removes_target_file() {
        let conn = fresh_conn();
        put_chunk(&conn, &row(1, 0, 0, 100, 0xAA)).unwrap();
        put_chunk(&conn, &row(2, 0, 0, 100, 0xBB)).unwrap();
        clear_file(&conn, 1).unwrap();
        assert_eq!(lookup_prior_chunks(&conn, 1).unwrap().len(), 0);
        assert_eq!(lookup_prior_chunks(&conn, 2).unwrap().len(), 1);
    }

    #[test]
    fn clear_all_wipes_table() {
        let conn = fresh_conn();
        put_chunk(&conn, &row(1, 0, 0, 100, 0xAA)).unwrap();
        clear_all(&conn).unwrap();
        assert_eq!(lookup_prior_chunks(&conn, 1).unwrap().len(), 0);
    }

    #[test]
    fn schema_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        ensure_schema(&conn).unwrap();
    }
}
