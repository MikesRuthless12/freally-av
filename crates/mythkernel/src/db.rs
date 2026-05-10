//! SQLite connection + migrations for the engine's persistent store.
//!
//! Phase 1 (TASK-011) ships migration `0001_initial.sql`. Future phases add
//! their own migrations alongside (`0002_...`, `0003_...`) — each is run in
//! filename order at startup if it has not already been recorded in
//! `schema_migrations`.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

const MIGRATIONS: &[(i64, &str)] = &[(1, include_str!("../migrations/0001_initial.sql"))];

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not resolve a per-user data directory")]
    NoDataDir,
}

/// Resolve the canonical engine data directory, creating it if missing.
///
/// - Windows: `%LOCALAPPDATA%\Mythodikal\`
/// - macOS:   `~/Library/Application Support/com.mythodikal.av/`
/// - Linux:   `$XDG_DATA_HOME/mythodikal/` or `~/.local/share/mythodikal/`
pub fn default_data_dir() -> Result<PathBuf, DbError> {
    let dirs = directories::ProjectDirs::from("com", "Mythodikal", "Mythodikal")
        .ok_or(DbError::NoDataDir)?;
    let dir = dirs.data_dir().to_path_buf();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Default DB path: `<data_dir>/mythodikal.db`.
pub fn default_db_path() -> Result<PathBuf, DbError> {
    Ok(default_data_dir()?.join("mythodikal.db"))
}

/// Open a connection at `path`, applying any pending migrations. The parent
/// directory is created on demand.
pub fn open(path: &Path) -> Result<Connection, DbError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    apply_migrations(&conn)?;
    Ok(conn)
}

/// Open an in-memory database (used by tests and the engine when running
/// `--ephemeral`).
pub fn open_in_memory() -> Result<Connection, DbError> {
    let conn = Connection::open_in_memory()?;
    apply_migrations(&conn)?;
    Ok(conn)
}

fn apply_migrations(conn: &Connection) -> Result<(), DbError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at_utc INTEGER NOT NULL
        );",
    )?;

    for (version, sql) in MIGRATIONS {
        let already_applied: bool = conn
            .query_row(
                "SELECT 1 FROM schema_migrations WHERE version = ?1",
                [version],
                |_| Ok(true),
            )
            .unwrap_or(false);
        if already_applied {
            continue;
        }
        conn.execute_batch(sql)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_in_memory_creates_tables() {
        let conn = open_in_memory().unwrap();
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        for required in [
            "exclusions",
            "findings",
            "quarantine",
            "scans",
            "schema_migrations",
        ] {
            assert!(
                tables.contains(&required.to_string()),
                "missing table {required}; tables = {tables:?}"
            );
        }
    }

    #[test]
    fn idempotent_migrations() {
        let conn = open_in_memory().unwrap();
        apply_migrations(&conn).unwrap();
        apply_migrations(&conn).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
