//! SQLite connection + migrations for the engine's persistent store.
//!
//! Phase 1 (TASK-011) ships migration `0001_initial.sql`. Future phases add
//! their own migrations alongside (`0002_...`, `0003_...`) — each is run in
//! filename order at startup if it has not already been recorded in
//! `schema_migrations`.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("../migrations/0001_initial.sql")),
    (2, include_str!("../migrations/0002_quarantine_batches.sql")),
];

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not resolve a per-user data directory")]
    NoDataDir,
    #[error("database lock poisoned (holder thread panicked)")]
    Poisoned,
}

/// Resolve the canonical engine data directory, creating it if missing. Per
/// `docs/prd.md` § 3 (line 256-258) — uses platform-native local-data paths,
/// **not** the synthetic bundle-id paths `directories::ProjectDirs` would
/// produce.
///
/// - Windows: `%LOCALAPPDATA%\Mythodikal\`
/// - macOS:   `~/Library/Application Support/Mythodikal/`
/// - Linux:   `$XDG_DATA_HOME/mythodikal/` or `~/.local/share/mythodikal/`
pub fn default_data_dir() -> Result<PathBuf, DbError> {
    let base = directories::BaseDirs::new().ok_or(DbError::NoDataDir)?;
    let dir = if cfg!(target_os = "windows") {
        base.data_local_dir().join("Mythodikal")
    } else if cfg!(target_os = "macos") {
        base.data_dir().join("Mythodikal")
    } else {
        base.data_dir().join("mythodikal")
    };
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
    let mut conn = Connection::open(path)?;
    configure_connection(&conn)?;
    apply_migrations(&mut conn)?;
    Ok(conn)
}

/// Open an in-memory database (used by tests and the engine when running
/// `--ephemeral`).
pub fn open_in_memory() -> Result<Connection, DbError> {
    let mut conn = Connection::open_in_memory()?;
    configure_connection(&conn)?;
    apply_migrations(&mut conn)?;
    Ok(conn)
}

/// Apply per-connection PRAGMAs that **must** run outside any transaction
/// (notably `journal_mode = WAL`, which fails with "Safety level may not be
/// changed inside a transaction" otherwise). For in-memory DBs the journal
/// pragma is a no-op; we still set `foreign_keys = ON` everywhere.
fn configure_connection(conn: &Connection) -> Result<(), DbError> {
    conn.pragma_update(None, "foreign_keys", "ON")?;
    // WAL is only meaningful on file-backed databases; SQLite returns "memory"
    // for in-memory DBs and silently ignores the change request.
    let _: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    Ok(())
}

fn apply_migrations(conn: &mut Connection) -> Result<(), DbError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at_utc INTEGER NOT NULL
        );",
    )?;

    for (version, sql) in MIGRATIONS {
        let already_applied: bool = match conn.query_row(
            "SELECT 1 FROM schema_migrations WHERE version = ?1",
            [version],
            |_| Ok(true),
        ) {
            Ok(_) => true,
            Err(rusqlite::Error::QueryReturnedNoRows) => false,
            Err(e) => return Err(e.into()),
        };
        if already_applied {
            continue;
        }

        // Run the migration body and the version-recording row in one
        // transaction so a partially-applied migration leaves no marker —
        // the next startup will retry it cleanly.
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at_utc) VALUES (?1, ?2)",
            [
                *version,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            ],
        )?;
        tx.commit()?;
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
            "quarantine_batches",
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
        let mut conn = open_in_memory().unwrap();
        apply_migrations(&mut conn).unwrap();
        apply_migrations(&mut conn).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, MIGRATIONS.len() as i64);
    }
}
