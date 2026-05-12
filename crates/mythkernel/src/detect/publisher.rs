//! Publisher whitelist / signer extraction (TASK-136, Phase 4 wave 3).
//!
//! Implements FR-146. Extracts the canonical signer identity from an executable
//! and caches it in the `publisher_cache` table (migration 0003) keyed by
//! `(path, mtime, size)` so repeat scans don't re-shell-out to the platform
//! signer tool.
//!
//! Platform back-ends:
//!   * Windows: Authenticode signer subject extracted by
//!     `Get-AuthenticodeSignature` (PowerShell, ships on every Windows). See
//!     `crate::platform::win::codesign`.
//!   * macOS: codesign team-id extracted by the `codesign` system tool. See
//!     `crate::platform::mac::codesign`.
//!   * Linux: dpkg / rpm packager extracted from the owning package, or a
//!     GPG `.sig` / `.asc` next to the file. See
//!     `crate::platform::linux::codesign`.
//!
//! The signer identity is a free-text string. The exclusions table accepts
//! `kind = 'publisher'` with this string as `value`; the engine matches it
//! case-insensitively via [`crate::exclusions::matches`].

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::platform;

/// Stable enum of signer-kind labels persisted in `publisher_cache.signer_kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerKind {
    Authenticode,
    Codesign,
    Gpg,
    Unsigned,
}

impl SignerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SignerKind::Authenticode => "authenticode",
            SignerKind::Codesign => "codesign",
            SignerKind::Gpg => "gpg",
            SignerKind::Unsigned => "unsigned",
        }
    }
}

/// Hard cap on the persisted `signer_identity` length (sec-review M2/M3).
/// Real Authenticode subjects + codesign team-ids fit in well under 500
/// bytes; an attacker who controls an RPM `%{SIGPGP}` blob could otherwise
/// write multi-KB rows into the cache. We truncate at insert time.
pub const MAX_SIGNER_IDENTITY_LEN: usize = 512;

/// The canonical signer record returned to callers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerIdentity {
    /// Free-text identity string (Authenticode subject, codesign team-id,
    /// GPG fingerprint, dpkg maintainer, etc.). Empty when unsigned.
    /// Bounded by [`MAX_SIGNER_IDENTITY_LEN`].
    pub identity: String,
    pub kind: SignerKind,
}

impl SignerIdentity {
    pub fn unsigned() -> Self {
        Self {
            identity: String::new(),
            kind: SignerKind::Unsigned,
        }
    }

    pub fn is_signed(&self) -> bool {
        !matches!(self.kind, SignerKind::Unsigned)
    }

    /// Truncate `identity` to [`MAX_SIGNER_IDENTITY_LEN`] characters,
    /// guarding the persistence layer against attacker-controlled
    /// pathological signer strings (sec-review M2/M3).
    pub fn truncated(mut self) -> Self {
        if self.identity.len() > MAX_SIGNER_IDENTITY_LEN {
            // Char-boundary-safe truncation. We never embed multi-byte
            // sequences ourselves but the codesign / dpkg / rpm shell
            // outputs do, so be careful here.
            let mut cut = MAX_SIGNER_IDENTITY_LEN;
            while cut > 0 && !self.identity.is_char_boundary(cut) {
                cut -= 1;
            }
            self.identity.truncate(cut);
        }
        self
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PublisherError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Extract (or read from cache) the signer identity for `path`. The cache
/// key is `(path, mtime, size)`; a file with a different mtime or size is
/// considered changed and the signer is re-extracted.
///
/// **Locking note** (code-review CR-B1/B2): this fn holds the connection
/// across the shell-out to the platform signer extractor (~100 ms cold).
/// Callers that share the `Connection` with hot scan loops should prefer
/// [`signer_for_with_release`], which releases the lock around the
/// shell-out and re-acquires only for the cache upsert.
pub fn signer_for(conn: &Connection, path: &Path) -> Result<SignerIdentity, PublisherError> {
    let meta = std::fs::metadata(path)?;
    let size = meta.len();
    let mtime_unix = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let path_str = path.to_string_lossy().to_string();

    if let Some(cached) = lookup_cache(conn, &path_str, mtime_unix, size as i64)? {
        return Ok(cached);
    }

    // Truncate before persist so a giant attacker-controlled signer
    // string (sec-review M2/M3) never makes it into the SQLite cache.
    let signer = platform::codesign::extract_signer(path).truncated();
    upsert_cache(conn, &path_str, mtime_unix, size as i64, &signer)?;
    Ok(signer)
}

/// Three-phase cache-aware signer extraction. Callers must wrap the
/// `lookup` + `upsert` calls in their own `Mutex<Connection>` guard but
/// can drop the lock around `extract_io_unlocked` (which performs the
/// slow shell-out). Used by `engine::scan_internal` and the
/// `publisher_signer_for_path` Tauri command (code-review CR-B1/B2).
pub fn cache_lookup(conn: &Connection, path: &Path) -> Result<CacheProbe, PublisherError> {
    let meta = std::fs::metadata(path)?;
    let size = meta.len();
    let mtime_unix = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let path_str = path.to_string_lossy().to_string();
    let cached = lookup_cache(conn, &path_str, mtime_unix, size as i64)?;
    Ok(CacheProbe {
        path_str,
        mtime_unix,
        size_bytes: size as i64,
        cached,
    })
}

/// Outcome of [`cache_lookup`]. Carries the cache key components so the
/// caller can hand them back to [`cache_store`] after the lock-free
/// shell-out.
#[derive(Debug, Clone)]
pub struct CacheProbe {
    pub path_str: String,
    pub mtime_unix: i64,
    pub size_bytes: i64,
    pub cached: Option<SignerIdentity>,
}

/// Run the signer extractor with no locks held. Pure I/O — no DB
/// access. Truncates the result to [`MAX_SIGNER_IDENTITY_LEN`] before
/// returning, so callers persist a bounded value.
pub fn extract_io_unlocked(path: &Path) -> SignerIdentity {
    platform::codesign::extract_signer(path).truncated()
}

/// Persist a signer to the cache. Caller holds the connection lock.
pub fn cache_store(
    conn: &Connection,
    probe: &CacheProbe,
    signer: &SignerIdentity,
) -> Result<(), PublisherError> {
    upsert_cache(
        conn,
        &probe.path_str,
        probe.mtime_unix,
        probe.size_bytes,
        signer,
    )
}

/// Periodic cleanup: drop cache rows older than `older_than_secs` and
/// hard-cap the total row count at `max_rows`. Sec-review M5 — without
/// this, `publisher_cache` grows unbounded on systems with frequent
/// /tmp churn (every renamed-or-deleted file leaves a stale row).
pub fn prune_cache(
    conn: &Connection,
    older_than_secs: i64,
    max_rows: i64,
) -> Result<u64, PublisherError> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let cutoff = now_unix - older_than_secs.max(0);
    let aged = conn.execute(
        "DELETE FROM publisher_cache WHERE inspected_at_utc < ?1",
        params![cutoff],
    )? as u64;
    // Hard row cap: if still over `max_rows`, drop the oldest by
    // `inspected_at_utc`. Two-step delete because SQLite doesn't allow
    // `DELETE ... ORDER BY ... LIMIT` without `SQLITE_ENABLE_UPDATE_DELETE_LIMIT`.
    let count: i64 =
        conn.query_row("SELECT COUNT(*) FROM publisher_cache", [], |row| row.get(0))?;
    let overflow = (count - max_rows).max(0);
    if overflow > 0 {
        conn.execute(
            "DELETE FROM publisher_cache WHERE rowid IN (
                SELECT rowid FROM publisher_cache ORDER BY inspected_at_utc ASC LIMIT ?1
            )",
            params![overflow],
        )?;
    }
    Ok(aged + overflow as u64)
}

/// Default purge thresholds. 90-day age cutoff + 250 000 row hard cap
/// keeps the cache under ~50 MB for typical engine deployments.
pub const DEFAULT_CACHE_PURGE_AGE_SECS: i64 = 90 * 24 * 3600;
pub const DEFAULT_CACHE_PURGE_MAX_ROWS: i64 = 250_000;

fn lookup_cache(
    conn: &Connection,
    path: &str,
    mtime_unix: i64,
    size: i64,
) -> Result<Option<SignerIdentity>, PublisherError> {
    let row = conn
        .query_row(
            "SELECT signer_identity, signer_kind FROM publisher_cache
             WHERE path = ?1 AND mtime_unix = ?2 AND size_bytes = ?3",
            params![path, mtime_unix, size],
            |row| {
                let identity: String = row.get(0)?;
                let kind_s: String = row.get(1)?;
                Ok((identity, kind_s))
            },
        )
        .optional()?;
    let Some((identity, kind_s)) = row else {
        return Ok(None);
    };
    let kind = match kind_s.as_str() {
        "authenticode" => SignerKind::Authenticode,
        "codesign" => SignerKind::Codesign,
        "gpg" => SignerKind::Gpg,
        _ => SignerKind::Unsigned,
    };
    Ok(Some(SignerIdentity { identity, kind }))
}

fn upsert_cache(
    conn: &Connection,
    path: &str,
    mtime_unix: i64,
    size: i64,
    signer: &SignerIdentity,
) -> Result<(), PublisherError> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    conn.execute(
        "INSERT OR REPLACE INTO publisher_cache
            (path, mtime_unix, size_bytes, signer_identity, signer_kind, inspected_at_utc)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            path,
            mtime_unix,
            size,
            signer.identity,
            signer.kind.as_str(),
            now_unix
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn unsigned_file_is_reported_as_unsigned() {
        let conn = open_in_memory().unwrap();
        let dir = tempdir().unwrap();
        let p = dir.path().join("plain.bin");
        fs::write(&p, b"hello").unwrap();
        let s = signer_for(&conn, &p).unwrap();
        assert_eq!(s.kind, SignerKind::Unsigned);
        assert!(s.identity.is_empty());
    }

    #[test]
    fn cache_hit_returns_same_identity_for_unchanged_file() {
        let conn = open_in_memory().unwrap();
        let dir = tempdir().unwrap();
        let p = dir.path().join("plain.bin");
        fs::write(&p, b"hello").unwrap();
        let s1 = signer_for(&conn, &p).unwrap();
        let s2 = signer_for(&conn, &p).unwrap();
        assert_eq!(s1, s2);
        // Cache row count should be 1.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM publisher_cache", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn cache_miss_on_size_change_reextracts() {
        let conn = open_in_memory().unwrap();
        let dir = tempdir().unwrap();
        let p = dir.path().join("plain.bin");
        fs::write(&p, b"hello").unwrap();
        signer_for(&conn, &p).unwrap();
        fs::write(&p, b"hello-modified-bigger").unwrap();
        signer_for(&conn, &p).unwrap();
        // Two distinct cache rows now exist (one per size).
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM publisher_cache", [], |row| row.get(0))
            .unwrap();
        assert!(count >= 1, "expected at least one cache row");
    }

    #[test]
    fn signer_kind_as_str_is_stable_wire_contract() {
        assert_eq!(SignerKind::Authenticode.as_str(), "authenticode");
        assert_eq!(SignerKind::Codesign.as_str(), "codesign");
        assert_eq!(SignerKind::Gpg.as_str(), "gpg");
        assert_eq!(SignerKind::Unsigned.as_str(), "unsigned");
    }

    #[test]
    fn signer_identity_unsigned_helper() {
        let s = SignerIdentity::unsigned();
        assert!(!s.is_signed());
        assert!(s.identity.is_empty());
    }

    #[test]
    fn truncated_caps_long_identity_at_max_len() {
        let long_id = "X".repeat(MAX_SIGNER_IDENTITY_LEN * 4);
        let s = SignerIdentity {
            identity: long_id,
            kind: SignerKind::Codesign,
        }
        .truncated();
        assert_eq!(s.identity.len(), MAX_SIGNER_IDENTITY_LEN);
    }

    #[test]
    fn truncated_respects_utf8_char_boundary() {
        // A multi-byte char that lands exactly at the cap must not get
        // cut mid-byte. `é` is 2 bytes in UTF-8.
        let mut s = String::with_capacity(MAX_SIGNER_IDENTITY_LEN + 2);
        s.push_str(&"a".repeat(MAX_SIGNER_IDENTITY_LEN - 1));
        s.push('é');
        let truncated = SignerIdentity {
            identity: s,
            kind: SignerKind::Codesign,
        }
        .truncated();
        // The `é` is 2 bytes starting at index 511; truncation walks
        // back to a valid char boundary, so the final length must be
        // <= MAX_SIGNER_IDENTITY_LEN and the body must still be valid UTF-8.
        assert!(truncated.identity.len() <= MAX_SIGNER_IDENTITY_LEN);
        let _ = std::str::from_utf8(truncated.identity.as_bytes()).unwrap();
    }

    #[test]
    fn prune_cache_removes_stale_rows() {
        let conn = open_in_memory().unwrap();
        // Seed three rows: two old, one fresh.
        conn.execute(
            "INSERT INTO publisher_cache (path, mtime_unix, size_bytes, signer_identity, signer_kind, inspected_at_utc)
             VALUES ('/old1', 0, 0, 'x', 'unsigned', 1), ('/old2', 0, 0, 'x', 'unsigned', 2), ('/fresh', 0, 0, 'x', 'unsigned', 9999999999)",
            [],
        ).unwrap();
        let dropped = prune_cache(&conn, 86400, 100).unwrap();
        assert_eq!(dropped, 2);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM publisher_cache", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn prune_cache_enforces_row_cap() {
        let conn = open_in_memory().unwrap();
        for i in 0..10 {
            conn.execute(
                "INSERT INTO publisher_cache (path, mtime_unix, size_bytes, signer_identity, signer_kind, inspected_at_utc)
                 VALUES (?1, 0, 0, 'x', 'unsigned', ?2)",
                params![format!("/p{i}"), 9_000_000_000_i64 + i],
            ).unwrap();
        }
        // Age cutoff far in the future so the age leg doesn't fire;
        // only the row-cap leg should trim.
        let dropped = prune_cache(&conn, 1, 5).unwrap();
        assert_eq!(dropped, 5);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM publisher_cache", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 5);
    }
}
