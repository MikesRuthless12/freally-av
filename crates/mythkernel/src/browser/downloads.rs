//! Downloaded-file post-mortem (TASK-258, FEAT-203, Phase 10 Wave 2).
//!
//! Reads Chromium-family `History` SQLite databases (`downloads` +
//! `downloads_url_chains` tables) and joins recent downloads to the
//! engine's scan-finding rows by path / SHA-256. Safari Downloads.plist
//! is a binary plist; coverage tracked as a Wave 2 follow-up once the
//! `plist` crate is added.
//!
//! Chrome holds an exclusive write lock on its live `History` DB. In
//! production, callers must snapshot the file (`std::fs::copy`) before
//! opening — every Chromium-derived browser releases its lock on the
//! copy. The tests open `:memory:` connections directly.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};

/// One row from a Chromium `downloads` table joined against the
/// initiating URL chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadRecord {
    pub browser: super::BrowserFamily,
    /// Absolute path the download saved to (Chromium `target_path`).
    pub target_path: PathBuf,
    /// SHA-256 of the downloaded file when Chromium recorded one;
    /// empty when the download is still in progress or Chromium chose
    /// not to hash it. Lower-case hex.
    pub sha256_hex: Option<String>,
    /// First entry of the redirect chain — the URL the user clicked.
    pub initial_url: Option<String>,
    /// Final entry — the URL the bytes were fetched from.
    pub final_url: Option<String>,
    /// Unix timestamp (seconds) the download started. Chromium
    /// stores microseconds since the Windows epoch (1601-01-01); the
    /// reader normalises here.
    pub start_unix_s: i64,
    pub end_unix_s: i64,
    pub total_bytes: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum DownloadReaderError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
}

/// Microseconds between the Windows file-time epoch (1601-01-01) and
/// the UNIX epoch (1970-01-01). 11_644_473_600 seconds × 1e6.
const WIN_EPOCH_OFFSET_MICROS: i64 = 11_644_473_600_000_000;

/// Convert a Chromium `INTEGER NOT NULL` time field (microseconds
/// since 1601) to UNIX seconds. Returns 0 for the sentinel zero value.
fn chromium_time_to_unix_s(chromium_micros: i64) -> i64 {
    if chromium_micros <= 0 {
        return 0;
    }
    (chromium_micros - WIN_EPOCH_OFFSET_MICROS) / 1_000_000
}

/// Read every download from a Chromium-shaped `History` SQLite at
/// `db_path`. Caller has already taken a snapshot copy of the live
/// browser file.
pub fn read_chromium_downloads(
    db_path: &Path,
    browser: super::BrowserFamily,
) -> Result<Vec<DownloadRecord>, DownloadReaderError> {
    // `OPEN_URI` lets the daemon side pass `file:?mode=ro` URIs once
    // it integrates with the live-file workaround. For now,
    // read-only suffices and works for both real files + the
    // snapshot copies the daemon will take.
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?;
    read_chromium_downloads_from_conn(&conn, browser)
}

/// Variant of [`read_chromium_downloads`] that takes an already-open
/// connection. Used by tests against `:memory:` and by callers that
/// want to share a connection across other read-only queries.
pub fn read_chromium_downloads_from_conn(
    conn: &Connection,
    browser: super::BrowserFamily,
) -> Result<Vec<DownloadRecord>, DownloadReaderError> {
    let mut stmt = conn.prepare(
        "SELECT d.id, d.target_path, d.start_time, d.end_time, d.total_bytes, d.hash
         FROM downloads d
         ORDER BY d.start_time DESC",
    )?;
    let rows = stmt
        .query_map([], |row| {
            let id: i64 = row.get(0)?;
            let target_path: String = row.get(1)?;
            let start_micros: i64 = row.get(2)?;
            let end_micros: i64 = row.get(3)?;
            let total_bytes: i64 = row.get(4)?;
            let hash: Vec<u8> = row.get(5).unwrap_or_default();
            Ok((id, target_path, start_micros, end_micros, total_bytes, hash))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut out = Vec::with_capacity(rows.len());
    for (id, target_path, start_micros, end_micros, total_bytes, hash) in rows {
        let chain = read_url_chain(conn, id)?;
        out.push(DownloadRecord {
            browser,
            target_path: PathBuf::from(target_path),
            sha256_hex: if hash.is_empty() {
                None
            } else {
                Some(hex::encode(&hash))
            },
            initial_url: chain.first().cloned(),
            final_url: chain.last().cloned(),
            start_unix_s: chromium_time_to_unix_s(start_micros),
            end_unix_s: chromium_time_to_unix_s(end_micros),
            total_bytes,
        });
    }
    Ok(out)
}

fn read_url_chain(conn: &Connection, download_id: i64) -> Result<Vec<String>, DownloadReaderError> {
    let mut stmt = conn.prepare(
        "SELECT url FROM downloads_url_chains
         WHERE id = ?
         ORDER BY chain_index ASC",
    )?;
    let urls = stmt
        .query_map(params![download_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(urls)
}

/// One side of the post-mortem join. Caller supplies the engine
/// finding row in this shape; the join is by canonical path and/or
/// SHA-256 hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingForJoin {
    pub finding_id: i64,
    pub path: PathBuf,
    pub sha256_hex: Option<String>,
}

/// One matched (download, finding) tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadFindingMatch {
    pub download: DownloadRecord,
    pub finding_id: i64,
    /// Which match condition fired. `"path"` or `"sha256"`.
    pub via: &'static str,
}

/// Join the per-browser downloads list against engine findings. A
/// match fires when **either** the target path equals the finding
/// path **or** both records carry the same lower-case hex SHA-256.
pub fn join_to_findings(
    downloads: &[DownloadRecord],
    findings: &[FindingForJoin],
) -> Vec<DownloadFindingMatch> {
    let mut out = Vec::new();
    for d in downloads {
        for f in findings {
            if d.target_path == f.path {
                out.push(DownloadFindingMatch {
                    download: d.clone(),
                    finding_id: f.finding_id,
                    via: "path",
                });
                continue;
            }
            match (&d.sha256_hex, &f.sha256_hex) {
                (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => {
                    out.push(DownloadFindingMatch {
                        download: d.clone(),
                        finding_id: f.finding_id,
                        via: "sha256",
                    });
                }
                _ => {}
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_chromium_schema(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE downloads(
                id INTEGER PRIMARY KEY,
                guid VARCHAR NOT NULL DEFAULT '',
                current_path LONGVARCHAR NOT NULL DEFAULT '',
                target_path LONGVARCHAR NOT NULL,
                start_time INTEGER NOT NULL,
                end_time INTEGER NOT NULL,
                received_bytes INTEGER NOT NULL DEFAULT 0,
                total_bytes INTEGER NOT NULL,
                hash BLOB NOT NULL DEFAULT X''
            );
            CREATE TABLE downloads_url_chains(
                id INTEGER NOT NULL,
                chain_index INTEGER NOT NULL,
                url LONGVARCHAR NOT NULL
            );",
        )
        .unwrap();
    }

    #[test]
    fn chromium_time_to_unix_handles_epoch_offset() {
        // 2024-01-01 00:00:00 UTC = 1704067200 unix
        // microseconds since 1601 = (11_644_473_600 + 1_704_067_200) * 1e6
        let chromium_micros: i64 = (11_644_473_600 + 1_704_067_200) * 1_000_000;
        assert_eq!(chromium_time_to_unix_s(chromium_micros), 1_704_067_200);
    }

    #[test]
    fn chromium_time_zero_stays_zero() {
        assert_eq!(chromium_time_to_unix_s(0), 0);
    }

    #[test]
    fn read_chromium_downloads_round_trips_one_record() {
        let conn = Connection::open_in_memory().unwrap();
        make_chromium_schema(&conn);
        let micros: i64 = (11_644_473_600i64 + 1_704_067_200) * 1_000_000;
        let end: i64 = (11_644_473_600i64 + 1_704_067_205) * 1_000_000;
        let sha = [0xab; 32];
        conn.execute(
            "INSERT INTO downloads (id, target_path, start_time, end_time, total_bytes, hash)
             VALUES (1, ?, ?, ?, 1024, ?)",
            params!["/tmp/installer.exe", micros, end, &sha[..]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO downloads_url_chains (id, chain_index, url) VALUES (1, 0, ?)",
            params!["https://example.com/installer.exe"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO downloads_url_chains (id, chain_index, url) VALUES (1, 1, ?)",
            params!["https://cdn.example.net/i.exe"],
        )
        .unwrap();

        let recs =
            read_chromium_downloads_from_conn(&conn, super::super::BrowserFamily::Chrome).unwrap();
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.target_path, PathBuf::from("/tmp/installer.exe"));
        assert_eq!(r.sha256_hex.as_deref(), Some(&hex::encode(sha)[..]));
        assert_eq!(
            r.initial_url.as_deref(),
            Some("https://example.com/installer.exe")
        );
        assert_eq!(
            r.final_url.as_deref(),
            Some("https://cdn.example.net/i.exe")
        );
        assert_eq!(r.start_unix_s, 1_704_067_200);
        assert_eq!(r.end_unix_s, 1_704_067_205);
        assert_eq!(r.total_bytes, 1024);
        assert_eq!(r.browser, super::super::BrowserFamily::Chrome);
    }

    #[test]
    fn empty_hash_blob_yields_no_sha() {
        let conn = Connection::open_in_memory().unwrap();
        make_chromium_schema(&conn);
        conn.execute(
            "INSERT INTO downloads (id, target_path, start_time, end_time, total_bytes, hash)
             VALUES (1, ?, 0, 0, 0, X'')",
            params!["/tmp/x"],
        )
        .unwrap();
        let recs =
            read_chromium_downloads_from_conn(&conn, super::super::BrowserFamily::Edge).unwrap();
        assert!(recs[0].sha256_hex.is_none());
    }

    #[test]
    fn join_finds_path_match() {
        let dl = DownloadRecord {
            browser: super::super::BrowserFamily::Chrome,
            target_path: PathBuf::from("/tmp/a.exe"),
            sha256_hex: Some("deadbeef".into()),
            initial_url: None,
            final_url: None,
            start_unix_s: 0,
            end_unix_s: 0,
            total_bytes: 0,
        };
        let f = FindingForJoin {
            finding_id: 7,
            path: PathBuf::from("/tmp/a.exe"),
            sha256_hex: None,
        };
        let hits = join_to_findings(&[dl], &[f]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].finding_id, 7);
        assert_eq!(hits[0].via, "path");
    }

    #[test]
    fn join_falls_back_to_sha_match() {
        let dl = DownloadRecord {
            browser: super::super::BrowserFamily::Chrome,
            target_path: PathBuf::from("/old/path"),
            sha256_hex: Some("AbCdEf".into()),
            initial_url: None,
            final_url: None,
            start_unix_s: 0,
            end_unix_s: 0,
            total_bytes: 0,
        };
        let f = FindingForJoin {
            finding_id: 99,
            path: PathBuf::from("/new/path"),
            sha256_hex: Some("abcdef".into()),
        };
        let hits = join_to_findings(&[dl], &[f]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].via, "sha256");
    }

    #[test]
    fn join_yields_nothing_when_both_keys_miss() {
        let dl = DownloadRecord {
            browser: super::super::BrowserFamily::Chrome,
            target_path: PathBuf::from("/a"),
            sha256_hex: Some("aa".into()),
            initial_url: None,
            final_url: None,
            start_unix_s: 0,
            end_unix_s: 0,
            total_bytes: 0,
        };
        let f = FindingForJoin {
            finding_id: 0,
            path: PathBuf::from("/b"),
            sha256_hex: Some("bb".into()),
        };
        assert!(join_to_findings(&[dl], &[f]).is_empty());
    }
}
