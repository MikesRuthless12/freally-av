//! Skip-if-unchanged verdict cache (Phase 5 wave 3 follow-up).
//!
//! Backed by the `verdict_cache` table (migration 0005). Keyed on
//! `(path, mtime_unix, size_bytes)` — the standard commercial-AV
//! triple that's stable across re-scans of unchanged files but
//! invalidates the moment the user edits, replaces, or restores a
//! file. The engine consults this cache **before** opening + hashing
//! a file: a hit replays the cached `pipeline_outcome` without I/O.
//!
//! Wire shape (cached_outcome): see [`CachedOutcome`]. The engine
//! serializes its [`crate::detect::PipelineOutcome`] into a short
//! string that round-trips deterministically.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::detect::{PipelineOutcome, Severity};

/// Wire-form of a cached verdict. Stored as JSON in
/// `verdict_cache.pipeline_outcome` per migration 0005 — JSON
/// because rule_ids commonly contain colons (`abusech:hash:0123abcd`),
/// which a colon-delimited custom format would have to escape
/// awkwardly. JSON is one line per row and round-trip-clean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CachedOutcome {
    Clean,
    SkippedByAllowlist {
        detector_id: String,
    },
    Detected {
        rule_id: String,
        rule_source: String,
        severity: Severity,
        evidence: Option<String>,
    },
}

impl CachedOutcome {
    /// JSON encoding for the cache row.
    pub fn to_wire(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{\"kind\":\"clean\"}".to_string())
    }

    /// Inverse of [`Self::to_wire`]. `None` on parse failure so the
    /// engine falls back to re-hashing (correct fallback — a corrupt
    /// cache row never causes a misdetection).
    pub fn from_wire(s: &str) -> Option<Self> {
        serde_json::from_str(s).ok()
    }

    /// Convert an in-flight [`PipelineOutcome`] into the cacheable
    /// form. The engine stores the result of every fresh pipeline
    /// run so the next scan can replay it.
    pub fn from_pipeline_outcome(outcome: &PipelineOutcome) -> Self {
        match outcome {
            PipelineOutcome::Clean => CachedOutcome::Clean,
            PipelineOutcome::SkippedByAllowlist { detector_id } => {
                CachedOutcome::SkippedByAllowlist {
                    detector_id: detector_id.clone(),
                }
            }
            PipelineOutcome::Detected {
                rule_id,
                rule_source,
                severity,
                evidence,
                ..
            } => CachedOutcome::Detected {
                rule_id: rule_id.clone(),
                rule_source: rule_source.clone(),
                severity: *severity,
                evidence: evidence.clone(),
            },
        }
    }
}

/// One cached row, projected for the engine's hot path.
#[derive(Debug, Clone)]
pub struct CachedVerdict {
    pub blake3_hex: String,
    pub sha256_hex: Option<String>,
    pub outcome: CachedOutcome,
}

/// Look up a cached verdict by `(path, mtime, size)`. Returns `None`
/// on miss or on any error (cache failures are *never* fatal — the
/// engine just re-hashes).
pub fn lookup(
    conn: &Connection,
    path: &Path,
    mtime_unix: i64,
    size_bytes: u64,
) -> Option<CachedVerdict> {
    let path_str = path.to_string_lossy();
    conn.query_row(
        "SELECT blake3_hex, sha256_hex, pipeline_outcome FROM verdict_cache \
         WHERE path = ?1 AND mtime_unix = ?2 AND size_bytes = ?3",
        params![path_str, mtime_unix, size_bytes as i64],
        |row| {
            let blake3_hex: String = row.get(0)?;
            let sha256_hex: Option<String> = row.get(1)?;
            let wire: String = row.get(2)?;
            Ok((blake3_hex, sha256_hex, wire))
        },
    )
    .optional()
    .ok()
    .flatten()
    .and_then(|(blake3_hex, sha256_hex, wire)| {
        CachedOutcome::from_wire(&wire).map(|outcome| CachedVerdict {
            blake3_hex,
            sha256_hex,
            outcome,
        })
    })
}

/// Persist a verdict for `(path, mtime, size)`. Idempotent via
/// `INSERT OR REPLACE`. Best-effort — failures are logged at TRACE
/// and don't propagate (cache miss on next scan is the worst case).
#[allow(clippy::too_many_arguments)]
pub fn store(
    conn: &Connection,
    path: &Path,
    mtime_unix: i64,
    size_bytes: u64,
    blake3_hex: &str,
    sha256_hex: Option<&str>,
    outcome: &CachedOutcome,
    now_utc: i64,
) {
    let path_str = path.to_string_lossy();
    let _ = conn.execute(
        "INSERT OR REPLACE INTO verdict_cache \
         (path, mtime_unix, size_bytes, blake3_hex, sha256_hex, pipeline_outcome, cached_at_utc) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            path_str,
            mtime_unix,
            size_bytes as i64,
            blake3_hex,
            sha256_hex,
            outcome.to_wire(),
            now_utc
        ],
    );
}

/// Clear the entire cache. Used by Settings → "Re-scan everything
/// from scratch" (UI surface lands later). Returns the count of rows
/// removed.
pub fn clear(conn: &Connection) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM verdict_cache", [])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use std::path::PathBuf;

    fn open_db() -> Connection {
        db::open_in_memory().unwrap()
    }

    #[test]
    fn wire_round_trip_clean() {
        let o = CachedOutcome::Clean;
        assert_eq!(CachedOutcome::from_wire(&o.to_wire()), Some(o));
    }

    #[test]
    fn wire_round_trip_skip() {
        let o = CachedOutcome::SkippedByAllowlist {
            detector_id: "goodware_allowlist".to_string(),
        };
        assert_eq!(CachedOutcome::from_wire(&o.to_wire()), Some(o));
    }

    #[test]
    fn wire_round_trip_detected_with_evidence() {
        let o = CachedOutcome::Detected {
            rule_id: "abusech:hash:0123abcd".to_string(),
            rule_source: "abusech".to_string(),
            severity: Severity::High,
            evidence: Some("sha256=deadbeef".to_string()),
        };
        assert_eq!(CachedOutcome::from_wire(&o.to_wire()), Some(o));
    }

    #[test]
    fn wire_garbage_returns_none() {
        assert!(CachedOutcome::from_wire("garbage").is_none());
        assert!(CachedOutcome::from_wire("{\"kind\":\"unknown\"}").is_none());
        assert!(CachedOutcome::from_wire("").is_none());
    }

    #[test]
    fn store_then_lookup_returns_same_row() {
        let conn = open_db();
        let path = PathBuf::from("/tmp/foo.bin");
        let outcome = CachedOutcome::Clean;
        store(
            &conn,
            &path,
            1_700_000_000,
            1024,
            "aa",
            None,
            &outcome,
            1_700_000_000,
        );

        let hit = lookup(&conn, &path, 1_700_000_000, 1024).expect("expected hit");
        assert_eq!(hit.blake3_hex, "aa");
        assert!(hit.sha256_hex.is_none());
        assert_eq!(hit.outcome, CachedOutcome::Clean);
    }

    #[test]
    fn lookup_with_mismatched_mtime_misses() {
        let conn = open_db();
        let path = PathBuf::from("/tmp/foo.bin");
        store(
            &conn,
            &path,
            100,
            1024,
            "aa",
            None,
            &CachedOutcome::Clean,
            0,
        );
        assert!(lookup(&conn, &path, 200, 1024).is_none());
    }

    #[test]
    fn lookup_with_mismatched_size_misses() {
        let conn = open_db();
        let path = PathBuf::from("/tmp/foo.bin");
        store(
            &conn,
            &path,
            100,
            1024,
            "aa",
            None,
            &CachedOutcome::Clean,
            0,
        );
        assert!(lookup(&conn, &path, 100, 2048).is_none());
    }

    #[test]
    fn store_is_idempotent_via_insert_or_replace() {
        let conn = open_db();
        let path = PathBuf::from("/tmp/foo.bin");
        store(
            &conn,
            &path,
            100,
            1024,
            "aa",
            None,
            &CachedOutcome::Clean,
            0,
        );
        store(
            &conn,
            &path,
            100,
            1024,
            "bb",
            Some("cc"),
            &CachedOutcome::SkippedByAllowlist {
                detector_id: "nsrl".to_string(),
            },
            10,
        );
        let hit = lookup(&conn, &path, 100, 1024).unwrap();
        assert_eq!(hit.blake3_hex, "bb");
        assert_eq!(hit.sha256_hex.as_deref(), Some("cc"));
        match hit.outcome {
            CachedOutcome::SkippedByAllowlist { detector_id } => {
                assert_eq!(detector_id, "nsrl");
            }
            _ => panic!("expected SkippedByAllowlist"),
        }
    }

    #[test]
    fn clear_drops_every_row() {
        let conn = open_db();
        let path_a = PathBuf::from("/tmp/a");
        let path_b = PathBuf::from("/tmp/b");
        store(&conn, &path_a, 100, 1, "aa", None, &CachedOutcome::Clean, 0);
        store(&conn, &path_b, 100, 1, "bb", None, &CachedOutcome::Clean, 0);
        assert_eq!(clear(&conn).unwrap(), 2);
        assert!(lookup(&conn, &path_a, 100, 1).is_none());
        assert!(lookup(&conn, &path_b, 100, 1).is_none());
    }
}
