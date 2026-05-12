//! Exclusions CRUD + matcher (TASK-042, Phase 4).
//!
//! Per `docs/prd.md` § 6.6 FR-060/061/062/134, exclusions are user-
//! defined rules that tell the engine to skip a path / glob / hash /
//! signing key / publisher. Phase 4 ships the four user-facing kinds
//! (path, glob, hash_blake3, hash_sha256); the signing-key + publisher
//! kinds land alongside TASK-136 (Phase 4 wave 2 / Phase 5).
//!
//! Each exclusion has:
//!   * `scope` — `scan_only | realtime_only | both` per FR-134.
//!   * `expires_at_utc` — optional unix seconds, after which the rule
//!     is ignored by [`matches`]. Stored even when expired; cleanup is
//!     a future Settings concern.
//!   * `reason` — free-text note for the audit trail (e.g.
//!     "Steam library — high-write area").
//!
//! The matcher is invoked by the scan engine and (future) real-time
//! daemons; allowlist hits short-circuit the detection pipeline.

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::db::DbError;

#[derive(Debug, thiserror::Error)]
pub enum ExclusionsError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("db: {0}")]
    Db(#[from] DbError),
    #[error("exclusion {0} not found")]
    NotFound(i64),
    #[error("invalid exclusion: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionKind {
    Path,
    Glob,
    HashBlake3,
    HashSha256,
}

impl ExclusionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ExclusionKind::Path => "path",
            ExclusionKind::Glob => "glob",
            ExclusionKind::HashBlake3 => "hash_blake3",
            ExclusionKind::HashSha256 => "hash_sha256",
        }
    }
}

impl std::str::FromStr for ExclusionKind {
    type Err = ExclusionsError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "path" => ExclusionKind::Path,
            "glob" => ExclusionKind::Glob,
            "hash_blake3" => ExclusionKind::HashBlake3,
            "hash_sha256" => ExclusionKind::HashSha256,
            other => {
                return Err(ExclusionsError::Invalid(format!(
                    "unknown exclusion kind: {other}"
                )));
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionScope {
    ScanOnly,
    RealtimeOnly,
    Both,
}

impl ExclusionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            ExclusionScope::ScanOnly => "scan_only",
            ExclusionScope::RealtimeOnly => "realtime_only",
            ExclusionScope::Both => "both",
        }
    }

    /// True if this scope applies during an on-demand scan.
    pub fn applies_to_scan(self) -> bool {
        matches!(self, ExclusionScope::ScanOnly | ExclusionScope::Both)
    }

    /// True if this scope applies to a real-time event.
    pub fn applies_to_realtime(self) -> bool {
        matches!(self, ExclusionScope::RealtimeOnly | ExclusionScope::Both)
    }
}

impl std::str::FromStr for ExclusionScope {
    type Err = ExclusionsError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "scan_only" => ExclusionScope::ScanOnly,
            "realtime_only" => ExclusionScope::RealtimeOnly,
            "both" => ExclusionScope::Both,
            other => {
                return Err(ExclusionsError::Invalid(format!(
                    "unknown exclusion scope: {other}"
                )));
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exclusion {
    pub id: i64,
    pub kind: ExclusionKind,
    pub value: String,
    pub scope: ExclusionScope,
    pub expires_at_utc: Option<i64>,
    pub created_at_utc: i64,
    pub reason: Option<String>,
}

impl Exclusion {
    /// True iff this exclusion is still active at `now_utc`.
    pub fn is_active(&self, now_utc: i64) -> bool {
        match self.expires_at_utc {
            Some(t) => t > now_utc,
            None => true,
        }
    }
}

/// What the engine asks the matcher about. Caller fills in only the
/// fields it has — a real-time file-open event may not have a
/// computed SHA-256 yet, so leave it `None`.
#[derive(Debug, Clone, Copy)]
pub struct MatchCtx<'a> {
    pub path: &'a str,
    pub blake3_hex: Option<&'a str>,
    pub sha256_hex: Option<&'a str>,
    /// Which scope the caller is in — `applies_to_scan` filters out
    /// realtime-only rules and vice versa.
    pub scope: MatchScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchScope {
    Scan,
    Realtime,
}

/// Maximum length of a value string. Cap protects the matcher from
/// degenerate inputs (security review M3); 4 KiB is plenty for any real
/// path or glob.
const MAX_VALUE_LEN: usize = 4096;
/// Maximum length of the `reason` audit string (security review L2).
const MAX_REASON_LEN: usize = 1024;

/// Insert a new exclusion. Returns the row id. Validates non-empty
/// value, length cap, hash format, and (for path kind) absence of `..`
/// traversal segments.
pub fn add(
    conn: &Connection,
    kind: ExclusionKind,
    value: &str,
    scope: ExclusionScope,
    expires_at_utc: Option<i64>,
    reason: Option<&str>,
) -> Result<i64, ExclusionsError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ExclusionsError::Invalid("value is empty".into()));
    }
    if trimmed.len() > MAX_VALUE_LEN {
        return Err(ExclusionsError::Invalid(format!(
            "value too long ({} chars, max {})",
            trimmed.len(),
            MAX_VALUE_LEN
        )));
    }
    if let Some(r) = reason
        && r.len() > MAX_REASON_LEN
    {
        return Err(ExclusionsError::Invalid(format!(
            "reason too long ({} chars, max {})",
            r.len(),
            MAX_REASON_LEN
        )));
    }
    if matches!(kind, ExclusionKind::HashBlake3 | ExclusionKind::HashSha256) && trimmed.len() != 64
    {
        return Err(ExclusionsError::Invalid(format!(
            "{} value must be 64 hex chars (got {})",
            kind.as_str(),
            trimmed.len()
        )));
    }
    // Path kind: reject traversal segments at insert time. Per security
    // review M2 a stored `..` would let a tampered row redirect the
    // matcher at `/etc/passwd` even though the rule "looks like"
    // `/home/me/safe`. Reject early.
    if matches!(kind, ExclusionKind::Path) {
        for seg in trimmed.split(['/', '\\']) {
            if seg == ".." {
                return Err(ExclusionsError::Invalid(
                    "path exclusions must not contain `..` segments".into(),
                ));
            }
        }
    }
    let now = now_utc_secs();
    conn.execute(
        "INSERT INTO exclusions (kind, value, scope, expires_at_utc, created_at_utc, reason)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            kind.as_str(),
            trimmed,
            scope.as_str(),
            expires_at_utc,
            now,
            reason
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn remove(conn: &Connection, id: i64) -> Result<(), ExclusionsError> {
    let affected = conn.execute("DELETE FROM exclusions WHERE id = ?1", params![id])?;
    if affected == 0 {
        return Err(ExclusionsError::NotFound(id));
    }
    Ok(())
}

pub fn get(conn: &Connection, id: i64) -> Result<Exclusion, ExclusionsError> {
    let row = conn
        .query_row(
            "SELECT id, kind, value, scope, expires_at_utc, created_at_utc, reason
             FROM exclusions WHERE id = ?1",
            params![id],
            row_to_exclusion,
        )
        .optional()?;
    row.transpose()?.ok_or(ExclusionsError::NotFound(id))
}

/// All exclusions ordered most-recent first. Includes expired entries —
/// the UI surfaces them with an "expired" pill so the user can prune.
pub fn list(conn: &Connection) -> Result<Vec<Exclusion>, ExclusionsError> {
    let mut stmt = conn.prepare(
        "SELECT id, kind, value, scope, expires_at_utc, created_at_utc, reason
         FROM exclusions ORDER BY created_at_utc DESC, id DESC",
    )?;
    let mut out = Vec::new();
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        out.push(row_to_exclusion(row)??);
    }
    Ok(out)
}

/// Same as [`list`] but only returns rules that are still active at
/// `now_utc`. Used by the matcher to avoid re-checking expiry per-rule
/// on the hot path (review MINOR — push the filter into SQL).
pub fn list_active(conn: &Connection, now_utc: i64) -> Result<Vec<Exclusion>, ExclusionsError> {
    let mut stmt = conn.prepare(
        "SELECT id, kind, value, scope, expires_at_utc, created_at_utc, reason
         FROM exclusions
         WHERE expires_at_utc IS NULL OR expires_at_utc > ?1
         ORDER BY created_at_utc DESC, id DESC",
    )?;
    let mut out = Vec::new();
    let mut rows = stmt.query([now_utc])?;
    while let Some(row) = rows.next()? {
        out.push(row_to_exclusion(row)??);
    }
    Ok(out)
}

/// Snapshot every currently-active exclusion as a JSON array. Stored
/// into `scans.exclusions_snap` per FR-062 so a re-run of an old scan
/// uses the rules in force at the original scan time, not whatever the
/// user has now.
pub fn snapshot_active_json(conn: &Connection) -> Result<String, ExclusionsError> {
    let now = now_utc_secs();
    let actives: Vec<Exclusion> = list(conn)?
        .into_iter()
        .filter(|e| e.is_active(now))
        .collect();
    Ok(serde_json::to_string(&actives).unwrap_or_else(|_| "[]".to_string()))
}

/// Test whether `ctx` matches any active exclusion that applies in
/// `ctx.scope`. The scan engine and (future) real-time daemons call
/// this; allowlist short-circuits the detection pipeline.
pub fn matches(
    conn: &Connection,
    ctx: &MatchCtx<'_>,
) -> Result<Option<Exclusion>, ExclusionsError> {
    let now = now_utc_secs();
    let rules = list_active(conn, now)?;
    for rule in rules {
        let scope_ok = match ctx.scope {
            MatchScope::Scan => rule.scope.applies_to_scan(),
            MatchScope::Realtime => rule.scope.applies_to_realtime(),
        };
        if !scope_ok {
            continue;
        }
        let hit = match rule.kind {
            ExclusionKind::Path => path_eq_ignore_sep(&rule.value, ctx.path),
            ExclusionKind::Glob => glob_match(&rule.value, ctx.path),
            ExclusionKind::HashBlake3 => match ctx.blake3_hex {
                // Note: a non-constant-time compare here is fine — file
                // hashes are public inputs in this engine (they appear in
                // threat-intel feeds), so timing leaks aren't a
                // confidentiality concern (security review L4).
                Some(h) => h.eq_ignore_ascii_case(&rule.value),
                None => false,
            },
            ExclusionKind::HashSha256 => match ctx.sha256_hex {
                Some(h) => h.eq_ignore_ascii_case(&rule.value),
                None => false,
            },
        };
        if hit {
            return Ok(Some(rule));
        }
    }
    Ok(None)
}

/// Path comparison that treats `\` and `/` as equivalent so a Windows-
/// authored exclusion still matches a forward-slash canonicalized path
/// (and vice versa).
fn path_eq_ignore_sep(rule: &str, candidate: &str) -> bool {
    let norm = |s: &str| s.replace('\\', "/").to_lowercase();
    norm(rule) == norm(candidate) || norm(candidate).starts_with(&format!("{}/", norm(rule)))
}

/// Glob matcher — supports:
///   * `**` — any chars *including* path separators (deep wildcard)
///   * `*`  — any chars within a single path segment (no `/`)
///   * `?`  — single non-separator char
///
/// Per security review the prior version treated `**` as `*`, so
/// `node_modules/**` wouldn't match a nested file. The matcher now
/// distinguishes `*` from `**`.
fn glob_match(pattern: &str, candidate: &str) -> bool {
    let p = pattern.replace('\\', "/").to_lowercase();
    let c = candidate.replace('\\', "/").to_lowercase();
    glob_inner(p.as_bytes(), c.as_bytes())
}

fn glob_inner(pat: &[u8], s: &[u8]) -> bool {
    // Iterative backtracking glob.
    // `star_i` is the last `*` position whose match can be extended;
    // `star_deep` records whether that star was the `**` (deep) form.
    let (mut i, mut j) = (0usize, 0usize);
    let mut star_i: Option<usize> = None;
    let mut star_deep = false;
    let mut match_j: usize = 0;
    while j < s.len() {
        // Detect `**` and `*` lookahead.
        if i < pat.len() && pat[i] == b'*' {
            let deep = i + 1 < pat.len() && pat[i + 1] == b'*';
            star_i = Some(i);
            star_deep = deep;
            i += if deep { 2 } else { 1 };
            match_j = j;
            continue;
        }
        if i < pat.len() && (pat[i] == b'?' && s[j] != b'/' || pat[i] == s[j]) {
            i += 1;
            j += 1;
        } else if let Some(si) = star_i {
            // Backtrack to the last star and try matching one more
            // character. A shallow `*` may not cross a `/`; `**` may.
            match_j += 1;
            if match_j > s.len() {
                return false;
            }
            if !star_deep && match_j > 0 && s[match_j - 1] == b'/' {
                return false;
            }
            i = si + if star_deep { 2 } else { 1 };
            j = match_j;
        } else {
            return false;
        }
    }
    // Skip any trailing `*`/`**` in the pattern.
    while i < pat.len() && pat[i] == b'*' {
        i += 1;
    }
    i == pat.len()
}

fn row_to_exclusion(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<Exclusion, ExclusionsError>> {
    let kind_s: String = row.get(1)?;
    let scope_s: String = row.get(3)?;
    let kind = match kind_s.parse::<ExclusionKind>() {
        Ok(k) => k,
        Err(err) => return Ok(Err(err)),
    };
    let scope = match scope_s.parse::<ExclusionScope>() {
        Ok(s) => s,
        Err(err) => return Ok(Err(err)),
    };
    Ok(Ok(Exclusion {
        id: row.get(0)?,
        kind,
        value: row.get(2)?,
        scope,
        expires_at_utc: row.get(4)?,
        created_at_utc: row.get(5)?,
        reason: row.get(6)?,
    }))
}

fn now_utc_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    #[test]
    fn add_and_list_roundtrip() {
        let conn = open_in_memory().unwrap();
        let id = add(
            &conn,
            ExclusionKind::Path,
            "/home/me/Downloads/safe",
            ExclusionScope::Both,
            None,
            Some("Trusted dev folder"),
        )
        .unwrap();
        let list = list(&conn).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, id);
        assert_eq!(list[0].kind, ExclusionKind::Path);
        assert_eq!(list[0].reason.as_deref(), Some("Trusted dev folder"));
    }

    #[test]
    fn rejects_empty_value() {
        let conn = open_in_memory().unwrap();
        let err = add(
            &conn,
            ExclusionKind::Path,
            "  ",
            ExclusionScope::Both,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, ExclusionsError::Invalid(_)));
    }

    #[test]
    fn rejects_short_hash() {
        let conn = open_in_memory().unwrap();
        let err = add(
            &conn,
            ExclusionKind::HashBlake3,
            "abc",
            ExclusionScope::Both,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, ExclusionsError::Invalid(_)));
    }

    #[test]
    fn remove_drops_row() {
        let conn = open_in_memory().unwrap();
        let id = add(
            &conn,
            ExclusionKind::Path,
            "/x",
            ExclusionScope::Both,
            None,
            None,
        )
        .unwrap();
        remove(&conn, id).unwrap();
        assert!(matches!(
            remove(&conn, id).unwrap_err(),
            ExclusionsError::NotFound(_)
        ));
        assert_eq!(list(&conn).unwrap().len(), 0);
    }

    #[test]
    fn matches_path_exact() {
        let conn = open_in_memory().unwrap();
        add(
            &conn,
            ExclusionKind::Path,
            "/home/me/safe",
            ExclusionScope::Both,
            None,
            None,
        )
        .unwrap();
        let ctx = MatchCtx {
            path: "/home/me/safe",
            blake3_hex: None,
            sha256_hex: None,
            scope: MatchScope::Scan,
        };
        let hit = matches(&conn, &ctx).unwrap().unwrap();
        assert_eq!(hit.kind, ExclusionKind::Path);
    }

    #[test]
    fn matches_path_subpath() {
        let conn = open_in_memory().unwrap();
        add(
            &conn,
            ExclusionKind::Path,
            "/home/me/safe",
            ExclusionScope::Both,
            None,
            None,
        )
        .unwrap();
        let ctx = MatchCtx {
            path: "/home/me/safe/inner/file.txt",
            blake3_hex: None,
            sha256_hex: None,
            scope: MatchScope::Scan,
        };
        let hit = matches(&conn, &ctx).unwrap();
        assert!(hit.is_some());
    }

    #[test]
    fn matches_path_normalizes_separators() {
        let conn = open_in_memory().unwrap();
        add(
            &conn,
            ExclusionKind::Path,
            r"C:\Users\me\safe",
            ExclusionScope::Both,
            None,
            None,
        )
        .unwrap();
        let ctx = MatchCtx {
            path: "c:/users/me/safe/inner",
            blake3_hex: None,
            sha256_hex: None,
            scope: MatchScope::Scan,
        };
        assert!(matches(&conn, &ctx).unwrap().is_some());
    }

    #[test]
    fn matches_glob_double_star_crosses_slashes() {
        // `**` is the explicit deep-wildcard form and crosses path
        // separators. Confirms the security-review fix: prior to it,
        // `**` was silently downgraded to `*`.
        let conn = open_in_memory().unwrap();
        add(
            &conn,
            ExclusionKind::Glob,
            "**/node_modules/**",
            ExclusionScope::Both,
            None,
            None,
        )
        .unwrap();
        let ctx = MatchCtx {
            path: "/home/me/proj/node_modules/foo/index.js",
            blake3_hex: None,
            sha256_hex: None,
            scope: MatchScope::Scan,
        };
        assert!(matches(&conn, &ctx).unwrap().is_some());
        let miss = MatchCtx {
            path: "/home/me/proj/src/index.js",
            blake3_hex: None,
            sha256_hex: None,
            scope: MatchScope::Scan,
        };
        assert!(matches(&conn, &miss).unwrap().is_none());
    }

    #[test]
    fn matches_glob_single_star_stays_in_segment() {
        // POSIX-strict: `*` matches within a single segment only.
        // Documents the new behavior so a user-typed `*.log` doesn't
        // accidentally allowlist `/etc/foo/passwd.log` plus everything
        // under `/etc/`.
        let conn = open_in_memory().unwrap();
        add(
            &conn,
            ExclusionKind::Glob,
            "*.log",
            ExclusionScope::Both,
            None,
            None,
        )
        .unwrap();
        let ctx_hit = MatchCtx {
            path: "app.log",
            blake3_hex: None,
            sha256_hex: None,
            scope: MatchScope::Scan,
        };
        assert!(matches(&conn, &ctx_hit).unwrap().is_some());
        let ctx_miss = MatchCtx {
            path: "/var/logs/app.log",
            blake3_hex: None,
            sha256_hex: None,
            scope: MatchScope::Scan,
        };
        assert!(matches(&conn, &ctx_miss).unwrap().is_none());
    }

    #[test]
    fn matches_hash_case_insensitive() {
        let conn = open_in_memory().unwrap();
        let hash = "a".repeat(64);
        add(
            &conn,
            ExclusionKind::HashBlake3,
            &hash,
            ExclusionScope::Both,
            None,
            None,
        )
        .unwrap();
        let upper = hash.to_uppercase();
        let ctx = MatchCtx {
            path: "/anywhere",
            blake3_hex: Some(&upper),
            sha256_hex: None,
            scope: MatchScope::Scan,
        };
        assert!(matches(&conn, &ctx).unwrap().is_some());
    }

    #[test]
    fn scope_filter_respected() {
        let conn = open_in_memory().unwrap();
        add(
            &conn,
            ExclusionKind::Path,
            "/realtime/only",
            ExclusionScope::RealtimeOnly,
            None,
            None,
        )
        .unwrap();
        let scan_ctx = MatchCtx {
            path: "/realtime/only",
            blake3_hex: None,
            sha256_hex: None,
            scope: MatchScope::Scan,
        };
        let rt_ctx = MatchCtx {
            scope: MatchScope::Realtime,
            ..scan_ctx
        };
        assert!(matches(&conn, &scan_ctx).unwrap().is_none());
        assert!(matches(&conn, &rt_ctx).unwrap().is_some());
    }

    #[test]
    fn expired_rule_not_matched() {
        let conn = open_in_memory().unwrap();
        // Expired 1 second after the unix epoch.
        add(
            &conn,
            ExclusionKind::Path,
            "/x",
            ExclusionScope::Both,
            Some(1),
            None,
        )
        .unwrap();
        let ctx = MatchCtx {
            path: "/x",
            blake3_hex: None,
            sha256_hex: None,
            scope: MatchScope::Scan,
        };
        assert!(matches(&conn, &ctx).unwrap().is_none());
    }

    #[test]
    fn snapshot_excludes_expired() {
        let conn = open_in_memory().unwrap();
        add(
            &conn,
            ExclusionKind::Path,
            "/active",
            ExclusionScope::Both,
            None,
            None,
        )
        .unwrap();
        add(
            &conn,
            ExclusionKind::Path,
            "/expired",
            ExclusionScope::Both,
            Some(1),
            None,
        )
        .unwrap();
        let json = snapshot_active_json(&conn).unwrap();
        assert!(json.contains("/active"));
        assert!(!json.contains("/expired"));
    }
}
