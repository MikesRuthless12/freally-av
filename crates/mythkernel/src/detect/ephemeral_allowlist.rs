//! TASK-190 — Ephemeral allowlist ("Trust this once" with auto-expiry).
//!
//! Per-user-grant entries in `ephemeral_allowlist` (migration 0006)
//! short-circuit the detection pipeline at allowlist priority 12 —
//! just above the goodware allowlist (10) so an explicit grant
//! takes precedence over even the bundled NSRL data.
//!
//! Grants self-destruct: the [`EphemeralAllowlistStore::prune_expired`]
//! call removes rows whose `expires_at_utc` has passed; the
//! [`EphemeralAllowlistDetector`]'s SQL lookup also filters by
//! `expires_at_utc >= now` so an unpruned-but-expired row never
//! matches.
//!
//! Distinct from [`crate::exclusions`] which is the permanent
//! user-managed allowlist (path / glob / hash / publisher). The
//! ephemeral surface is the "I know this is fine for the next 7
//! days" flow and intentionally cannot be made permanent through
//! this API.

use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};

use super::{Detector, DetectorVerdict, FileCtx, HashKind};

pub const DETECTOR_ID: &str = "ephemeral_allowlist";

/// Pipeline priority. Below the goodware allowlist (10) so the
/// pre-existing NSRL hit wins on the rare overlap, but above the
/// blacklists (100+) so an explicit grant beats them.
pub const PRIORITY: u32 = 12;

#[derive(Debug, Clone, Copy)]
pub enum TrustDuration {
    Days7,
    Days30,
    Days365,
}

impl TrustDuration {
    pub fn seconds(self) -> i64 {
        match self {
            TrustDuration::Days7 => 7 * 24 * 60 * 60,
            TrustDuration::Days30 => 30 * 24 * 60 * 60,
            TrustDuration::Days365 => 365 * 24 * 60 * 60,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            TrustDuration::Days7 => "7d",
            TrustDuration::Days30 => "30d",
            TrustDuration::Days365 => "365d",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EphemeralAllowlistStore {
    conn: Arc<Mutex<Connection>>,
}

impl EphemeralAllowlistStore {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    /// Insert a trust grant. Returns the row id. The DB enforces
    /// `reason NOT NULL` so the caller must provide one (empty
    /// strings allowed but discouraged — the audit trail benefits
    /// from a one-liner).
    pub fn grant(
        &self,
        sha256_hex: &str,
        scope_path: Option<&str>,
        reason: &str,
        duration: TrustDuration,
        created_by: &str,
    ) -> rusqlite::Result<i64> {
        let now = unix_now();
        let conn = self.conn.lock().expect("ephemeral allowlist mutex poisoned");
        conn.execute(
            "INSERT INTO ephemeral_allowlist
                (sha256_hex, scope_path, reason, created_at_utc, expires_at_utc, created_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                sha256_hex,
                scope_path,
                reason,
                now,
                now + duration.seconds(),
                created_by,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Drop rows whose `expires_at_utc` is at or before `now`. Called
    /// at scan-start so the detector path doesn't bother evaluating
    /// stale rows.
    pub fn prune_expired(&self, now: i64) -> rusqlite::Result<usize> {
        let conn = self.conn.lock().expect("ephemeral allowlist mutex poisoned");
        conn.execute(
            "DELETE FROM ephemeral_allowlist WHERE expires_at_utc <= ?1",
            params![now],
        )
        .map(|n| n as usize)
    }

    /// Look up whether `sha256_hex` is currently trusted. Honors
    /// `scope_path` if set on the row — a scope of `/home/me/x.exe`
    /// won't match a probe for `/tmp/x.exe`.
    pub fn is_trusted(
        &self,
        sha256_hex: &str,
        candidate_path: Option<&str>,
        now: i64,
    ) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().expect("ephemeral allowlist mutex poisoned");
        // Prefer the path-scoped row if one matches; fall back to
        // an unscoped row.
        if let Some(p) = candidate_path {
            let scoped: Option<i64> = conn
                .query_row(
                    "SELECT id FROM ephemeral_allowlist
                      WHERE sha256_hex = ?1
                        AND scope_path = ?2
                        AND expires_at_utc > ?3
                      LIMIT 1",
                    params![sha256_hex, p, now],
                    |r| r.get(0),
                )
                .optional()?;
            if scoped.is_some() {
                return Ok(true);
            }
        }
        let unscoped: Option<i64> = conn
            .query_row(
                "SELECT id FROM ephemeral_allowlist
                  WHERE sha256_hex = ?1
                    AND scope_path IS NULL
                    AND expires_at_utc > ?2
                  LIMIT 1",
                params![sha256_hex, now],
                |r| r.get(0),
            )
            .optional()?;
        Ok(unscoped.is_some())
    }
}

/// Detector instance. Cheap to clone — wraps an `Arc<Mutex<Connection>>`.
#[derive(Clone)]
pub struct EphemeralAllowlistDetector {
    store: EphemeralAllowlistStore,
}

impl EphemeralAllowlistDetector {
    pub fn new(store: EphemeralAllowlistStore) -> Self {
        Self { store }
    }
}

impl Detector for EphemeralAllowlistDetector {
    fn id(&self) -> &str {
        DETECTOR_ID
    }
    fn priority(&self) -> u32 {
        PRIORITY
    }
    fn requires_sha256(&self) -> bool {
        true
    }
    fn check(&self, ctx: &FileCtx<'_>) -> DetectorVerdict {
        let Some(sha256) = HashKind::Sha256.select(ctx) else {
            return DetectorVerdict::Clean;
        };
        let hex = hex::encode(sha256);
        let path_str = ctx.path.to_str();
        match self.store.is_trusted(&hex, path_str, unix_now()) {
            Ok(true) => DetectorVerdict::SkipFile,
            Ok(false) => DetectorVerdict::Clean,
            Err(e) => {
                tracing::warn!(error = %e, "ephemeral allowlist lookup failed (skipping)");
                DetectorVerdict::Clean
            }
        }
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Convenience type alias for the engine wiring layer.
pub type SharedEphemeralAllowlistStore = EphemeralAllowlistStore;

#[allow(dead_code)]
fn _ensure_path_is_used(_: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn fresh_store() -> EphemeralAllowlistStore {
        let conn = db::open_in_memory().unwrap();
        EphemeralAllowlistStore::new(Arc::new(Mutex::new(conn)))
    }

    #[test]
    fn grant_then_trusted() {
        let store = fresh_store();
        store.grant("abc", None, "test", TrustDuration::Days7, "user").unwrap();
        let trusted = store.is_trusted("abc", None, unix_now()).unwrap();
        assert!(trusted);
    }

    #[test]
    fn scope_path_enforced() {
        let store = fresh_store();
        store
            .grant("abc", Some("/home/me/x.exe"), "test", TrustDuration::Days7, "user")
            .unwrap();
        // Matching path is trusted.
        assert!(store
            .is_trusted("abc", Some("/home/me/x.exe"), unix_now())
            .unwrap());
        // Different path is NOT trusted (no fallback to unscoped — there's no unscoped row).
        assert!(!store
            .is_trusted("abc", Some("/tmp/x.exe"), unix_now())
            .unwrap());
    }

    #[test]
    fn expired_row_not_trusted() {
        let store = fresh_store();
        store.grant("abc", None, "test", TrustDuration::Days7, "user").unwrap();
        // Probe far into the future — past expiry.
        let way_future = unix_now() + 365 * 24 * 60 * 60;
        assert!(!store.is_trusted("abc", None, way_future).unwrap());
    }

    #[test]
    fn prune_drops_expired() {
        let store = fresh_store();
        store.grant("abc", None, "old", TrustDuration::Days7, "user").unwrap();
        let way_future = unix_now() + 365 * 24 * 60 * 60;
        let pruned = store.prune_expired(way_future).unwrap();
        assert_eq!(pruned, 1);
        assert!(!store.is_trusted("abc", None, way_future).unwrap());
    }

    #[test]
    fn duration_seconds() {
        assert_eq!(TrustDuration::Days7.seconds(), 7 * 86400);
        assert_eq!(TrustDuration::Days30.seconds(), 30 * 86400);
        assert_eq!(TrustDuration::Days365.seconds(), 365 * 86400);
    }
}
