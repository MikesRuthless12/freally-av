//! File-mutation baseline + detection (TASK-138, FR-131).
//!
//! Per-scan inventory of "interesting" files — autostart paths, `$PATH`
//! binaries, login scripts — captured into the `file_baseline` table.
//! At each subsequent scan, when one of those files reappears with a
//! changed BLAKE3, and the **prior** snapshot was signed-or-NSRL-known,
//! the detector emits a `Malicious` finding with severity `medium`
//! (mutation is a strong post-compromise persistence signal but the
//! file may still be legitimate — e.g. self-updating installer; we
//! surface it for the user to triage, we don't auto-quarantine).
//!
//! Boundary with the existing pipeline:
//! - The standard [`crate::detect::DetectionPipeline`] is per-file and
//!   stateless across files in a scan.
//! - This module is **per-scan stateful**: it carries the set of
//!   interesting paths, opens the DB to look up the most recent prior
//!   baseline, INSERTs the new baseline row, and reports a finding when
//!   the diff fires the rule. The engine drives it from outside the
//!   pipeline (see `engine.rs`'s post-hash hook).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};

use crate::detect::publisher::SignerIdentity;

/// What sourced the path into the interesting set. Mirrors the
/// `file_baseline.source` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineSource {
    Autostart,
    PathBin,
    Script,
    Other,
}

impl BaselineSource {
    pub fn as_str(self) -> &'static str {
        match self {
            BaselineSource::Autostart => "autostart",
            BaselineSource::PathBin => "path_bin",
            BaselineSource::Script => "script",
            BaselineSource::Other => "other",
        }
    }
}

/// One mutation finding to emit. The engine translates this into a
/// `ScanProgress::Finding` + `findings` row at scan time.
#[derive(Debug, Clone)]
pub struct MutationFinding {
    pub path: PathBuf,
    pub rule_id: String,
    pub severity: crate::detect::Severity,
    pub evidence: String,
}

/// One pending baseline row queued for batch flush at scan end.
/// Phase 5 wave 3 perf push: instead of one IMMEDIATE transaction per
/// file (~5-15 ms each, multiply by hundreds of `$PATH` binaries),
/// we accumulate rows in memory and flush them all in a single
/// transaction at the end of the scan.
#[derive(Debug, Clone)]
struct PendingBaselineRow {
    scan_id: i64,
    path: PathBuf,
    blake3_hex: String,
    sha256_hex: Option<String>,
    size_bytes: u64,
    signer: SignerIdentity,
    nsrl_known: bool,
    source: BaselineSource,
    recorded_at_utc: i64,
}

/// Per-scan baseline state. Construct once at scan start with
/// [`FileBaseline::from_platform`]; call [`Self::check_and_enqueue`]
/// every time the engine successfully hashes a file. Drain the
/// accumulated rows via [`Self::flush_pending`] at scan end.
#[derive(Default)]
pub struct FileBaseline {
    /// Lower-cased path strings (Windows) or as-is (Unix) — interpreted
    /// by [`Self::source_for`] to classify a path into a
    /// [`BaselineSource`]. We don't canonicalize at construction time:
    /// the autostart enumerator already returns the canonical-ish
    /// `Path::is_file` shape, and per-scan files arrive with whatever
    /// form the walker emitted. Comparison is byte-exact (case-folded
    /// on Windows) so a tiny extra perf cost beats a hard-to-debug
    /// case-mismatch miss.
    autostart: BTreeSet<PathBuf>,
    path_bins: BTreeSet<PathBuf>,
    enabled: bool,
    /// In-memory queue for the deferred batch flush. Behind a Mutex
    /// so the multi-threaded worker pool can append from any worker
    /// (Phase 5 wave 3 perf phase 1).
    pending: Mutex<Vec<PendingBaselineRow>>,
}

impl FileBaseline {
    /// Empty baseline. `is_interesting` always returns `None`. Useful
    /// for tests and for the early-return path in tiny scans where the
    /// platform enumerator would surface zero entries.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Collect autostart + `$PATH` files from the host platform.
    /// Best-effort — missing directories or unreadable `$PATH`
    /// entries are silently skipped.
    pub fn from_platform() -> Self {
        let autostart: BTreeSet<PathBuf> = platform_autostart().into_iter().collect();
        let path_bins: BTreeSet<PathBuf> = path_binaries().into_iter().collect();
        let enabled = !autostart.is_empty() || !path_bins.is_empty();
        Self {
            autostart,
            path_bins,
            enabled,
            pending: Mutex::new(Vec::new()),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn autostart_count(&self) -> usize {
        self.autostart.len()
    }

    pub fn path_bin_count(&self) -> usize {
        self.path_bins.len()
    }

    /// Classify `path` into a [`BaselineSource`] when it's part of the
    /// interesting set; `None` otherwise.
    pub fn source_for(&self, path: &Path) -> Option<BaselineSource> {
        if self.autostart.contains(path) {
            let kind = if path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| {
                    matches!(
                        e.to_ascii_lowercase().as_str(),
                        "sh" | "bash" | "zsh" | "ps1" | "bat" | "cmd"
                    )
                })
                .unwrap_or(false)
            {
                BaselineSource::Script
            } else {
                BaselineSource::Autostart
            };
            return Some(kind);
        }
        if self.path_bins.contains(path) {
            return Some(BaselineSource::PathBin);
        }
        None
    }

    /// Perf phase 5 — check for drift against the most recent prior
    /// baseline (read-only DB op), then **enqueue** the new row for a
    /// batched flush at scan end. Replaces the prior
    /// `record_and_check` which did one IMMEDIATE transaction per
    /// file; per-file DB write overhead vanishes from the hot path.
    ///
    /// Returns `Some(MutationFinding)` when the hash drifted from a
    /// prior signed-or-NSRL-known snapshot, mirroring the previous
    /// contract. Returns `None` for first-snapshot files, unchanged
    /// files, and drift from unsigned/unknown priors.
    #[allow(clippy::too_many_arguments)]
    pub fn check_and_enqueue(
        &self,
        db: &Mutex<Connection>,
        scan_id: i64,
        path: &Path,
        blake3_hex: &str,
        sha256_hex: Option<&str>,
        size_bytes: u64,
        signer: &SignerIdentity,
        nsrl_known: bool,
    ) -> Option<MutationFinding> {
        let source = self.source_for(path)?;
        // Read the prior snapshot — single-statement SELECT, no
        // transaction needed. The previous IMMEDIATE-txn guard was
        // there to serialize the read+insert pair; with the insert
        // now deferred to a batched flush, the read can race
        // harmlessly with concurrent writers (the worst case is two
        // workers both observe the same prior + both enqueue a new
        // row, which the batch flush handles by appending both —
        // file_baseline is append-only).
        let prior = match db.lock() {
            Ok(conn) => read_latest_prior(&conn, path).ok().flatten(),
            Err(_) => None,
        };
        let recorded_at_utc = now_utc();
        // Sec-review M1 (defense-in-depth): truncate signer identity
        // before storage so direct callers can't bypass the 512-byte
        // cap. Also keeps the pending queue size predictable.
        let signer_truncated = signer.clone().truncated();
        let row = PendingBaselineRow {
            scan_id,
            path: path.to_path_buf(),
            blake3_hex: blake3_hex.to_string(),
            sha256_hex: sha256_hex.map(|s| s.to_string()),
            size_bytes,
            signer: signer_truncated,
            nsrl_known,
            source,
            recorded_at_utc,
        };
        if let Ok(mut q) = self.pending.lock() {
            q.push(row);
        }
        let prior = prior?;
        if prior.blake3_hex == blake3_hex {
            return None;
        }
        // Hash differs. Alert only when the prior version was
        // signed-or-NSRL-known — without that gate every cosmetic edit
        // to ~/.zshrc would surface as a finding, which would burn
        // user trust fast.
        if !(prior.was_signed || prior.nsrl_known) {
            return None;
        }
        let evidence = format!(
            "mutated {} (was BLAKE3 {} signed={} nsrl_known={}; now BLAKE3 {} signed={} nsrl_known={})",
            source.as_str(),
            prior.blake3_hex,
            prior.was_signed,
            prior.nsrl_known,
            blake3_hex,
            signer.is_signed(),
            nsrl_known,
        );
        Some(MutationFinding {
            path: path.to_path_buf(),
            rule_id: format!("freally:file_mutation:{}", source.as_str()),
            severity: crate::detect::Severity::Medium,
            evidence,
        })
    }

    /// Batch-flush every pending baseline row in a single transaction.
    /// Call once at scan end (or pause, where the resume token's
    /// `processed_paths` keeps the baseline intent correct across
    /// resume). Returns the number of rows persisted.
    ///
    /// Soft-failure: a DB lock error or transaction failure logs at
    /// WARN and returns 0 — the cache miss on next scan re-discovers
    /// every file the same way. The append-only `file_baseline`
    /// table tolerates the loss cleanly.
    pub fn flush_pending(&self, db: &Mutex<Connection>) -> usize {
        let rows = match self.pending.lock() {
            Ok(mut q) => std::mem::take(&mut *q),
            Err(_) => return 0,
        };
        if rows.is_empty() {
            return 0;
        }
        let mut conn = match db.lock() {
            Ok(c) => c,
            Err(_) => return 0,
        };
        let tx = match conn.transaction() {
            Ok(t) => t,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    rows_dropped = rows.len(),
                    "file_mutation: failed to open flush transaction; baseline rows lost"
                );
                return 0;
            }
        };
        let written = {
            let mut stmt = match tx.prepare(
                "INSERT INTO file_baseline \
                 (scan_id, path, blake3_hex, sha256_hex, size_bytes, \
                  signer_identity, signer_kind, nsrl_known, source, recorded_at_utc) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            ) {
                Ok(s) => s,
                Err(err) => {
                    tracing::warn!(error = %err, "file_mutation: prepare failed");
                    return 0;
                }
            };
            let mut count = 0usize;
            for r in &rows {
                let path_str = r.path.to_string_lossy();
                if stmt
                    .execute(params![
                        r.scan_id,
                        path_str,
                        r.blake3_hex,
                        r.sha256_hex,
                        r.size_bytes as i64,
                        r.signer.identity.as_str(),
                        r.signer.kind.as_str(),
                        r.nsrl_known as i64,
                        r.source.as_str(),
                        r.recorded_at_utc,
                    ])
                    .is_ok()
                {
                    count += 1;
                }
            }
            count
        };
        if let Err(err) = tx.commit() {
            tracing::warn!(error = %err, "file_mutation: commit failed");
            return 0;
        }
        written
    }
}

/// One prior baseline row, projected down to the fields the detector
/// needs for the diff.
struct PriorBaseline {
    blake3_hex: String,
    was_signed: bool,
    nsrl_known: bool,
}

/// Read the most recent baseline row for `path`. `None` when this is
/// the first time we've snapshotted this path. The deferred-batch
/// design (perf phase 5) means this runs without a wrapping
/// transaction; concurrent baseline appends from sibling workers
/// race harmlessly because every (scan_id, path, mtime) tuple is
/// unique within a single scan.
fn read_latest_prior(
    conn: &rusqlite::Connection,
    path: &Path,
) -> rusqlite::Result<Option<PriorBaseline>> {
    let path_str = path.to_string_lossy();
    conn.query_row(
        "SELECT blake3_hex, signer_identity, nsrl_known FROM file_baseline \
         WHERE path = ?1 ORDER BY recorded_at_utc DESC LIMIT 1",
        params![path_str],
        |row| {
            let blake3_hex: String = row.get(0)?;
            let signer: String = row.get(1)?;
            let nsrl_known: i64 = row.get(2)?;
            Ok(PriorBaseline {
                blake3_hex,
                was_signed: !signer.is_empty() && signer != SignerIdentity::unsigned().identity,
                nsrl_known: nsrl_known != 0,
            })
        },
    )
    .optional()
}

fn now_utc() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ===========================================================================
// Platform shims
// ===========================================================================

/// Autostart-class paths on this host. Wraps the per-platform
/// enumerator so the detector + tests stay portable.
pub fn platform_autostart() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        crate::platform::linux::autostart::enumerate_autostart()
    }
    #[cfg(target_os = "macos")]
    {
        crate::platform::mac::autostart::enumerate_autostart()
    }
    #[cfg(target_os = "windows")]
    {
        crate::platform::win::autostart::enumerate_autostart()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Vec::new()
    }
}

/// Every executable on `$PATH` (Unix) / `PATH` (Windows). Returns the
/// canonical path of every regular file in each `$PATH` directory,
/// deduped via the caller's `BTreeSet`. Windows includes only files
/// whose extension is in `PATHEXT` (case-insensitive); Unix includes
/// every regular file. Symbolic links are dereferenced once via
/// `Path::canonicalize` so two `$PATH` entries pointing at the same
/// underlying file collapse into one baseline row.
pub fn path_binaries() -> Vec<PathBuf> {
    let Some(path) = std::env::var_os("PATH") else {
        return Vec::new();
    };
    let pathext_lc: Vec<String> = if cfg!(target_os = "windows") {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD;.PS1".to_string())
            .split(';')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        Vec::new()
    };
    let mut out: BTreeSet<PathBuf> = BTreeSet::new();
    for dir in std::env::split_paths(&path) {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            if cfg!(target_os = "windows") {
                let ext = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| format!(".{}", e.to_ascii_lowercase()))
                    .unwrap_or_default();
                if !pathext_lc.iter().any(|p| p == &ext) {
                    continue;
                }
            }
            let canonical = std::fs::canonicalize(&p).unwrap_or(p);
            out.insert(canonical);
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use std::sync::Mutex;

    fn baseline_with_paths(autostart: &[&Path]) -> FileBaseline {
        let mut b = FileBaseline::empty();
        for p in autostart {
            b.autostart.insert(p.to_path_buf());
        }
        b.enabled = !b.autostart.is_empty() || !b.path_bins.is_empty();
        b
    }

    /// Insert a `scans` row so the `file_baseline` FK constraint is
    /// satisfied. Test helper only.
    fn make_scan(conn: &Connection, scan_id: i64) {
        conn.execute(
            "INSERT INTO scans (id, started_at_utc, trigger, target_kind, target_paths, \
             exclusions_snap, engine_version, feed_versions, status) \
             VALUES (?1, 0, 'manual', 'path', '[]', '[]', 'test', '{}', 'running')",
            rusqlite::params![scan_id],
        )
        .expect("insert scans row");
    }

    #[test]
    fn empty_baseline_classifies_nothing() {
        let b = FileBaseline::empty();
        assert!(b.source_for(Path::new("/anywhere/x")).is_none());
    }

    #[test]
    fn classifies_autostart_extension_as_script() {
        let p = std::path::PathBuf::from("/tmp/.zshrc");
        let mut b = FileBaseline::empty();
        // Use a script-ish extension explicitly.
        let target = std::path::PathBuf::from("/tmp/foo.sh");
        b.autostart.insert(target.clone());
        assert_eq!(b.source_for(&target), Some(BaselineSource::Script));
        b.autostart.insert(p.clone());
        // .zshrc has no extension → Autostart, not Script.
        assert_eq!(b.source_for(&p), Some(BaselineSource::Autostart));
    }

    #[test]
    fn unchanged_hash_emits_no_finding() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t.db");
        let conn = db::open(&db_path).unwrap();
        make_scan(&conn, 1);
        make_scan(&conn, 2);
        let db = Mutex::new(conn);
        let target = dir.path().join("rc");
        std::fs::write(&target, b"hello").unwrap();

        let baseline = baseline_with_paths(&[&target]);
        let signer = SignerIdentity::unsigned();

        // First record — no prior, no finding (and the prior wouldn't
        // have been "signed-or-known" anyway).
        let f1 = baseline.check_and_enqueue(&db, 1, &target, "aa", None, 5, &signer, false);
        assert!(f1.is_none());
        assert_eq!(baseline.flush_pending(&db), 1);

        // Second record, same hash — no diff.
        let f2 = baseline.check_and_enqueue(&db, 2, &target, "aa", None, 5, &signer, false);
        assert!(f2.is_none());
        baseline.flush_pending(&db);
    }

    #[test]
    fn mutation_after_signed_prior_emits_finding() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t.db");
        let conn = db::open(&db_path).unwrap();
        make_scan(&conn, 1);
        make_scan(&conn, 2);
        let db = Mutex::new(conn);
        let target = dir.path().join("agent.plist");
        std::fs::write(&target, b"hello").unwrap();

        let baseline = baseline_with_paths(&[&target]);
        let signed = SignerIdentity {
            identity: "Apple Inc.".into(),
            kind: crate::detect::publisher::SignerKind::Codesign,
        };

        // Prior snapshot: signed.
        baseline.check_and_enqueue(&db, 1, &target, "aa", None, 5, &signed, false);
        assert_eq!(baseline.flush_pending(&db), 1);
        // Now the hash drifts.
        let f2 = baseline
            .check_and_enqueue(
                &db,
                2,
                &target,
                "bb",
                None,
                5,
                &SignerIdentity::unsigned(),
                false,
            )
            .expect("expected mutation finding");
        assert_eq!(f2.severity, crate::detect::Severity::Medium);
        assert!(f2.rule_id.starts_with("freally:file_mutation:"));
        baseline.flush_pending(&db);
    }

    #[test]
    fn mutation_after_unsigned_unknown_prior_emits_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t.db");
        let conn = db::open(&db_path).unwrap();
        make_scan(&conn, 1);
        make_scan(&conn, 2);
        let db = Mutex::new(conn);
        let target = dir.path().join("script");
        std::fs::write(&target, b"hello").unwrap();

        let baseline = baseline_with_paths(&[&target]);
        let unsigned = SignerIdentity::unsigned();

        baseline.check_and_enqueue(&db, 1, &target, "aa", None, 5, &unsigned, false);
        baseline.flush_pending(&db);
        let f = baseline.check_and_enqueue(&db, 2, &target, "bb", None, 5, &unsigned, false);
        assert!(
            f.is_none(),
            "no finding expected for mutated previously-unsigned file"
        );
        baseline.flush_pending(&db);
    }

    #[test]
    fn mutation_after_nsrl_known_prior_emits_finding() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("t.db");
        let conn = db::open(&db_path).unwrap();
        make_scan(&conn, 1);
        make_scan(&conn, 2);
        let db = Mutex::new(conn);
        let target = dir.path().join("ls");
        std::fs::write(&target, b"hello").unwrap();

        let baseline = baseline_with_paths(&[&target]);
        let unsigned = SignerIdentity::unsigned();

        baseline.check_and_enqueue(&db, 1, &target, "aa", None, 5, &unsigned, true);
        assert_eq!(baseline.flush_pending(&db), 1);
        let f = baseline
            .check_and_enqueue(&db, 2, &target, "bb", None, 5, &unsigned, false)
            .expect("expected mutation finding for previously NSRL-known file");
        assert_eq!(f.severity, crate::detect::Severity::Medium);
        baseline.flush_pending(&db);
    }

    #[test]
    fn path_binaries_returns_files_only() {
        let bins = path_binaries();
        // CI hosts always have at least /usr/bin or C:\Windows\System32
        // populated; we just assert correctness, not non-emptiness.
        for p in bins {
            assert!(p.is_absolute(), "expected absolute path: {}", p.display());
        }
    }
}
