//! NSRL goodware allowlist detector (TASK-021, Phase 2).
//!
//! Reads `<data_dir>/feeds/nsrl_sha256.bin` — same on-disk 32-byte-key format
//! as the abuse.ch blacklist (see [`super::hash_set_file`]) — and returns
//! [`DetectorVerdict::SkipFile`] on hit. The pipeline short-circuits when a
//! `SkipFile` is returned, so an NSRL match ends evaluation before any
//! blacklist detector is consulted. This is the "fast skip" mentioned in the
//! Phase 2 roadmap for TASK-019.
//!
//! **Hash function:** SHA-256 by default. NSRL RDS Modern publishes SHA-256
//! per hash (alongside SHA-1 and MD5 for legacy compatibility); BLAKE3 is
//! not available upstream. The engine must therefore set
//! `ScanOptions::compute_sha256 = true` whenever this detector is loaded,
//! otherwise the allowlist short-circuit never fires. Override via
//! [`GoodwareAllowlistDetector::with_hash_kind`] if a BLAKE3-keyed corpus
//! is ever shipped.
//!
//! Built by the NSRL feed updater (TASK-023) from NIST's Reference Data Set
//! (RDS) — a US public-domain corpus of known-good file hashes for OS
//! installs, mainstream applications, and developer tooling. Per
//! `docs/prd.md` § 1.5.1 NSRL is unrestricted for commercial redistribution.

use std::path::Path;
use std::sync::Arc;

use super::hash_set_file::{HashSetError, HashSetFile};
use super::{Detector, DetectorVerdict, FileCtx, HashKind};

/// Stable detector id used in logs, audit, and the pipeline's
/// `feed_versions` summary.
pub const DETECTOR_ID: &str = "goodware_allowlist";

/// Pipeline priority. Allowlists run **before** blacklists so an NSRL hit
/// short-circuits the rest of the pipeline. 10 is comfortably below the
/// hash-blacklist's 100.
pub const PRIORITY: u32 = 10;

/// NSRL goodware allowlist detector. Cheap to clone.
#[derive(Clone)]
pub struct GoodwareAllowlistDetector {
    set: Arc<HashSetFile>,
    hash_kind: HashKind,
}

impl GoodwareAllowlistDetector {
    /// Open the NSRL hash-set file at the given path. Defaults to
    /// [`HashKind::Sha256`] (the format NSRL RDS Modern publishes).
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, HashSetError> {
        let set = HashSetFile::open(path)?;
        Ok(Self {
            set: Arc::new(set),
            hash_kind: HashKind::Sha256,
        })
    }

    /// Override the default hash kind.
    pub fn with_hash_kind(mut self, kind: HashKind) -> Self {
        self.hash_kind = kind;
        self
    }

    /// Number of hashes loaded — surfaced in `scans.feed_versions` and the
    /// About page (FR-157).
    pub fn loaded_count(&self) -> u64 {
        self.set.len()
    }

    /// Which hash this detector queries.
    pub fn hash_kind(&self) -> HashKind {
        self.hash_kind
    }
}

impl Detector for GoodwareAllowlistDetector {
    fn id(&self) -> &str {
        DETECTOR_ID
    }

    fn priority(&self) -> u32 {
        PRIORITY
    }

    fn requires_sha256(&self) -> bool {
        matches!(self.hash_kind, HashKind::Sha256)
    }

    fn check(&self, ctx: &FileCtx<'_>) -> DetectorVerdict {
        let Some(digest) = self.hash_kind.select(ctx) else {
            // SHA-256 not computed — engine misconfigured. Fail clean (no
            // allowlist match) so the pipeline still evaluates blacklists
            // rather than silently skipping every file.
            return DetectorVerdict::Clean;
        };
        if self.set.contains(digest) {
            DetectorVerdict::SkipFile
        } else {
            DetectorVerdict::Clean
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::hash_set_file::write_sorted;
    use super::super::{
        DetectionPipeline, DetectorVerdict, FileCtx, PipelineOutcome, Severity,
        hash_blacklist::HashBlacklistDetector,
    };
    use super::*;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

    fn make_set(hashes: &[[u8; 32]]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nsrl_hashes.bin");
        write_sorted(&path, hashes.iter().copied()).unwrap();
        (dir, path)
    }

    /// SHA-256 ctx — matches production wiring (NSRL is SHA-256, engine
    /// must set `compute_sha256 = true` when this detector is loaded).
    fn ctx_sha<'a>(path: &'a Path, zero_blake3: &'a [u8; 32], sha: &'a [u8; 32]) -> FileCtx<'a> {
        FileCtx {
            path,
            size_bytes: 0,
            blake3: zero_blake3,
            sha256: Some(sha),
        }
    }

    #[test]
    fn defaults_to_sha256() {
        let (_dir, path) = make_set(&[[0; 32]]);
        let d = GoodwareAllowlistDetector::open(&path).unwrap();
        assert_eq!(d.hash_kind(), super::HashKind::Sha256);
    }

    #[test]
    fn miss_returns_clean() {
        let good = [0x77; 32];
        let (_dir, path) = make_set(&[good]);
        let d = GoodwareAllowlistDetector::open(&path).unwrap();
        let other = [0x99; 32];
        let zero = [0u8; 32];
        assert_eq!(
            d.check(&ctx_sha(Path::new("/x"), &zero, &other)),
            DetectorVerdict::Clean
        );
    }

    #[test]
    fn hit_returns_skip_file_not_malicious() {
        let good = [0x77; 32];
        let (_dir, path) = make_set(&[good]);
        let d = GoodwareAllowlistDetector::open(&path).unwrap();
        assert_eq!(d.id(), "goodware_allowlist");
        assert_eq!(d.priority(), 10);
        let zero = [0u8; 32];
        assert_eq!(
            d.check(&ctx_sha(Path::new("/y"), &zero, &good)),
            DetectorVerdict::SkipFile
        );
    }

    #[test]
    fn missing_sha256_in_ctx_returns_clean() {
        // Engine misconfiguration: SHA-256 not computed. Allowlist must
        // fail clean so the pipeline still evaluates blacklists rather
        // than silently allowing every file.
        let good = [0x77; 32];
        let (_dir, path) = make_set(&[good]);
        let d = GoodwareAllowlistDetector::open(&path).unwrap();
        let ctx = FileCtx {
            path: Path::new("/x"),
            size_bytes: 0,
            blake3: &good,
            sha256: None,
        };
        assert_eq!(d.check(&ctx), DetectorVerdict::Clean);
    }

    #[test]
    fn allowlist_beats_blacklist_when_both_match() {
        // Same hash present in both feeds — allowlist's lower priority must win.
        let h = [0x42; 32];
        let (_allow_dir, allow_path) = make_set(&[h]);

        let block_dir = tempdir().unwrap();
        let block_path = block_dir.path().join("block.bin");
        write_sorted(&block_path, [h]).unwrap();

        let allow = GoodwareAllowlistDetector::open(&allow_path).unwrap();
        let block = HashBlacklistDetector::open(&block_path)
            .unwrap()
            .with_severity(Severity::High);

        let pipeline = DetectionPipeline::new(vec![Box::new(block), Box::new(allow)]);
        let zero = [0u8; 32];
        let outcome = pipeline.evaluate(&ctx_sha(Path::new("/z"), &zero, &h));
        assert_eq!(
            outcome,
            PipelineOutcome::SkippedByAllowlist {
                detector_id: "goodware_allowlist".into()
            }
        );
    }
}
