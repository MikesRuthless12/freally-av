//! NSRL goodware allowlist detector (TASK-021, Phase 2).
//!
//! Reads `<data_dir>/feeds/nsrl_hashes.bin` — same on-disk format as the
//! abuse.ch blacklist (see [`super::hash_set_file`]) — and returns
//! [`DetectorVerdict::SkipFile`] on hit. The pipeline short-circuits when a
//! `SkipFile` is returned, so an NSRL match ends evaluation before any
//! blacklist detector is consulted. This is the "fast skip" mentioned in the
//! Phase 2 roadmap for TASK-019.
//!
//! Built by the NSRL feed updater (TASK-023) from NIST's Reference Data Set
//! (RDS) — a US public-domain corpus of known-good file hashes for OS
//! installs, mainstream applications, and developer tooling. Per
//! `docs/prd.md` § 1.5.1 NSRL is unrestricted for commercial redistribution.

use std::path::Path;
use std::sync::Arc;

use super::hash_set_file::{HashSetError, HashSetFile};
use super::{Detector, DetectorVerdict, FileCtx};

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
}

impl GoodwareAllowlistDetector {
    /// Open the NSRL hash-set file at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, HashSetError> {
        let set = HashSetFile::open(path)?;
        Ok(Self { set: Arc::new(set) })
    }

    /// Number of hashes loaded — surfaced in `scans.feed_versions` and the
    /// About page (FR-157).
    pub fn loaded_count(&self) -> u64 {
        self.set.len()
    }
}

impl Detector for GoodwareAllowlistDetector {
    fn id(&self) -> &str {
        DETECTOR_ID
    }

    fn priority(&self) -> u32 {
        PRIORITY
    }

    fn check(&self, ctx: &FileCtx<'_>) -> DetectorVerdict {
        if self.set.contains(ctx.blake3) {
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

    fn ctx<'a>(path: &'a Path, hash: &'a [u8; 32]) -> FileCtx<'a> {
        FileCtx {
            path,
            size_bytes: 0,
            blake3: hash,
            sha256: None,
        }
    }

    #[test]
    fn miss_returns_clean() {
        let good = [0x77; 32];
        let (_dir, path) = make_set(&[good]);
        let d = GoodwareAllowlistDetector::open(&path).unwrap();
        let other = [0x99; 32];
        assert_eq!(
            d.check(&ctx(Path::new("/x"), &other)),
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
        assert_eq!(
            d.check(&ctx(Path::new("/y"), &good)),
            DetectorVerdict::SkipFile
        );
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
        let outcome = pipeline.evaluate(&ctx(Path::new("/z"), &h));
        assert_eq!(
            outcome,
            PipelineOutcome::SkippedByAllowlist {
                detector_id: "goodware_allowlist".into()
            }
        );
    }
}
