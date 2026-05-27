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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::hash_set_file::{HashSetError, HashSetFile};
use super::{Detector, DetectorVerdict, FileCtx, HashKind};

/// TASK-183 — Resolve the per-OS NSRL slice the engine should
/// load. End users who opted into NSRL via the first-run prompt
/// (TASK-Phase-7B UI) get one of:
///
///   * `nsrl_sha256_windows.bin` / `_macos.bin` / `_linux.bin` —
///     the host-OS slice, ~50% the size of the full union (Wave 2
///     space win).
///   * `nsrl_sha256_other.bin` — cross-platform manufacturer rows
///     (e.g. embedded firmware, generic Unix). Always loaded
///     alongside the host slice because some packages live there.
///   * `nsrl_sha256.bin` — full union, fallback for forensic /
///     multi-platform machines (and for users who haven't moved to
///     per-OS slices yet).
///
/// Resolution preference per host:
///   1. If the host-OS slice + `_other` slice both exist, return them.
///   2. If only the host-OS slice exists, return just that.
///   3. If only the union `.bin` exists, return that.
///   4. If nothing exists, return an empty vec (caller skips load).
///
/// Returns paths in the order the engine should load them.
pub fn resolve_nsrl_slice_paths(feeds_dir: &Path) -> Vec<PathBuf> {
    let host_slice_name = match std::env::consts::OS {
        "windows" => "nsrl_sha256_windows.bin",
        "macos" => "nsrl_sha256_macos.bin",
        "linux" | "android" => "nsrl_sha256_linux.bin",
        // FreeBSD/Solaris/Other → use the `other` bucket plus the
        // full union as a backstop.
        _ => "nsrl_sha256_other.bin",
    };
    let host_slice = feeds_dir.join(host_slice_name);
    let other_slice = feeds_dir.join("nsrl_sha256_other.bin");
    let union = feeds_dir.join("nsrl_sha256.bin");

    let mut out: Vec<PathBuf> = Vec::new();
    if host_slice.exists() {
        out.push(host_slice.clone());
        // The `_other` slice carries cross-platform packages that
        // might land on any host. If it exists and isn't the same
        // file we already picked (FreeBSD/Solaris falls through to
        // the other-slice as the host slice), include it.
        if other_slice.exists() && other_slice != host_slice {
            out.push(other_slice);
        }
        return out;
    }
    // No host-OS slice — fall back to the union.
    if union.exists() {
        out.push(union);
    }
    out
}

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
    fn resolve_picks_host_slice_when_present_with_other() {
        let dir = tempdir().unwrap();
        let host_slice = match std::env::consts::OS {
            "windows" => "nsrl_sha256_windows.bin",
            "macos" => "nsrl_sha256_macos.bin",
            "linux" | "android" => "nsrl_sha256_linux.bin",
            _ => "nsrl_sha256_other.bin",
        };
        std::fs::write(dir.path().join(host_slice), b"x").unwrap();
        if host_slice != "nsrl_sha256_other.bin" {
            std::fs::write(dir.path().join("nsrl_sha256_other.bin"), b"x").unwrap();
        }
        std::fs::write(dir.path().join("nsrl_sha256.bin"), b"x").unwrap();
        let paths = super::resolve_nsrl_slice_paths(dir.path());
        // Host slice should be first.
        assert!(paths[0].ends_with(host_slice));
        // _other should be loaded too unless host = other.
        if host_slice != "nsrl_sha256_other.bin" {
            assert_eq!(paths.len(), 2);
            assert!(paths[1].ends_with("nsrl_sha256_other.bin"));
        } else {
            assert_eq!(paths.len(), 1);
        }
        // The full union must NOT be loaded when slices are present
        // (avoids double-counting the same hashes).
        assert!(paths.iter().all(|p| !p.ends_with("nsrl_sha256.bin")
            || p.file_name().unwrap().to_string_lossy().contains('_')));
    }

    #[test]
    fn resolve_falls_back_to_union_when_no_slices() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("nsrl_sha256.bin"), b"x").unwrap();
        let paths = super::resolve_nsrl_slice_paths(dir.path());
        assert_eq!(paths.len(), 1);
        assert!(paths[0].ends_with("nsrl_sha256.bin"));
    }

    #[test]
    fn resolve_returns_empty_when_no_files() {
        let dir = tempdir().unwrap();
        let paths = super::resolve_nsrl_slice_paths(dir.path());
        assert!(paths.is_empty());
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
