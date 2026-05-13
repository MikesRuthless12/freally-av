//! BYOVD (Bring Your Own Vulnerable Driver) detector (TASK-139,
//! FR-141 static portion).
//!
//! Wraps the same on-disk sorted-set format the abuse.ch and NSRL feeds
//! use, but is keyed off the loldrivers.io blocklist published in
//! `<feeds_dir>/byovd_sha256.bin` by
//! [`crate::updater::loldrivers::LolDriversUpdater`]. Upstream license
//! is **Apache-2.0** per
//! <https://github.com/magicsword-io/LOLDrivers/blob/main/LICENSE> —
//! we redistribute SHA-256 digests only.
//!
//! A hit emits a `Critical` verdict with rule id `loldrivers:byovd:<prefix>`
//! and rule source `"loldrivers"`. The severity is higher than abuse.ch
//! (`High`) because the file is by definition a kernel driver with a
//! known privilege-escalation primitive; landing one of these on disk is
//! a strong post-compromise signal.
//!
//! Driver-load-time enforcement (refusing to load the driver via WDAC)
//! is TASK-154 / Phase 12; this module ships only the static at-rest
//! hash-match.

use std::path::Path;
use std::sync::Arc;

use super::hash_set_file::{HashSetError, HashSetFile};
use super::{Detector, DetectorVerdict, FileCtx, HashKind, Severity};

const RULE_SOURCE: &str = "loldrivers";
const RULE_ID_PREFIX: &str = "loldrivers:byovd";

/// Stable detector id used in logs, audit, and the pipeline's
/// `feed_versions` summary.
pub const DETECTOR_ID: &str = "byovd_blocklist";

/// Pipeline priority. Sits at the abuse.ch tier (100) so an NSRL
/// allowlist hit still short-circuits ahead of it.
pub const PRIORITY: u32 = 110;

/// BYOVD blocklist detector. Cheap to clone (mmap reference-counted via
/// `Arc`).
#[derive(Clone)]
pub struct ByovdDetector {
    set: Arc<HashSetFile>,
    severity: Severity,
}

impl ByovdDetector {
    /// Open `<feeds_dir>/byovd_sha256.bin`. Returns the standard
    /// [`HashSetError`] when the file is missing or malformed; callers
    /// drop the detector in that case.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, HashSetError> {
        let set = HashSetFile::open(path)?;
        Ok(Self {
            set: Arc::new(set),
            severity: Severity::Critical,
        })
    }

    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn loaded_count(&self) -> u64 {
        self.set.len()
    }
}

impl Detector for ByovdDetector {
    fn id(&self) -> &str {
        DETECTOR_ID
    }

    fn priority(&self) -> u32 {
        PRIORITY
    }

    fn requires_sha256(&self) -> bool {
        // loldrivers.io publishes SHA-256 only.
        true
    }

    fn check(&self, ctx: &FileCtx<'_>) -> DetectorVerdict {
        // loldrivers publishes SHA-256 only; mirror the engine gate the
        // abuse.ch detector uses — fail clean when SHA-256 isn't on.
        let Some(digest) = HashKind::Sha256.select(ctx) else {
            return DetectorVerdict::Clean;
        };
        if self.set.contains(digest) {
            let rule_id = format!("{RULE_ID_PREFIX}:{}", hex_prefix(digest, 8));
            let evidence = format!("sha256={}", hex::encode(digest));
            DetectorVerdict::Malicious {
                rule_id,
                rule_source: RULE_SOURCE.to_string(),
                severity: self.severity,
                evidence: Some(evidence),
            }
        } else {
            DetectorVerdict::Clean
        }
    }
}

fn hex_prefix(bytes: &[u8], n: usize) -> String {
    let take = n.min(bytes.len());
    hex::encode(&bytes[..take])
}

#[cfg(test)]
mod tests {
    use super::super::hash_set_file::write_sorted;
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn known_byovd_hash_emits_critical_finding() {
        let dir = tempdir().unwrap();
        let feed = dir.path().join("byovd_sha256.bin");
        let mut victim = [0u8; 32];
        victim[31] = 0xab;
        write_sorted(&feed, [victim]).unwrap();

        let detector = ByovdDetector::open(&feed).unwrap();
        let path = std::path::PathBuf::from("/sys/drivers/bad.sys");
        let ctx = FileCtx {
            path: &path,
            size_bytes: 1024,
            blake3: &[0u8; 32],
            sha256: Some(&victim),
        };
        match detector.check(&ctx) {
            DetectorVerdict::Malicious {
                severity,
                rule_source,
                ..
            } => {
                assert_eq!(severity, Severity::Critical);
                assert_eq!(rule_source, "loldrivers");
            }
            other => panic!("expected Malicious, got {other:?}"),
        }
    }

    #[test]
    fn unknown_hash_is_clean() {
        let dir = tempdir().unwrap();
        let feed = dir.path().join("byovd_sha256.bin");
        let mut victim = [0u8; 32];
        victim[31] = 0x01;
        write_sorted(&feed, [victim]).unwrap();

        let detector = ByovdDetector::open(&feed).unwrap();
        let path = std::path::PathBuf::from("/sys/drivers/cleanly-loaded.sys");
        let unrelated = [0xffu8; 32];
        let ctx = FileCtx {
            path: &path,
            size_bytes: 2048,
            blake3: &[0u8; 32],
            sha256: Some(&unrelated),
        };
        assert_eq!(detector.check(&ctx), DetectorVerdict::Clean);
    }

    #[test]
    fn missing_sha256_fails_clean_not_panic() {
        let dir = tempdir().unwrap();
        let feed = dir.path().join("byovd_sha256.bin");
        let mut victim = [0u8; 32];
        victim[0] = 0x01;
        write_sorted(&feed, [victim]).unwrap();
        let detector = ByovdDetector::open(&feed).unwrap();
        let path = std::path::PathBuf::from("/x");
        let ctx = FileCtx {
            path: &path,
            size_bytes: 0,
            blake3: &[0u8; 32],
            sha256: None,
        };
        assert_eq!(detector.check(&ctx), DetectorVerdict::Clean);
    }
}
