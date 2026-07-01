//! Hash-blacklist detector (TASK-020, Phase 2).
//!
//! Reads `<data_dir>/feeds/abusech_sha256.bin` (the on-disk sorted-32-byte-key
//! format from [`super::hash_set_file`]) and emits a
//! [`DetectorVerdict::Malicious`] on hit. Built by the abuse.ch feed updater
//! (TASK-022) which packages MalwareBazaar bulk dumps + ThreatFox into the
//! same `.bin` format.
//!
//! **Hash function:** SHA-256 by default — abuse.ch publishes SHA-256 in
//! MalwareBazaar bulk dumps and ThreatFox IOC JSON; BLAKE3 is not available
//! upstream. The engine must therefore set `ScanOptions::compute_sha256 =
//! true` whenever this detector is loaded, otherwise every file looks
//! clean. Override via [`HashBlacklistDetector::with_hash_kind`] if a
//! Freally-internal BLAKE3-keyed feed is ever shipped.
//!
//! The detector keeps the feed mmap'd; lookups are O(log N) binary searches
//! and touch a single 32-byte cache line in the common case. We do not load
//! the file into RAM — a 10M-entry feed is ~320 MB, which is much cheaper to
//! page-map than to copy.

use std::path::Path;
use std::sync::Arc;

use super::hash_set_file::{HashSetError, HashSetFile};
use super::{Detector, DetectorVerdict, FileCtx, HashKind, Severity};

/// Per-feed metadata that the detector adds to its [`DetectorVerdict::Malicious`]
/// evidence blob, so the UI explainer (FR-040) can name the upstream source.
const RULE_SOURCE: &str = "abusech";
const RULE_ID_PREFIX: &str = "abusech:hash";

/// Stable detector id used in logs, audit, and the pipeline's `feed_versions`
/// summary.
pub const DETECTOR_ID: &str = "hash_blacklist";

/// Pipeline priority. Allowlists run earlier (priority ≈ 10–20); blacklists
/// sit at 100+ so an NSRL hit short-circuits before we consult abuse.ch.
pub const PRIORITY: u32 = 100;

/// Hash-blacklist detector. Cheap to clone (the underlying mmap is reference-
/// counted via `Arc`).
#[derive(Clone)]
pub struct HashBlacklistDetector {
    set: Arc<HashSetFile>,
    hash_kind: HashKind,
    severity: Severity,
}

impl HashBlacklistDetector {
    /// Open the abuse.ch hash-set file at the given path. Returns an error if
    /// the file is malformed or missing. Defaults to [`HashKind::Sha256`].
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, HashSetError> {
        let set = HashSetFile::open(path)?;
        Ok(Self {
            set: Arc::new(set),
            hash_kind: HashKind::Sha256,
            severity: Severity::High,
        })
    }

    /// Override the default hash kind. Use [`HashKind::Blake3`] only for a
    /// Freally-internal feed that ships BLAKE3-keyed hashes; abuse.ch
    /// upstream stays SHA-256.
    pub fn with_hash_kind(mut self, kind: HashKind) -> Self {
        self.hash_kind = kind;
        self
    }

    /// Override the default severity (`High`) — used by tests and by future
    /// per-feed severity tuning if upstream metadata gains it.
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Number of hashes loaded — surfaced in `scans.feed_versions` and the
    /// About page (FR-157).
    pub fn loaded_count(&self) -> u64 {
        self.set.len()
    }

    /// Which hash this detector queries — useful for engine-side gating
    /// (`ScanOptions::compute_sha256` must be on when this returns Sha256).
    pub fn hash_kind(&self) -> HashKind {
        self.hash_kind
    }
}

impl Detector for HashBlacklistDetector {
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
            // SHA-256 not computed for this file — engine misconfigured.
            // Fail clean rather than mis-flag.
            return DetectorVerdict::Clean;
        };
        if self.set.contains(digest) {
            let rule_id = format!("{RULE_ID_PREFIX}:{}", hex_prefix(digest, 8));
            let evidence = format!("{}={}", self.hash_kind.as_str(), hex::encode(digest));
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

/// Hex-encode the first `n` bytes of a digest. Used to keep rule_ids short
/// while still uniquely naming the match in the UI (`abusech:hash:0123abcd…`).
fn hex_prefix(bytes: &[u8], n: usize) -> String {
    let take = n.min(bytes.len());
    hex::encode(&bytes[..take])
}

#[cfg(test)]
mod tests {
    use super::super::hash_set_file::write_sorted;
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn make_feed(hashes: &[[u8; 32]]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("abusech_hashes.bin");
        write_sorted(&path, hashes.iter().copied()).unwrap();
        (dir, path)
    }

    /// SHA-256 ctx — matches the production wiring (abuse.ch hashes are
    /// SHA-256, and the engine sets `compute_sha256 = true` whenever this
    /// detector is loaded).
    fn ctx_sha<'a>(
        path: &'a std::path::Path,
        zero_blake3: &'a [u8; 32],
        sha: &'a [u8; 32],
    ) -> FileCtx<'a> {
        FileCtx {
            path,
            size_bytes: 0,
            blake3: zero_blake3,
            sha256: Some(sha),
        }
    }

    /// BLAKE3 ctx — only used by `with_hash_kind(Blake3)` test below.
    fn ctx_blake3<'a>(path: &'a std::path::Path, blake3: &'a [u8; 32]) -> FileCtx<'a> {
        FileCtx {
            path,
            size_bytes: 0,
            blake3,
            sha256: None,
        }
    }

    #[test]
    fn missing_file_returns_io_error() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.bin");
        assert!(HashBlacklistDetector::open(missing).is_err());
    }

    #[test]
    fn defaults_to_sha256() {
        let (_dir, path) = make_feed(&[[0; 32]]);
        let d = HashBlacklistDetector::open(&path).unwrap();
        assert_eq!(d.hash_kind(), HashKind::Sha256);
    }

    #[test]
    fn hit_returns_malicious_with_expected_rule_id_and_source() {
        let bad = [0xab; 32];
        let (_dir, path) = make_feed(&[bad]);
        let d = HashBlacklistDetector::open(&path).unwrap();
        assert_eq!(d.id(), "hash_blacklist");
        assert_eq!(d.priority(), 100);

        let zero = [0u8; 32];
        let verdict = d.check(&ctx_sha(std::path::Path::new("/x"), &zero, &bad));
        match verdict {
            DetectorVerdict::Malicious {
                rule_id,
                rule_source,
                severity,
                evidence,
            } => {
                assert!(
                    rule_id.starts_with("abusech:hash:abababab"),
                    "got {rule_id}"
                );
                assert_eq!(rule_source, "abusech");
                assert_eq!(severity, Severity::High);
                let ev = evidence.expect("evidence present");
                assert!(ev.starts_with("sha256="), "got {ev}");
            }
            other => panic!("expected Malicious, got {other:?}"),
        }
    }

    #[test]
    fn miss_returns_clean() {
        let bad = [0xab; 32];
        let (_dir, path) = make_feed(&[bad]);
        let d = HashBlacklistDetector::open(&path).unwrap();
        let other = [0x11; 32];
        let zero = [0u8; 32];
        assert_eq!(
            d.check(&ctx_sha(std::path::Path::new("/y"), &zero, &other)),
            DetectorVerdict::Clean
        );
    }

    #[test]
    fn empty_feed_returns_clean_for_everything() {
        let (_dir, path) = make_feed(&[]);
        let d = HashBlacklistDetector::open(&path).unwrap();
        assert_eq!(d.loaded_count(), 0);
        let zero = [0u8; 32];
        for byte in [0u8, 1, 7, 13, 0xff] {
            let sha = [byte; 32];
            assert_eq!(
                d.check(&ctx_sha(std::path::Path::new("/z"), &zero, &sha)),
                DetectorVerdict::Clean
            );
        }
    }

    #[test]
    fn missing_sha256_in_ctx_returns_clean_not_panic() {
        // Engine misconfiguration: SHA-256 not computed. Detector must fail
        // clean rather than crash or mis-flag.
        let bad = [0xab; 32];
        let (_dir, path) = make_feed(&[bad]);
        let d = HashBlacklistDetector::open(&path).unwrap();
        // bad bytes only in blake3 slot; sha256 absent
        assert_eq!(
            d.check(&ctx_blake3(std::path::Path::new("/x"), &bad)),
            DetectorVerdict::Clean
        );
    }

    #[test]
    fn blake3_override_queries_blake3_slot() {
        let bad = [0xcd; 32];
        let (_dir, path) = make_feed(&[bad]);
        let d = HashBlacklistDetector::open(&path)
            .unwrap()
            .with_hash_kind(HashKind::Blake3);
        let verdict = d.check(&ctx_blake3(std::path::Path::new("/x"), &bad));
        match verdict {
            DetectorVerdict::Malicious { evidence, .. } => {
                let ev = evidence.expect("evidence");
                assert!(ev.starts_with("blake3="), "got {ev}");
            }
            other => panic!("expected Malicious, got {other:?}"),
        }
    }

    #[test]
    fn integrates_with_detection_pipeline() {
        let bad = [0xcc; 32];
        let (_dir, path) = make_feed(&[bad]);
        let d = HashBlacklistDetector::open(&path).unwrap();

        let pipeline = super::super::DetectionPipeline::new(vec![Box::new(d)]);
        let zero = [0u8; 32];
        let outcome = pipeline.evaluate(&ctx_sha(std::path::Path::new("/p"), &zero, &bad));
        match outcome {
            super::super::PipelineOutcome::Detected {
                detector_id,
                rule_source,
                ..
            } => {
                assert_eq!(detector_id, "hash_blacklist");
                assert_eq!(rule_source, "abusech");
            }
            other => panic!("expected Detected, got {other:?}"),
        }
    }
}
