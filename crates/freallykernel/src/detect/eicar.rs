//! EICAR built-in test detector.
//!
//! The EICAR Standard Anti-Virus Test File is a 68-byte ASCII string
//! every AV vendor agrees to flag. It's used to verify a scanner is
//! actually inspecting file contents — no real malware required.
//!
//! Drop the EICAR string into a `.txt` file and scan it. This
//! detector compares the file's BLAKE3 against the precomputed hash
//! of the literal EICAR bytes and emits a `Detected` verdict on
//! match. Hardcoded — no feed download required.
//!
//! Reference: <https://www.eicar.org/?page_id=3950>

use super::{Detector, DetectorVerdict, FileCtx, Severity};

/// Stable detector id used in logs and `feed_versions`.
pub const DETECTOR_ID: &str = "eicar_test";

/// Detector priority — same band as the hash blacklist (100). Sits
/// after allowlists (≤20) so a goodware hit shorts before we
/// consider the EICAR pattern.
pub const PRIORITY: u32 = 100;

/// The canonical 68-byte EICAR Standard Anti-Virus Test File.
/// Quoted exactly per the EICAR spec; the trailing `H+H*` and the
/// `$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$` middle are load-bearing.
const EICAR_BYTES: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// EICAR detector. Hashes the canonical bytes once at construction
/// and caches the digest; per-file `check` is a constant-time `==`.
pub struct EicarDetector {
    blake3_target: [u8; 32],
}

impl EicarDetector {
    pub fn new() -> Self {
        let blake3_target = *blake3::hash(EICAR_BYTES).as_bytes();
        Self { blake3_target }
    }
}

impl Default for EicarDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for EicarDetector {
    fn id(&self) -> &str {
        DETECTOR_ID
    }

    fn priority(&self) -> u32 {
        PRIORITY
    }

    fn requires_sha256(&self) -> bool {
        false
    }

    fn check(&self, ctx: &FileCtx<'_>) -> DetectorVerdict {
        if ctx.blake3 == &self.blake3_target {
            DetectorVerdict::Malicious {
                rule_id: "eicar:test-file".to_string(),
                rule_source: "eicar".to_string(),
                severity: Severity::Medium,
                evidence: Some(
                    "EICAR Standard Anti-Virus Test File — synthetic test signature, not actual malware".to_string(),
                ),
            }
        } else {
            DetectorVerdict::Clean
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_canonical_eicar_bytes() {
        let d = EicarDetector::new();
        let blake3 = *blake3::hash(EICAR_BYTES).as_bytes();
        let ctx = FileCtx {
            path: std::path::Path::new("/tmp/eicar.txt"),
            size_bytes: EICAR_BYTES.len() as u64,
            blake3: &blake3,
            sha256: None,
        };
        match d.check(&ctx) {
            DetectorVerdict::Malicious {
                rule_id,
                rule_source,
                severity,
                ..
            } => {
                assert_eq!(rule_id, "eicar:test-file");
                assert_eq!(rule_source, "eicar");
                assert_eq!(severity, Severity::Medium);
            }
            other => panic!("expected Malicious, got {other:?}"),
        }
    }

    #[test]
    fn misses_arbitrary_bytes() {
        let d = EicarDetector::new();
        let zero = [0u8; 32];
        let ctx = FileCtx {
            path: std::path::Path::new("/tmp/clean.txt"),
            size_bytes: 0,
            blake3: &zero,
            sha256: None,
        };
        assert_eq!(d.check(&ctx), DetectorVerdict::Clean);
    }

    #[test]
    fn does_not_require_sha256() {
        let d = EicarDetector::new();
        assert!(!d.requires_sha256());
    }
}
