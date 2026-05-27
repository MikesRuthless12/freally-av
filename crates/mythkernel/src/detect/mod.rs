//! Detection pipeline (TASK-019, Phase 2).
//!
//! The engine hashes every file, then asks the pipeline whether the file is
//! malicious, allowlisted, or unknown. Detectors are tried in priority order
//! (lowest number first); the first non-`Clean` verdict short-circuits.
//!
//! Per `docs/prd.md` § 6.2 the goodware allowlist (TASK-021) runs at the
//! lowest priority value so an NSRL hit ends evaluation before any blacklist
//! detector is consulted — that is the "fast skip" mentioned in the roadmap
//! for TASK-019.
//!
//! Detector authors return [`DetectorVerdict::Malicious`] with the rule body
//! shape from `docs/prd.md` § 3.1 (the `findings` row): `rule_id`,
//! `rule_source`, `severity`, and an optional `evidence` blob shown in the
//! explainer (FR-040).

use std::fmt;

use serde::{Deserialize, Serialize};

pub mod active_findings;
pub mod bloom;
pub mod byovd;
pub mod crc32_set_file;
pub mod cuckoo;
pub mod dev_publisher_allowlist;
pub mod dual_key_gate;
pub mod eicar;
pub mod ephemeral_allowlist;
pub mod file_mutation;
pub mod goodware_allowlist;
pub mod hash_blacklist;
pub mod hash_lookup_explain;
pub mod hash_set_file;
pub mod heuristics;
pub mod honeyfiles;
pub mod package_manager_allowlist;
pub mod partial_match;
pub mod platform_store_allowlist;
pub mod publisher;
pub mod sbom_allowlist;
pub mod user_iocs;
pub mod verdict_cache;
pub mod yara_engine;

/// What a detector is given for one file. The engine fills this in after the
/// hasher runs but before any I/O on the file's contents — detectors that
/// need to read the file (e.g. YARA in Phase 7) must open it themselves.
#[derive(Debug, Clone)]
pub struct FileCtx<'a> {
    pub path: &'a std::path::Path,
    pub size_bytes: u64,
    /// Raw BLAKE3 digest. Detectors should compare against this directly
    /// rather than re-decoding hex.
    pub blake3: &'a [u8; 32],
    /// Raw SHA-256 digest if `ScanOptions::compute_sha256` was set; absent
    /// otherwise (the engine never re-hashes inside the pipeline).
    pub sha256: Option<&'a [u8; 32]>,
}

/// Which hash function a hash-keyed detector should query the [`FileCtx`]
/// against. abuse.ch (MalwareBazaar + ThreatFox) and NIST NSRL both publish
/// **SHA-256**, so the hash blacklist (TASK-020) and goodware allowlist
/// (TASK-021) default to [`HashKind::Sha256`]. A future Mythodikal-internal
/// blacklist (e.g. user-discovered samples) could use [`HashKind::Blake3`]
/// since the engine computes BLAKE3 unconditionally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashKind {
    Blake3,
    Sha256,
}

impl HashKind {
    /// Look up the matching 32-byte digest in a [`FileCtx`]. Returns `None`
    /// only for `Sha256` when `ScanOptions::compute_sha256` was disabled.
    pub fn select<'a>(self, ctx: &'a FileCtx<'_>) -> Option<&'a [u8; 32]> {
        match self {
            HashKind::Blake3 => Some(ctx.blake3),
            HashKind::Sha256 => ctx.sha256,
        }
    }

    /// Short name written into rule IDs and the per-finding explainer.
    pub fn as_str(self) -> &'static str {
        match self {
            HashKind::Blake3 => "blake3",
            HashKind::Sha256 => "sha256",
        }
    }
}

/// Severity ladder used by every detector. Stored as the `findings.severity`
/// column. The ordering (`Critical` > `Info`) is meaningful — UI and CLI
/// sort by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// String form written to SQLite (`findings.severity`).
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One detector's answer for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectorVerdict {
    /// This detector has no opinion. Pipeline continues to the next detector.
    Clean,
    /// This file is known-good. Pipeline halts; the engine skips remaining
    /// detectors and records nothing for this file.
    SkipFile,
    /// This file matches a known-bad rule. Pipeline halts; the engine
    /// records a `findings` row.
    Malicious {
        rule_id: String,
        rule_source: String,
        severity: Severity,
        evidence: Option<String>,
    },
}

/// What the engine sees after running every detector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineOutcome {
    /// No detector matched.
    Clean,
    /// An allowlist detector matched. Caller may want to log which one for
    /// the per-finding explainer / audit log.
    SkippedByAllowlist { detector_id: String },
    /// A blacklist detector matched.
    Detected {
        rule_id: String,
        rule_source: String,
        severity: Severity,
        evidence: Option<String>,
        detector_id: String,
    },
}

/// One pluggable detector. Implementations must be `Send + Sync` so the
/// engine can share a single [`DetectionPipeline`] across the rayon worker
/// pool.
pub trait Detector: Send + Sync {
    /// Stable identifier for logs and audit (e.g. `"hash_blacklist"`,
    /// `"goodware_allowlist"`).
    fn id(&self) -> &str;

    /// Pipeline priority. Lower runs first. Allowlists should use a low value
    /// (10–20); blacklists 100+; heuristics 1000+.
    fn priority(&self) -> u32;

    /// Inspect one file. Must be fast — this runs in the hash worker pool.
    fn check(&self, ctx: &FileCtx<'_>) -> DetectorVerdict;

    /// Whether this detector needs the SHA-256 digest present in
    /// [`FileCtx::sha256`]. The engine uses the per-pipeline rollup
    /// ([`DetectionPipeline::requires_sha256`]) to skip SHA-256
    /// computation entirely when no loaded detector needs it —
    /// roughly a 5× hash speedup on big files since SHA-256 is the
    /// slower of the two. Default `false`; SHA-256-keyed detectors
    /// (abuse.ch hash blacklist, NSRL allowlist, BYOVD loldrivers)
    /// override to `true`.
    fn requires_sha256(&self) -> bool {
        false
    }
}

/// Runs a fixed set of detectors in priority order for each file. Built once
/// per scan; cheap to share across worker threads.
pub struct DetectionPipeline {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectionPipeline {
    /// Build a pipeline from an unordered list of detectors. Order is
    /// determined entirely by [`Detector::priority`]; ties are stable.
    pub fn new(mut detectors: Vec<Box<dyn Detector>>) -> Self {
        detectors.sort_by_key(|d| d.priority());
        Self { detectors }
    }

    /// Number of registered detectors.
    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }

    /// Returns `true` when at least one registered detector needs the
    /// SHA-256 digest (the abuse.ch hash blacklist, NSRL allowlist,
    /// and BYOVD loldrivers detector all do). The engine reads this
    /// once per scan to decide whether to compute SHA-256 at all —
    /// when no detector needs it, BLAKE3 alone runs and the per-file
    /// hash work is ~5× faster.
    pub fn requires_sha256(&self) -> bool {
        self.detectors.iter().any(|d| d.requires_sha256())
    }

    /// Detector ids in execution order. Useful for `scans.feed_versions` and
    /// for the per-finding explainer.
    pub fn detector_ids(&self) -> impl Iterator<Item = &str> {
        self.detectors.iter().map(|d| d.id())
    }

    /// Evaluate one file. Returns at the first non-`Clean` verdict.
    pub fn evaluate(&self, ctx: &FileCtx<'_>) -> PipelineOutcome {
        for d in &self.detectors {
            match d.check(ctx) {
                DetectorVerdict::Clean => continue,
                DetectorVerdict::SkipFile => {
                    return PipelineOutcome::SkippedByAllowlist {
                        detector_id: d.id().to_string(),
                    };
                }
                DetectorVerdict::Malicious {
                    rule_id,
                    rule_source,
                    severity,
                    evidence,
                } => {
                    return PipelineOutcome::Detected {
                        rule_id,
                        rule_source,
                        severity,
                        evidence,
                        detector_id: d.id().to_string(),
                    };
                }
            }
        }
        PipelineOutcome::Clean
    }
}

/// Decode a 64-char hex BLAKE3 string into the 32-byte raw form expected by
/// [`FileCtx::blake3`]. Returns `None` on malformed input.
pub fn blake3_hex_to_bytes(hex_str: &str) -> Option<[u8; 32]> {
    if hex_str.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test fixture that records how often it was called and returns a fixed
    /// verdict.
    struct ScriptedDetector {
        id: &'static str,
        prio: u32,
        verdict: DetectorVerdict,
        calls: Arc<AtomicUsize>,
    }

    impl Detector for ScriptedDetector {
        fn id(&self) -> &str {
            self.id
        }
        fn priority(&self) -> u32 {
            self.prio
        }
        fn check(&self, _ctx: &FileCtx<'_>) -> DetectorVerdict {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.verdict.clone()
        }
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
    fn empty_pipeline_returns_clean() {
        let p = DetectionPipeline::new(vec![]);
        let h = [0u8; 32];
        assert_eq!(
            p.evaluate(&ctx(Path::new("/a"), &h)),
            PipelineOutcome::Clean
        );
    }

    #[test]
    fn priority_orders_execution_low_first() {
        let calls_a = Arc::new(AtomicUsize::new(0));
        let calls_b = Arc::new(AtomicUsize::new(0));

        // B has lower priority (runs first) and returns Malicious — A must
        // never be consulted.
        let a = Box::new(ScriptedDetector {
            id: "a",
            prio: 100,
            verdict: DetectorVerdict::Clean,
            calls: calls_a.clone(),
        });
        let b = Box::new(ScriptedDetector {
            id: "b",
            prio: 10,
            verdict: DetectorVerdict::Malicious {
                rule_id: "rule-1".into(),
                rule_source: "test".into(),
                severity: Severity::High,
                evidence: None,
            },
            calls: calls_b.clone(),
        });

        let p = DetectionPipeline::new(vec![a, b]);
        let h = [0u8; 32];
        let outcome = p.evaluate(&ctx(Path::new("/x"), &h));

        match outcome {
            PipelineOutcome::Detected {
                detector_id,
                rule_id,
                severity,
                ..
            } => {
                assert_eq!(detector_id, "b");
                assert_eq!(rule_id, "rule-1");
                assert_eq!(severity, Severity::High);
            }
            other => panic!("expected Detected, got {other:?}"),
        }
        assert_eq!(calls_b.load(Ordering::SeqCst), 1);
        assert_eq!(calls_a.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn allowlist_short_circuits_subsequent_detectors() {
        let calls_allow = Arc::new(AtomicUsize::new(0));
        let calls_block = Arc::new(AtomicUsize::new(0));

        let allow = Box::new(ScriptedDetector {
            id: "allow",
            prio: 10,
            verdict: DetectorVerdict::SkipFile,
            calls: calls_allow.clone(),
        });
        let block = Box::new(ScriptedDetector {
            id: "block",
            prio: 100,
            verdict: DetectorVerdict::Malicious {
                rule_id: "rule-X".into(),
                rule_source: "test".into(),
                severity: Severity::Critical,
                evidence: None,
            },
            calls: calls_block.clone(),
        });

        let p = DetectionPipeline::new(vec![block, allow]);
        let h = [0u8; 32];
        let outcome = p.evaluate(&ctx(Path::new("/y"), &h));
        assert_eq!(
            outcome,
            PipelineOutcome::SkippedByAllowlist {
                detector_id: "allow".into()
            }
        );
        assert_eq!(calls_allow.load(Ordering::SeqCst), 1);
        assert_eq!(calls_block.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn clean_detectors_run_through_to_clean_outcome() {
        let a = Box::new(ScriptedDetector {
            id: "a",
            prio: 10,
            verdict: DetectorVerdict::Clean,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let b = Box::new(ScriptedDetector {
            id: "b",
            prio: 20,
            verdict: DetectorVerdict::Clean,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let p = DetectionPipeline::new(vec![a, b]);
        let h = [0u8; 32];
        assert_eq!(
            p.evaluate(&ctx(Path::new("/z"), &h)),
            PipelineOutcome::Clean
        );
    }

    #[test]
    fn detector_ids_iterate_in_priority_order() {
        let p = DetectionPipeline::new(vec![
            Box::new(ScriptedDetector {
                id: "third",
                prio: 1000,
                verdict: DetectorVerdict::Clean,
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            Box::new(ScriptedDetector {
                id: "first",
                prio: 10,
                verdict: DetectorVerdict::Clean,
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            Box::new(ScriptedDetector {
                id: "second",
                prio: 100,
                verdict: DetectorVerdict::Clean,
                calls: Arc::new(AtomicUsize::new(0)),
            }),
        ]);
        let ids: Vec<&str> = p.detector_ids().collect();
        assert_eq!(ids, vec!["first", "second", "third"]);
    }

    #[test]
    fn blake3_hex_to_bytes_roundtrips() {
        let raw = [0xab; 32];
        let hex_str = hex::encode(raw);
        assert_eq!(blake3_hex_to_bytes(&hex_str), Some(raw));
        assert!(blake3_hex_to_bytes("too-short").is_none());
        assert!(blake3_hex_to_bytes(&"z".repeat(64)).is_none());
    }

    #[test]
    fn severity_serializes_to_lowercase_string() {
        assert_eq!(Severity::Critical.as_str(), "critical");
        assert_eq!(serde_json::to_string(&Severity::High).unwrap(), "\"high\"");
    }
}
