//! TASK-199 — BLAKE3 + SHA-256 dual-key gate.
//!
//! Defense against pathological cross-tier collisions. A "gold-tier"
//! blacklist row carries all six hashes; the engine computes BLAKE3
//! (always) + SHA-256 (when at least one SHA-256-keyed detector is
//! loaded). For any P0 ("block") verdict on a gold-tier hit, we
//! require **both** hashes match an entry in the blacklist before
//! promoting the verdict to P0 confidence — otherwise it stays at
//! P1 / silver (still rendered, still actionable, but downgraded so
//! the UI doesn't automatically quarantine).
//!
//! Why this matters: silver-tier rows (TASK-167 hashlist subcommand)
//! only carry md5 + sha256, so the engine has only one strong key
//! to lean on for those. The dual-key gate ensures that a single
//! SHA-256 match against a silver-tier row doesn't get treated with
//! the same trust as a BLAKE3+SHA-256 match against a gold-tier row.
//!
//! ## Wiring
//!
//! Two `HashBlacklistDetector` instances run in parallel — one per
//! hash kind. Each emits its own `DetectorVerdict::Malicious`. The
//! engine collects both verdicts for a single file and calls
//! [`combine`] to produce one final outcome whose `match_strength`
//! reflects the confirmation level.
//!
//! ## Match-strength ladder
//!
//!   * `GoldMultihash` — both BLAKE3 and SHA-256 hit on rows with
//!     matching `sha256` cross-reference. P0 verdict; safe to
//!     auto-quarantine per default Settings.
//!   * `GoldSingle`    — exactly one of BLAKE3 / SHA-256 hit. P1
//!     verdict; user-confirmed quarantine recommended.
//!   * `Silver`        — md5 or sha256 hit on a silver-tier row.
//!     P1; same posture as GoldSingle.
//!   * `Partial`       — partial-match (TASK-180) prefix hit
//!     without a full-hash confirmation. P2; informational —
//!     scanner should chase a full hash to upgrade or drop.

use super::{Detector, DetectorVerdict, FileCtx, HashKind, PipelineOutcome, Severity};
use std::sync::Arc;

/// Per-finding match-strength ladder. Surfaced via the UI's finding
/// tooltip so the user understands the confidence behind a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchStrength {
    /// Multi-hash gold-tier match (typically BLAKE3 + SHA-256 both
    /// matched the same blacklist row). Highest confidence.
    GoldMultihash,
    /// Single-hash gold-tier match. Confidence-graded down per
    /// TASK-199.
    GoldSingle,
    /// Silver-tier match (md5 or sha256 only).
    Silver,
    /// Partial-match (prefix hit per TASK-180). Lowest confidence;
    /// full-hash follow-up required to confirm.
    Partial,
}

impl MatchStrength {
    pub fn as_str(self) -> &'static str {
        match self {
            MatchStrength::GoldMultihash => "gold_multihash",
            MatchStrength::GoldSingle => "gold_single",
            MatchStrength::Silver => "silver",
            MatchStrength::Partial => "partial",
        }
    }
}

/// Combine the parallel verdicts from two hash-keyed detectors (one
/// BLAKE3-keyed, one SHA-256-keyed) into a single outcome.
///
/// Cases:
///   * Both detectors returned Malicious AND target the same rule
///     source/family → `GoldMultihash`. The verdict is taken from
///     either detector (they're equivalent); we prefer the BLAKE3
///     one because BLAKE3 is the canonical engine hash.
///   * Exactly one returned Malicious → `GoldSingle` (or `Silver`
///     when the caller marks the underlying row as silver-tier via
///     the `is_silver` flag).
///   * Both SkipFile / one SkipFile → SkipFile wins (allowlist
///     beats blacklist, same as the existing pipeline semantics).
///   * Both Clean → Clean.
pub fn combine(
    blake3_verdict: DetectorVerdict,
    sha256_verdict: DetectorVerdict,
    is_silver: bool,
) -> (PipelineOutcome, MatchStrength) {
    use DetectorVerdict::*;

    // Allowlist beats blacklist on either branch.
    if matches!(blake3_verdict, SkipFile) || matches!(sha256_verdict, SkipFile) {
        return (
            PipelineOutcome::SkippedByAllowlist {
                detector_id: "dual_key_gate".to_string(),
            },
            // Match strength isn't meaningful on a skip — surface
            // something inert.
            MatchStrength::Silver,
        );
    }

    match (blake3_verdict, sha256_verdict) {
        (
            Malicious {
                rule_id: b_id,
                rule_source: b_src,
                severity: b_sev,
                evidence: b_ev,
            },
            Malicious {
                rule_id: _s_id,
                rule_source: s_src,
                severity: _s_sev,
                evidence: _s_ev,
            },
        ) if b_src == s_src => (
            PipelineOutcome::Detected {
                rule_id: b_id,
                rule_source: b_src,
                severity: b_sev,
                evidence: b_ev,
                detector_id: "hash_blacklist".to_string(),
            },
            MatchStrength::GoldMultihash,
        ),
        (
            Malicious {
                rule_id,
                rule_source,
                severity,
                evidence,
            },
            _,
        ) => (
            PipelineOutcome::Detected {
                rule_id,
                rule_source,
                severity: downgrade_if_silver(severity, is_silver),
                evidence,
                detector_id: "hash_blacklist".to_string(),
            },
            if is_silver {
                MatchStrength::Silver
            } else {
                MatchStrength::GoldSingle
            },
        ),
        (
            _,
            Malicious {
                rule_id,
                rule_source,
                severity,
                evidence,
            },
        ) => (
            PipelineOutcome::Detected {
                rule_id,
                rule_source,
                severity: downgrade_if_silver(severity, is_silver),
                evidence,
                detector_id: "hash_blacklist".to_string(),
            },
            if is_silver {
                MatchStrength::Silver
            } else {
                MatchStrength::GoldSingle
            },
        ),
        (Clean, Clean) => (PipelineOutcome::Clean, MatchStrength::GoldSingle),
        // SkipFile pairs are already handled by the early-return
        // above; the exhaustiveness checker just doesn't know.
        (SkipFile, _) | (_, SkipFile) => unreachable!("SkipFile handled above"),
    }
}

/// When the underlying row is silver-tier, drop a Critical or High
/// severity by one notch (P0 → P1 effective) since the dual-key
/// confirmation isn't available. Keeps Medium and Low untouched.
fn downgrade_if_silver(sev: Severity, is_silver: bool) -> Severity {
    if !is_silver {
        return sev;
    }
    match sev {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        other => other,
    }
}

/// Convenience: run two hash-keyed detectors against the same ctx
/// and feed their verdicts through [`combine`]. Used by the engine
/// scan worker when two HashBlacklistDetector instances are loaded
/// (one for BLAKE3, one for SHA-256).
pub fn run_dual_key<B, S>(
    blake3_det: &Arc<B>,
    sha256_det: &Arc<S>,
    ctx: &FileCtx<'_>,
    is_silver_hint: bool,
) -> (PipelineOutcome, MatchStrength)
where
    B: Detector + ?Sized,
    S: Detector + ?Sized,
{
    let b = blake3_det.check(ctx);
    let s = sha256_det.check(ctx);
    combine(b, s, is_silver_hint)
}

/// Default hash kinds for the dual gate. Engine wires this so
/// callers don't need to remember which side is which.
pub fn dual_kinds() -> (HashKind, HashKind) {
    (HashKind::Blake3, HashKind::Sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn malicious(rule_id: &str, source: &str, sev: Severity) -> DetectorVerdict {
        DetectorVerdict::Malicious {
            rule_id: rule_id.to_string(),
            rule_source: source.to_string(),
            severity: sev,
            evidence: Some("test".to_string()),
        }
    }

    #[test]
    fn both_hit_same_source_promotes_to_gold_multihash() {
        let (outcome, strength) = combine(
            malicious("rule:blake3:abcd", "abusech", Severity::High),
            malicious("rule:sha256:abcd", "abusech", Severity::High),
            false,
        );
        assert_eq!(strength, MatchStrength::GoldMultihash);
        match outcome {
            PipelineOutcome::Detected {
                rule_source,
                severity,
                ..
            } => {
                assert_eq!(rule_source, "abusech");
                assert_eq!(severity, Severity::High);
            }
            other => panic!("expected Detected, got {other:?}"),
        }
    }

    #[test]
    fn only_blake3_hits_stays_gold_single() {
        let (_, strength) = combine(
            malicious("rule:blake3:1", "abusech", Severity::Critical),
            DetectorVerdict::Clean,
            false,
        );
        assert_eq!(strength, MatchStrength::GoldSingle);
    }

    #[test]
    fn only_sha256_hits_stays_gold_single() {
        let (_, strength) = combine(
            DetectorVerdict::Clean,
            malicious("rule:sha256:1", "abusech", Severity::Critical),
            false,
        );
        assert_eq!(strength, MatchStrength::GoldSingle);
    }

    #[test]
    fn silver_hint_downgrades_severity() {
        let (outcome, strength) = combine(
            DetectorVerdict::Clean,
            malicious("rule:silver", "virusshare", Severity::Critical),
            true,
        );
        assert_eq!(strength, MatchStrength::Silver);
        match outcome {
            PipelineOutcome::Detected { severity, .. } => {
                assert_eq!(severity, Severity::High); // critical → high
            }
            other => panic!("expected Detected, got {other:?}"),
        }
    }

    #[test]
    fn silver_hint_medium_stays_medium() {
        let (_, _) = combine(
            DetectorVerdict::Clean,
            malicious("rule:silver", "virusshare", Severity::Medium),
            true,
        );
        // Just ensure it doesn't panic. Severity assert above.
        // Medium stays Medium per downgrade_if_silver logic.
        assert_eq!(
            downgrade_if_silver(Severity::Medium, true),
            Severity::Medium
        );
    }

    #[test]
    fn skip_on_either_branch_wins() {
        let (outcome, _) = combine(
            DetectorVerdict::SkipFile,
            malicious("rule:sha256:x", "abusech", Severity::High),
            false,
        );
        match outcome {
            PipelineOutcome::SkippedByAllowlist { .. } => {}
            other => panic!("expected SkippedByAllowlist, got {other:?}"),
        }
    }

    #[test]
    fn both_clean_stays_clean() {
        let (outcome, _) = combine(DetectorVerdict::Clean, DetectorVerdict::Clean, false);
        assert_eq!(outcome, PipelineOutcome::Clean);
    }

    #[test]
    fn cross_source_mismatch_stays_gold_single() {
        // Two different rule sources matched — treat as single hit
        // (the cross-tier collision concern is exactly this case;
        // a multi-source confluence shouldn't promote).
        let (_, strength) = combine(
            malicious("rule:a", "abusech", Severity::High),
            malicious("rule:b", "loldrivers", Severity::High),
            false,
        );
        assert_eq!(strength, MatchStrength::GoldSingle);
    }

    #[test]
    fn match_strength_as_str_stable() {
        assert_eq!(MatchStrength::GoldMultihash.as_str(), "gold_multihash");
        assert_eq!(MatchStrength::GoldSingle.as_str(), "gold_single");
        assert_eq!(MatchStrength::Silver.as_str(), "silver");
        assert_eq!(MatchStrength::Partial.as_str(), "partial");
    }
}
