//! Detonate-in-VM coordination stub (TASK-280).
//!
//! Mythodikal is read-only by default. Detonation is an
//! **opt-in** convenience that signs the file off to a
//! caller-supplied VM (Hyper-V / VMware / Parallels / UTM /
//! libvirt) and reads back the resulting telemetry. The actual
//! integration depends on the user's hypervisor and lands at the
//! Phase 13 donor-tier wave (TASK-433+).
//!
//! This module foundation defines the policy + decision shape
//! that the engine emits **before** any external action is
//! taken so the UI can surface a "Detonate this in a VM?"
//! confirm sheet. Per `docs/prd.md` § 1.5.4 we ship no
//! kernel-mode hooks — the VM is always a separate sandbox.

use serde::{Deserialize, Serialize};

/// User-configurable detonation rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetonationPolicy {
    /// Never offer detonation — engine emits informational
    /// findings only.
    NeverOffer,
    /// Offer the modal sheet but require an explicit per-file
    /// click. This is the default for the free tier.
    OfferOnP1,
    /// Offer for P1 and P2 findings (more aggressive — donor /
    /// pro setting).
    OfferOnP1OrP2,
}

impl Default for DetonationPolicy {
    fn default() -> Self {
        DetonationPolicy::OfferOnP1
    }
}

/// Decision emitted by [`should_offer_detonation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetonationDecision {
    /// UI should not surface the detonation control.
    Suppress,
    /// UI should surface "Detonate this in a VM?" as an opt-in.
    Offer,
}

/// `severity` follows the engine's P0-P3 enum. The numeric
/// representation is `0 = P0` (informational) … `3 = P3`
/// (critical). The function is total: every (policy, severity)
/// pair returns a defined decision.
pub fn should_offer_detonation(
    policy: DetonationPolicy,
    severity: u8,
) -> DetonationDecision {
    match policy {
        DetonationPolicy::NeverOffer => DetonationDecision::Suppress,
        DetonationPolicy::OfferOnP1 => {
            if severity >= 2 {
                DetonationDecision::Offer
            } else {
                DetonationDecision::Suppress
            }
        }
        DetonationPolicy::OfferOnP1OrP2 => {
            if severity >= 1 {
                DetonationDecision::Offer
            } else {
                DetonationDecision::Suppress
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_offer_suppresses_unconditionally() {
        for sev in 0u8..=3 {
            assert_eq!(
                should_offer_detonation(DetonationPolicy::NeverOffer, sev),
                DetonationDecision::Suppress
            );
        }
    }

    #[test]
    fn offer_on_p1_fires_for_severities_two_and_three() {
        assert_eq!(
            should_offer_detonation(DetonationPolicy::OfferOnP1, 3),
            DetonationDecision::Offer
        );
        assert_eq!(
            should_offer_detonation(DetonationPolicy::OfferOnP1, 2),
            DetonationDecision::Offer
        );
        assert_eq!(
            should_offer_detonation(DetonationPolicy::OfferOnP1, 1),
            DetonationDecision::Suppress
        );
        assert_eq!(
            should_offer_detonation(DetonationPolicy::OfferOnP1, 0),
            DetonationDecision::Suppress
        );
    }

    #[test]
    fn offer_on_p1_or_p2_widens_the_band() {
        assert_eq!(
            should_offer_detonation(DetonationPolicy::OfferOnP1OrP2, 1),
            DetonationDecision::Offer
        );
        assert_eq!(
            should_offer_detonation(DetonationPolicy::OfferOnP1OrP2, 0),
            DetonationDecision::Suppress
        );
    }

    #[test]
    fn default_policy_is_offer_on_p1() {
        assert_eq!(DetonationPolicy::default(), DetonationPolicy::OfferOnP1);
    }
}
