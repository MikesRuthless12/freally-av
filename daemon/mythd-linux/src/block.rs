//! Block-on-detected for fanotify (TASK-140, Phase 8).
//!
//! Owns the in-memory denylist + the verdict-policy function. The
//! engine pushes the path set via
//! [`mythkernel::ipc::linfan::IpcFrame::ActiveFindingsPush`] every
//! time the underlying `findings` table changes. The denylist lives
//! in this module so a verdict request can be answered in O(log n)
//! without round-tripping the engine.
//!
//! Per FR-160 point 5: block-on-detected is honored **even when
//! Shields=OFF**. The Shields short-circuit only suppresses
//! "everything else is ALLOW" — paths with open `detected` findings
//! still DENY.

use std::collections::BTreeSet;

use mythkernel::ipc::linfan::{Verdict, VerdictResponse};
use mythkernel::realtime::shields::ShieldsState;

/// Daemon-side cache of "paths with an open `detected` finding". The
/// engine pushes; the daemon reads on the verdict hot path.
#[derive(Debug, Default, Clone)]
pub struct ActiveDenylist {
    paths: BTreeSet<String>,
}

impl ActiveDenylist {
    pub fn replace(&mut self, paths: impl IntoIterator<Item = String>) {
        self.paths = paths.into_iter().collect();
    }

    pub fn contains(&self, path: &str) -> bool {
        self.paths.contains(path)
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

/// Apply the verdict policy for one open. Returns the wire response
/// the daemon sends back through fanotify.
///
/// Priority order (matches PRD § 4.3 + FR-160 point 5):
///
///   1. Path in the active denylist → DENY with `block_on_detected`.
///   2. Shields=OFF → ALLOW with `shields_off` (no engine round-trip).
///   3. Otherwise DEFER — the daemon will pass the request to the
///      engine for the full hash + pipeline decision.
pub fn decide(
    req_id: u64,
    path: &str,
    denylist: &ActiveDenylist,
    shields: ShieldsState,
    now_utc: i64,
) -> VerdictResponse {
    if denylist.contains(path) {
        return VerdictResponse {
            req_id,
            verdict: Verdict::Deny,
            policy_id: "block_on_detected".into(),
            reason: Some(format!("path '{path}' has an open `detected` finding")),
        };
    }
    // FR-160.3: a paused Shields state must auto-resume when its
    // `pause_until_utc` has passed. Without `resolved_at(now)` the
    // daemon would honor the pause forever if the engine crashed or
    // the IPC link blipped between expiry and the next ShieldsPush.
    let effective = shields.resolved_at(now_utc);
    if !effective.enabled {
        return VerdictResponse {
            req_id,
            verdict: Verdict::Allow,
            policy_id: "shields_off".into(),
            reason: Some("Shields disabled — daemon short-circuits ALLOW".into()),
        };
    }
    VerdictResponse {
        req_id,
        verdict: Verdict::Defer,
        policy_id: "defer_engine".into(),
        reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shields_on() -> ShieldsState {
        ShieldsState {
            enabled: true,
            pause_until_utc: None,
        }
    }

    fn shields_off() -> ShieldsState {
        ShieldsState {
            enabled: false,
            pause_until_utc: None,
        }
    }

    #[test]
    fn denylisted_path_denies_even_with_shields_off() {
        let mut dl = ActiveDenylist::default();
        dl.replace(["/bad.bin".to_string()]);
        let r = decide(1, "/bad.bin", &dl, shields_off(), 0);
        assert_eq!(r.verdict, Verdict::Deny);
        assert_eq!(r.policy_id, "block_on_detected");
    }

    #[test]
    fn shields_off_with_clean_path_allows_locally() {
        let dl = ActiveDenylist::default();
        let r = decide(7, "/home/me/x.bin", &dl, shields_off(), 0);
        assert_eq!(r.verdict, Verdict::Allow);
        assert_eq!(r.policy_id, "shields_off");
    }

    #[test]
    fn shields_on_with_clean_path_defers_to_engine() {
        let dl = ActiveDenylist::default();
        let r = decide(2, "/home/me/y.bin", &dl, shields_on(), 0);
        assert_eq!(r.verdict, Verdict::Defer);
        assert_eq!(r.policy_id, "defer_engine");
    }

    #[test]
    fn expired_pause_auto_resumes_on_daemon_side() {
        let dl = ActiveDenylist::default();
        let paused = ShieldsState {
            enabled: false,
            pause_until_utc: Some(100),
        };
        // now > pause_until_utc → daemon must treat as ON and defer
        // to the engine, not return ALLOW.
        let r = decide(9, "/home/me/x.bin", &dl, paused, 200);
        assert_eq!(r.verdict, Verdict::Defer);
        assert_eq!(r.policy_id, "defer_engine");
    }

    #[test]
    fn active_pause_still_short_circuits_allow() {
        let dl = ActiveDenylist::default();
        let paused = ShieldsState {
            enabled: false,
            pause_until_utc: Some(2_000_000_000),
        };
        let r = decide(10, "/home/me/x.bin", &dl, paused, 100);
        assert_eq!(r.verdict, Verdict::Allow);
        assert_eq!(r.policy_id, "shields_off");
    }

    #[test]
    fn replace_swaps_the_full_set() {
        let mut dl = ActiveDenylist::default();
        dl.replace(["/a".to_string(), "/b".to_string()]);
        assert!(dl.contains("/a"));
        assert!(dl.contains("/b"));
        dl.replace(["/c".to_string()]);
        assert!(!dl.contains("/a"));
        assert!(dl.contains("/c"));
        assert_eq!(dl.len(), 1);
    }
}
