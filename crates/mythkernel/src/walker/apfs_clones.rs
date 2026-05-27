//! TASK-213 — APFS clone-aware scan.
//!
//! Apple File System (APFS) supports `clonefile(2)`-style copy-on-write
//! clones: two paths that share the same on-disk extents until one is
//! written. A naive scan hashes both paths, even though they are
//! byte-identical. On a Time Machine local-snapshot directory that can
//! mean hashing every macOS app three or four times.
//!
//! The fix: query the `ATTR_CMNEXT_CLONEID` attribute via `getattrlist`.
//! Paths that share a clone-id share extents — hash one, propagate the
//! verdict to all the others within the same scan.
//!
//! This module:
//! - exposes `clone_id(path) -> Option<u64>` — caller-side platform
//!   shim that returns `None` everywhere except macOS, where it'll
//!   call the BSD attrlist syscall in the engine-integration commit;
//! - exposes `CloneGroups` — the per-scan registry that maps
//!   `clone_id` → `(representative_path, verdict)` so we hash the
//!   first clone we encounter and short-circuit later siblings.
//!
//! The verdict-inheritance contract is *per-scan only*. `file_state`
//! (TASK-202) keys on path so the persistent layer stays unaware of
//! cloning. The reason: clone groups can dissolve mid-scan (someone
//! `cp`'s a clone with `--reflink=never`), so the safe invariant is
//! "every path's persisted result is identical to a non-clone-aware
//! scan's output".

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Verdict carried through the clone group. We keep this enum
/// independent of `DetectorVerdict` so the clone-grouping layer
/// doesn't take a hard dep on the detection pipeline's types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloneVerdict {
    /// Clean / no finding.
    Clean,
    /// One or more detectors matched. Carries the JSON-encoded
    /// `Detected` outcome verbatim so the scan layer can propagate
    /// without lossy projection.
    Detected(String),
    /// Allowlisted skip — the engine records nothing for the file.
    Skipped(String),
}

/// Per-scan clone-group registry.
///
/// Cheap to clone; the engine keeps one of these per scan and shares
/// it across the rayon worker pool (wrap in `Arc<Mutex>` at the call
/// site).
#[derive(Debug, Default, Clone)]
pub struct CloneGroups {
    by_id: HashMap<u64, GroupState>,
    /// Hits the slow path counter at the rate of every scanned path;
    /// the engine surfaces "bytes saved by clone awareness" in
    /// telemetry from these counters.
    pub stats: CloneStats,
}

#[derive(Debug, Clone)]
struct GroupState {
    representative: PathBuf,
    verdict: Option<CloneVerdict>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CloneStats {
    /// Number of paths that triggered hashing (first member of the
    /// group, or files that aren't part of any group).
    pub hashed: u64,
    /// Number of paths that inherited a sibling's verdict.
    pub inherited: u64,
    /// Bytes saved by clone awareness (each inheritance counts the
    /// file's size as "would have been re-hashed").
    pub bytes_saved: u64,
}

/// Result of asking the registry what to do with a given path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloneDecision {
    /// First time we've seen this clone group (or the file isn't part
    /// of any group). Caller should hash the file normally and
    /// invoke [`CloneGroups::record_verdict`] with the outcome.
    Hash,
    /// Path is a clone of a previously-hashed sibling. The verdict
    /// is supplied; caller surfaces it without hashing.
    Inherit(CloneVerdict),
    /// Path is a clone of a sibling that we've started hashing but
    /// not yet completed. Caller should hash (cheap; the worker
    /// pool can't safely wait on another worker without risking
    /// dead-lock with a single-threaded executor).
    Race,
}

impl CloneGroups {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decide what to do with `path`. The clone_id is queried via
    /// the OS-specific shim ([`clone_id`]); when it returns `None`
    /// we always answer `Hash` and bump the appropriate stat.
    pub fn observe_or_inherit(&mut self, path: &Path, size: u64) -> CloneDecision {
        let Some(id) = clone_id(path) else {
            self.stats.hashed += 1;
            return CloneDecision::Hash;
        };
        if let Some(state) = self.by_id.get(&id) {
            if let Some(v) = state.verdict.clone() {
                self.stats.inherited += 1;
                self.stats.bytes_saved += size;
                return CloneDecision::Inherit(v);
            }
            // Group exists but no verdict yet — caller hashes
            // independently to avoid a wait/race.
            self.stats.hashed += 1;
            return CloneDecision::Race;
        }
        // First sighting — register as the group's representative.
        self.by_id.insert(
            id,
            GroupState {
                representative: path.to_path_buf(),
                verdict: None,
            },
        );
        self.stats.hashed += 1;
        CloneDecision::Hash
    }

    /// Record the verdict for the group `path` belongs to. Safe to
    /// call even for non-clone files (the call resolves the id via
    /// the shim again and is a no-op when `None`).
    pub fn record_verdict(&mut self, path: &Path, verdict: CloneVerdict) {
        let Some(id) = clone_id(path) else {
            return;
        };
        let state = self.by_id.entry(id).or_insert_with(|| GroupState {
            representative: path.to_path_buf(),
            verdict: None,
        });
        state.verdict = Some(verdict);
    }

    /// Direct version of [`Self::observe_or_inherit`] for tests and
    /// callers that already have the clone-id in hand (skips the
    /// platform shim). Same contract.
    pub fn observe_or_inherit_with_id(
        &mut self,
        path: &Path,
        size: u64,
        id: Option<u64>,
    ) -> CloneDecision {
        match id {
            None => {
                self.stats.hashed += 1;
                CloneDecision::Hash
            }
            Some(id) => {
                if let Some(state) = self.by_id.get(&id) {
                    if let Some(v) = state.verdict.clone() {
                        self.stats.inherited += 1;
                        self.stats.bytes_saved += size;
                        return CloneDecision::Inherit(v);
                    }
                    self.stats.hashed += 1;
                    return CloneDecision::Race;
                }
                self.by_id.insert(
                    id,
                    GroupState {
                        representative: path.to_path_buf(),
                        verdict: None,
                    },
                );
                self.stats.hashed += 1;
                CloneDecision::Hash
            }
        }
    }

    /// Direct version of [`Self::record_verdict`] for tests; pairs
    /// with [`Self::observe_or_inherit_with_id`].
    pub fn record_verdict_with_id(&mut self, id: u64, path: &Path, verdict: CloneVerdict) {
        let state = self.by_id.entry(id).or_insert_with(|| GroupState {
            representative: path.to_path_buf(),
            verdict: None,
        });
        state.verdict = Some(verdict);
    }

    pub fn group_count(&self) -> usize {
        self.by_id.len()
    }

    pub fn representative(&self, id: u64) -> Option<&Path> {
        self.by_id.get(&id).map(|s| s.representative.as_path())
    }
}

/// Platform shim for querying an APFS clone id.
///
/// macOS calls `getattrlist` with `ATTR_CMNEXT_CLONEID`. Every other
/// OS returns `None`. The actual `libc` ioctl binding lands in the
/// engine-integration commit; this stub keeps the callers
/// cross-platform.
pub fn clone_id(_path: &Path) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_clone_id_always_hashes() {
        let mut g = CloneGroups::new();
        let d = g.observe_or_inherit_with_id(Path::new("/a"), 100, None);
        assert_eq!(d, CloneDecision::Hash);
        assert_eq!(g.stats.hashed, 1);
        assert_eq!(g.stats.inherited, 0);
    }

    #[test]
    fn first_clone_in_group_hashes_subsequent_inherits() {
        let mut g = CloneGroups::new();
        // First sibling: gets `Hash`.
        let d1 = g.observe_or_inherit_with_id(Path::new("/a"), 1024, Some(42));
        assert_eq!(d1, CloneDecision::Hash);
        // Caller records the verdict.
        g.record_verdict_with_id(42, Path::new("/a"), CloneVerdict::Clean);
        // Second sibling: inherits.
        let d2 = g.observe_or_inherit_with_id(Path::new("/b"), 1024, Some(42));
        assert_eq!(d2, CloneDecision::Inherit(CloneVerdict::Clean));
        // Third sibling: also inherits.
        let d3 = g.observe_or_inherit_with_id(Path::new("/c"), 1024, Some(42));
        assert_eq!(d3, CloneDecision::Inherit(CloneVerdict::Clean));
        assert_eq!(g.stats.hashed, 1);
        assert_eq!(g.stats.inherited, 2);
        assert_eq!(g.stats.bytes_saved, 2048);
    }

    #[test]
    fn race_when_group_exists_but_no_verdict_yet() {
        let mut g = CloneGroups::new();
        g.observe_or_inherit_with_id(Path::new("/a"), 200, Some(7));
        // Sibling arrives before verdict is recorded.
        let d = g.observe_or_inherit_with_id(Path::new("/b"), 200, Some(7));
        assert_eq!(d, CloneDecision::Race);
        // Both count as hashed.
        assert_eq!(g.stats.hashed, 2);
    }

    #[test]
    fn distinct_clone_ids_dont_share() {
        let mut g = CloneGroups::new();
        g.observe_or_inherit_with_id(Path::new("/a"), 10, Some(1));
        g.record_verdict_with_id(1, Path::new("/a"), CloneVerdict::Clean);
        let d = g.observe_or_inherit_with_id(Path::new("/b"), 10, Some(2));
        assert_eq!(d, CloneDecision::Hash);
        assert_eq!(g.group_count(), 2);
    }

    #[test]
    fn detected_verdict_is_propagated_verbatim() {
        let mut g = CloneGroups::new();
        let v = CloneVerdict::Detected("{\"rule\":\"trojan-xyz\"}".into());
        g.observe_or_inherit_with_id(Path::new("/a"), 10, Some(5));
        g.record_verdict_with_id(5, Path::new("/a"), v.clone());
        let d = g.observe_or_inherit_with_id(Path::new("/b"), 10, Some(5));
        assert_eq!(d, CloneDecision::Inherit(v));
    }

    #[test]
    fn representative_path_is_first_seen() {
        let mut g = CloneGroups::new();
        g.observe_or_inherit_with_id(Path::new("/first"), 0, Some(99));
        g.observe_or_inherit_with_id(Path::new("/second"), 0, Some(99));
        assert_eq!(g.representative(99), Some(Path::new("/first")));
    }

    #[test]
    fn skipped_verdict_propagates() {
        let mut g = CloneGroups::new();
        g.observe_or_inherit_with_id(Path::new("/a"), 0, Some(11));
        g.record_verdict_with_id(11, Path::new("/a"), CloneVerdict::Skipped("nsrl".into()));
        let d = g.observe_or_inherit_with_id(Path::new("/b"), 0, Some(11));
        assert_eq!(
            d,
            CloneDecision::Inherit(CloneVerdict::Skipped("nsrl".into()))
        );
    }

    #[test]
    fn shim_returns_none_off_macos() {
        // The foundation shim returns None for every input; that's
        // what the engine relies on until per-OS bindings land.
        assert!(clone_id(Path::new("/anything")).is_none());
    }

    #[test]
    fn record_verdict_through_public_api_no_op_when_shim_none() {
        // Tests we don't panic on the path-based API even when the
        // shim has nothing to say.
        let mut g = CloneGroups::new();
        g.record_verdict(Path::new("/x"), CloneVerdict::Clean);
        assert_eq!(g.group_count(), 0);
    }
}
