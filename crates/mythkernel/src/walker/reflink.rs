//! TASK-214 — Btrfs / ZFS reflink-aware scan.
//!
//! Same core invariant as TASK-213 (APFS clones): files that share
//! on-disk extents hash identically, so we can hash one and inherit
//! the verdict for every reflinked sibling within a single scan.
//!
//! Two key types live in this module:
//!
//! - `ExtentKey` — a stable identifier for the shared-extent group
//!   on either filesystem. Btrfs surfaces this as a
//!   `(subvol_id, root_id, file_extent_item.disk_bytenr)` triple;
//!   ZFS surfaces it as `(dnode_id, block_pointer)`. We hash both
//!   into a single `u128` so the registry stays filesystem-agnostic.
//! - `ReflinkGroups` — per-scan registry, mirrors
//!   `walker::apfs_clones::CloneGroups` in shape but uses the
//!   `ExtentKey` instead of an opaque `u64` clone id.
//!
//! Defaults:
//! - Btrfs path: enabled.
//! - ZFS path: disabled by default. The ZFS ioctl
//!   (`zfs_ioc_objset_stats`) is gated by user permissions in many
//!   distros; falling back to per-file hashing keeps the scan
//!   running rather than aborting.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExtentKey(pub u128);

impl ExtentKey {
    /// Construct from a Btrfs `(subvol_id, file_extent_disk_bytenr)`
    /// pair. The two u64s pack into a u128 with no information loss.
    pub fn btrfs(subvol_id: u64, disk_bytenr: u64) -> Self {
        Self(((subvol_id as u128) << 64) | (disk_bytenr as u128))
    }

    /// Construct from a ZFS `(dnode_id, block_pointer)` pair.
    pub fn zfs(dnode_id: u64, block_pointer: u64) -> Self {
        // Tag bit so a Btrfs (subvol=N, bytenr=M) and a ZFS
        // (dnode=N, bp=M) with the same numeric values don't alias.
        Self((1u128 << 127) | ((dnode_id as u128) << 64) | (block_pointer as u128))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReflinkVerdict {
    Clean,
    Detected(String),
    Skipped(String),
}

#[derive(Debug, Clone)]
struct GroupState {
    representative: PathBuf,
    verdict: Option<ReflinkVerdict>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReflinkStats {
    pub hashed: u64,
    pub inherited: u64,
    pub bytes_saved: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReflinkDecision {
    Hash,
    Inherit(ReflinkVerdict),
    /// First-time-seen but another worker is racing to fill the
    /// verdict. Caller hashes independently to avoid deadlock.
    Race,
}

#[derive(Debug, Default, Clone)]
pub struct ReflinkGroups {
    by_key: HashMap<ExtentKey, GroupState>,
    pub stats: ReflinkStats,
    /// Whether the ZFS code path is allowed to register groups. Set
    /// `false` to keep the engine on the per-file path on ZFS for
    /// hosts where `zfs_ioc_objset_stats` permissions are restricted.
    /// Btrfs is unaffected.
    pub zfs_enabled: bool,
}

impl ReflinkGroups {
    pub fn new() -> Self {
        Self {
            zfs_enabled: false, // safe default per spec
            ..Self::default()
        }
    }

    pub fn with_zfs_enabled(mut self, enabled: bool) -> Self {
        self.zfs_enabled = enabled;
        self
    }

    /// Decide what to do with `path` based on its extent group.
    /// Use [`group_for`] in the engine to obtain the key, then call
    /// this with `Some(key)` (or `None` when the FS doesn't support
    /// reflinks or ZFS is disabled).
    pub fn observe_or_inherit(
        &mut self,
        path: &Path,
        size: u64,
        key: Option<ExtentKey>,
    ) -> ReflinkDecision {
        let Some(k) = key else {
            self.stats.hashed += 1;
            return ReflinkDecision::Hash;
        };
        if let Some(state) = self.by_key.get(&k) {
            if let Some(v) = state.verdict.clone() {
                self.stats.inherited += 1;
                self.stats.bytes_saved += size;
                return ReflinkDecision::Inherit(v);
            }
            self.stats.hashed += 1;
            return ReflinkDecision::Race;
        }
        self.by_key.insert(
            k,
            GroupState {
                representative: path.to_path_buf(),
                verdict: None,
            },
        );
        self.stats.hashed += 1;
        ReflinkDecision::Hash
    }

    pub fn record_verdict(&mut self, key: ExtentKey, path: &Path, verdict: ReflinkVerdict) {
        let state = self.by_key.entry(key).or_insert_with(|| GroupState {
            representative: path.to_path_buf(),
            verdict: None,
        });
        state.verdict = Some(verdict);
    }

    pub fn group_count(&self) -> usize {
        self.by_key.len()
    }

    pub fn representative(&self, key: ExtentKey) -> Option<&Path> {
        self.by_key.get(&key).map(|s| s.representative.as_path())
    }
}

/// Platform shim — given a path, return its `ExtentKey` if the FS
/// supports reflink grouping and the caller has read permission.
///
/// Foundation-only: returns `None` everywhere until the per-OS ioctl
/// bindings land. Linux callers eventually wire `BTRFS_IOC_TREE_SEARCH_V2`
/// + `zfs_ioc_objset_stats`; macOS / Windows return `None`.
pub fn group_for(_path: &Path) -> Option<ExtentKey> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btrfs_and_zfs_keys_do_not_alias() {
        let btrfs = ExtentKey::btrfs(1, 2);
        let zfs = ExtentKey::zfs(1, 2);
        assert_ne!(btrfs, zfs);
    }

    #[test]
    fn first_member_hashes_others_inherit() {
        let mut g = ReflinkGroups::new();
        let k = ExtentKey::btrfs(1, 100);
        let d1 = g.observe_or_inherit(Path::new("/a"), 1000, Some(k));
        assert_eq!(d1, ReflinkDecision::Hash);
        g.record_verdict(k, Path::new("/a"), ReflinkVerdict::Clean);
        let d2 = g.observe_or_inherit(Path::new("/b"), 1000, Some(k));
        assert_eq!(d2, ReflinkDecision::Inherit(ReflinkVerdict::Clean));
        assert_eq!(g.stats.hashed, 1);
        assert_eq!(g.stats.inherited, 1);
        assert_eq!(g.stats.bytes_saved, 1000);
    }

    #[test]
    fn distinct_groups_dont_share() {
        let mut g = ReflinkGroups::new();
        let k1 = ExtentKey::btrfs(1, 100);
        let k2 = ExtentKey::btrfs(1, 200);
        g.observe_or_inherit(Path::new("/a"), 0, Some(k1));
        g.record_verdict(k1, Path::new("/a"), ReflinkVerdict::Clean);
        let d = g.observe_or_inherit(Path::new("/b"), 0, Some(k2));
        assert_eq!(d, ReflinkDecision::Hash);
    }

    #[test]
    fn race_when_verdict_pending() {
        let mut g = ReflinkGroups::new();
        let k = ExtentKey::btrfs(2, 200);
        g.observe_or_inherit(Path::new("/a"), 0, Some(k));
        let d = g.observe_or_inherit(Path::new("/b"), 0, Some(k));
        assert_eq!(d, ReflinkDecision::Race);
    }

    #[test]
    fn unknown_key_always_hashes() {
        let mut g = ReflinkGroups::new();
        let d = g.observe_or_inherit(Path::new("/a"), 0, None);
        assert_eq!(d, ReflinkDecision::Hash);
        assert_eq!(g.stats.inherited, 0);
    }

    #[test]
    fn detected_verdict_round_trips() {
        let mut g = ReflinkGroups::new();
        let k = ExtentKey::zfs(7, 99);
        g.observe_or_inherit(Path::new("/a"), 0, Some(k));
        let v = ReflinkVerdict::Detected("{\"rule\":\"abc\"}".into());
        g.record_verdict(k, Path::new("/a"), v.clone());
        let d = g.observe_or_inherit(Path::new("/b"), 0, Some(k));
        assert_eq!(d, ReflinkDecision::Inherit(v));
    }

    #[test]
    fn group_for_shim_returns_none() {
        assert!(group_for(Path::new("/x")).is_none());
    }

    #[test]
    fn representative_path_is_first_seen() {
        let mut g = ReflinkGroups::new();
        let k = ExtentKey::btrfs(3, 333);
        g.observe_or_inherit(Path::new("/first"), 0, Some(k));
        g.observe_or_inherit(Path::new("/second"), 0, Some(k));
        assert_eq!(g.representative(k), Some(Path::new("/first")));
    }
}
