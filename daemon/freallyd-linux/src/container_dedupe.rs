//! Container bind-mount dedupe (TASK-239, Phase 8 Wave 2).
//!
//! Prevents N-times-rescan on hosts running Docker/Podman/LXC: a file
//! event that arrives via a container's view of a host-scanned path
//! is silently dropped before hashing.
//!
//! The detector parses peer-group columns (column 7 onwards) in
//! `/proc/self/mountinfo`, builds a `dev_t → canonical mountpoint`
//! map, and uses a bounded LRU(64K) of `(st_dev, st_ino)` to detect
//! the duplicate. Overlayfs upper-layer writes are NOT deduped —
//! they are real new writes, only lower-layer shared bind-mount reads
//! qualify.

use std::collections::{BTreeMap, VecDeque};

/// Default LRU capacity. 64K inodes sized to keep memory bounded at
/// ~5 MB while still catching the duplicate events from a noisy
/// `docker run --rm -v /etc:/host-etc:ro alpine cat /host-etc/hostname`.
pub const DEFAULT_LRU_CAPACITY: usize = 64 * 1024;

/// One observation key. fanotify's `FAN_REPORT_FID` extension lets the
/// daemon recover `(st_dev, st_ino)` without a `stat()` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InodeKey {
    pub dev: u64,
    pub ino: u64,
}

/// One mountpoint peer-group entry, derived from `mountinfo` columns
/// `7..` (the optional-fields block before the `-` separator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerMount {
    pub mountpoint: String,
    pub peer_group: String,
}

/// Build the canonical-mountpoint map: for each peer group present
/// in `mounts`, return one representative mountpoint. The daemon
/// considers the **first-seen** mount the canonical one (insertion
/// order of `mounts` determines this; the caller is expected to
/// stable-sort).
pub fn canonical_map(mounts: &[PeerMount]) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for m in mounts {
        out.entry(m.peer_group.clone())
            .or_insert_with(|| m.mountpoint.clone());
    }
    out
}

/// Bounded FIFO dedup window the daemon consults on every fanotify
/// event. `is_duplicate(key)` returns true when the key was already
/// observed; a fresh observation moves to the back of the queue,
/// which for the bind-mount-dedup use case is the correct semantics
/// — a single host scan emits the same inode at most once per
/// 60 s window so true-LRU semantics (re-promoting on hit) would buy
/// nothing. The previous name `InodeDedupLru` over-claimed; renamed
/// to `InodeDedupQueue` so a reviewer doesn't expect re-promote.
pub struct InodeDedupQueue {
    capacity: usize,
    order: VecDeque<InodeKey>,
    set: BTreeMap<InodeKey, ()>,
}

/// Backwards-compat alias for the prior name — kept so call sites
/// using `InodeDedupLru` keep compiling, but new code should prefer
/// the queue name which matches the implementation.
pub type InodeDedupLru = InodeDedupQueue;

impl InodeDedupQueue {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::with_capacity(capacity),
            set: BTreeMap::new(),
        }
    }

    pub fn is_duplicate(&mut self, key: InodeKey) -> bool {
        if self.set.contains_key(&key) {
            return true;
        }
        if self.order.len() >= self.capacity {
            if let Some(evict) = self.order.pop_front() {
                self.set.remove(&evict);
            }
        }
        self.order.push_back(key);
        self.set.insert(key, ());
        false
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_map_picks_first_seen_per_peer_group() {
        let mounts = vec![
            PeerMount {
                mountpoint: "/etc".into(),
                peer_group: "1".into(),
            },
            PeerMount {
                mountpoint: "/var/lib/docker/.../merged/host-etc".into(),
                peer_group: "1".into(),
            },
        ];
        let m = canonical_map(&mounts);
        assert_eq!(m.get("1").map(String::as_str), Some("/etc"));
    }

    #[test]
    fn queue_flags_repeat_within_window() {
        let mut l = InodeDedupQueue::with_capacity(4);
        let k = InodeKey { dev: 1, ino: 1 };
        assert!(!l.is_duplicate(k));
        assert!(l.is_duplicate(k));
    }

    #[test]
    fn queue_evicts_oldest_when_full() {
        let mut l = InodeDedupQueue::with_capacity(2);
        l.is_duplicate(InodeKey { dev: 1, ino: 1 });
        l.is_duplicate(InodeKey { dev: 1, ino: 2 });
        l.is_duplicate(InodeKey { dev: 1, ino: 3 }); // evicts (1,1)
        // (1,1) was evicted → no longer a duplicate.
        assert!(!l.is_duplicate(InodeKey { dev: 1, ino: 1 }));
        // (1,3) still in set.
        assert!(l.is_duplicate(InodeKey { dev: 1, ino: 3 }));
    }

    #[test]
    fn queue_distinct_keys_are_independent() {
        let mut l = InodeDedupQueue::with_capacity(10);
        assert!(!l.is_duplicate(InodeKey { dev: 1, ino: 1 }));
        assert!(!l.is_duplicate(InodeKey { dev: 1, ino: 2 }));
        assert!(!l.is_duplicate(InodeKey { dev: 2, ino: 1 }));
        assert_eq!(l.len(), 3);
    }
}
