//! Process-ancestry view (TASK-303, Phase 10 Wave 3).
//!
//! Walks the PPID chain to PID 1 (Linux `init`, macOS `launchd`)
//! or to the Windows root (`wininit.exe` parents `services.exe`
//! and the user session `winlogon.exe`; both eventually parent
//! to PID 0 / the System Idle Process).
//!
//! At first observation of a pid, the daemon snapshots the
//! resolved chain into the [`AncestryCache`]. Later UI lookups
//! survive the process's death, which is the whole point of the
//! cache — by the time the user clicks "show ancestry of pid X"
//! the process may be long gone.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub image_path: String,
}

/// One resolved chain, root first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AncestryChain {
    pub nodes: Vec<ProcessNode>,
}

impl AncestryChain {
    pub fn leaf_pid(&self) -> Option<u32> {
        self.nodes.last().map(|n| n.pid)
    }
}

#[derive(Debug, Default, Clone)]
pub struct AncestryCache {
    by_pid: HashMap<u32, AncestryChain>,
}

impl AncestryCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.by_pid.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_pid.is_empty()
    }

    pub fn get(&self, pid: u32) -> Option<&AncestryChain> {
        self.by_pid.get(&pid)
    }

    /// Resolve the chain for `pid` from the supplied process table
    /// and insert it into the cache. Subsequent calls for the same
    /// pid are no-ops (first-observation snapshot wins, so the
    /// view stays stable across pid reuse).
    pub fn resolve(&mut self, pid: u32, table: &HashMap<u32, ProcessNode>) -> &AncestryChain {
        if self.by_pid.contains_key(&pid) {
            return &self.by_pid[&pid];
        }
        let chain = build_chain(pid, table);
        self.by_pid.insert(pid, chain);
        &self.by_pid[&pid]
    }
}

/// Walk up from `pid` to a process whose ppid is 0 or which is
/// itself missing from the table. Cycles are guarded by a visited
/// set; depth is capped at 64 to handle pathologically deep trees
/// without unbounded growth.
pub fn build_chain(pid: u32, table: &HashMap<u32, ProcessNode>) -> AncestryChain {
    const MAX_DEPTH: usize = 64;
    let mut chain = Vec::with_capacity(8);
    let mut seen = std::collections::HashSet::new();
    let mut cursor = pid;
    while chain.len() < MAX_DEPTH && seen.insert(cursor) {
        match table.get(&cursor) {
            Some(node) => {
                chain.push(node.clone());
                if node.ppid == 0 || node.ppid == cursor {
                    break;
                }
                cursor = node.ppid;
            }
            None => break,
        }
    }
    chain.reverse();
    AncestryChain { nodes: chain }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(pid: u32, ppid: u32, path: &str) -> ProcessNode {
        ProcessNode {
            pid,
            ppid,
            image_path: path.to_string(),
        }
    }

    fn three_deep_table() -> HashMap<u32, ProcessNode> {
        let mut t = HashMap::new();
        t.insert(1, node(1, 0, "/sbin/init"));
        t.insert(100, node(100, 1, "/usr/bin/bash"));
        t.insert(200, node(200, 100, "/usr/bin/curl"));
        t
    }

    #[test]
    fn builds_root_first_chain() {
        let t = three_deep_table();
        let chain = build_chain(200, &t);
        assert_eq!(chain.nodes.len(), 3);
        assert_eq!(chain.nodes[0].pid, 1);
        assert_eq!(chain.nodes[1].pid, 100);
        assert_eq!(chain.nodes[2].pid, 200);
        assert_eq!(chain.leaf_pid(), Some(200));
    }

    #[test]
    fn cache_returns_first_observation() {
        let t = three_deep_table();
        let mut cache = AncestryCache::new();
        cache.resolve(200, &t);
        // Mutate table so 200 now has a different parent.
        let mut t2 = t.clone();
        t2.insert(200, node(200, 999, "/imposter"));
        let chain = cache.resolve(200, &t2);
        // First observation wins.
        assert_eq!(chain.nodes.len(), 3);
        assert_eq!(chain.nodes[1].pid, 100);
    }

    #[test]
    fn cycle_is_guarded() {
        let mut t = HashMap::new();
        t.insert(10, node(10, 20, "/a"));
        t.insert(20, node(20, 10, "/b"));
        let chain = build_chain(10, &t);
        // Two distinct nodes; the second hop closes the loop and
        // the walker stops.
        assert_eq!(chain.nodes.len(), 2);
    }

    #[test]
    fn missing_pid_yields_empty_chain() {
        let t = three_deep_table();
        let chain = build_chain(9999, &t);
        assert!(chain.nodes.is_empty());
        assert!(chain.leaf_pid().is_none());
    }
}
