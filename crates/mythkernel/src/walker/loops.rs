//! TASK-210 — Symlink-loop detector with breadcrumb log.
//!
//! Tracks the `(device, inode)` of every directory the walker enters
//! during a single scan. A repeat `(dev, ino)` is a symlink loop:
//! [`LoopGuard::enter`] returns an error containing the path chain
//! from the duplicate ancestor down to the current candidate, and the
//! walker skips descent. A separate per-scan max-depth counter
//! catches non-loop pathological trees that aren't a cycle (default
//! 64; configurable).
//!
//! On Windows the same primitive works against the
//! `(volume_serial, file_index)` tuple returned by
//! `GetFileInformationByHandle`. The struct doesn't care where the
//! (dev, ino) pair came from — caller provides them.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Default max-depth for the per-scan recursion limiter. Generous
/// enough that every legitimate filesystem tree clears it (the deepest
/// known real-world filesystem path is < 50 components even on
/// pathological CI archives) but tight enough that an attacker can't
/// recurse the engine into a stack overflow.
pub const DEFAULT_MAX_DEPTH: usize = 64;

/// Maximum length of the breadcrumb chain reported in a
/// `LoopDetected` event. Keeps log lines bounded; the chain is
/// truncated from the front, preserving the tail (the last 8
/// directories before the loop closed).
pub const MAX_BREADCRUMB_LEN: usize = 8;

/// Per-scan loop / depth guard. Construct one per scan, hand a clone
/// to each walker thread, and call [`Self::enter`] before descending
/// into a directory.
#[derive(Debug)]
pub struct LoopGuard {
    seen: HashSet<(u64, u64)>,
    stack: Vec<PathBuf>,
    max_depth: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopGuardError {
    /// `(dev, ino)` already on the stack — symlink loop.
    Loop {
        chain: Vec<PathBuf>,
        offender: PathBuf,
    },
    /// Stack depth would exceed `max_depth`.
    DepthExceeded {
        max_depth: usize,
        attempted_depth: usize,
        offender: PathBuf,
    },
}

impl LoopGuard {
    pub fn new() -> Self {
        Self::with_max_depth(DEFAULT_MAX_DEPTH)
    }

    pub fn with_max_depth(max_depth: usize) -> Self {
        Self {
            seen: HashSet::new(),
            stack: Vec::new(),
            max_depth,
        }
    }

    /// Attempt to enter a directory. Returns `Err` if `(dev, ino)` is
    /// already on the stack (loop) or if entering would exceed the
    /// configured max depth. On success the directory is pushed; pair
    /// with [`Self::exit`] when the caller is done with it (RAII
    /// pattern from the caller side — there is intentionally no
    /// auto-exit Drop guard because walkers want explicit ordering).
    pub fn enter(&mut self, path: &Path, dev: u64, ino: u64) -> Result<(), LoopGuardError> {
        if self.stack.len() + 1 > self.max_depth {
            return Err(LoopGuardError::DepthExceeded {
                max_depth: self.max_depth,
                attempted_depth: self.stack.len() + 1,
                offender: path.to_path_buf(),
            });
        }
        if !self.seen.insert((dev, ino)) {
            // Loop — assemble the breadcrumb from the stack tail.
            let chain_tail = if self.stack.len() > MAX_BREADCRUMB_LEN {
                self.stack[self.stack.len() - MAX_BREADCRUMB_LEN..].to_vec()
            } else {
                self.stack.clone()
            };
            return Err(LoopGuardError::Loop {
                chain: chain_tail,
                offender: path.to_path_buf(),
            });
        }
        self.stack.push(path.to_path_buf());
        Ok(())
    }

    /// Pop the most recently entered directory. Idempotent on empty
    /// stack (a defensive no-op rather than a panic, since walkers
    /// often unwind on error paths and we don't want a panic to mask
    /// the original cause).
    pub fn exit(&mut self) {
        // We don't remove the (dev, ino) from `seen` — even when the
        // walker finishes a subtree, re-entering the same (dev, ino)
        // via a different parent symlink is still a loop and should
        // be caught. The set grows once per directory; bounded by the
        // total inode count of the tree.
        let _ = self.stack.pop();
    }

    pub fn current_depth(&self) -> usize {
        self.stack.len()
    }

    pub fn max_depth(&self) -> usize {
        self.max_depth
    }
}

impl Default for LoopGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn fresh_guard_accepts_distinct_entries() {
        let mut g = LoopGuard::new();
        assert!(g.enter(&p("/a"), 1, 1).is_ok());
        assert!(g.enter(&p("/a/b"), 1, 2).is_ok());
        assert!(g.enter(&p("/a/b/c"), 1, 3).is_ok());
        assert_eq!(g.current_depth(), 3);
    }

    #[test]
    fn repeat_dev_ino_triggers_loop_error() {
        let mut g = LoopGuard::new();
        g.enter(&p("/a"), 1, 100).unwrap();
        g.enter(&p("/a/sym"), 1, 200).unwrap();
        let err = g.enter(&p("/a/sym/back_to_a"), 1, 100).unwrap_err();
        match err {
            LoopGuardError::Loop { chain, offender } => {
                assert_eq!(offender, p("/a/sym/back_to_a"));
                assert!(!chain.is_empty());
            }
            other => panic!("expected Loop, got {other:?}"),
        }
    }

    #[test]
    fn depth_cap_fires_before_loop_check() {
        let mut g = LoopGuard::with_max_depth(3);
        g.enter(&p("/a"), 1, 1).unwrap();
        g.enter(&p("/a/b"), 1, 2).unwrap();
        g.enter(&p("/a/b/c"), 1, 3).unwrap();
        let err = g.enter(&p("/a/b/c/d"), 1, 4).unwrap_err();
        assert!(matches!(
            err,
            LoopGuardError::DepthExceeded {
                max_depth: 3,
                attempted_depth: 4,
                ..
            }
        ));
    }

    #[test]
    fn loop_chain_truncates_to_last_8() {
        let mut g = LoopGuard::with_max_depth(20);
        for i in 1..=15 {
            g.enter(&p(&format!("/a/{i}")), 1, i as u64).unwrap();
        }
        let err = g.enter(&p("/a/loop"), 1, 1).unwrap_err();
        match err {
            LoopGuardError::Loop { chain, .. } => {
                assert_eq!(
                    chain.len(),
                    MAX_BREADCRUMB_LEN,
                    "chain should be truncated to {MAX_BREADCRUMB_LEN}"
                );
                // Tail-preserving: the last entry in chain should be
                // the deepest before the loop closed (/a/15).
                assert_eq!(chain.last().unwrap(), &p("/a/15"));
            }
            other => panic!("expected Loop, got {other:?}"),
        }
    }

    #[test]
    fn exit_decreases_depth_but_keeps_seen() {
        // Walker finished a subtree → pop the stack; but re-encountering
        // the same (dev, ino) elsewhere should STILL trip the loop
        // check, because a symlink can resurrect a previously-walked
        // inode under a different path.
        let mut g = LoopGuard::new();
        g.enter(&p("/a"), 1, 1).unwrap();
        g.enter(&p("/a/b"), 1, 2).unwrap();
        g.exit();
        assert_eq!(g.current_depth(), 1);
        // /a/b unwound; resurrect (1, 2) under /a/other → still loop.
        let err = g.enter(&p("/a/other"), 1, 2).unwrap_err();
        assert!(matches!(err, LoopGuardError::Loop { .. }));
    }

    #[test]
    fn exit_on_empty_is_noop() {
        let mut g = LoopGuard::new();
        g.exit();
        g.exit();
        assert_eq!(g.current_depth(), 0);
    }
}
