//! Nested-archive recursion-depth limit (TASK-284).
//!
//! Each time the engine opens an archive-inside-an-archive, it
//! must bump a depth counter. If the counter exceeds the cap,
//! the deeper extraction is aborted with [`DepthExceededError`].
//!
//! The walker uses an [`ArchiveDepthGuard`] handle: clone it on
//! the way *in* (returns a new guard with depth+1), drop it on
//! the way *out*. The struct is `Send + Sync` so it can be
//! threaded through Rayon scopes without locks — the depth lives
//! on the stack of the recursing task.

use serde::{Deserialize, Serialize};

/// Default maximum nested-archive depth. Three is sufficient for
/// every legitimate `.tar.gz` (1 step) / `.tar.xz` inside a
/// `.zip` (2 steps) workflow we've observed, and rules out the
/// 42.zip-style 6-level recursion in one configuration knob.
pub const DEFAULT_MAX_DEPTH: usize = 3;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ArchiveDepthGuard {
    depth: usize,
    max_depth: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepthExceededError {
    pub depth: usize,
    pub max_depth: usize,
}

impl std::fmt::Display for DepthExceededError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "archive nesting depth {} exceeded cap of {}",
            self.depth, self.max_depth
        )
    }
}

impl std::error::Error for DepthExceededError {}

impl ArchiveDepthGuard {
    /// Construct a fresh guard at depth zero.
    pub fn root() -> Self {
        Self {
            depth: 0,
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }

    /// Construct a fresh guard with a non-default cap.
    pub fn with_max(max_depth: usize) -> Self {
        Self {
            depth: 0,
            max_depth,
        }
    }

    /// Returns the current nesting depth (0 = top-level scan).
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Returns a new guard one level deeper, or
    /// `Err(DepthExceededError)` when the cap is reached.
    pub fn descend(&self) -> Result<Self, DepthExceededError> {
        let next = self.depth + 1;
        if next > self.max_depth {
            return Err(DepthExceededError {
                depth: next,
                max_depth: self.max_depth,
            });
        }
        Ok(Self {
            depth: next,
            max_depth: self.max_depth,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_starts_at_depth_zero() {
        let g = ArchiveDepthGuard::root();
        assert_eq!(g.depth(), 0);
    }

    #[test]
    fn descend_within_cap_succeeds() {
        let g = ArchiveDepthGuard::with_max(3);
        let g1 = g.descend().unwrap();
        let g2 = g1.descend().unwrap();
        let g3 = g2.descend().unwrap();
        assert_eq!(g3.depth(), 3);
    }

    #[test]
    fn descend_past_cap_returns_error() {
        let g = ArchiveDepthGuard::with_max(2);
        let g1 = g.descend().unwrap();
        let g2 = g1.descend().unwrap();
        let err = g2.descend().expect_err("must trip");
        assert_eq!(err.depth, 3);
        assert_eq!(err.max_depth, 2);
    }

    #[test]
    fn default_cap_is_three() {
        let g = ArchiveDepthGuard::root();
        assert_eq!(g.descend().unwrap().depth(), 1);
        let g3 = g
            .descend()
            .unwrap()
            .descend()
            .unwrap()
            .descend()
            .unwrap();
        assert_eq!(g3.depth(), 3);
        assert!(g3.descend().is_err());
    }

    #[test]
    fn zero_cap_blocks_immediately() {
        let g = ArchiveDepthGuard::with_max(0);
        let err = g.descend().expect_err("must trip");
        assert_eq!(err.depth, 1);
        assert_eq!(err.max_depth, 0);
    }
}
