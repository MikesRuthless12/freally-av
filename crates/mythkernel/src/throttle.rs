//! Static concurrency throttle.
//!
//! TASK-013 (Phase 1) — fixed worker count, no adaptive feedback. The
//! adaptive CPU/IO throttle that watches system load and lowers worker count
//! when the user is interactive lands in TASK-039 (Phase 4); this struct is
//! the minimum surface every backend can rely on until then.

use serde::{Deserialize, Serialize};

/// Static throttle configuration. Default = `available_parallelism / 2`,
/// minimum 1, so a quad-core box scans with 2 workers and a 16-core box
/// scans with 8.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Throttle {
    pub max_workers: usize,
}

impl Default for Throttle {
    fn default() -> Self {
        let par = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2);
        Self {
            max_workers: (par / 2).max(1),
        }
    }
}

impl Throttle {
    /// Construct a throttle with an explicit worker count (useful for tests
    /// and the upcoming `--workers N` CLI flag).
    pub fn with_workers(n: usize) -> Self {
        Self {
            max_workers: n.max(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_at_least_one() {
        assert!(Throttle::default().max_workers >= 1);
    }

    #[test]
    fn explicit_zero_clamped_to_one() {
        assert_eq!(Throttle::with_workers(0).max_workers, 1);
    }
}
