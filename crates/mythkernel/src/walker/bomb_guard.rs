//! TASK-233 — Archive bomb guard (cancellable expansion).
//!
//! Tracks two budgets during archive recursion: cumulative
//! decompressed bytes + recursion depth. Either crossing its limit
//! aborts further expansion with a structured error the caller
//! surfaces as a finding. Decoupled from any specific archive
//! library — the format-specific expander (zip / tar / 7z) calls
//! `BombGuard::observe_entry` per emitted entry; the guard does the
//! accounting.
//!
//! Defaults are conservative:
//!   * 1 GiB cumulative decompressed budget per archive.
//!   * Recursion depth 8 (archive-inside-archive-inside-...).
//!   * 1000:1 expansion ratio per entry (entry uncompressed /
//!     compressed). A zip bomb's hallmark is a tiny compressed payload
//!     blowing up to gigabytes.
//!
//! The guard does NOT manage cancellation flag wiring — pass the
//! existing `Arc<AtomicBool> cancel_flag` to the expander; this module
//! is the per-archive resource ceiling.

use std::sync::atomic::{AtomicU64, Ordering};

pub const DEFAULT_MAX_DECOMPRESSED_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB
pub const DEFAULT_MAX_DEPTH: u32 = 8;
pub const DEFAULT_MAX_EXPANSION_RATIO: u64 = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BombGuardError {
    /// Cumulative decompressed bytes exceeded the per-archive budget.
    DecompressedTooLarge { observed: u64, limit: u64 },
    /// Nested archive depth exceeded the configured maximum.
    DepthExceeded { observed: u32, limit: u32 },
    /// A single entry's expansion ratio crossed the per-entry limit.
    /// (uncompressed_bytes / compressed_bytes > limit). Catches the
    /// classic zip-bomb where a small file decompresses to gigabytes.
    EntryRatioExceeded {
        compressed: u64,
        uncompressed: u64,
        ratio_observed: u64,
        ratio_limit: u64,
    },
}

#[derive(Debug)]
pub struct BombGuard {
    max_decompressed: u64,
    max_depth: u32,
    max_ratio: u64,
    decompressed_total: AtomicU64,
    depth: AtomicU64,
}

impl BombGuard {
    pub fn new() -> Self {
        Self::with_limits(
            DEFAULT_MAX_DECOMPRESSED_BYTES,
            DEFAULT_MAX_DEPTH,
            DEFAULT_MAX_EXPANSION_RATIO,
        )
    }

    pub fn with_limits(max_decompressed: u64, max_depth: u32, max_ratio: u64) -> Self {
        Self {
            max_decompressed,
            max_depth,
            max_ratio,
            decompressed_total: AtomicU64::new(0),
            depth: AtomicU64::new(0),
        }
    }

    /// Account one entry's compressed + uncompressed sizes. Returns an
    /// error if any budget would be exceeded by this entry; the caller
    /// must abort expansion on Err. On Ok the cumulative counter is
    /// bumped.
    pub fn observe_entry(&self, compressed: u64, uncompressed: u64) -> Result<(), BombGuardError> {
        // Per-entry ratio check first — cheapest and catches the
        // classic zip bomb without needing the cumulative state.
        if compressed > 0 {
            let ratio = uncompressed / compressed;
            if ratio > self.max_ratio {
                return Err(BombGuardError::EntryRatioExceeded {
                    compressed,
                    uncompressed,
                    ratio_observed: ratio,
                    ratio_limit: self.max_ratio,
                });
            }
        }
        // Cumulative.
        let new_total = self
            .decompressed_total
            .load(Ordering::Relaxed)
            .saturating_add(uncompressed);
        if new_total > self.max_decompressed {
            return Err(BombGuardError::DecompressedTooLarge {
                observed: new_total,
                limit: self.max_decompressed,
            });
        }
        self.decompressed_total.store(new_total, Ordering::Relaxed);
        Ok(())
    }

    /// Open a nested archive. Returns `DepthExceeded` if entering
    /// would cross the configured depth limit. Pair with [`Self::pop`]
    /// when the nested archive finishes.
    pub fn push(&self) -> Result<(), BombGuardError> {
        let prior = self.depth.fetch_add(1, Ordering::Relaxed);
        let depth = prior + 1;
        if depth > self.max_depth as u64 {
            // Roll back so we don't leave the counter inflated.
            self.depth.fetch_sub(1, Ordering::Relaxed);
            return Err(BombGuardError::DepthExceeded {
                observed: depth as u32,
                limit: self.max_depth,
            });
        }
        Ok(())
    }

    pub fn pop(&self) {
        let prior = self.depth.load(Ordering::Relaxed);
        if prior > 0 {
            self.depth.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn current_depth(&self) -> u32 {
        self.depth.load(Ordering::Relaxed) as u32
    }

    pub fn decompressed_total(&self) -> u64 {
        self.decompressed_total.load(Ordering::Relaxed)
    }
}

impl Default for BombGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_limits_accepts_entries() {
        let g = BombGuard::with_limits(1024, 4, 100);
        assert!(g.observe_entry(10, 100).is_ok());
        assert!(g.observe_entry(20, 200).is_ok());
        assert_eq!(g.decompressed_total(), 300);
    }

    #[test]
    fn cumulative_over_budget_rejects() {
        let g = BombGuard::with_limits(500, 4, 100);
        g.observe_entry(10, 400).unwrap();
        let err = g.observe_entry(10, 200).unwrap_err();
        assert!(matches!(
            err,
            BombGuardError::DecompressedTooLarge {
                observed: 600,
                limit: 500,
            }
        ));
    }

    #[test]
    fn zip_bomb_ratio_rejected() {
        let g = BombGuard::with_limits(u64::MAX, 4, 100);
        // 1 byte compressed → 1 MiB uncompressed = ratio 1_048_576.
        let err = g.observe_entry(1, 1024 * 1024).unwrap_err();
        assert!(matches!(
            err,
            BombGuardError::EntryRatioExceeded {
                ratio_observed: 1_048_576,
                ratio_limit: 100,
                ..
            }
        ));
    }

    #[test]
    fn push_pop_depth_tracking() {
        let g = BombGuard::with_limits(u64::MAX, 3, 1_000_000);
        g.push().unwrap(); // depth 1
        g.push().unwrap(); // 2
        g.push().unwrap(); // 3
        let err = g.push().unwrap_err(); // 4 — over
        assert!(matches!(
            err,
            BombGuardError::DepthExceeded {
                observed: 4,
                limit: 3,
            }
        ));
        // Depth rolled back.
        assert_eq!(g.current_depth(), 3);
        g.pop();
        assert_eq!(g.current_depth(), 2);
    }

    #[test]
    fn pop_on_empty_is_noop() {
        let g = BombGuard::new();
        g.pop();
        g.pop();
        assert_eq!(g.current_depth(), 0);
    }

    #[test]
    fn zero_compressed_entry_skips_ratio_check() {
        // Some formats record 0 compressed bytes for stored (no-
        // compression) entries; avoid divide-by-zero + don't treat
        // those as bombs.
        let g = BombGuard::with_limits(u64::MAX, 4, 100);
        assert!(g.observe_entry(0, 200).is_ok());
    }
}
