//! Zip-bomb compression-ratio guard (TASK-281).
//!
//! Default policy:
//!
//!   * compressed ≥ 1 KiB **AND**
//!   * uncompressed / compressed ratio > 1_000 **AND**
//!   * uncompressed ≥ 100 MiB
//!
//! Together these rule out the routine "1.5 GB log file compresses
//! to 80 MB at 18×" false positive while catching the canonical
//! 42.zip-style bombs that explode by 10⁴–10⁶ ×. Callers can tune
//! every threshold via [`BombGuardConfig`].

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BombGuardConfig {
    pub min_compressed_bytes: u64,
    pub min_uncompressed_bytes: u64,
    pub max_ratio: u64,
}

impl Default for BombGuardConfig {
    fn default() -> Self {
        Self {
            min_compressed_bytes: 1024,
            min_uncompressed_bytes: 100 * 1024 * 1024,
            max_ratio: 1000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BombFinding {
    pub entry_name: String,
    pub compressed_bytes: u64,
    pub uncompressed_bytes: u64,
    pub ratio: u64,
}

/// Evaluate a single archive entry. Returns `Some(BombFinding)`
/// when the entry trips every limb of the policy and `None`
/// otherwise.
pub fn is_zip_bomb_ratio(
    entry_name: &str,
    compressed: u64,
    uncompressed: u64,
    cfg: &BombGuardConfig,
) -> Option<BombFinding> {
    if compressed < cfg.min_compressed_bytes {
        return None;
    }
    if uncompressed < cfg.min_uncompressed_bytes {
        return None;
    }
    if compressed == 0 {
        return None;
    }
    let ratio = uncompressed.saturating_div(compressed);
    if ratio <= cfg.max_ratio {
        return None;
    }
    Some(BombFinding {
        entry_name: entry_name.to_string(),
        compressed_bytes: compressed,
        uncompressed_bytes: uncompressed,
        ratio,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legit_logfile_18x_ratio_not_flagged() {
        let cfg = BombGuardConfig::default();
        // 1.5 GiB → 80 MiB ≈ 19×.
        let r = is_zip_bomb_ratio("server.log", 80 * 1024 * 1024, 1500 * 1024 * 1024, &cfg);
        assert!(r.is_none());
    }

    #[test]
    fn classic_zip_bomb_is_flagged() {
        let cfg = BombGuardConfig::default();
        // Second-level entry once the outer 42.zip layer is
        // peeled: ~4 KiB compressed -> 4.5 GiB → > 1e6×. Above
        // both the compressed and uncompressed floors.
        let r = is_zip_bomb_ratio("a.zip", 4_096, 4_500_000_000, &cfg);
        let f = r.expect("flagged");
        assert!(f.ratio > 1_000);
    }

    #[test]
    fn small_compressed_below_floor_skipped() {
        let cfg = BombGuardConfig::default();
        // 100 bytes compressed even with absurd ratio is skipped
        // (below the 1 KiB compressed floor).
        let r = is_zip_bomb_ratio("tiny.txt", 100, 200 * 1024 * 1024, &cfg);
        assert!(r.is_none());
    }

    #[test]
    fn below_uncompressed_floor_skipped() {
        let cfg = BombGuardConfig::default();
        // 5 KiB → 5 MiB is 1000× but uncompressed is below 100 MiB.
        let r = is_zip_bomb_ratio("foo.txt", 5 * 1024, 5 * 1024 * 1024, &cfg);
        assert!(r.is_none());
    }

    #[test]
    fn config_overrides_apply() {
        let cfg = BombGuardConfig {
            min_compressed_bytes: 1,
            min_uncompressed_bytes: 1,
            max_ratio: 2,
        };
        let r = is_zip_bomb_ratio("x", 10, 30, &cfg);
        assert!(r.is_some());
    }

    #[test]
    fn ratio_one_thousand_exactly_is_not_flagged() {
        // Threshold uses strict greater-than to give a deterministic boundary.
        let cfg = BombGuardConfig::default();
        let r = is_zip_bomb_ratio(
            "x",
            200 * 1024,
            200 * 1024 * 1000, // exactly 1000×
            &cfg,
        );
        assert!(r.is_none());
    }
}
