//! TASK-226 — Statistical anomaly engine (per-machine prior).
//!
//! Builds a per-machine Bayes prior over the file population this
//! machine has been seen scanning. At scan time, we ask "how surprising
//! is this row compared to the baseline?" and surface the answer as
//! a confidence *bump*, not a standalone finding.
//!
//! Cell-key: `(extension, size_decile, entropy_bucket, hardening_score)`.
//! Each cell carries a count of clean files seen with that profile;
//! a row whose cell has zero (or extremely rare) prior bumps
//! confidence.
//!
//! Cold-start gate: < 10 prior clean scans → engine returns `None`
//! (anomaly engine disabled). Avoids noisy bumps before the prior
//! has any statistical power.

use crate::store::baseline::CellKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// One scan row's feature vector. Keeps the anomaly engine
/// independent of `findings.rs` types — the engine adapter feeds
/// this from whatever shape it has.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScanRow {
    pub extension: String,
    /// 1..=10. Computed as `floor(log2(size_in_kib + 1) / 2)` (capped
    /// at 10) so empty files → 1, 1 GiB → 10, with monotonic bucketing
    /// in between.
    pub size_decile: u8,
    /// 0..=7. `floor(shannon_entropy(file) * 8 / 8)` — entropy is
    /// bucketed at 1.0-unit granularity since the heatmap from
    /// TASK-225 already quantises in 1.0 units per window.
    pub entropy_bucket: u8,
    /// 0..=4 from TASK-224 ELF hardening score (Linux); other OSes
    /// stub to 0.
    pub hardening_score: u8,
}

impl ScanRow {
    /// Convert to the canonical [`CellKey`] used by the persistence
    /// layer. Lowercases the extension so the in-memory baseline
    /// agrees with the SQLite baseline (`store::baseline` normalises
    /// extensions in `encode()`).
    fn to_cell_key(&self) -> CellKey {
        CellKey {
            extension: self.extension.to_ascii_lowercase(),
            size_decile: self.size_decile,
            entropy_bucket: self.entropy_bucket,
            hardening_score: self.hardening_score,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyScore {
    /// Cell is well-represented in the baseline. No confidence bump.
    Normal,
    /// Cell is rare in the baseline (< 5 prior observations).
    /// Surface as a *bump* on any other finding for the same file.
    Bump { cell_count: u64 },
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    /// Number of clean scans whose verdicts have been folded into
    /// this prior. Cold-start gate fires when below
    /// [`Self::MIN_PRIOR_SCANS`].
    pub scans_observed: u64,
    /// (cell, count) entries.
    ///
    /// **Important persistence contract:** This in-memory copy is
    /// only authoritative for the lifetime of one engine process. On
    /// process restart, [`crate::store::baseline`] is the source of
    /// truth — call [`Self::rehydrate_from`] to refill the RAM
    /// counts + `scans_observed` from SQLite at scan-engine startup
    /// before any `score()` call.
    ///
    /// `serde(skip)` because `CellKey`'s composite shape is awkward
    /// to round-trip through JSON and SQLite is the cross-restart
    /// authority anyway.
    #[serde(skip)]
    counts: HashMap<CellKey, u64>,
}

impl Anomaly {
    /// Minimum prior clean scans before the engine returns scores.
    pub const MIN_PRIOR_SCANS: u64 = 10;
    /// Cell-count threshold below which a row is flagged.
    pub const RARE_CELL_THRESHOLD: u64 = 5;

    pub fn new() -> Self {
        Self::default()
    }

    /// Fold a batch of clean-scan rows into the prior. Caller invokes
    /// once per finished clean scan (or set of rows when a scan's
    /// clean-only verdict closes out).
    pub fn update_prior(&mut self, rows: &[ScanRow]) {
        for row in rows {
            *self.counts.entry(row.to_cell_key()).or_insert(0) += 1;
        }
        self.scans_observed += 1;
    }

    /// Score a single row. Returns `None` while the prior is still
    /// in cold-start mode (< MIN_PRIOR_SCANS scans observed).
    pub fn score(&self, row: &ScanRow) -> Option<AnomalyScore> {
        if self.scans_observed < Self::MIN_PRIOR_SCANS {
            return None;
        }
        let key = row.to_cell_key();
        let count = self.counts.get(&key).copied().unwrap_or(0);
        if count < Self::RARE_CELL_THRESHOLD {
            Some(AnomalyScore::Bump { cell_count: count })
        } else {
            Some(AnomalyScore::Normal)
        }
    }

    /// Number of distinct `(extension, size_decile, entropy_bucket,
    /// hardening_score)` cells observed so far. Useful for telemetry +
    /// settings UI ("baseline contains 8.4k cells").
    pub fn cell_count(&self) -> usize {
        self.counts.len()
    }

    /// Reset the prior (e.g. on epoch advance per TASK-202 invalidation).
    pub fn reset(&mut self) {
        self.counts.clear();
        self.scans_observed = 0;
    }

    /// Rehydrate the in-memory map from a `(CellKey, count)` iterator.
    /// The caller (engine startup) reads from
    /// [`crate::store::baseline`] and pipes the rows in. `scans_observed`
    /// is supplied separately because the baseline table doesn't
    /// store the per-scan timestamp — engine persists that counter
    /// in `meta` or a parallel small table.
    pub fn rehydrate_from(
        &mut self,
        rows: impl IntoIterator<Item = (CellKey, u64)>,
        scans_observed: u64,
    ) {
        self.counts.clear();
        for (k, v) in rows {
            self.counts.insert(k, v);
        }
        self.scans_observed = scans_observed;
    }
}

/// Bucket helpers — the engine adapter uses these so every layer that
/// produces a `ScanRow` (live scan, persistence import) bucketises
/// identically.
pub fn size_decile_for_bytes(size: u64) -> u8 {
    if size == 0 {
        return 1;
    }
    let kib = (size as f64 / 1024.0) + 1.0;
    let bucket = (kib.log2() / 2.0).floor() as u32;
    bucket.clamp(1, 10) as u8
}

pub fn entropy_bucket_for(entropy: f32) -> u8 {
    let b = entropy.floor() as i32;
    b.clamp(0, 7) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(ext: &str, size: u8, entropy: u8, hard: u8) -> ScanRow {
        ScanRow {
            extension: ext.into(),
            size_decile: size,
            entropy_bucket: entropy,
            hardening_score: hard,
        }
    }

    #[test]
    fn cold_start_returns_none() {
        let mut a = Anomaly::new();
        for _ in 0..9 {
            a.update_prior(&[row("exe", 3, 5, 3)]);
        }
        assert!(a.score(&row("exe", 3, 5, 3)).is_none());
    }

    #[test]
    fn warm_baseline_scores_common_as_normal() {
        let mut a = Anomaly::new();
        for _ in 0..20 {
            a.update_prior(&[row("exe", 3, 5, 3)]);
        }
        assert_eq!(a.score(&row("exe", 3, 5, 3)), Some(AnomalyScore::Normal));
    }

    #[test]
    fn warm_baseline_scores_rare_as_bump() {
        let mut a = Anomaly::new();
        // 20 scans observed (well above MIN_PRIOR_SCANS) but only
        // one observation of the rare cell.
        for _ in 0..20 {
            a.update_prior(&[row("exe", 3, 5, 3)]);
        }
        a.update_prior(&[row("scr", 9, 7, 0)]);
        match a.score(&row("scr", 9, 7, 0)) {
            Some(AnomalyScore::Bump { cell_count: 1 }) => {}
            other => panic!("expected Bump{{1}}, got {other:?}"),
        }
    }

    #[test]
    fn zero_count_cell_is_bump_too() {
        let mut a = Anomaly::new();
        for _ in 0..20 {
            a.update_prior(&[row("exe", 3, 5, 3)]);
        }
        match a.score(&row("hot_new_ext", 2, 1, 0)) {
            Some(AnomalyScore::Bump { cell_count: 0 }) => {}
            other => panic!("expected Bump{{0}}, got {other:?}"),
        }
    }

    #[test]
    fn reset_clears_baseline() {
        let mut a = Anomaly::new();
        for _ in 0..20 {
            a.update_prior(&[row("exe", 3, 5, 3)]);
        }
        a.reset();
        assert_eq!(a.scans_observed, 0);
        assert_eq!(a.cell_count(), 0);
        assert!(a.score(&row("exe", 3, 5, 3)).is_none());
    }

    #[test]
    fn cell_count_grows_with_distinct_cells() {
        let mut a = Anomaly::new();
        a.update_prior(&[
            row("exe", 3, 5, 3),
            row("dll", 4, 6, 3),
            row("exe", 3, 5, 3), // dup → no new cell
        ]);
        assert_eq!(a.cell_count(), 2);
    }

    #[test]
    fn size_decile_bucket_known_anchors() {
        assert_eq!(size_decile_for_bytes(0), 1);
        assert!(size_decile_for_bytes(1024) >= 1);
        assert!(size_decile_for_bytes(1024 * 1024 * 1024) >= 5);
        // Bucket is monotonic non-decreasing.
        let mut prev = 0u8;
        for size in [
            0,
            1,
            1024,
            10 * 1024,
            100 * 1024,
            1024 * 1024,
            10 * 1024 * 1024,
            100 * 1024 * 1024,
            1024 * 1024 * 1024,
        ] {
            let b = size_decile_for_bytes(size);
            assert!(b >= prev, "size {size} bucket {b} regressed from {prev}");
            prev = b;
        }
    }

    #[test]
    fn entropy_bucket_clamps_to_7() {
        assert_eq!(entropy_bucket_for(0.0), 0);
        assert_eq!(entropy_bucket_for(3.5), 3);
        assert_eq!(entropy_bucket_for(7.9), 7);
        assert_eq!(entropy_bucket_for(8.5), 7); // clamp
        assert_eq!(entropy_bucket_for(-1.0), 0); // clamp
    }

    #[test]
    fn update_prior_with_empty_batch_still_increments_scans() {
        let mut a = Anomaly::new();
        a.update_prior(&[]);
        assert_eq!(a.scans_observed, 1);
    }

    #[test]
    fn rehydrate_replaces_in_memory_state_from_sqlite_rows() {
        let mut a = Anomaly::new();
        // Mid-process state: a single observation.
        a.update_prior(&[row("foo", 1, 1, 0)]);
        // Pretend SQLite has 50 historical scans + a busy "exe/3/5/3" cell.
        let rows = vec![(
            CellKey {
                extension: "exe".into(),
                size_decile: 3,
                entropy_bucket: 5,
                hardening_score: 3,
            },
            42,
        )];
        a.rehydrate_from(rows, 50);
        // The "foo/1/1/0" mid-process observation is gone — rehydrate
        // is a replace, not a merge.
        assert_eq!(a.scans_observed, 50);
        assert_eq!(a.cell_count(), 1);
        // Warm enough now → score returns Some.
        assert_eq!(a.score(&row("exe", 3, 5, 3)), Some(AnomalyScore::Normal));
    }

    #[test]
    fn in_memory_baseline_uses_lowercased_extension_matching_sqlite() {
        // Update with uppercase extension; lookup with lowercase
        // should still hit the same cell since the SQLite path
        // canonicalises to lowercase in CellKey::encode().
        let mut a = Anomaly::new();
        for _ in 0..15 {
            a.update_prior(&[row("EXE", 3, 5, 3)]);
        }
        assert_eq!(a.score(&row("exe", 3, 5, 3)), Some(AnomalyScore::Normal));
    }

    #[test]
    fn baseline_serde_serializable() {
        let mut a = Anomaly::new();
        a.update_prior(&[row("exe", 3, 5, 3)]);
        let _ = serde_json::to_string(&a).unwrap();
    }
}
