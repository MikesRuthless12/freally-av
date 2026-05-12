//! Calibrated ETA estimator (TASK-038, Phase 4).
//!
//! Per `docs/prd.md` § 7 and `docs/product-vision.md` § 3.3, the engine's
//! ETA must be **monotone-non-increasing after the first 3% of work**.
//! Naïve rate-of-progress estimates yo-yo wildly on heterogeneous data
//! (a directory of 4 KB JSON followed by a 10 GB ISO blows up the
//! seconds-remaining number); we use an exponential moving average over
//! recent throughput samples and hold the displayed value below any new
//! upward swing post-baseline.
//!
//! The estimator is **bytes-aware** when total bytes are known (TASK-137
//! locks them in Phase 5+ via the enumeration pass); until then it falls
//! back to a file-count rate.

use std::time::Instant;

/// Smoothing factor for the EMA. 0.2 → ~5-sample memory; quick enough to
/// react to genuine slowdowns, slow enough that one outlier file doesn't
/// dominate.
const EMA_ALPHA: f64 = 0.2;

/// Fraction of total work that has to complete before the monotone-non-
/// increasing constraint kicks in. Below this, the ETA can swing freely
/// (we don't have enough samples yet to claim a stable estimate).
const BASELINE_FRACTION: f64 = 0.03;

/// One progress sample fed to the estimator.
#[derive(Debug, Clone, Copy)]
pub struct Progress {
    /// Files processed so far (X). Monotone non-decreasing.
    pub files_done: u64,
    /// Total files target. `None` if enumeration hasn't locked Y yet
    /// (FR-135 — Phase 5 TASK-137 supplies the running value).
    pub files_total: Option<u64>,
    /// Bytes processed so far. Monotone non-decreasing.
    pub bytes_done: u64,
    /// Total bytes target. `None` while enumeration is still running
    /// or when the engine is in unknown-total mode.
    pub bytes_total: Option<u64>,
    /// Monotonic clock reading at sample time.
    pub now: Instant,
}

/// EMA-smoothed ETA with the post-baseline monotone-non-increasing clamp.
#[derive(Debug, Clone)]
pub struct EtaEstimator {
    started: Option<Instant>,
    last_sample: Option<Progress>,
    /// EMA of "bytes per second" (or "files per second" when bytes are unknown).
    rate_ema: Option<f64>,
    /// Last ETA we *emitted* — the monotone clamp ratchets this down.
    last_eta_secs: Option<f64>,
    /// True once `files_done / files_total` has crossed the baseline.
    past_baseline: bool,
}

impl Default for EtaEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl EtaEstimator {
    pub fn new() -> Self {
        Self {
            started: None,
            last_sample: None,
            rate_ema: None,
            last_eta_secs: None,
            past_baseline: false,
        }
    }

    /// Reset the estimator (call between scans).
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Feed one progress sample. Returns the **displayed** ETA in
    /// seconds, post-clamp. Returns `None` until enough samples have
    /// accumulated to produce a stable estimate (the very first sample,
    /// or any sample with a zero-elapsed delta).
    pub fn observe(&mut self, sample: Progress) -> Option<f64> {
        let started = *self.started.get_or_insert(sample.now);

        // Compute the rate of progress since the last sample. Prefer
        // bytes if both ends know the totals; fall back to file count.
        let prev = self.last_sample.replace(sample);
        let Some(prev) = prev else {
            // First sample — nothing to compare against yet.
            return None;
        };
        let dt = sample.now.duration_since(prev.now).as_secs_f64();
        if dt <= 0.0 {
            // Same instant; skip.
            return self.last_eta_secs;
        }

        let (delta, remaining) =
            if let (Some(bt), true) = (sample.bytes_total, sample.bytes_total.is_some()) {
                let delta = (sample.bytes_done as f64) - (prev.bytes_done as f64);
                let remaining = (bt.saturating_sub(sample.bytes_done)) as f64;
                (delta, remaining)
            } else if let Some(ft) = sample.files_total {
                let delta = (sample.files_done as f64) - (prev.files_done as f64);
                let remaining = (ft.saturating_sub(sample.files_done)) as f64;
                (delta, remaining)
            } else {
                // No total yet; can't form an ETA.
                return None;
            };

        if delta <= 0.0 || remaining <= 0.0 {
            return self.last_eta_secs;
        }

        let instant_rate = delta / dt;
        let smoothed = match self.rate_ema {
            None => instant_rate,
            Some(prev_ema) => EMA_ALPHA * instant_rate + (1.0 - EMA_ALPHA) * prev_ema,
        };
        self.rate_ema = Some(smoothed);

        if smoothed <= 0.0 {
            return self.last_eta_secs;
        }

        let raw_eta = remaining / smoothed;

        // Update past_baseline flag once we cross the 3% threshold on
        // *files* (the bytes denominator can be wildly imbalanced — a
        // single 10 GB file would push bytes_done past 50% on the first
        // hash). Files are a fairer "amount of work" proxy.
        if let Some(ft) = sample.files_total {
            if (sample.files_done as f64) >= (ft as f64) * BASELINE_FRACTION {
                self.past_baseline = true;
            }
        }

        let elapsed = sample.now.duration_since(started).as_secs_f64();
        let _ = elapsed; // reserved for future calibration warm-up logic.

        let final_eta = if self.past_baseline {
            // Monotone-non-increasing clamp: never let the displayed ETA
            // increase post-baseline. If the raw EMA-derived ETA wants
            // to go up (slower files, larger files), we hold the
            // previous value until the new estimate catches down to it.
            match self.last_eta_secs {
                None => raw_eta,
                Some(prev_displayed) if raw_eta > prev_displayed => prev_displayed,
                Some(_) => raw_eta,
            }
        } else {
            raw_eta
        };

        self.last_eta_secs = Some(final_eta);
        Some(final_eta)
    }

    /// Currently-displayed ETA (the last value returned by [`observe`]).
    pub fn current(&self) -> Option<f64> {
        self.last_eta_secs
    }

    /// Whether the estimator has crossed the 3% baseline. Useful for
    /// labelling the UI ("ETA calibrating…" vs the numeric form).
    pub fn past_baseline(&self) -> bool {
        self.past_baseline
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_progress(
        files_done: u64,
        files_total: u64,
        bytes_done: u64,
        bytes_total: u64,
        now: Instant,
    ) -> Progress {
        Progress {
            files_done,
            files_total: Some(files_total),
            bytes_done,
            bytes_total: Some(bytes_total),
            now,
        }
    }

    #[test]
    fn first_sample_returns_none() {
        let mut e = EtaEstimator::new();
        let t0 = Instant::now();
        let result = e.observe(make_progress(10, 1000, 0, 0, t0));
        assert!(result.is_none());
    }

    #[test]
    fn produces_an_eta_after_two_samples_at_steady_rate() {
        let mut e = EtaEstimator::new();
        let t0 = Instant::now();
        e.observe(make_progress(10, 1000, 10_000, 1_000_000, t0));
        let result = e
            .observe(make_progress(
                110,
                1000,
                110_000,
                1_000_000,
                t0 + Duration::from_secs(1),
            ))
            .expect("eta after second sample");
        // Steady 100 files/s rate over 100 KB increments → 1_000_000 - 110_000 = 890_000 bytes / 100_000 bytes/s = ~8.9s
        // (we use byte rate when both bytes totals are known)
        assert!(result > 5.0 && result < 15.0, "got {result}");
    }

    #[test]
    fn monotone_non_increasing_after_baseline() {
        // Force "past baseline" by exceeding 3% of files, then feed a
        // slowdown sample. The displayed ETA must NOT swing upward.
        let mut e = EtaEstimator::new();
        let t0 = Instant::now();
        // Sample 1: 40/1000 files = 4% (past baseline)
        e.observe(make_progress(40, 1000, 40_000, 1_000_000, t0));
        // Sample 2: 80/1000 files at a fast steady rate
        let eta1 = e
            .observe(make_progress(
                80,
                1000,
                80_000,
                1_000_000,
                t0 + Duration::from_secs(1),
            ))
            .expect("eta1");
        assert!(e.past_baseline());

        // Sample 3: slow down dramatically — only +10 files in 5s.
        // The raw rate would say "ETA huge"; the clamp must hold it at ≤ eta1.
        let eta2 = e
            .observe(make_progress(
                90,
                1000,
                90_000,
                1_000_000,
                t0 + Duration::from_secs(6),
            ))
            .expect("eta2");
        assert!(
            eta2 <= eta1 + f64::EPSILON,
            "post-baseline ETA must not climb: {eta1} -> {eta2}"
        );
    }

    #[test]
    fn no_clamp_before_baseline() {
        // Below the 3% threshold the estimator can swing freely — this
        // is the "calibrating…" window.
        let mut e = EtaEstimator::new();
        let t0 = Instant::now();
        // 5 / 1000 = 0.5% (well below 3%)
        e.observe(make_progress(2, 1000, 2_000, 1_000_000, t0));
        let _ = e.observe(make_progress(
            5,
            1000,
            5_000,
            1_000_000,
            t0 + Duration::from_secs(1),
        ));
        assert!(!e.past_baseline());
    }

    #[test]
    fn handles_unknown_total_by_returning_none() {
        let mut e = EtaEstimator::new();
        let t0 = Instant::now();
        let r = e.observe(Progress {
            files_done: 10,
            files_total: None,
            bytes_done: 1000,
            bytes_total: None,
            now: t0,
        });
        assert!(r.is_none());
        let r = e.observe(Progress {
            files_done: 20,
            files_total: None,
            bytes_done: 2000,
            bytes_total: None,
            now: t0 + Duration::from_secs(1),
        });
        assert!(r.is_none());
    }

    #[test]
    fn falls_back_to_file_rate_when_bytes_total_unknown() {
        let mut e = EtaEstimator::new();
        let t0 = Instant::now();
        let p1 = Progress {
            files_done: 10,
            files_total: Some(1000),
            bytes_done: 0,
            bytes_total: None,
            now: t0,
        };
        e.observe(p1);
        let p2 = Progress {
            files_done: 110,
            files_total: Some(1000),
            bytes_done: 0,
            bytes_total: None,
            now: t0 + Duration::from_secs(1),
        };
        let eta = e.observe(p2).expect("eta with file-rate fallback");
        // 100 files/s, 890 remaining → ~8.9s
        assert!(eta > 6.0 && eta < 12.0, "got {eta}");
    }

    #[test]
    fn reset_clears_state() {
        let mut e = EtaEstimator::new();
        let t0 = Instant::now();
        e.observe(make_progress(40, 1000, 40_000, 1_000_000, t0));
        e.observe(make_progress(
            80,
            1000,
            80_000,
            1_000_000,
            t0 + Duration::from_secs(1),
        ));
        assert!(e.past_baseline());
        e.reset();
        assert!(!e.past_baseline());
        assert!(e.current().is_none());
    }

    #[test]
    fn duplicate_sample_does_not_advance() {
        let mut e = EtaEstimator::new();
        let t0 = Instant::now();
        e.observe(make_progress(10, 1000, 10_000, 1_000_000, t0));
        let first = e.observe(make_progress(
            110,
            1000,
            110_000,
            1_000_000,
            t0 + Duration::from_secs(1),
        ));
        // Same instant again — function must not divide by zero or
        // skew the EMA. It returns the previous displayed value.
        let second = e.observe(make_progress(
            110,
            1000,
            110_000,
            1_000_000,
            t0 + Duration::from_secs(1),
        ));
        assert_eq!(first, second);
    }
}
