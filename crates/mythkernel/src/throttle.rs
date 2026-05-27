//! Concurrency throttle — static baseline + adaptive feedback (TASK-013 + TASK-039).
//!
//! TASK-013 (Phase 1) shipped the static baseline: a fixed `max_workers`
//! count of `available_parallelism / 2`. TASK-039 (Phase 4) adds the
//! [`AdaptiveThrottle`] wrapper that combines that ceiling with a live
//! reading from [`crate::sysload`] to reduce active workers when the
//! user is interactive (background scan must not melt a video call).
//!
//! Per `docs/prd.md` § 7 Algorithm Notes the policy is:
//!
//!   * External CPU < 30 % → run at `max_workers` (idle machine; full speed).
//!   * 30 % ≤ external CPU < 70 % → ramp linearly from `max_workers`
//!     down to `max_workers / 2`.
//!   * External CPU ≥ 70 % → 1 worker (minimum throughput; the user
//!     gets the box back).
//!
//! "External CPU" is the global CPU usage minus the engine's own
//! contribution, so a scan that pegs all cores doesn't keep clamping
//! itself further.

use serde::{Deserialize, Serialize};

use crate::sysload::{SysLoad, SysLoadSampler};

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

/// Adaptive throttle that combines the static `Throttle` ceiling with a
/// live system-load reading to choose how many workers to run *right
/// now*. Cheap to construct; the underlying [`SysLoadSampler`] caches
/// its `System` instance so repeated `current_workers()` calls do not
/// re-allocate.
pub struct AdaptiveThrottle {
    base: Throttle,
    sampler: SysLoadSampler,
}

impl AdaptiveThrottle {
    pub fn new(base: Throttle) -> Self {
        Self {
            base,
            sampler: SysLoadSampler::new(),
        }
    }

    /// Refresh sysload and compute the per-policy worker count. Returns
    /// at least 1.
    pub fn current_workers(&mut self) -> usize {
        let load = self.sampler.observe();
        Self::policy(self.base.max_workers, load)
    }

    /// The pure function that maps `(max_workers, load) -> workers`.
    /// Exposed for unit tests and so callers that already have a load
    /// reading (e.g., the engine's per-second scheduler tick) can
    /// avoid double-sampling.
    pub fn policy(max_workers: usize, load: SysLoad) -> usize {
        let external = load.external_cpu_percent();
        if external < 30.0 {
            max_workers
        } else if external >= 70.0 {
            1
        } else {
            // Linear from max_workers @ 30% down to max_workers/2 @ 70%.
            let span = max_workers as f32 - (max_workers / 2) as f32;
            let t = (external - 30.0) / 40.0; // 0..=1
            let workers = max_workers as f32 - t * span;
            (workers.round() as usize).max(1)
        }
    }

    /// TASK-204 — Same as [`Self::policy`] but applies an additional
    /// downshift when the user's foreground app is interactive. The
    /// caller subscribes to the per-OS foreground watcher
    /// ([`foreground_state`]); when the watcher reports
    /// [`ForegroundState::Interactive`], the worker count is clamped
    /// to `max(1, base/2)` regardless of the CPU-driven policy. Idle
    /// foreground (or no signal) preserves the pure CPU policy.
    pub fn policy_with_foreground(
        max_workers: usize,
        load: SysLoad,
        fg: ForegroundState,
    ) -> usize {
        let cpu_choice = Self::policy(max_workers, load);
        match fg {
            ForegroundState::Idle => cpu_choice,
            ForegroundState::Interactive => {
                let foreground_ceiling = (max_workers / 2).max(1);
                cpu_choice.min(foreground_ceiling)
            }
        }
    }

    /// TASK-204 — Resize the ceiling: useful when the user toggles
    /// `Battery-gentle` mode (TASK-208) or moves the
    /// `Performance → Worker count` slider in Settings. The new
    /// ceiling is clamped to ≥ 1; subsequent `current_workers` calls
    /// reflect it immediately.
    pub fn resize(&mut self, new_max: usize) {
        self.base.max_workers = new_max.max(1);
    }

    pub fn base(&self) -> Throttle {
        self.base
    }

    pub fn last_load(&self) -> Option<SysLoad> {
        self.sampler.last()
    }
}

/// TASK-204 — Foreground-window state. Set by a per-OS watcher; read
/// by the throttle when computing the live worker count. `Idle` is the
/// safe default — when no watcher has reported yet, behave as if the
/// machine has nothing interactive going on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForegroundState {
    /// No foreground change observed (or watcher not yet running).
    Idle,
    /// User just changed window focus → likely interacting; downshift.
    Interactive,
}

/// Process-wide foreground state holder. The per-OS watcher updates it
/// via [`set_foreground_state`]; the throttle reads via
/// [`current_foreground_state`]. Cheap atomic load.
static FOREGROUND_STATE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

pub fn current_foreground_state() -> ForegroundState {
    match FOREGROUND_STATE.load(std::sync::atomic::Ordering::Relaxed) {
        1 => ForegroundState::Interactive,
        _ => ForegroundState::Idle,
    }
}

pub fn set_foreground_state(state: ForegroundState) {
    let val = match state {
        ForegroundState::Idle => 0,
        ForegroundState::Interactive => 1,
    };
    FOREGROUND_STATE.store(val, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(external: f32) -> SysLoad {
        // Build a SysLoad whose external_cpu_percent() equals the
        // requested figure (global - mythodikal = external).
        SysLoad {
            global_cpu_percent: external,
            mythodikal_cpu_percent: 0.0,
        }
    }

    #[test]
    fn default_at_least_one() {
        assert!(Throttle::default().max_workers >= 1);
    }

    #[test]
    fn explicit_zero_clamped_to_one() {
        assert_eq!(Throttle::with_workers(0).max_workers, 1);
    }

    #[test]
    fn idle_machine_runs_at_full_workers() {
        assert_eq!(AdaptiveThrottle::policy(8, load(5.0)), 8);
        assert_eq!(AdaptiveThrottle::policy(8, load(29.9)), 8);
    }

    #[test]
    fn moderate_load_ramps_down_linearly() {
        // At 50% external load we expect halfway between max_workers and
        // max_workers/2 = midpoint of 8 and 4 = 6.
        let workers = AdaptiveThrottle::policy(8, load(50.0));
        assert_eq!(workers, 6);
    }

    #[test]
    fn high_load_drops_to_one() {
        assert_eq!(AdaptiveThrottle::policy(8, load(70.0)), 1);
        assert_eq!(AdaptiveThrottle::policy(8, load(95.0)), 1);
    }

    #[test]
    fn never_returns_zero_workers() {
        for max in 1..=16 {
            for ext in (0..=100).step_by(10) {
                let w = AdaptiveThrottle::policy(max, load(ext as f32));
                assert!(w >= 1, "max={max} ext={ext} -> {w}");
            }
        }
    }

    #[test]
    fn external_cpu_subtracts_own_load_before_policy() {
        // A scan that pegs all cores still reads "global=100%"; the
        // policy must subtract the engine's contribution so it doesn't
        // throttle itself for being busy.
        let scan_pegging = SysLoad {
            global_cpu_percent: 100.0,
            mythodikal_cpu_percent: 90.0,
        };
        assert_eq!(AdaptiveThrottle::policy(8, scan_pegging), 8);
    }

    // TASK-204 — adaptive parallelism + foreground backoff tests.

    #[test]
    fn task_204_foreground_idle_preserves_cpu_policy() {
        assert_eq!(
            AdaptiveThrottle::policy_with_foreground(8, load(5.0), ForegroundState::Idle),
            8
        );
        assert_eq!(
            AdaptiveThrottle::policy_with_foreground(8, load(50.0), ForegroundState::Idle),
            6
        );
    }

    #[test]
    fn task_204_foreground_interactive_clamps_to_half() {
        // Even with idle CPU, an interactive foreground clamps to
        // max(1, base/2).
        assert_eq!(
            AdaptiveThrottle::policy_with_foreground(8, load(5.0), ForegroundState::Interactive),
            4
        );
        // CPU-driven downshift wins when it's tighter than the
        // foreground clamp.
        assert_eq!(
            AdaptiveThrottle::policy_with_foreground(8, load(95.0), ForegroundState::Interactive),
            1
        );
        // Floor at 1 even for tiny base.
        assert_eq!(
            AdaptiveThrottle::policy_with_foreground(1, load(5.0), ForegroundState::Interactive),
            1
        );
    }

    #[test]
    fn task_204_resize_updates_base() {
        let mut t = AdaptiveThrottle::new(Throttle::with_workers(4));
        assert_eq!(t.base().max_workers, 4);
        t.resize(12);
        assert_eq!(t.base().max_workers, 12);
        // Zero clamps to 1.
        t.resize(0);
        assert_eq!(t.base().max_workers, 1);
    }

    #[test]
    fn task_204_foreground_state_atomic_set_get() {
        // Default is Idle.
        set_foreground_state(ForegroundState::Idle);
        assert_eq!(current_foreground_state(), ForegroundState::Idle);
        set_foreground_state(ForegroundState::Interactive);
        assert_eq!(current_foreground_state(), ForegroundState::Interactive);
        // Reset so other tests aren't affected by the shared static.
        set_foreground_state(ForegroundState::Idle);
    }
}
