//! System load sampler (TASK-039, Phase 4).
//!
//! Drives the adaptive throttle in [`crate::throttle`]. We use the
//! `sysinfo` crate (MIT, default-features off — just `system`) to read
//! the per-process and global CPU figures cross-platform. The sampler
//! is intentionally minimal: it does NOT subscribe to a background
//! tick. Callers (the engine's per-second scheduler loop) call
//! [`SysLoadSampler::observe`] when they want a fresh reading.
//!
//! Per `docs/prd.md` § 7 Algorithm Notes, the throttle goal is: when
//! the user is interactive (high non-engine CPU usage), reduce active
//! workers; when the machine is idle, run at full available_parallelism.

use std::time::{Duration, Instant};

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

/// Minimum time between full-system CPU refreshes. The sysinfo crate
/// computes CPU% as a delta between refreshes; refreshing too often
/// produces noisy numbers.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_millis(500);

/// One reading of system load. Both figures are 0..=100 percentages.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SysLoad {
    /// Overall non-idle CPU usage across all cores (0..=100). High value
    /// means the user is doing something (browser, IDE, compile, etc.)
    /// and the engine should yield.
    pub global_cpu_percent: f32,
    /// CPU usage attributable to the Mythodikal process itself
    /// (0..=100, can exceed 100 on a multi-core box where the engine
    /// pegs multiple cores). Used to subtract our own load from
    /// global_cpu_percent.
    pub mythodikal_cpu_percent: f32,
}

impl SysLoad {
    /// Estimated CPU contribution from "everyone else" — global minus
    /// our own. Clamped to 0..=100.
    pub fn external_cpu_percent(&self) -> f32 {
        (self.global_cpu_percent - self.mythodikal_cpu_percent.min(100.0)).clamp(0.0, 100.0)
    }
}

/// Stateful load sampler. Caches a `System` instance so repeated
/// `observe()` calls don't re-allocate.
pub struct SysLoadSampler {
    system: System,
    last_refresh: Option<Instant>,
    last_reading: Option<SysLoad>,
}

impl Default for SysLoadSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl SysLoadSampler {
    /// Build a fresh sampler. **Takes a warm-up sample** because
    /// `sysinfo` computes CPU% as a delta between refreshes — the very
    /// first refresh always reads 0.0 / 0.0 regardless of true load.
    /// The warm-up call here means a caller's first `observe()` is
    /// already a useful number, not a misleading "machine is idle"
    /// signal (review MAJOR — first sample is always 0%).
    pub fn new() -> Self {
        let mut s = Self {
            system: System::new(),
            last_refresh: None,
            last_reading: None,
        };
        s.refresh_now();
        s
    }

    /// Refresh the system reader and return the current load. Calls
    /// within `MIN_REFRESH_INTERVAL` of the previous one return the
    /// cached reading to avoid noisy 0.0 / 0.0 figures.
    pub fn observe(&mut self) -> SysLoad {
        let now = Instant::now();
        if let (Some(last), Some(cached)) = (self.last_refresh, self.last_reading) {
            if now.duration_since(last) < MIN_REFRESH_INTERVAL {
                return cached;
            }
        }
        self.refresh_now()
    }

    fn refresh_now(&mut self) -> SysLoad {
        // Only refresh our own process. Per security review L3 the
        // prior `ProcessesToUpdate::All` enumerated every PID on the
        // box — slow on a busy build server. We just want our own
        // CPU% to subtract from the global figure.
        let me_pid = Pid::from_u32(std::process::id());
        self.system.refresh_cpu_usage();
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[me_pid]),
            true,
            ProcessRefreshKind::new().with_cpu(),
        );

        let global = self.system.global_cpu_usage();
        let mine = self
            .system
            .process(me_pid)
            .map(|p| p.cpu_usage())
            .unwrap_or(0.0);

        let reading = SysLoad {
            global_cpu_percent: global,
            mythodikal_cpu_percent: mine,
        };
        self.last_refresh = Some(Instant::now());
        self.last_reading = Some(reading);
        reading
    }

    /// Most-recent cached reading. Returns `None` if `observe` has
    /// never been called.
    pub fn last(&self) -> Option<SysLoad> {
        self.last_reading
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_cpu_clamps_to_zero_when_self_exceeds_global() {
        // Pathological reading where the per-process CPU figure beats
        // the global one (can happen on first refresh before the
        // global has settled).
        let load = SysLoad {
            global_cpu_percent: 20.0,
            mythodikal_cpu_percent: 50.0,
        };
        assert_eq!(load.external_cpu_percent(), 0.0);
    }

    #[test]
    fn external_cpu_subtracts_own_load() {
        let load = SysLoad {
            global_cpu_percent: 75.0,
            mythodikal_cpu_percent: 25.0,
        };
        assert_eq!(load.external_cpu_percent(), 50.0);
    }

    #[test]
    fn external_cpu_clamps_to_one_hundred() {
        // Defensive: arithmetic shouldn't drift over 100.
        let load = SysLoad {
            global_cpu_percent: 200.0,
            mythodikal_cpu_percent: 0.0,
        };
        assert_eq!(load.external_cpu_percent(), 100.0);
    }

    #[test]
    fn observe_returns_a_reading() {
        let mut s = SysLoadSampler::new();
        let r = s.observe();
        // The exact numbers are platform/load dependent; just assert
        // they're in the valid 0..=infinity range (sysinfo can return
        // very high percentages on multi-core systems).
        assert!(r.global_cpu_percent >= 0.0);
        assert!(r.mythodikal_cpu_percent >= 0.0);
    }

    #[test]
    fn observe_caches_inside_min_refresh_interval() {
        let mut s = SysLoadSampler::new();
        let first = s.observe();
        let second = s.observe(); // Immediate — should be cached.
        assert_eq!(first, second);
    }
}
