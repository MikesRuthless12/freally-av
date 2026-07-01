//! TASK-208 — Battery-aware throttle modes.
//!
//! Tri-state preset:
//!
//!   - `AcAggressive` — full throttle ceiling (default). The engine
//!     behaves exactly as before.
//!   - `BatteryGentle` — hasher Semaphore capped at `max(1, num_cpus/4)`
//!     permits, ≤ 25 % one-core CPU budget. Scheduled scans are
//!     deferred until AC.
//!   - `BatteryOff` — full + scheduled scans suspended. Real-time
//!     hooks (TASK-073..) are unaffected — they remain on so the
//!     machine still has on-access protection. Auto-resume when AC
//!     comes back.
//!
//! The "is AC plugged in?" reading comes from
//! `GetSystemPowerStatus` (Windows), `IOPSCopyPowerSourcesInfo`
//! (macOS), `/sys/class/power_supply/*` (Linux). The per-OS poll
//! lives in the daemon; here we own the policy state machine and
//! the worker-count clamp.

use serde::{Deserialize, Serialize};

/// Tri-state preset surfaced in the Settings → Performance UI.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatteryPreset {
    #[default]
    AcAggressive,
    BatteryGentle,
    BatteryOff,
}

/// Latest power-state reading from the OS. Fed into the engine via
/// the daemon → engine `PowerStateChanged` IPC frame at 5 s cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerState {
    pub on_ac: bool,
    /// 0..=100 when available, `None` for desktops with no battery.
    pub battery_pct: Option<u8>,
}

impl PowerState {
    pub fn ac_default() -> Self {
        Self {
            on_ac: true,
            battery_pct: None,
        }
    }
}

/// What the throttle should do right now. Combines the preset + the
/// live power state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanGate {
    /// Run scans at the standard worker count.
    Full,
    /// Run scans at the gentle-budget worker count.
    Gentle,
    /// Pause full / scheduled scans entirely. Real-time hooks
    /// continue.
    Pause,
}

#[derive(Debug, Clone)]
pub struct BatteryThrottle {
    preset: BatteryPreset,
    power: PowerState,
    num_cpus: usize,
}

impl BatteryThrottle {
    pub fn new(num_cpus: usize) -> Self {
        Self {
            preset: BatteryPreset::default(),
            power: PowerState::ac_default(),
            num_cpus: num_cpus.max(1),
        }
    }

    pub fn with_preset(mut self, preset: BatteryPreset) -> Self {
        self.preset = preset;
        self
    }

    pub fn with_power(mut self, power: PowerState) -> Self {
        self.power = power;
        self
    }

    pub fn preset(&self) -> BatteryPreset {
        self.preset
    }

    pub fn power(&self) -> PowerState {
        self.power
    }

    pub fn set_preset(&mut self, preset: BatteryPreset) {
        self.preset = preset;
    }

    pub fn set_power(&mut self, power: PowerState) {
        self.power = power;
    }

    /// Live decision. Cheap; reads only the cached preset + power.
    pub fn gate(&self) -> ScanGate {
        match (self.preset, self.power.on_ac) {
            (BatteryPreset::AcAggressive, _) => ScanGate::Full,
            (BatteryPreset::BatteryGentle, true) => ScanGate::Full,
            (BatteryPreset::BatteryGentle, false) => ScanGate::Gentle,
            (BatteryPreset::BatteryOff, true) => ScanGate::Full,
            (BatteryPreset::BatteryOff, false) => ScanGate::Pause,
        }
    }

    /// Effective worker-count ceiling.
    pub fn effective_workers(&self, base_max: usize) -> usize {
        match self.gate() {
            ScanGate::Full => base_max.max(1),
            ScanGate::Gentle => (self.num_cpus / 4).max(1).min(base_max),
            // Pause keeps a `1` worker slot so the engine can still
            // process IPC + real-time hooks without churning the
            // worker pool's lifecycle. The actual scan loop checks
            // `gate() == Pause` separately and short-circuits.
            ScanGate::Pause => 1,
        }
    }

    /// Whether scheduled scans should fire under the current
    /// preset + power state. Gentle defers; Off suspends.
    pub fn allow_scheduled(&self) -> bool {
        match self.gate() {
            ScanGate::Full => true,
            ScanGate::Gentle | ScanGate::Pause => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ac_aggressive_runs_full_regardless_of_power() {
        let mut t = BatteryThrottle::new(8).with_preset(BatteryPreset::AcAggressive);
        assert_eq!(t.gate(), ScanGate::Full);
        t.set_power(PowerState {
            on_ac: false,
            battery_pct: Some(50),
        });
        assert_eq!(t.gate(), ScanGate::Full);
        assert_eq!(t.effective_workers(8), 8);
        assert!(t.allow_scheduled());
    }

    #[test]
    fn battery_gentle_clamps_to_quarter_cpus_on_battery() {
        let mut t = BatteryThrottle::new(8).with_preset(BatteryPreset::BatteryGentle);
        t.set_power(PowerState {
            on_ac: false,
            battery_pct: Some(80),
        });
        assert_eq!(t.gate(), ScanGate::Gentle);
        assert_eq!(t.effective_workers(8), 2); // 8/4
        // Floor at 1 for tiny cores.
        let small = BatteryThrottle::new(2)
            .with_preset(BatteryPreset::BatteryGentle)
            .with_power(PowerState {
                on_ac: false,
                battery_pct: Some(80),
            });
        assert_eq!(small.effective_workers(8), 1);
    }

    #[test]
    fn battery_gentle_full_speed_on_ac() {
        let t = BatteryThrottle::new(8).with_preset(BatteryPreset::BatteryGentle);
        assert_eq!(t.gate(), ScanGate::Full);
    }

    #[test]
    fn battery_off_pauses_on_battery_resumes_on_ac() {
        let mut t = BatteryThrottle::new(8).with_preset(BatteryPreset::BatteryOff);
        t.set_power(PowerState {
            on_ac: false,
            battery_pct: Some(60),
        });
        assert_eq!(t.gate(), ScanGate::Pause);
        assert!(!t.allow_scheduled());
        t.set_power(PowerState::ac_default());
        assert_eq!(t.gate(), ScanGate::Full);
        assert!(t.allow_scheduled());
    }

    #[test]
    fn effective_workers_pause_keeps_one_slot() {
        let t = BatteryThrottle::new(16)
            .with_preset(BatteryPreset::BatteryOff)
            .with_power(PowerState {
                on_ac: false,
                battery_pct: Some(20),
            });
        assert_eq!(t.effective_workers(16), 1);
    }

    #[test]
    fn effective_workers_respects_base_ceiling() {
        let t = BatteryThrottle::new(16)
            .with_preset(BatteryPreset::BatteryGentle)
            .with_power(PowerState {
                on_ac: false,
                battery_pct: Some(50),
            });
        // 16/4 = 4, but base_max=2 limits.
        assert_eq!(t.effective_workers(2), 2);
    }

    #[test]
    fn scheduled_allowed_on_ac_aggressive_only_when_full() {
        let t = BatteryThrottle::new(8).with_preset(BatteryPreset::AcAggressive);
        assert!(t.allow_scheduled());
    }

    #[test]
    fn battery_pct_is_informational_only() {
        // Same gate decision regardless of battery percent.
        let a = BatteryThrottle::new(8)
            .with_preset(BatteryPreset::BatteryOff)
            .with_power(PowerState {
                on_ac: false,
                battery_pct: Some(5),
            });
        let b = BatteryThrottle::new(8)
            .with_preset(BatteryPreset::BatteryOff)
            .with_power(PowerState {
                on_ac: false,
                battery_pct: Some(99),
            });
        assert_eq!(a.gate(), b.gate());
    }

    #[test]
    fn preset_round_trip_in_serde() {
        let p = BatteryPreset::BatteryGentle;
        let s = serde_json::to_string(&p).unwrap();
        assert_eq!(s, "\"battery_gentle\"");
        let p2: BatteryPreset = serde_json::from_str(&s).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn num_cpus_zero_clamps_to_one() {
        let t = BatteryThrottle::new(0);
        assert!(t.effective_workers(8) >= 1);
    }
}
