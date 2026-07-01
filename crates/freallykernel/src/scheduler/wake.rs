//! TASK-207 — Smart resumption after laptop wake.
//!
//! When a laptop wakes from S3/S4 sleep we *don't* immediately resume
//! a paused scan: the user might be checking email, in a meeting, or
//! on battery. Instead, we wait for `WakeEvent { is_ac, idle_seconds }`
//! followed by:
//!
//!   - `is_ac == true` (charger reconnected, or never disconnected),
//!   - `idle_seconds >= MIN_IDLE_SECONDS` (default 30 s; configurable).
//!
//! Until both conditions hold, the scheduler stays paused and surfaces
//! a `"Resuming after wake — waiting for idle"` status string.
//!
//! Per-OS plumbing for `WM_POWERBROADCAST` (Windows),
//! `IORegisterForSystemPower` (macOS via objc2), and
//! `org.freedesktop.login1.Manager.Inhibit` (Linux) lives in the
//! daemons. This module owns the pure decision logic so we can unit
//! test it without spinning up a real power broker.

use serde::{Deserialize, Serialize};

/// Default minimum idle time before resuming. Matches the spec.
pub const MIN_IDLE_SECONDS: u64 = 30;

/// Power state at wake time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeEvent {
    /// Whether the machine is on AC power at the moment of the event.
    pub on_ac: bool,
    /// Seconds since the last user input. Reported via
    /// `GetLastInputInfo` (Windows), `CGEventSourceSecondsSinceLastEventType`
    /// (macOS), `XScreenSaverQueryInfo` / portal-idle (Linux).
    pub idle_seconds: u64,
    /// `true` when this event was emitted because of a freshly-woken
    /// machine; `false` for the periodic "still on AC + still idle"
    /// re-evaluation event the daemon emits every 5 s.
    pub fresh_wake: bool,
}

/// Per-gate config — tunable in Settings.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WakeGateConfig {
    pub min_idle_seconds: u64,
    /// When `true` the gate ignores `on_ac` (mostly useful for
    /// desktops that always read as on AC).
    pub require_ac: bool,
}

impl Default for WakeGateConfig {
    fn default() -> Self {
        Self {
            min_idle_seconds: MIN_IDLE_SECONDS,
            require_ac: true,
        }
    }
}

/// Decision produced by [`WakeGate::observe`]. Drives the scheduler
/// state machine: `Resume` releases the pause; `Wait { reason }`
/// keeps the scan paused and surfaces the reason string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WakeDecision {
    Resume,
    Wait {
        reason: String,
        seconds_remaining: Option<u64>,
    },
}

/// Per-scan state machine. The scheduler keeps one of these per
/// paused scan; on each `WakeEvent` it calls `observe` and acts on
/// the returned decision.
#[derive(Debug, Clone)]
pub struct WakeGate {
    config: WakeGateConfig,
    /// Once a fresh-wake event arrives, this latches to `true`. The
    /// gate then waits for AC + idle to be satisfied before
    /// returning `Resume`.
    armed: bool,
    /// `true` once a `Resume` decision has been produced. Subsequent
    /// observations stay `Resume` so the scheduler doesn't ping-pong.
    resumed: bool,
}

impl Default for WakeGate {
    fn default() -> Self {
        Self::new(WakeGateConfig::default())
    }
}

impl WakeGate {
    pub fn new(config: WakeGateConfig) -> Self {
        Self {
            config,
            armed: false,
            resumed: false,
        }
    }

    pub fn armed(&self) -> bool {
        self.armed
    }

    pub fn resumed(&self) -> bool {
        self.resumed
    }

    /// Force-arm the gate (used when the scheduler restarts after a
    /// crash and doesn't know whether a wake event preceded it).
    pub fn arm(&mut self) {
        self.armed = true;
        self.resumed = false;
    }

    pub fn reset(&mut self) {
        self.armed = false;
        self.resumed = false;
    }

    /// Observe a wake event. Returns the decision the caller should
    /// act on.
    pub fn observe(&mut self, event: WakeEvent) -> WakeDecision {
        if event.fresh_wake {
            self.armed = true;
            self.resumed = false;
        }
        if !self.armed {
            return WakeDecision::Resume;
        }
        if self.resumed {
            return WakeDecision::Resume;
        }
        if self.config.require_ac && !event.on_ac {
            return WakeDecision::Wait {
                reason: "on battery — waiting for AC".into(),
                seconds_remaining: None,
            };
        }
        if event.idle_seconds < self.config.min_idle_seconds {
            return WakeDecision::Wait {
                reason: format!(
                    "waiting for {} s of idle (current {} s)",
                    self.config.min_idle_seconds, event.idle_seconds
                ),
                seconds_remaining: Some(self.config.min_idle_seconds - event.idle_seconds),
            };
        }
        self.resumed = true;
        WakeDecision::Resume
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_wake_arms_gate() {
        let mut g = WakeGate::default();
        let d = g.observe(WakeEvent {
            on_ac: false,
            idle_seconds: 0,
            fresh_wake: true,
        });
        assert!(g.armed());
        assert!(matches!(d, WakeDecision::Wait { .. }));
    }

    #[test]
    fn battery_blocks_resume() {
        let mut g = WakeGate::default();
        g.arm();
        let d = g.observe(WakeEvent {
            on_ac: false,
            idle_seconds: 999,
            fresh_wake: false,
        });
        match d {
            WakeDecision::Wait { reason, .. } => {
                assert!(reason.contains("battery") || reason.contains("AC"));
            }
            other => panic!("expected Wait, got {other:?}"),
        }
    }

    #[test]
    fn ac_plus_idle_resumes() {
        let mut g = WakeGate::default();
        g.arm();
        let d = g.observe(WakeEvent {
            on_ac: true,
            idle_seconds: MIN_IDLE_SECONDS,
            fresh_wake: false,
        });
        assert_eq!(d, WakeDecision::Resume);
        assert!(g.resumed());
    }

    #[test]
    fn idle_below_threshold_keeps_waiting_with_countdown() {
        let mut g = WakeGate::default();
        g.arm();
        let d = g.observe(WakeEvent {
            on_ac: true,
            idle_seconds: 10,
            fresh_wake: false,
        });
        match d {
            WakeDecision::Wait {
                seconds_remaining: Some(20),
                ..
            } => {}
            other => panic!("expected Wait{{20}}, got {other:?}"),
        }
    }

    #[test]
    fn require_ac_false_resumes_on_battery() {
        let mut g = WakeGate::new(WakeGateConfig {
            min_idle_seconds: 5,
            require_ac: false,
        });
        g.arm();
        let d = g.observe(WakeEvent {
            on_ac: false,
            idle_seconds: 10,
            fresh_wake: false,
        });
        assert_eq!(d, WakeDecision::Resume);
    }

    #[test]
    fn fresh_wake_re_arms_after_resume() {
        let mut g = WakeGate::default();
        g.arm();
        g.observe(WakeEvent {
            on_ac: true,
            idle_seconds: 60,
            fresh_wake: false,
        });
        assert!(g.resumed());
        let d = g.observe(WakeEvent {
            on_ac: true,
            idle_seconds: 0,
            fresh_wake: true,
        });
        assert!(g.armed());
        assert!(!g.resumed());
        assert!(matches!(d, WakeDecision::Wait { .. }));
    }

    #[test]
    fn unarmed_gate_always_resumes() {
        // Gate that has never seen a fresh_wake event treats every
        // observation as "no pause needed".
        let mut g = WakeGate::default();
        assert_eq!(
            g.observe(WakeEvent {
                on_ac: false,
                idle_seconds: 0,
                fresh_wake: false,
            }),
            WakeDecision::Resume
        );
    }

    #[test]
    fn config_defaults_match_spec() {
        let c = WakeGateConfig::default();
        assert_eq!(c.min_idle_seconds, 30);
        assert!(c.require_ac);
    }

    #[test]
    fn reset_clears_armed_and_resumed() {
        let mut g = WakeGate::default();
        g.arm();
        g.observe(WakeEvent {
            on_ac: true,
            idle_seconds: 30,
            fresh_wake: false,
        });
        assert!(g.resumed());
        g.reset();
        assert!(!g.armed());
        assert!(!g.resumed());
    }
}
