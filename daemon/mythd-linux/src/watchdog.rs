//! Daemon watchdog + start-on-boot policy (TASK-076, Phase 8).
//!
//! The actual systemd unit lives in
//! `packaging/linux/mythd.service`; this module owns the **crash
//! budget tracker** that the daemon ships to the engine over the IPC
//! heartbeat. The UI surfaces "real-time crashed (> 3 restarts/hr)"
//! when the tracker trips.
//!
//! Distinction from FR-161 / TASK-157 (user-app autostart): this
//! module governs the **daemon** lifecycle (root, systemd-level). The
//! user-mode UI app's start-at-login is governed by
//! `tauri-plugin-autostart` writing per-user XDG `.desktop` files
//! and is unrelated.

use std::time::Duration;

/// Default budget: > 3 restarts within 60 minutes trips the UI badge.
pub const DEFAULT_BUDGET_RESTARTS: u32 = 3;
pub const DEFAULT_BUDGET_WINDOW: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone)]
pub struct CrashBudget {
    pub window: Duration,
    pub max_restarts: u32,
    restarts: Vec<i64>,
}

impl CrashBudget {
    pub fn new(window: Duration, max_restarts: u32) -> Self {
        Self {
            window,
            max_restarts,
            restarts: Vec::new(),
        }
    }

    /// Record a restart at `now_utc_secs`. Returns true when the
    /// budget is exceeded after the record.
    pub fn record(&mut self, now_utc_secs: i64) -> bool {
        let earliest = now_utc_secs - self.window.as_secs() as i64;
        self.restarts.retain(|t| *t >= earliest);
        self.restarts.push(now_utc_secs);
        self.is_tripped()
    }

    pub fn is_tripped(&self) -> bool {
        self.restarts.len() as u32 > self.max_restarts
    }

    pub fn recent_count(&self) -> usize {
        self.restarts.len()
    }
}

impl Default for CrashBudget {
    fn default() -> Self {
        Self::new(DEFAULT_BUDGET_WINDOW, DEFAULT_BUDGET_RESTARTS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn under_budget_does_not_trip() {
        let mut b = CrashBudget::default();
        assert!(!b.record(0));
        assert!(!b.record(10));
        assert!(!b.record(20));
        assert!(!b.is_tripped());
    }

    #[test]
    fn over_budget_trips() {
        let mut b = CrashBudget::default();
        b.record(0);
        b.record(60);
        b.record(120);
        assert!(b.record(180), "fourth restart in window should trip");
    }

    #[test]
    fn old_restarts_age_out_of_window() {
        let mut b = CrashBudget::default();
        b.record(0);
        b.record(60);
        b.record(120);
        // 5000s later — older entries should be evicted.
        let tripped = b.record(5000);
        assert!(!tripped);
        assert_eq!(b.recent_count(), 1);
    }
}
