//! Per-process network-byte counters (TASK-301, Phase 10 Wave 3).
//!
//! Daemon-side platform shims sample raw per-pid byte counters
//! from the kernel (`/proc/<pid>/net/dev` lines on Linux, `libproc`
//! `proc_pidinfo` with `PROC_PIDFDVNODEPATHINFO` + the per-socket
//! flavor on macOS, `GetExtendedTcpTable` / `GetExtendedUdpTable`
//! grouped by owning pid on Windows). Those samples become
//! [`NetCounterSnapshot`] rows that the UI charts.
//!
//! This module is the **shape** + the rate computation only —
//! platform code lives under `daemon/freallyd-*`.

use serde::{Deserialize, Serialize};

/// One sample of cumulative network-byte counters for one pid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetCounterSnapshot {
    pub pid: u32,
    /// Cumulative bytes since pid started (never wraps within a
    /// reasonable session).
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Monotonic clock millis at the moment of sampling.
    pub sampled_unix_ms: i64,
}

/// Per-pid rate derived from two consecutive snapshots.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetCounterRate {
    pub pid: u32,
    pub rx_bytes_per_s: f64,
    pub tx_bytes_per_s: f64,
}

/// Compute rate between two ordered samples for the same pid.
///
/// Returns `None` when `later` doesn't strictly follow `earlier`
/// in time, when the pids disagree, or when the elapsed interval
/// is zero (would divide by zero).
pub fn rate(earlier: &NetCounterSnapshot, later: &NetCounterSnapshot) -> Option<NetCounterRate> {
    if earlier.pid != later.pid {
        return None;
    }
    let dt_ms = later.sampled_unix_ms.checked_sub(earlier.sampled_unix_ms)?;
    if dt_ms <= 0 {
        return None;
    }
    let dt_s = dt_ms as f64 / 1000.0;
    let drx = later.rx_bytes.saturating_sub(earlier.rx_bytes) as f64;
    let dtx = later.tx_bytes.saturating_sub(earlier.tx_bytes) as f64;
    Some(NetCounterRate {
        pid: earlier.pid,
        rx_bytes_per_s: drx / dt_s,
        tx_bytes_per_s: dtx / dt_s,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(pid: u32, rx: u64, tx: u64, t: i64) -> NetCounterSnapshot {
        NetCounterSnapshot {
            pid,
            rx_bytes: rx,
            tx_bytes: tx,
            sampled_unix_ms: t,
        }
    }

    #[test]
    fn computes_simple_rate() {
        let a = snap(42, 0, 0, 1_000);
        let b = snap(42, 1_000, 500, 2_000);
        let r = rate(&a, &b).unwrap();
        assert_eq!(r.pid, 42);
        assert!((r.rx_bytes_per_s - 1000.0).abs() < 1e-6);
        assert!((r.tx_bytes_per_s - 500.0).abs() < 1e-6);
    }

    #[test]
    fn rate_rejects_mismatched_pids() {
        let a = snap(1, 0, 0, 1_000);
        let b = snap(2, 100, 100, 2_000);
        assert!(rate(&a, &b).is_none());
    }

    #[test]
    fn rate_rejects_zero_interval() {
        let a = snap(1, 0, 0, 1_000);
        let b = snap(1, 100, 100, 1_000);
        assert!(rate(&a, &b).is_none());
    }

    #[test]
    fn rate_rejects_reversed_time() {
        let a = snap(1, 0, 0, 2_000);
        let b = snap(1, 100, 100, 1_000);
        assert!(rate(&a, &b).is_none());
    }

    #[test]
    fn counter_decrease_saturates_to_zero() {
        // pid reuse — fresh counters smaller than the older sample.
        let a = snap(1, 5_000, 5_000, 1_000);
        let b = snap(1, 100, 100, 2_000);
        let r = rate(&a, &b).unwrap();
        assert_eq!(r.rx_bytes_per_s, 0.0);
        assert_eq!(r.tx_bytes_per_s, 0.0);
    }
}
