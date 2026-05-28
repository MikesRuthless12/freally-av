//! Per-process file-write counters (TASK-302, Phase 10 Wave 3).
//!
//! The daemon samples `write_bytes` from
//! `/proc/<pid>/io` (Linux), `proc_pid_rusage` (macOS), and
//! `GetProcessIoCounters().WriteTransferCount` (Windows). The
//! samples flow into the UI as cumulative-per-pid rows. A
//! configurable threshold raises a `process-heavy-writer`
//! finding for non-system processes that exceed it inside a
//! rolling 24-hour window.
//!
//! This module owns the shape, the threshold default, and the
//! finding-emit decision. Platform sampling code lives in the
//! per-OS daemon.

use serde::{Deserialize, Serialize};

/// Default Top-N alert threshold: 10 GB written by a single
/// non-system pid inside the rolling daily window.
pub const DEFAULT_DAILY_WRITE_ALERT_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// One sample of cumulative file-write bytes for one pid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoCounterSnapshot {
    pub pid: u32,
    pub image_path: String,
    pub write_bytes: u64,
    pub sampled_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeavyWriterFinding {
    pub pid: u32,
    pub image_path: String,
    pub written_bytes_in_window: u64,
    /// Elapsed ms between the two snapshots — the caller can
    /// trivially see whether the window was the daily ~86_400_000
    /// ms or shorter/longer.
    pub window_ms: i64,
    pub threshold_bytes: u64,
}

/// Returns `Some(finding)` when the pid has written more than
/// `threshold` bytes in the interval between the two snapshots.
///
/// `earliest` and `latest` must be the same pid AND ordered in
/// time (latest's clock must be strictly greater than earliest's).
/// The caller is expected to pre-bucket samples per-pid and to
/// pick a window that approximates the daily semantics it cares
/// about (default thresholds in this module are tuned for a
/// 24-hour window).
pub fn evaluate(
    earliest: &IoCounterSnapshot,
    latest: &IoCounterSnapshot,
    threshold_bytes: u64,
) -> Option<HeavyWriterFinding> {
    if earliest.pid != latest.pid {
        return None;
    }
    let window_ms = latest
        .sampled_unix_ms
        .checked_sub(earliest.sampled_unix_ms)?;
    if window_ms <= 0 {
        return None;
    }
    let delta = latest.write_bytes.saturating_sub(earliest.write_bytes);
    if delta < threshold_bytes {
        return None;
    }
    Some(HeavyWriterFinding {
        pid: latest.pid,
        image_path: latest.image_path.clone(),
        written_bytes_in_window: delta,
        window_ms,
        threshold_bytes,
    })
}

/// Returns `true` when `image_path` is a known OS system binary
/// the heavy-writer rule should suppress (`backupd`, `mds_stores`,
/// `svchost`, kernel writers, …). Membership is intentionally
/// conservative — under-suppressing yields a noisy finding;
/// over-suppressing hides real exfil.
pub fn is_system_writer(image_path: &str) -> bool {
    const KNOWN: &[&str] = &[
        // macOS Spotlight + Time Machine + log rotation.
        "/usr/libexec/mds_stores",
        "/System/Library/CoreServices/backupd.bundle/Contents/Resources/backupd-helper",
        "/usr/sbin/syslogd",
        // Linux systemd-journald rotates aggressively.
        "/lib/systemd/systemd-journald",
        "/usr/lib/systemd/systemd-journald",
        // Windows service host writers (telemetry / WU).
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\System32\\SearchIndexer.exe",
        "C:\\Windows\\System32\\WerFault.exe",
    ];
    KNOWN.iter().any(|s| s.eq_ignore_ascii_case(image_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(pid: u32, path: &str, write: u64, t: i64) -> IoCounterSnapshot {
        IoCounterSnapshot {
            pid,
            image_path: path.to_string(),
            write_bytes: write,
            sampled_unix_ms: t,
        }
    }

    #[test]
    fn raises_finding_above_threshold() {
        let a = snap(1, "/usr/bin/curl", 0, 0);
        let b = snap(1, "/usr/bin/curl", 11 * 1024 * 1024 * 1024, 86_400_000);
        let f = evaluate(&a, &b, DEFAULT_DAILY_WRITE_ALERT_BYTES).unwrap();
        assert_eq!(f.pid, 1);
        assert!(f.written_bytes_in_window > DEFAULT_DAILY_WRITE_ALERT_BYTES);
        assert_eq!(f.window_ms, 86_400_000);
    }

    #[test]
    fn silent_below_threshold() {
        let a = snap(1, "/usr/bin/curl", 0, 0);
        let b = snap(1, "/usr/bin/curl", 5 * 1024 * 1024 * 1024, 86_400_000);
        assert!(evaluate(&a, &b, DEFAULT_DAILY_WRITE_ALERT_BYTES).is_none());
    }

    #[test]
    fn rejects_mismatched_pids() {
        let a = snap(1, "/a", 0, 0);
        let b = snap(2, "/b", u64::MAX, 1);
        assert!(evaluate(&a, &b, 0).is_none());
    }

    #[test]
    fn rejects_zero_or_reversed_window() {
        let a = snap(1, "/a", 0, 1_000);
        let b = snap(1, "/a", u64::MAX, 1_000);
        assert!(evaluate(&a, &b, 0).is_none());
        let c = snap(1, "/a", 0, 2_000);
        let d = snap(1, "/a", u64::MAX, 1_000);
        assert!(evaluate(&c, &d, 0).is_none());
    }

    #[test]
    fn system_writer_recognised() {
        assert!(is_system_writer("/usr/libexec/mds_stores"));
        assert!(is_system_writer("C:\\Windows\\System32\\svchost.exe"));
        assert!(!is_system_writer("/Users/alice/Downloads/curl"));
    }
}
