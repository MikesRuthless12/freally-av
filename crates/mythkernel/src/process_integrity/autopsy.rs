//! Killed-process autopsy log (TASK-299).
//!
//! When a process dies — crash, signal, OOM kill, deliberate
//! `kill -9`, Windows `TerminateProcess` — the daemon writes an
//! [`AutopsyEntry`] into a fixed-size ring buffer. The UI's
//! "process timeline" reads from this buffer so the user can
//! see why pid 12345 vanished mid-scan.
//!
//! Ring-buffer capacity defaults to 1024 entries — enough to
//! cover a full scan session even on a busy desktop.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitReason {
    NormalExit,
    Signal,
    OutOfMemory,
    AccessViolation,
    UnhandledException,
    TerminatedByUser,
    TerminatedBySystem,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutopsyEntry {
    pub pid: u32,
    pub image_path: String,
    pub exit_unix_s: i64,
    pub reason: ExitReason,
    /// Platform-specific code (Windows ExitCode / Unix signo
    /// or wstatus). Zero when not meaningful.
    pub exit_code: i32,
}

const DEFAULT_CAPACITY: usize = 1024;

#[derive(Debug, Clone)]
pub struct AutopsyLog {
    entries: Vec<AutopsyEntry>,
    capacity: usize,
    next: usize,
    len: usize,
}

impl Default for AutopsyLog {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

impl AutopsyLog {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity.min(8)),
            capacity,
            next: 0,
            len: 0,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append a new entry. Oldest entry is overwritten when
    /// the buffer is full.
    pub fn push(&mut self, entry: AutopsyEntry) {
        if self.entries.len() < self.capacity {
            self.entries.push(entry);
        } else {
            self.entries[self.next] = entry;
        }
        self.next = (self.next + 1) % self.capacity;
        if self.len < self.capacity {
            self.len += 1;
        }
    }

    /// Returns the entries in chronological order (oldest
    /// first).
    pub fn chronological(&self) -> Vec<AutopsyEntry> {
        if self.len < self.capacity {
            return self.entries.iter().take(self.len).cloned().collect();
        }
        let start = self.next;
        let mut out = Vec::with_capacity(self.len);
        for i in 0..self.len {
            out.push(self.entries[(start + i) % self.capacity].clone());
        }
        out
    }

    /// Lookup by pid — useful for the "what happened to this
    /// process" UI deep-link. Returns the most recent entry
    /// (autopsy may contain repeats if the same pid was reused
    /// after a wraparound).
    pub fn by_pid(&self, pid: u32) -> Option<AutopsyEntry> {
        self.chronological()
            .into_iter()
            .rev()
            .find(|e| e.pid == pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(pid: u32, reason: ExitReason) -> AutopsyEntry {
        AutopsyEntry {
            pid,
            image_path: format!("/proc/{pid}/exe"),
            exit_unix_s: pid as i64 * 1000,
            reason,
            exit_code: 0,
        }
    }

    #[test]
    fn pushes_within_capacity() {
        let mut log = AutopsyLog::with_capacity(4);
        log.push(entry(1, ExitReason::NormalExit));
        log.push(entry(2, ExitReason::Signal));
        assert_eq!(log.len(), 2);
        assert!(!log.is_empty());
        let order = log.chronological();
        assert_eq!(order[0].pid, 1);
        assert_eq!(order[1].pid, 2);
    }

    #[test]
    fn wraps_around_capacity() {
        let mut log = AutopsyLog::with_capacity(3);
        for pid in 1u32..=5 {
            log.push(entry(pid, ExitReason::Signal));
        }
        assert_eq!(log.len(), 3);
        let order = log.chronological();
        assert_eq!(order[0].pid, 3);
        assert_eq!(order[1].pid, 4);
        assert_eq!(order[2].pid, 5);
    }

    #[test]
    fn by_pid_returns_most_recent_match() {
        let mut log = AutopsyLog::with_capacity(4);
        log.push(entry(1, ExitReason::NormalExit));
        log.push(entry(2, ExitReason::Signal));
        log.push(entry(1, ExitReason::OutOfMemory));
        let recent = log.by_pid(1).unwrap();
        assert_eq!(recent.reason, ExitReason::OutOfMemory);
    }

    #[test]
    fn empty_log_reports_zero() {
        let log = AutopsyLog::default();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert!(log.by_pid(1).is_none());
    }

    #[test]
    fn default_capacity_is_documented() {
        let log = AutopsyLog::default();
        assert_eq!(log.capacity(), 1024);
    }
}
