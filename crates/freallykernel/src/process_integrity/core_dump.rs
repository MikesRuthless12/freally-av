//! Crashed-process core-dump YARA pass (TASK-300).
//!
//! When a process crashes the OS writes a core dump to disk
//! (`coredumpctl` on systemd Linux, `/cores/` on macOS,
//! `%LOCALAPPDATA%\CrashDumps\` on Windows). The daemon
//! notices the new dump via the existing FS-event ring and
//! enqueues a [`CoreDumpYaraRequest`] for the engine to run
//! the standard ruleset over the dump bytes. A
//! [`CoreDumpYaraVerdict`] is emitted back through the
//! daemon-internal channel.
//!
//! ## IPC framing
//!
//! These types are *not* yet variants of
//! [`crate::ipc::linfan::IpcFrame`]. They are the canonical
//! daemon-internal request/reply shapes; an IpcFrame variant
//! lands at closeout when the per-OS daemon hooks are wired.

use serde::{Deserialize, Serialize};

use crate::memory_scan::Pid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreDumpYaraRequest {
    /// Absolute path to the on-disk core file.
    pub dump_path: String,
    /// `pid` recorded at crash time (may be `None` when the
    /// dump didn't preserve it). Reuses [`crate::memory_scan::Pid`]
    /// so process identifiers carry the same newtype across both
    /// memory-scan and process-integrity subsystems.
    pub original_pid: Option<Pid>,
    /// Optional: image path the dead process was running.
    pub image_path: Option<String>,
    pub dump_unix_s: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreDumpYaraVerdict {
    /// No rule matched.
    Clean,
    /// One or more rules matched; engine surfaces a finding
    /// row deep-linking to the dump.
    HitFound,
    /// Scan was skipped because the dump was larger than the
    /// configured size cap or the file was unreadable.
    Skipped,
}

impl CoreDumpYaraVerdict {
    pub fn label(self) -> &'static str {
        match self {
            CoreDumpYaraVerdict::Clean => "clean",
            CoreDumpYaraVerdict::HitFound => "hit",
            CoreDumpYaraVerdict::Skipped => "skipped",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_through_serde_json() {
        let req = CoreDumpYaraRequest {
            dump_path: "/var/crash/core.12345".to_string(),
            original_pid: Some(Pid(12345)),
            image_path: Some("/usr/bin/firefox".to_string()),
            dump_unix_s: 1716840000,
        };
        let s = serde_json::to_string(&req).unwrap();
        let back: CoreDumpYaraRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn verdict_labels_are_stable() {
        assert_eq!(CoreDumpYaraVerdict::Clean.label(), "clean");
        assert_eq!(CoreDumpYaraVerdict::HitFound.label(), "hit");
        assert_eq!(CoreDumpYaraVerdict::Skipped.label(), "skipped");
    }

    #[test]
    fn optional_pid_and_image_path_serialise_as_null() {
        let req = CoreDumpYaraRequest {
            dump_path: "/cores/core".to_string(),
            original_pid: None,
            image_path: None,
            dump_unix_s: 0,
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"original_pid\":null"));
        assert!(s.contains("\"image_path\":null"));
    }
}
