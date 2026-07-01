//! Hijacked thread-start detector (TASK-297).
//!
//! A "hijacked" thread is one whose `StartAddress` (Windows
//! `NtQueryInformationThread::ThreadQuerySetWin32StartAddress` /
//! Linux `/proc/<pid>/task/<tid>/syscall` PC / macOS
//! `thread_get_state`) points **outside the loaded image
//! ranges** that the process owns. Daemon-side code provides
//! the loaded-module list + the per-thread start address;
//! [`detect_hijacked_thread`] checks the address against the
//! ranges and emits a finding when it falls in unmapped /
//! anonymous / shellcode-shaped territory.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadedModuleRange {
    pub path: String,
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadHijackFinding {
    pub thread_id: u64,
    pub start_address: u64,
    /// `true` when the address lies inside a region the
    /// daemon flagged as anonymous-executable (otherwise
    /// it's just "outside all known modules").
    pub in_anonymous_exec: bool,
}

pub fn detect_hijacked_thread(
    thread_id: u64,
    start_address: u64,
    modules: &[LoadedModuleRange],
    in_anonymous_exec: bool,
) -> Option<ThreadHijackFinding> {
    for m in modules {
        if start_address >= m.start && start_address < m.end {
            return None;
        }
    }
    Some(ThreadHijackFinding {
        thread_id,
        start_address,
        in_anonymous_exec,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(path: &str, start: u64, end: u64) -> LoadedModuleRange {
        LoadedModuleRange {
            path: path.to_string(),
            start,
            end,
        }
    }

    #[test]
    fn start_inside_known_module_is_clean() {
        let modules = vec![module("kernel32.dll", 0x7000, 0x8000)];
        assert!(detect_hijacked_thread(1, 0x7500, &modules, false).is_none());
    }

    #[test]
    fn start_outside_all_modules_flagged() {
        let modules = vec![module("kernel32.dll", 0x7000, 0x8000)];
        let f = detect_hijacked_thread(2, 0x9000, &modules, true).unwrap();
        assert!(f.in_anonymous_exec);
        assert_eq!(f.start_address, 0x9000);
    }

    #[test]
    fn empty_module_list_always_flags() {
        let f = detect_hijacked_thread(7, 0x42, &[], false).unwrap();
        assert!(!f.in_anonymous_exec);
    }

    #[test]
    fn boundary_at_module_end_is_outside() {
        let modules = vec![module("user32.dll", 0x10000, 0x11000)];
        // end is exclusive — start_address == end should flag.
        assert!(detect_hijacked_thread(1, 0x11000, &modules, false).is_some());
    }

    #[test]
    fn boundary_at_module_start_is_inside() {
        let modules = vec![module("user32.dll", 0x10000, 0x11000)];
        assert!(detect_hijacked_thread(1, 0x10000, &modules, false).is_none());
    }
}
