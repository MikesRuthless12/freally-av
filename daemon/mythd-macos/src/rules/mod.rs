//! macOS-specific real-time rule set (Phase 8 Wave 2 + Phase 9).

pub mod app_on_usb;
/// Ransomware honeyfile tripwires + SIGSTOP-on-canary-write action
/// (TASK-161, FR-142). Cross-platform planning lives in
/// `mythkernel::detect::honeyfiles`; this module owns the macOS-only
/// `sysctl(KERN_PROC_ALL)` process-tree walk + SIGSTOP delivery.
pub mod honey;
