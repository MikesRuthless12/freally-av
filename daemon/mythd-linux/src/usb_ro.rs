//! Read-only mount auto-policy for unknown USBs (TASK-245 Linux).
//!
//! When an unknown VID:PID:Serial arrives, re-mount the volume read-
//! only via `mount -o remount,ro <mountpoint>`. Requires the daemon's
//! existing CAP_SYS_ADMIN. Reverts to rw when the user toggles the
//! per-device switch.
//!
//! Per § 1.5.4: macOS uses `diskutil mount readOnly`; Windows
//! surfaces a hint card and never auto-applies (no kernel driver).
//!
//! This module owns the **mount command builder** + the event row
//! the daemon appends to `usb_policy_events` for audit. The actual
//! subprocess invocation is a one-liner the caller (the daemon main
//! loop) wires up; we keep it out of the library so the unit tests
//! don't shell out.

#[cfg(target_os = "linux")]
use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum UsbRoError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("mount(8) returned non-zero: {0}")]
    NonZeroExit(i32),
}

/// One row appended to `usb_policy_events` on every RO mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbPolicyEvent {
    pub ts_utc: i64,
    pub vid: String,
    pub pid: String,
    pub serial: String,
    pub mountpoint: String,
    pub action: &'static str,
}

/// Build the argv for `mount -o remount,ro -- <mountpoint>`. Returned
/// instead of executed so the unit tests can assert the shape
/// without spawning a process.
///
/// The literal `--` separator forces `mount(8)` to treat the
/// mountpoint as a positional argument even if it begins with `-`,
/// preventing a corrupted mount table row from being interpreted as
/// extra `mount` flags. The caller still validates that the
/// mountpoint is absolute and contains no NUL bytes or `..` —
/// `--` defends against a narrower attack (the `mount` argv parser)
/// (security-review follow-up, Phase 9 Wave 2 closeout).
pub fn remount_ro_argv(mountpoint: &str) -> Vec<String> {
    vec![
        "mount".to_string(),
        "-o".to_string(),
        "remount,ro".to_string(),
        "--".to_string(),
        mountpoint.to_string(),
    ]
}

pub fn remount_rw_argv(mountpoint: &str) -> Vec<String> {
    vec![
        "mount".to_string(),
        "-o".to_string(),
        "remount,rw".to_string(),
        "--".to_string(),
        mountpoint.to_string(),
    ]
}

/// Execute the argv via `Command::new(argv[0]).args(argv[1..])`. Only
/// callable from a Linux build because the only host where `mount(8)`
/// makes sense is Linux. On other OSes the function compiles but the
/// `start()` returns an error so the daemon binary still links.
#[cfg(target_os = "linux")]
pub fn run_argv(argv: &[String]) -> Result<(), UsbRoError> {
    let mut iter = argv.iter();
    let prog = iter.next().expect("argv must have at least the program");
    let status = Command::new(prog).args(iter).status()?;
    if !status.success() {
        return Err(UsbRoError::NonZeroExit(status.code().unwrap_or(-1)));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn run_argv(_argv: &[String]) -> Result<(), UsbRoError> {
    Err(UsbRoError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "mount(8) only available on Linux",
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ro_argv_is_canonical() {
        let argv = remount_ro_argv("/mnt/usb");
        assert_eq!(argv, vec!["mount", "-o", "remount,ro", "--", "/mnt/usb"]);
    }

    #[test]
    fn rw_argv_is_canonical() {
        let argv = remount_rw_argv("/mnt/usb");
        assert_eq!(argv, vec!["mount", "-o", "remount,rw", "--", "/mnt/usb"]);
    }

    #[test]
    fn ro_argv_separator_protects_dash_prefixed_mountpoint() {
        // A corrupted mount table row whose `mountpoint` begins with
        // `-` (e.g., `-osource=...`) must NOT be consumed by mount(8)
        // as extra flags. The `--` separator is the standard guard.
        let argv = remount_ro_argv("-evil");
        let dash_dash_idx = argv.iter().position(|a| a == "--").unwrap();
        let mp_idx = argv.iter().position(|a| a == "-evil").unwrap();
        assert!(
            dash_dash_idx < mp_idx,
            "the `--` argv separator must appear before any mountpoint that begins with `-`"
        );
    }
}
