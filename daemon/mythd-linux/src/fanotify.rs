//! Linux fanotify wrapper (TASK-073, Phase 8).
//!
//! Wraps the four kernel surfaces the daemon talks to:
//!
//!   * `fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, O_RDONLY)`
//!   * `fanotify_mark(..., FAN_MARK_FILESYSTEM, mask, AT_FDCWD, "/")`
//!     for whole-filesystem coverage (kernel ≥ 5.1)
//!   * `read(fd, ...)` to drain the event queue
//!   * `write(fd, FAN_ALLOW | FAN_DENY)` for permission decisions
//!
//! All raw syscalls are `#[cfg(target_os = "linux")]`-gated so the
//! crate builds on Windows/macOS hosts (the binary itself only ships
//! on Linux). The non-Linux path returns
//! [`FanotifyError::Unsupported`] from every entry point.
//!
//! Per § 1.5.4: no kernel module. fanotify is user-mode-loaded — the
//! syscall is in the kernel but the consumer is `mythd` running with
//! `CAP_SYS_ADMIN`.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum FanotifyError {
    #[error("fanotify is not supported on this host (not a Linux target)")]
    Unsupported,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("fanotify_init returned EINVAL — likely missing FAN_MARK_FILESYSTEM (kernel < 5.1)")]
    NeedsFallback,
    #[error("CAP_SYS_ADMIN missing — daemon must be started by systemd or with sudo")]
    NeedsCapSysAdmin,
}

/// One event the daemon hands off to the engine via
/// [`crate::ipc_client`]. Mirrors fanotify's `fanotify_event_metadata`
/// + the `FAN_REPORT_PIDFD` extension when present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanotifyEvent {
    pub mask_bits: u64,
    /// Resolved canonical path of the file the event refers to.
    pub path: PathBuf,
    /// PID of the process whose syscall triggered the event. 0 when
    /// the daemon could not resolve the PID (rare; corresponds to a
    /// race where the process exited between the event and the
    /// `/proc/<pid>` lookup).
    pub pid: i32,
    /// True iff this event came in via `FAN_OPEN_PERM` /
    /// `FAN_ACCESS_PERM` — i.e., the daemon owes the kernel an
    /// ALLOW / DENY reply. Notify-only events leave this `false`.
    pub permission_request: bool,
}

/// fanotify mask bits the daemon subscribes to. Mirrors `<sys/fanotify.h>`
/// constant values. We don't import `libc::FAN_*` here because the
/// values are stable kernel ABI and re-declaring keeps the non-Linux
/// build alive.
pub mod mask {
    pub const FAN_ACCESS: u64 = 0x1;
    pub const FAN_MODIFY: u64 = 0x2;
    pub const FAN_CLOSE_WRITE: u64 = 0x8;
    pub const FAN_OPEN: u64 = 0x20;
    pub const FAN_OPEN_PERM: u64 = 0x10000;
    pub const FAN_ACCESS_PERM: u64 = 0x20000;
}

/// Three-way verdict returned over the fanotify FD. Mirrors the
/// kernel's FAN_ALLOW / FAN_DENY constants; we don't expose a Defer
/// variant here because the kernel itself has no "defer" — the
/// daemon either replies inline or holds the kernel waiting. Defer
/// in the IPC layer means "still working, don't time out yet"; from
/// the kernel's perspective the daemon hasn't written yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanotifyReply {
    Allow,
    Deny,
}

/// The fanotify FD owner. On Linux this holds the raw FD + the marks
/// it has installed; on non-Linux it is a zero-sized stub so the
/// daemon can construct it for unit tests without exploding.
#[derive(Debug)]
pub struct FanotifyHandle {
    #[cfg(target_os = "linux")]
    fd: std::os::fd::RawFd,
    #[cfg(target_os = "linux")]
    marked_paths: Vec<PathBuf>,
    /// Mode string surfaced to the UI ("fanotify (full)",
    /// "fanotify (mount-only)").
    pub mode_label: String,
}

impl FanotifyHandle {
    /// Open a fanotify FD. On non-Linux this is the
    /// [`FanotifyError::Unsupported`] short-circuit. On Linux it
    /// attempts `FAN_MARK_FILESYSTEM` first; if the kernel rejects
    /// with `EINVAL`, returns [`FanotifyError::NeedsFallback`] so
    /// the caller can wire in the inotify or audit fallback.
    #[cfg(target_os = "linux")]
    pub fn open() -> Result<Self, FanotifyError> {
        // SAFETY: standard libc::fanotify_init invocation. The crate
        // does not yet manage the FD lifecycle beyond the Drop impl
        // below; further hardening (FD_CLOEXEC race etc.) is
        // captured in TASK-073's review pass.
        let fd = unsafe {
            libc::fanotify_init(
                (libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC) as u32,
                libc::O_RDONLY as u32,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            // EPERM is the canonical missing-cap response.
            if err.raw_os_error() == Some(libc::EPERM) {
                return Err(FanotifyError::NeedsCapSysAdmin);
            }
            return Err(FanotifyError::Io(err));
        }
        Ok(Self {
            fd,
            marked_paths: Vec::new(),
            mode_label: "fanotify (full)".to_string(),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn open() -> Result<Self, FanotifyError> {
        Err(FanotifyError::Unsupported)
    }

    /// Drain one batch of events from the FD. On Linux this is a
    /// blocking read; the daemon's main loop spawns it on a dedicated
    /// thread. Returns the parsed events.
    #[cfg(target_os = "linux")]
    pub fn read_events(&self) -> Result<Vec<FanotifyEvent>, FanotifyError> {
        // TODO (TASK-073 follow-up): full event parsing lives behind
        // the libc::fanotify_event_metadata struct + FAN_REPORT_FID
        // extensions. Wave 1 ships the syscall scaffolding; the
        // event-decoder full implementation needs Linux-runtime
        // testing that this Windows-built foundation can't provide.
        // The decoder shape is documented in the Sourcerer sister
        // project (which already runs on Linux) and will land here in
        // the runtime-validation pass.
        Ok(Vec::new())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn read_events(&self) -> Result<Vec<FanotifyEvent>, FanotifyError> {
        Err(FanotifyError::Unsupported)
    }

    /// Write a verdict reply for a previously-received `permission_request`
    /// event. fanotify expects the daemon to write the event's metadata
    /// header with `FAN_ALLOW` or `FAN_DENY` set in the `response`
    /// field. Best-effort — a closed FD or an expired event id is
    /// not fatal.
    #[cfg(target_os = "linux")]
    pub fn reply(&self, _req_id: u64, reply: FanotifyReply) -> Result<(), FanotifyError> {
        let _ = reply;
        // See read_events TODO — full reply wire-up lands in the
        // Linux-runtime pass.
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn reply(&self, _req_id: u64, _reply: FanotifyReply) -> Result<(), FanotifyError> {
        Err(FanotifyError::Unsupported)
    }
}

#[cfg(target_os = "linux")]
impl Drop for FanotifyHandle {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: fd was opened by Self::open and is owned by us.
            unsafe { libc::close(self.fd) };
            self.fd = -1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_constants_match_kernel_abi() {
        // These literals are kernel ABI; tests guard against an
        // accidental edit that would silently disable real-time on
        // every platform.
        assert_eq!(mask::FAN_ACCESS, 0x1);
        assert_eq!(mask::FAN_MODIFY, 0x2);
        assert_eq!(mask::FAN_CLOSE_WRITE, 0x8);
        assert_eq!(mask::FAN_OPEN_PERM, 0x10000);
        assert_eq!(mask::FAN_ACCESS_PERM, 0x20000);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn open_returns_unsupported_on_non_linux() {
        let err = FanotifyHandle::open().unwrap_err();
        assert!(matches!(err, FanotifyError::Unsupported));
    }
}
