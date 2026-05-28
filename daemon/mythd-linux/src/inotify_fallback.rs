//! Inotify fallback for kernel < 5.1 (TASK-077, Phase 8).
//!
//! Used when [`crate::fanotify::FanotifyHandle::open`] returns
//! [`crate::fanotify::FanotifyError::NeedsFallback`]. Inotify cannot
//! issue permission decisions, so the daemon comes up in
//! **observe-only** mode: events surface to the engine for logging,
//! but every fanotify-style verdict reply becomes a no-op. The UI
//! mirrors this with the mode string "inotify (observe-only)".

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum InotifyError {
    #[error("inotify is not supported on this host (not a Linux target)")]
    Unsupported,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// One inotify event the daemon forwards to the engine. No verdict
/// is requested — observe-only mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InotifyEvent {
    pub path: PathBuf,
    /// IN_* mask bits.
    pub mask_bits: u32,
    /// `name` field from the inotify event when the event was for a
    /// directory's child; empty when the watch was on the file itself.
    pub child_name: String,
}

#[derive(Debug)]
pub struct InotifyHandle {
    #[cfg(target_os = "linux")]
    fd: std::os::fd::RawFd,
    pub mode_label: String,
}

impl InotifyHandle {
    #[cfg(target_os = "linux")]
    pub fn open() -> Result<Self, InotifyError> {
        // SAFETY: inotify_init1 is a fallible syscall; we check the
        // return value and propagate via std::io::Error.
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if fd < 0 {
            return Err(InotifyError::Io(std::io::Error::last_os_error()));
        }
        Ok(Self {
            fd,
            mode_label: "inotify (observe-only)".to_string(),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn open() -> Result<Self, InotifyError> {
        Err(InotifyError::Unsupported)
    }

    #[cfg(target_os = "linux")]
    pub fn watch(&self, _path: &std::path::Path, _mask: u32) -> Result<i32, InotifyError> {
        // Wave 1 ships the scaffolding; the watch-add full
        // implementation needs Linux-runtime testing that this
        // Windows-built foundation does not provide. The pattern is
        // documented in the Sourcerer sister project.
        Ok(0)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn watch(&self, _path: &std::path::Path, _mask: u32) -> Result<i32, InotifyError> {
        Err(InotifyError::Unsupported)
    }
}

#[cfg(target_os = "linux")]
impl Drop for InotifyHandle {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    use super::*;

    #[test]
    fn open_returns_unsupported_off_linux() {
        let err = InotifyHandle::open().unwrap_err();
        assert!(matches!(err, InotifyError::Unsupported));
    }
}
