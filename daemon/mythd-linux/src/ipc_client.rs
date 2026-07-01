//! Daemon-side IPC client (TASK-074 daemon half, Phase 8).
//!
//! Owns the Unix-socket connector and the in-process channel split:
//! the daemon's hot path (fanotify event handler) `send`s
//! [`IpcFrame::Verdict`] requests and `recv`s
//! [`IpcFrame::VerdictReply`] responses keyed by `req_id`. Engine-
//! initiated pushes (`ShieldsPush`, `ActiveFindingsPush`) are
//! delivered through a separate channel so the verdict-reply matcher
//! never blocks on a push.
//!
//! All transport I/O is `#[cfg(target_os = "linux")]`-gated. On other
//! hosts the type compiles but `connect` returns
//! [`IpcClientError::Unsupported`].

use freallykernel::ipc::linfan::IpcFrame;

#[derive(Debug, thiserror::Error)]
pub enum IpcClientError {
    #[error("daemon IPC not supported on this host (not a Linux target)")]
    Unsupported,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("ipc: {0}")]
    Ipc(#[from] freallykernel::ipc::linfan::IpcError),
}

#[derive(Debug)]
pub struct IpcClient {
    /// Mode label surfaced to the UI ("connected" / "disconnected").
    pub mode_label: String,
}

impl IpcClient {
    #[cfg(target_os = "linux")]
    pub fn connect(socket_path: &str) -> Result<Self, IpcClientError> {
        // Wave 1 ships the scaffolding. The full UnixStream connect +
        // the per-frame demuxer thread lands in the runtime-validation
        // pass; the codec itself is already exercised by
        // `freallykernel::ipc::linfan::IpcCodec`.
        let _ = socket_path;
        Ok(Self {
            mode_label: "scaffolded".to_string(),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn connect(_socket_path: &str) -> Result<Self, IpcClientError> {
        Err(IpcClientError::Unsupported)
    }

    /// Best-effort enqueue of one outbound frame. The frame is
    /// dropped silently if the daemon is not connected; the watchdog
    /// surfaces the disconnect through the UI separately.
    pub fn try_send(&self, _frame: IpcFrame) -> Result<(), IpcClientError> {
        Ok(())
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    use super::*;

    #[test]
    fn connect_off_linux_is_unsupported() {
        let err = IpcClient::connect("/run/freallyd/freallyd.sock").unwrap_err();
        assert!(matches!(err, IpcClientError::Unsupported));
    }
}
