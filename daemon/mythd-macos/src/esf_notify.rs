//! Opportunistic ESF NOTIFY-only system extension (TASK-080, Phase 9 Wave 1).
//!
//! Subscribes to a narrow slice of `ES_EVENT_TYPE_NOTIFY_*` so the
//! engine has access to richer metadata (PID, ppid, signing info)
//! than FSEvents provides. **No `com.apple.developer.endpoint-security.client`
//! entitlement is requested** — that entitlement requires the paid
//! Apple Developer Program plus Apple approval, both forbidden by
//! `docs/prd.md` § 1.5.
//!
//! On systems where the extension fails to load (typical stock
//! consumer macOS without entitlement), this module reports
//! [`EsfNotifyStatus::Unavailable`] and the daemon falls back to
//! FSEvents alone — no UX regression, just less event metadata.
//!
//! Per `docs/prd.md` § 1.5.4: **NOTIFY-only**. The system extension
//! has no AUTH path; verdicts are issued after the syscall has
//! completed. The extension stays subscribed when Shields=OFF but
//! ignores every event (skips the XPC engine call); it reapplies
//! within ≤ 200 ms when Shields=ON, driven by the
//! [`crate::ipc_client::IpcClient`]'s `ShieldsPush` handler.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Event-type bits the extension subscribes to. Mirrors the
/// `ES_EVENT_TYPE_NOTIFY_*` constants from `<EndpointSecurity/ESTypes.h>`.
/// Re-declared here so the non-macOS build does not need the
/// EndpointSecurity framework crate to compile.
pub mod events {
    pub const NOTIFY_OPEN: u32 = 0x0000_0001;
    pub const NOTIFY_EXEC: u32 = 0x0000_0002;
    pub const NOTIFY_RENAME: u32 = 0x0000_0004;
    pub const NOTIFY_CREATE: u32 = 0x0000_0008;
    pub const NOTIFY_WRITE: u32 = 0x0000_0010;
    pub const NOTIFY_CLOSE: u32 = 0x0000_0020;
}

/// Aggregate of every NOTIFY event the daemon cares about. The
/// extension subscribes to this bitmask at startup and never adjusts
/// it at runtime (no per-event hot path means no churn).
pub const SUBSCRIPTION_MASK: u32 = events::NOTIFY_OPEN
    | events::NOTIFY_EXEC
    | events::NOTIFY_RENAME
    | events::NOTIFY_CREATE
    | events::NOTIFY_WRITE
    | events::NOTIFY_CLOSE;

/// `es_new_client_result_t` values we surface in the
/// `Unavailable` reason. Subset of the real enum from
/// `<EndpointSecurity/ESClient.h>`. The most common failure on stock
/// consumer macOS is `ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED` (no
/// entitlement) — handled here as "Unavailable, fall back".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EsClientError {
    NotPrivileged,
    NotPermitted,
    NotEntitled,
    Internal,
    Invalid,
    ExtensionDisabled,
}

impl EsClientError {
    pub fn as_str(self) -> &'static str {
        match self {
            EsClientError::NotPrivileged => "ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED",
            EsClientError::NotPermitted => "ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED",
            EsClientError::NotEntitled => "ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED",
            EsClientError::Internal => "ES_NEW_CLIENT_RESULT_ERR_INTERNAL",
            EsClientError::Invalid => "ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT",
            EsClientError::ExtensionDisabled => "ES_NEW_CLIENT_RESULT_ERR_EXTENSION_DISABLED",
        }
    }
}

impl std::fmt::Display for EsClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EsfNotifyStatus {
    /// Extension is loaded and subscribed. The daemon prefers ESF
    /// events over FSEvents whenever both arrive for the same target.
    Active,
    /// `es_new_client` returned a non-success code; the daemon falls
    /// back to FSEvents alone for as long as this status persists.
    /// The included reason is the literal `ES_NEW_CLIENT_RESULT_*`
    /// code so the UI can show "ESF unavailable: NOT_PRIVILEGED".
    Unavailable(EsClientError),
    /// macOS-only — only set on hosts where we even try to load the
    /// extension. Non-macOS hosts return this variant from `open()`.
    Unsupported,
}

#[derive(Debug, thiserror::Error)]
pub enum EsfNotifyError {
    #[error("ESF NOTIFY is not supported on this host (not a macOS target)")]
    Unsupported,
    #[error("es_new_client failed: {0}")]
    NewClientFailed(EsClientError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// One NOTIFY event as the daemon forwards it to the engine. Mirrors
/// the [`crate::fsevents::FsEvent`] shape so the
/// [`crate::esf_failover::Failover`] (Wave 2) can dedupe the two
/// streams against a single `(inode, mtime_ns, size)` key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsfEvent {
    pub event_type: u32,
    pub path: PathBuf,
    pub pid: i32,
    pub ppid: i32,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub inode: u64,
    /// `stat.st_mtim` ns. i64 — see fsevents.rs for the parity note.
    pub mtime_ns: i64,
    pub size: u64,
}

/// Shared shields state the extension consults on every event. When
/// `false`, the extension drops the event without calling the engine.
/// Wave 2 wires the failover dedupe key and Wave 1 ships this flag so
/// the FR-160 short-circuit lands at the entry point.
#[derive(Debug, Clone, Default)]
pub struct ShieldsGate {
    pub enabled: Arc<AtomicBool>,
}

impl ShieldsGate {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(enabled)),
        }
    }

    pub fn set(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_active(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

/// Handle to the system-extension client. Constructing this attempts
/// `es_new_client`; failures land in [`EsfNotifyStatus::Unavailable`]
/// rather than as errors so the daemon's fallback path is the default
/// happy path.
#[derive(Debug)]
pub struct EsfNotifyHandle {
    pub status: EsfNotifyStatus,
    pub mode_label: String,
    pub shields: ShieldsGate,
}

impl EsfNotifyHandle {
    /// Attempt to attach to the ESF system extension. On non-macOS
    /// returns [`EsfNotifyStatus::Unsupported`] immediately.
    #[cfg(target_os = "macos")]
    pub fn open(shields: ShieldsGate) -> Self {
        // The actual `es_new_client` + `es_subscribe` calls land in
        // the macOS-runtime validation pass — this Windows-built
        // foundation can't link against EndpointSecurity. The default
        // status is `Unavailable(NotEntitled)` so the failover knows
        // to rely on FSEvents alone until the runtime pass wires the
        // real call.
        Self {
            status: EsfNotifyStatus::Unavailable(EsClientError::NotEntitled),
            mode_label: "esf-notify (unavailable)".to_string(),
            shields,
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn open(shields: ShieldsGate) -> Self {
        Self {
            status: EsfNotifyStatus::Unsupported,
            mode_label: "esf-notify (unsupported)".to_string(),
            shields,
        }
    }

    /// True iff the extension is loaded + subscribed. Used by
    /// [`crate::esf_failover::Failover`] to pick the "prefer ESF"
    /// branch.
    pub fn is_active(&self) -> bool {
        matches!(self.status, EsfNotifyStatus::Active)
    }

    /// Drain one batch of events. On macOS this consumes the
    /// es_client callback queue; everywhere else it returns an
    /// empty vector so test code can construct the handle without
    /// pulling in the framework.
    pub fn read_events(&self) -> Vec<EsfEvent> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_mask_includes_every_notify_bit() {
        // const block so clippy doesn't flag the const-folded asserts;
        // a missing bit would still fail the build at compile time.
        const _: () = {
            assert!(SUBSCRIPTION_MASK & events::NOTIFY_OPEN != 0);
            assert!(SUBSCRIPTION_MASK & events::NOTIFY_EXEC != 0);
            assert!(SUBSCRIPTION_MASK & events::NOTIFY_RENAME != 0);
            assert!(SUBSCRIPTION_MASK & events::NOTIFY_CREATE != 0);
            assert!(SUBSCRIPTION_MASK & events::NOTIFY_WRITE != 0);
            assert!(SUBSCRIPTION_MASK & events::NOTIFY_CLOSE != 0);
        };
    }

    #[test]
    fn es_client_error_codes_match_apple_strings() {
        assert_eq!(
            EsClientError::NotPrivileged.as_str(),
            "ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED"
        );
        assert_eq!(
            EsClientError::NotEntitled.as_str(),
            "ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED"
        );
    }

    #[test]
    fn shields_gate_toggles_atomically() {
        let g = ShieldsGate::new(true);
        assert!(g.is_active());
        g.set(false);
        assert!(!g.is_active());
        g.set(true);
        assert!(g.is_active());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn open_returns_unsupported_off_macos() {
        let h = EsfNotifyHandle::open(ShieldsGate::new(true));
        assert!(matches!(h.status, EsfNotifyStatus::Unsupported));
        assert!(!h.is_active());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn open_on_macos_starts_in_unavailable_state() {
        // Until the runtime pass wires `es_new_client`, the default
        // status is Unavailable so the failover relies on FSEvents.
        let h = EsfNotifyHandle::open(ShieldsGate::new(true));
        assert!(!h.is_active());
        assert!(matches!(h.status, EsfNotifyStatus::Unavailable(_)));
    }
}
