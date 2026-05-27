//! Platform-specific code (TASK-136 / TASK-138 / future Phase 5+).
//!
//! Each submodule provides a single entry point with a cross-platform shape:
//! the actual implementation lives in the cfg-gated `linux` / `mac` / `win`
//! children. Callers (engine, detectors, real-time daemons) never `cfg!` —
//! they go through these shims.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod mac;
#[cfg(target_os = "windows")]
pub mod win;

/// WSL distro parser — shared between the Windows host bridge and the
/// Linux peer tagger (TASK-240, Phase 8 Wave 2). Pure parsing; the
/// actual `wsl.exe` shell-out lives in
/// `daemon/mythd-windows/src/wsl_bridge.rs`.
pub mod wsl;

pub mod codesign {
    //! Cross-platform signer extraction (TASK-136).

    use crate::detect::publisher::SignerIdentity;
    use std::path::Path;

    /// Best-effort signer extraction. Always returns a [`SignerIdentity`];
    /// platforms or files without a recognized signature return
    /// `SignerIdentity::unsigned()`.
    pub fn extract_signer(path: &Path) -> SignerIdentity {
        #[cfg(target_os = "linux")]
        {
            crate::platform::linux::codesign::extract_signer(path)
        }
        #[cfg(target_os = "macos")]
        {
            crate::platform::mac::codesign::extract_signer(path)
        }
        #[cfg(target_os = "windows")]
        {
            crate::platform::win::codesign::extract_signer(path)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let _ = path;
            SignerIdentity::unsigned()
        }
    }
}
