//! TASK-229 — Zero-trust newly-downloaded mode.
//!
//! Files that recently entered the user's machine via a browser or
//! mail client get extra scrutiny: full YARA pass, no verdict-cache
//! short-circuit, optional auto-quarantine on any non-clean finding.
//!
//! The "newly downloaded" signal comes from two sources:
//!   - **Windows**: the `Zone.Identifier:$DATA` alternate data stream
//!     (Mark of the Web). The browser writes one when downloading;
//!     `MOTW_ZONE_INTERNET` (3) or `MOTW_ZONE_RESTRICTED` (4) marks
//!     untrusted origins.
//!   - **macOS / Linux**: the `com.apple.quarantine` xattr on macOS
//!     and the file's birth/mtime relative to "now" elsewhere.
//!
//! The classifier returns a simple verdict; the engine layers it onto
//! the existing pipeline. Real xattr / ADS access is platform-
//! conditional and runs only when this mode is enabled.

use std::path::Path;
use std::time::SystemTime;

/// Default freshness window for non-Windows / non-macOS hosts.
pub const DEFAULT_FRESH_HOURS: u64 = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadOrigin {
    /// Windows Zone.Identifier ADS exists and the zone is Internet or
    /// Restricted; OR macOS com.apple.quarantine xattr present.
    Untrusted,
    /// File is newer than the configured freshness window but has no
    /// explicit untrusted marker. Treated as "elevated scrutiny but
    /// not auto-quarantine".
    Recent,
    /// No download evidence detected.
    None,
}

/// Pure classifier: given a path + its modified time + the current
/// time + the policy window, decide the download-origin label. The
/// Windows / macOS xattr reads happen separately at the engine's
/// per-platform shim and feed [`classify_with_marker`].
pub fn classify_age_only(
    mtime_secs: i64,
    now_unix_secs: i64,
    fresh_window_hours: u64,
) -> DownloadOrigin {
    let age_secs = (now_unix_secs - mtime_secs).max(0) as u64;
    let window_secs = fresh_window_hours.saturating_mul(3600);
    if age_secs < window_secs {
        DownloadOrigin::Recent
    } else {
        DownloadOrigin::None
    }
}

/// Classifier that combines a platform-provided "is this marked
/// untrusted?" signal with the age fallback. Pass `marker_untrusted =
/// true` when the Windows ADS / macOS xattr read indicates Internet
/// origin; the age check still runs as a fallback.
pub fn classify_with_marker(
    _path: &Path,
    mtime_secs: i64,
    now_unix_secs: i64,
    fresh_window_hours: u64,
    marker_untrusted: bool,
) -> DownloadOrigin {
    if marker_untrusted {
        return DownloadOrigin::Untrusted;
    }
    classify_age_only(mtime_secs, now_unix_secs, fresh_window_hours)
}

/// Convenience wrapper that fetches "now" from the system clock.
pub fn classify_now(
    path: &Path,
    mtime_secs: i64,
    fresh_window_hours: u64,
    marker_untrusted: bool,
) -> DownloadOrigin {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    classify_with_marker(path, mtime_secs, now, fresh_window_hours, marker_untrusted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn fresh_file_classifies_recent() {
        // mtime 1 hour ago, 24h window.
        assert_eq!(
            classify_age_only(1000, 1000 + 3600, 24),
            DownloadOrigin::Recent
        );
    }

    #[test]
    fn old_file_classifies_none() {
        // mtime 100h ago, 24h window.
        assert_eq!(
            classify_age_only(1000, 1000 + 360_000, 24),
            DownloadOrigin::None
        );
    }

    #[test]
    fn marker_overrides_age() {
        // Old file but marker says untrusted → Untrusted wins.
        assert_eq!(
            classify_with_marker(&PathBuf::from("/x"), 1000, 1000 + 1_000_000, 24, true,),
            DownloadOrigin::Untrusted
        );
        // Fresh file with marker also Untrusted (not Recent).
        assert_eq!(
            classify_with_marker(&PathBuf::from("/x"), 1000, 1000 + 60, 24, true),
            DownloadOrigin::Untrusted
        );
    }

    #[test]
    fn no_marker_falls_back_to_age() {
        assert_eq!(
            classify_with_marker(&PathBuf::from("/x"), 1000, 1000 + 60, 24, false),
            DownloadOrigin::Recent
        );
        assert_eq!(
            classify_with_marker(&PathBuf::from("/x"), 1000, 1000 + 1_000_000, 24, false,),
            DownloadOrigin::None
        );
    }

    #[test]
    fn future_mtime_treated_as_zero_age() {
        // Clock skew or restore-from-backup; mtime in the future
        // shouldn't crash or flip behavior.
        assert_eq!(
            classify_age_only(1_000_000, 500, 24),
            DownloadOrigin::Recent
        );
    }
}
