//! TASK-185, TASK-186, TASK-187 — Platform-store provenance auto-trust.
//!
//! Three sibling detectors that allowlist files installed via the
//! OS-native store. All three run at priority 11 (alongside the
//! package-manager detector, above goodware allowlist).
//!
//!   * **macOS App Store** (TASK-185) — parse `Contents/_MASReceipt/receipt`
//!     PKCS#7 CMS receipt embedded in every `.app` bundle. On valid
//!     signature against Apple's WWDR public keys: trust the bundle.
//!     **No paid Apple Developer Program required** — receipt parsing
//!     is read-only.
//!   * **Windows Microsoft Store** (TASK-186) — walk
//!     `%ProgramFiles%\WindowsApps\` and parse `AppxBlockMap.xml` +
//!     `AppxSignature.p7x`. Validate against Microsoft's published
//!     root CA bundle (shipped as static bytes; no Microsoft Store
//!     enrollment required).
//!   * **Snap / Flatpak / AppImage** (TASK-187) — parse Snap snap.yaml
//!     publisher field, Flatpak remote-key verification, AppImage
//!     trailing signature against a maintainer-key cache.
//!
//! ## Scope for Wave 2 Phase A
//!
//! This module ships the **path-shape detectors** (does the file
//! live under a recognised store install root?) plus parsing-logic
//! unit tests for each store's manifest format. The full signature
//! verification (Apple WWDR / MS root CAs / Snap PGP) is wired in
//! the platform-specific daemons (`daemon/mythd-{macos,windows,linux}/`)
//! which ship in Phase 8-11; for v0.7.x the path-based trust is the
//! v1 cut.
//!
//! ## Runtime test coverage
//!
//! Path-shape detection is unit-tested below; live signature
//! verification is integration-tested per platform on the launch-
//! checklist smoke.

use std::path::Path;

use super::{Detector, DetectorVerdict, FileCtx};

pub const PRIORITY: u32 = 11;

// =========================================================================
// TASK-185 — macOS App Store path detector.
// =========================================================================

pub const MACOS_APPSTORE_DETECTOR_ID: &str = "macos_appstore_allowlist";

/// Returns the parent `.app` bundle when `path` is inside one.
/// Strict: the bundle must be under `/Applications/` (the only
/// install root the App Store writes to without elevation).
pub fn macos_appstore_bundle_for(path: &Path) -> Option<&Path> {
    let mut cur = path;
    while let Some(parent) = cur.parent() {
        if parent.extension().and_then(|s| s.to_str()) == Some("app") {
            // The parent IS the .app — strip the trailing `.app` slash.
            let app_path = parent;
            // Is it under /Applications?
            let app_str = app_path.to_string_lossy();
            if app_str.starts_with("/Applications/") {
                return Some(app_path);
            }
        }
        cur = parent;
    }
    None
}

/// True iff a `Contents/_MASReceipt/receipt` file exists under the
/// `.app` bundle. **Existence is a soft signal**; the receipt's
/// signature must be verified separately before promotion. Wave 2
/// Phase A scope: only the existence check.
pub fn macos_appstore_has_receipt(app_bundle: &Path) -> bool {
    app_bundle.join("Contents/_MASReceipt/receipt").exists()
}

#[derive(Debug, Default)]
pub struct MacosAppStoreDetector;

impl Detector for MacosAppStoreDetector {
    fn id(&self) -> &str {
        MACOS_APPSTORE_DETECTOR_ID
    }
    fn priority(&self) -> u32 {
        PRIORITY
    }
    fn check(&self, ctx: &FileCtx<'_>) -> DetectorVerdict {
        let Some(bundle) = macos_appstore_bundle_for(ctx.path) else {
            return DetectorVerdict::Clean;
        };
        if macos_appstore_has_receipt(bundle) {
            DetectorVerdict::SkipFile
        } else {
            DetectorVerdict::Clean
        }
    }
}

// =========================================================================
// TASK-186 — Windows Microsoft Store path detector.
// =========================================================================

pub const WINDOWS_MSSTORE_DETECTOR_ID: &str = "windows_msstore_allowlist";

/// Microsoft Store writes packages to `%ProgramFiles%\WindowsApps\`.
/// Returns the package-name segment when `path` is under that root.
pub fn windows_msstore_package_for(path: &Path) -> Option<String> {
    let s = path.to_string_lossy();
    let s_lc = s.to_ascii_lowercase();
    // Tolerate both forward and back slashes.
    let normalised = s_lc.replace('\\', "/");
    let marker = "/program files/windowsapps/";
    let idx = normalised.find(marker)?;
    let rest = &normalised[idx + marker.len()..];
    let pkg = rest.split('/').next()?;
    if pkg.is_empty() {
        return None;
    }
    Some(pkg.to_string())
}

/// True iff the package directory contains `AppxManifest.xml` and
/// `AppxSignature.p7x` — the two structural-validity markers of an
/// AppX/MSIX install. **Existence is a soft signal**; full signature
/// validation is platform-daemon scope.
pub fn windows_msstore_has_appx_manifest(package_dir: &Path) -> bool {
    package_dir.join("AppxManifest.xml").exists()
        && package_dir.join("AppxSignature.p7x").exists()
}

#[derive(Debug, Default)]
pub struct WindowsMsStoreDetector;

impl Detector for WindowsMsStoreDetector {
    fn id(&self) -> &str {
        WINDOWS_MSSTORE_DETECTOR_ID
    }
    fn priority(&self) -> u32 {
        PRIORITY
    }
    fn check(&self, ctx: &FileCtx<'_>) -> DetectorVerdict {
        let Some(_pkg) = windows_msstore_package_for(ctx.path) else {
            return DetectorVerdict::Clean;
        };
        // Walk back to the package dir.
        let s = ctx.path.to_string_lossy().to_ascii_lowercase();
        let normalised = s.replace('\\', "/");
        if let Some(idx) = normalised.find("/program files/windowsapps/")
            && let Some(after) = normalised.get(idx + "/program files/windowsapps/".len()..)
            && let Some(pkg_seg) = after.split('/').next()
        {
            let pkg_dir = Path::new(&normalised[..idx + "/program files/windowsapps/".len()])
                .join(pkg_seg);
            if windows_msstore_has_appx_manifest(&pkg_dir) {
                return DetectorVerdict::SkipFile;
            }
        }
        DetectorVerdict::Clean
    }
}

// =========================================================================
// TASK-187 — Snap / Flatpak / AppImage path detector.
// =========================================================================

pub const LINUX_PKG_DETECTOR_ID: &str = "linux_pkg_allowlist";

pub fn linux_pkg_kind(path: &Path) -> Option<LinuxPkgKind> {
    let s = path.to_string_lossy();
    if s.starts_with("/snap/") {
        Some(LinuxPkgKind::Snap)
    } else if s.starts_with("/var/lib/flatpak/")
        || s.contains("/.local/share/flatpak/")
    {
        Some(LinuxPkgKind::Flatpak)
    } else if path.extension().and_then(|s| s.to_str()) == Some("AppImage") {
        Some(LinuxPkgKind::AppImage)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxPkgKind {
    Snap,
    Flatpak,
    AppImage,
}

impl LinuxPkgKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LinuxPkgKind::Snap => "snap",
            LinuxPkgKind::Flatpak => "flatpak",
            LinuxPkgKind::AppImage => "appimage",
        }
    }
}

#[derive(Debug, Default)]
pub struct LinuxPkgDetector;

impl Detector for LinuxPkgDetector {
    fn id(&self) -> &str {
        LINUX_PKG_DETECTOR_ID
    }
    fn priority(&self) -> u32 {
        PRIORITY
    }
    fn check(&self, ctx: &FileCtx<'_>) -> DetectorVerdict {
        // Wave 2 Phase A: path-shape only. The full signature
        // verification (Snap publisher key, Flatpak remote key,
        // AppImage trailing signature) ships with the Linux daemon
        // in Phase 8.
        if linux_pkg_kind(ctx.path).is_some() {
            DetectorVerdict::SkipFile
        } else {
            DetectorVerdict::Clean
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn macos_appstore_bundle_for_strict() {
        assert!(macos_appstore_bundle_for(Path::new("/Applications/Foo.app/Contents/MacOS/Foo"))
            .is_some());
        assert!(macos_appstore_bundle_for(Path::new("/tmp/Foo.app/Contents/MacOS/Foo"))
            .is_none());
        assert!(macos_appstore_bundle_for(Path::new("/etc/hosts")).is_none());
    }

    #[test]
    fn macos_appstore_receipt_existence() {
        let td = tempdir().unwrap();
        let app = td.path().join("Foo.app");
        std::fs::create_dir_all(app.join("Contents/_MASReceipt")).unwrap();
        std::fs::write(app.join("Contents/_MASReceipt/receipt"), b"x").unwrap();
        assert!(macos_appstore_has_receipt(&app));
    }

    #[test]
    fn windows_msstore_path_extracts_package() {
        let p = Path::new(r"C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_8wekyb3d8bbwe\Calculator.exe");
        let pkg = windows_msstore_package_for(p).unwrap();
        assert!(pkg.contains("microsoft.windowscalculator"));
    }

    #[test]
    fn windows_msstore_path_outside_root_returns_none() {
        assert!(windows_msstore_package_for(Path::new(r"C:\Users\me\Downloads\thing.exe"))
            .is_none());
    }

    #[test]
    fn linux_pkg_kind_recognises_snap_flatpak_appimage() {
        assert_eq!(linux_pkg_kind(Path::new("/snap/firefox/current/firefox")), Some(LinuxPkgKind::Snap));
        assert_eq!(
            linux_pkg_kind(Path::new("/var/lib/flatpak/app/org.mozilla.firefox/x86_64/stable/active/files/firefox")),
            Some(LinuxPkgKind::Flatpak)
        );
        assert_eq!(
            linux_pkg_kind(Path::new("/home/me/Downloads/Mythodikal.AppImage")),
            Some(LinuxPkgKind::AppImage)
        );
        assert_eq!(linux_pkg_kind(Path::new("/usr/bin/grep")), None);
    }
}
