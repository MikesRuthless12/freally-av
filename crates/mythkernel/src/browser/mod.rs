//! Browser-forensics module (Phase 10 Wave 2 — TASK-256..270).
//!
//! Cross-browser support for the five families the roadmap calls out:
//! Chrome, Edge, Brave, Arc (all Chromium-derived) plus Firefox. Each
//! browser has a documented on-disk layout for the artefacts this
//! module reads: extensions, downloads history, persistent cookies,
//! cached resources, saved passwords, root certificates, autofill, and
//! Local State / `key4.db` — the so-called "master key" files that
//! infostealers target. The submodules implement one read-only surface
//! per file, with caller-supplied profile roots so the matchers stay
//! pure-logic and trivially testable.
//!
//! ## Scope split
//!
//! Phase 10 Wave 2 lands the **engine-side foundations**: type shapes,
//! parsers, walkers, and matchers, each with unit tests against
//! synthetic data. The closeout UI pass (Solid.js, gitignored frontend
//! tree) lands the four new pages (`BrowserExtensions.tsx`,
//! `BrowserCerts.tsx`, `BrowserAutofill.tsx`, and the
//! `BrowserDownloads` history view), the corresponding Tauri commands
//! in `crates/ui-bridge`, and the network-fetching updaters
//! (PhishTank flat-file, browser cert-store delta cron) — every
//! follow-up is mechanical because the shapes here are stable.
//!
//! All file access is read-only. No browser is ever launched, paused,
//! or queried via DevTools network; no off-host send is ever made
//! from these readers. Per `docs/prd.md` § 1.5.4 the entire surface
//! stays in the user-mode read-only stack.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub mod autofill_inventory;
pub mod cache_scan;
pub mod cert_store_delta;
pub mod cookie_exfil;
pub mod downloads;
pub mod driveby;
pub mod extensions;
pub mod idn_spoof;
pub mod malvert;
pub mod master_key_watch;
pub mod mime_mismatch;
pub mod password_store_integrity;
pub mod permissions;
pub mod phishtank;
pub mod tab_process;

/// Closed enum of supported browser families. Stored in DB rows + JSON
/// payloads as the lower-case string returned by [`BrowserFamily::as_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFamily {
    Chrome,
    Edge,
    Brave,
    Arc,
    Firefox,
    Safari,
}

impl BrowserFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            BrowserFamily::Chrome => "chrome",
            BrowserFamily::Edge => "edge",
            BrowserFamily::Brave => "brave",
            BrowserFamily::Arc => "arc",
            BrowserFamily::Firefox => "firefox",
            BrowserFamily::Safari => "safari",
        }
    }

    /// `true` when the browser stores artefacts in Chromium's
    /// canonical layout (`Default/`, `Profile <n>/`, `Extensions/`,
    /// `History` SQLite, `Login Data`, `Cookies`, `Local State`,
    /// `Web Data`, `Certificates`). Used by the submodules to
    /// avoid re-listing the same four browsers per scanner.
    pub fn is_chromium(self) -> bool {
        matches!(
            self,
            BrowserFamily::Chrome | BrowserFamily::Edge | BrowserFamily::Brave | BrowserFamily::Arc
        )
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "chrome" => BrowserFamily::Chrome,
            "edge" => BrowserFamily::Edge,
            "brave" => BrowserFamily::Brave,
            "arc" => BrowserFamily::Arc,
            "firefox" => BrowserFamily::Firefox,
            "safari" => BrowserFamily::Safari,
            _ => return None,
        })
    }
}

/// Caller-supplied root paths for browser data discovery. Each entry
/// is the per-browser **user-data root** — the directory that contains
/// `Default/` (Chromium) or profile-id-named subdirs (Firefox). The
/// submodules join in the per-artefact subpath themselves.
///
/// Per-OS canonical roots (for the daemon side / Tauri config):
///
///   * Chrome on Windows: `%LOCALAPPDATA%\Google\Chrome\User Data`
///   * Chrome on macOS: `~/Library/Application Support/Google/Chrome`
///   * Chrome on Linux: `~/.config/google-chrome`
///   * Edge on Windows: `%LOCALAPPDATA%\Microsoft\Edge\User Data`
///   * Brave on Windows: `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data`
///   * Arc on macOS: `~/Library/Application Support/Arc/User Data`
///   * Firefox on Windows: `%APPDATA%\Mozilla\Firefox\Profiles`
///   * Firefox on macOS: `~/Library/Application Support/Firefox/Profiles`
///   * Firefox on Linux: `~/.mozilla/firefox`
///   * Safari on macOS: `~/Library/Safari` (only macOS has Safari)
///
/// Tests supply tempdir paths; the daemon supplies env-resolved
/// absolute paths. Missing roots are silently tolerated by every
/// submodule.
#[derive(Debug, Clone, Default)]
pub struct BrowserRoots {
    pub chrome: Vec<PathBuf>,
    pub edge: Vec<PathBuf>,
    pub brave: Vec<PathBuf>,
    pub arc: Vec<PathBuf>,
    pub firefox: Vec<PathBuf>,
    pub safari: Vec<PathBuf>,
}

impl BrowserRoots {
    /// Iterate `(family, root)` pairs across every populated browser.
    pub fn iter(&self) -> impl Iterator<Item = (BrowserFamily, &Path)> {
        self.chrome
            .iter()
            .map(|p| (BrowserFamily::Chrome, p.as_path()))
            .chain(self.edge.iter().map(|p| (BrowserFamily::Edge, p.as_path())))
            .chain(
                self.brave
                    .iter()
                    .map(|p| (BrowserFamily::Brave, p.as_path())),
            )
            .chain(self.arc.iter().map(|p| (BrowserFamily::Arc, p.as_path())))
            .chain(
                self.firefox
                    .iter()
                    .map(|p| (BrowserFamily::Firefox, p.as_path())),
            )
            .chain(
                self.safari
                    .iter()
                    .map(|p| (BrowserFamily::Safari, p.as_path())),
            )
    }
}

/// Locate profile sub-directories under a Chromium user-data root.
/// Profiles are `Default/`, `Profile 1/`, `Profile 2/`, … and any
/// `Guest Profile/`. Returns the absolute path to each. Non-existent
/// user-data root yields an empty vec.
pub fn chromium_profile_dirs(user_data_root: &Path) -> Vec<PathBuf> {
    let Ok(read) = std::fs::read_dir(user_data_root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in read.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name == "Default"
            || name == "Guest Profile"
            || name.starts_with("Profile ")
            || name.starts_with("Profile_")
        {
            out.push(p);
        }
    }
    out
}

/// Locate profile sub-directories under a Firefox profiles root.
/// Each Firefox profile dir is named `<random>.<profile-name>` (e.g.
/// `xyz123.default-release`).
pub fn firefox_profile_dirs(profiles_root: &Path) -> Vec<PathBuf> {
    let Ok(read) = std::fs::read_dir(profiles_root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in read.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        // Firefox profile dir names embed a `.` separating the
        // random prefix from the profile label. Skip
        // `Crash Reports`, `Pending Pings`, etc. that sit alongside
        // profiles but aren't profile dirs themselves.
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.contains('.') {
            continue;
        }
        // Mozilla writes `profiles.ini` next to these dirs; presence of
        // `prefs.js` inside is the cheapest validity probe.
        if p.join("prefs.js").is_file() || p.join("times.json").is_file() {
            out.push(p);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn family_string_round_trip() {
        for f in [
            BrowserFamily::Chrome,
            BrowserFamily::Edge,
            BrowserFamily::Brave,
            BrowserFamily::Arc,
            BrowserFamily::Firefox,
            BrowserFamily::Safari,
        ] {
            assert_eq!(BrowserFamily::parse(f.as_str()), Some(f));
        }
        assert!(BrowserFamily::parse("nonsense").is_none());
    }

    #[test]
    fn is_chromium_partitions_correctly() {
        assert!(BrowserFamily::Chrome.is_chromium());
        assert!(BrowserFamily::Edge.is_chromium());
        assert!(BrowserFamily::Brave.is_chromium());
        assert!(BrowserFamily::Arc.is_chromium());
        assert!(!BrowserFamily::Firefox.is_chromium());
        assert!(!BrowserFamily::Safari.is_chromium());
    }

    #[test]
    fn chromium_profile_dirs_includes_default_and_numbered() {
        let dir = tempdir().unwrap();
        for p in &["Default", "Profile 1", "Profile 2", "Guest Profile"] {
            std::fs::create_dir_all(dir.path().join(p)).unwrap();
        }
        // Sibling that isn't a profile.
        std::fs::create_dir_all(dir.path().join("System Profile")).unwrap();
        let profiles = chromium_profile_dirs(dir.path());
        let names: Vec<String> = profiles
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"Default".to_string()));
        assert!(names.contains(&"Profile 1".to_string()));
        assert!(names.contains(&"Profile 2".to_string()));
        assert!(names.contains(&"Guest Profile".to_string()));
        assert!(!names.contains(&"System Profile".to_string()));
    }

    #[test]
    fn chromium_profile_dirs_tolerates_missing_root() {
        let profiles = chromium_profile_dirs(Path::new("/does/not/exist"));
        assert!(profiles.is_empty());
    }

    #[test]
    fn firefox_profile_dirs_only_returns_validated_profile_layouts() {
        let dir = tempdir().unwrap();
        let profile_a = dir.path().join("abc123.default-release");
        std::fs::create_dir_all(&profile_a).unwrap();
        std::fs::write(profile_a.join("prefs.js"), b"// stub").unwrap();

        let profile_b = dir.path().join("xyz789.dev-edition");
        std::fs::create_dir_all(&profile_b).unwrap();
        std::fs::write(profile_b.join("times.json"), b"{}").unwrap();

        // Decoy: lacks the validity probe.
        let decoy = dir.path().join("hash.fake-profile");
        std::fs::create_dir_all(&decoy).unwrap();

        // Decoy: name without `.` is skipped (Crash Reports / Pending Pings).
        std::fs::create_dir_all(dir.path().join("Crash Reports")).unwrap();

        let profiles = firefox_profile_dirs(dir.path());
        let names: Vec<String> = profiles
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"abc123.default-release".to_string()));
        assert!(names.contains(&"xyz789.dev-edition".to_string()));
    }

    #[test]
    fn browser_roots_iter_yields_every_populated_pair() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        let roots = BrowserRoots {
            chrome: vec![a.clone()],
            firefox: vec![b.clone()],
            ..Default::default()
        };
        let pairs: Vec<(BrowserFamily, PathBuf)> =
            roots.iter().map(|(f, p)| (f, p.to_path_buf())).collect();
        assert_eq!(pairs.len(), 2);
        assert!(pairs.contains(&(BrowserFamily::Chrome, a)));
        assert!(pairs.contains(&(BrowserFamily::Firefox, b)));
    }
}
