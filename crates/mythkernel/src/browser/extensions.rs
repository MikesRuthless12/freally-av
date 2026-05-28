//! Browser-extension enumeration (TASK-256, FEAT-201, Phase 10 Wave 2).
//!
//! Walks every Chrome / Edge / Brave / Arc profile's `Extensions/` dir
//! and every Firefox profile's `extensions/` dir, yielding one
//! [`BrowserExtension`] row per installed extension. The yara-x pass
//! over each extension's bundled JS / `manifest.json` is wired in the
//! Wave 2 closeout via the existing `yara_engine` detector — this
//! module supplies the manifest paths.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{BrowserFamily, BrowserRoots, chromium_profile_dirs, firefox_profile_dirs};

/// One installed browser extension observed on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserExtension {
    pub family: BrowserFamily,
    /// Absolute path to the profile directory the extension lives
    /// under (`Default`, `Profile 1`, `<random>.default-release`, …).
    pub profile_path: PathBuf,
    /// Chromium extension id (32-char alphabetical) or Firefox add-on
    /// id (`uuid@example.com` / `name@domain`).
    pub extension_id: String,
    pub name: Option<String>,
    pub version: Option<String>,
    /// Absolute path to the parsed `manifest.json`.
    pub manifest_path: PathBuf,
}

/// Enumerate every extension across every supplied root.
pub fn enumerate(roots: &BrowserRoots) -> Vec<BrowserExtension> {
    let mut out = Vec::new();
    for (family, root) in roots.iter() {
        if family.is_chromium() {
            enumerate_chromium(family, root, &mut out);
        } else if family == BrowserFamily::Firefox {
            enumerate_firefox(root, &mut out);
        }
        // Safari extensions ship as App Extensions (`.appex`) inside
        // signed app bundles — Safari does not honor a plain
        // `Extensions/` dir; coverage tracked under TASK-256 follow-up.
    }
    out
}

fn enumerate_chromium(
    family: BrowserFamily,
    user_data_root: &Path,
    out: &mut Vec<BrowserExtension>,
) {
    for profile_dir in chromium_profile_dirs(user_data_root) {
        let ext_root = profile_dir.join("Extensions");
        let Ok(read) = std::fs::read_dir(&ext_root) else {
            continue;
        };
        for entry in read.flatten() {
            let ext_dir = entry.path();
            if !ext_dir.is_dir() {
                continue;
            }
            let ext_id = match ext_dir.file_name().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            // Each extension dir contains one or more
            // `<version>/manifest.json` sub-directories. Pick the
            // lexically-greatest version present so re-scans on an
            // updated extension stamp the latest manifest.
            let mut versions: Vec<PathBuf> = match std::fs::read_dir(&ext_dir) {
                Ok(r) => r
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_dir())
                    .collect(),
                Err(_) => continue,
            };
            versions.sort();
            let Some(version_dir) = versions.pop() else {
                continue;
            };
            let manifest_path = version_dir.join("manifest.json");
            if let Some(manifest) = read_manifest(&manifest_path) {
                out.push(BrowserExtension {
                    family,
                    profile_path: profile_dir.clone(),
                    extension_id: ext_id,
                    name: manifest.name,
                    version: manifest.version,
                    manifest_path,
                });
            }
        }
    }
}

fn enumerate_firefox(profiles_root: &Path, out: &mut Vec<BrowserExtension>) {
    for profile_dir in firefox_profile_dirs(profiles_root) {
        let ext_root = profile_dir.join("extensions");
        let Ok(read) = std::fs::read_dir(&ext_root) else {
            continue;
        };
        for entry in read.flatten() {
            let ext_path = entry.path();
            let file_name = match ext_path.file_name().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            // Modern Firefox stores extensions as `<id>.xpi` (zip)
            // OR as unpacked `<id>/` directories when developer-mode
            // `xpinstall.signatures.required = false` is set.
            if ext_path.is_dir() {
                let manifest_path = ext_path.join("manifest.json");
                if let Some(m) = read_manifest(&manifest_path) {
                    out.push(BrowserExtension {
                        family: BrowserFamily::Firefox,
                        profile_path: profile_dir.clone(),
                        extension_id: file_name,
                        name: m.name,
                        version: m.version,
                        manifest_path,
                    });
                }
            } else if let Some(stem) = file_name.strip_suffix(".xpi") {
                // .xpi is a zip; parsing its inner manifest.json
                // would re-use the engine's `walker::archives`
                // pipeline. The foundation records the .xpi path
                // and id; full manifest extraction lands with the
                // closeout pass.
                out.push(BrowserExtension {
                    family: BrowserFamily::Firefox,
                    profile_path: profile_dir.clone(),
                    extension_id: stem.to_string(),
                    name: None,
                    version: None,
                    manifest_path: ext_path,
                });
            }
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct ManifestSummary {
    pub name: Option<String>,
    pub version: Option<String>,
}

pub(crate) fn read_manifest(path: &Path) -> Option<ManifestSummary> {
    let body = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&body).ok()?;
    Some(ManifestSummary {
        name: json
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        version: json
            .get("version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_manifest(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn chromium_enumeration_finds_default_profile_extensions() {
        let dir = tempdir().unwrap();
        let user_data = dir.path();
        let ext = "abcdefghijklmnopqrstuvwxyzabcdef";
        let version = "1.2.3";
        write_manifest(
            &user_data
                .join("Default/Extensions")
                .join(ext)
                .join(version)
                .join("manifest.json"),
            r#"{"name":"Test Ext","version":"1.2.3","manifest_version":3}"#,
        );
        std::fs::create_dir_all(user_data.join("Default")).unwrap();

        let roots = BrowserRoots {
            chrome: vec![user_data.to_path_buf()],
            ..Default::default()
        };
        let exts = enumerate(&roots);
        assert_eq!(exts.len(), 1);
        let only = &exts[0];
        assert_eq!(only.family, BrowserFamily::Chrome);
        assert_eq!(only.extension_id, ext);
        assert_eq!(only.name.as_deref(), Some("Test Ext"));
        assert_eq!(only.version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn chromium_picks_lexically_greatest_version_dir() {
        let dir = tempdir().unwrap();
        let user_data = dir.path();
        let ext = "p".repeat(32);
        // Two versions present; expect the higher one's manifest.
        write_manifest(
            &user_data
                .join("Default/Extensions")
                .join(&ext)
                .join("1.0.0")
                .join("manifest.json"),
            r#"{"name":"A","version":"1.0.0"}"#,
        );
        write_manifest(
            &user_data
                .join("Default/Extensions")
                .join(&ext)
                .join("2.0.0")
                .join("manifest.json"),
            r#"{"name":"B","version":"2.0.0"}"#,
        );
        std::fs::create_dir_all(user_data.join("Default")).unwrap();
        let roots = BrowserRoots {
            chrome: vec![user_data.to_path_buf()],
            ..Default::default()
        };
        let exts = enumerate(&roots);
        assert_eq!(exts.len(), 1);
        assert_eq!(exts[0].version.as_deref(), Some("2.0.0"));
        assert_eq!(exts[0].name.as_deref(), Some("B"));
    }

    #[test]
    fn firefox_enumeration_handles_unpacked_and_xpi() {
        let dir = tempdir().unwrap();
        let profiles_root = dir.path();
        let profile = profiles_root.join("abc.default-release");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::write(profile.join("prefs.js"), b"// stub").unwrap();

        // Unpacked extension.
        write_manifest(
            &profile.join("extensions/unpacked@example.com/manifest.json"),
            r#"{"name":"Unpacked","version":"0.9"}"#,
        );
        // .xpi (zip), not unpacked.
        std::fs::write(
            profile.join("extensions/packed@example.com.xpi"),
            b"PK\x03\x04 stub-zip",
        )
        .unwrap();

        let roots = BrowserRoots {
            firefox: vec![profiles_root.to_path_buf()],
            ..Default::default()
        };
        let exts = enumerate(&roots);
        assert_eq!(exts.len(), 2);
        let unpacked = exts
            .iter()
            .find(|e| e.extension_id == "unpacked@example.com")
            .unwrap();
        assert_eq!(unpacked.name.as_deref(), Some("Unpacked"));
        let packed = exts
            .iter()
            .find(|e| e.extension_id == "packed@example.com")
            .unwrap();
        assert!(packed.name.is_none());
        assert!(packed.manifest_path.extension().and_then(|s| s.to_str()) == Some("xpi"));
    }

    #[test]
    fn multiple_chromium_browsers_share_pipeline() {
        let dir = tempdir().unwrap();
        let chrome_root = dir.path().join("chrome-data");
        let edge_root = dir.path().join("edge-data");
        write_manifest(
            &chrome_root.join("Default/Extensions/aa/1.0/manifest.json"),
            r#"{"name":"FromChrome","version":"1.0"}"#,
        );
        write_manifest(
            &edge_root.join("Default/Extensions/bb/1.0/manifest.json"),
            r#"{"name":"FromEdge","version":"1.0"}"#,
        );
        std::fs::create_dir_all(chrome_root.join("Default")).unwrap();
        std::fs::create_dir_all(edge_root.join("Default")).unwrap();
        let roots = BrowserRoots {
            chrome: vec![chrome_root],
            edge: vec![edge_root],
            ..Default::default()
        };
        let exts = enumerate(&roots);
        assert_eq!(exts.len(), 2);
        assert!(
            exts.iter()
                .any(|e| e.family == BrowserFamily::Chrome
                    && e.name.as_deref() == Some("FromChrome"))
        );
        assert!(
            exts.iter()
                .any(|e| e.family == BrowserFamily::Edge && e.name.as_deref() == Some("FromEdge"))
        );
    }

    #[test]
    fn missing_extensions_dir_is_silent() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("Default")).unwrap();
        let roots = BrowserRoots {
            chrome: vec![dir.path().to_path_buf()],
            ..Default::default()
        };
        assert!(enumerate(&roots).is_empty());
    }

    #[test]
    fn malformed_manifest_is_skipped() {
        let dir = tempdir().unwrap();
        let user_data = dir.path();
        write_manifest(
            &user_data.join("Default/Extensions/aa/1.0/manifest.json"),
            "not valid json {{{",
        );
        std::fs::create_dir_all(user_data.join("Default")).unwrap();
        let roots = BrowserRoots {
            chrome: vec![user_data.to_path_buf()],
            ..Default::default()
        };
        assert!(enumerate(&roots).is_empty());
    }
}
