//! `.app`-on-USB-drive heuristic (TASK-247, Phase 8 Wave 2).
//!
//! macOS-only — on every USB-insert scan, glob `<mountpoint>/**/*.app`
//! at depth ≤ 3, consult the per-device allowlist (TASK-242) and a
//! separate per-bundle allowlist (`usb_app_allowlist (bundle_id,
//! team_id)`), and raise `Finding::AppOnRemovableMedia` for any
//! unmatched bundle.
//!
//! Alert-only — the bundle is not blocked from running, per § 1.5.4
//! (no ESF AUTH).

use std::path::{Path, PathBuf};

/// Default depth cap for the `.app` recursion. Avoids scanning a user
/// backup dump or a virtualized macOS image.
pub const DEFAULT_MAX_DEPTH: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppOnRemovableMediaFinding {
    pub bundle_path: PathBuf,
    pub bundle_id: Option<String>,
}

/// Enumerate every `.app` bundle under `root` at depth ≤ `max_depth`.
/// Pure helper — does not stat the bundle's contents; the caller
/// reads `Info.plist` for the bundle_id + team_id.
pub fn enumerate_app_bundles(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(root, 0, max_depth, &mut out);
    out
}

fn walk(dir: &Path, depth: usize, max_depth: usize, out: &mut Vec<PathBuf>) {
    if depth > max_depth {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_app = path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|n| n.ends_with(".app"));
        if is_app {
            out.push(path);
            continue;
        }
        if path.is_dir() {
            walk(&path, depth + 1, max_depth, out);
        }
    }
}

/// Build the finding shape from a bundle path. Caller is responsible
/// for parsing `Info.plist` (path is `<bundle>/Contents/Info.plist`)
/// for the bundle_id; the planner only needs the path to label.
pub fn build_finding(
    bundle_path: PathBuf,
    bundle_id: Option<String>,
) -> AppOnRemovableMediaFinding {
    AppOnRemovableMediaFinding {
        bundle_path,
        bundle_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn enumerates_app_bundles_at_depth_limit() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a/b/c/Deep.app")).unwrap();
        std::fs::create_dir_all(dir.path().join("Shallow.app")).unwrap();
        let apps = enumerate_app_bundles(dir.path(), 3);
        let names: Vec<String> = apps
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|n| n == "Shallow.app"));
        assert!(names.iter().any(|n| n == "Deep.app"));
    }

    #[test]
    fn depth_limit_excludes_deeper_bundles() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a/b/c/d/TooDeep.app")).unwrap();
        let apps = enumerate_app_bundles(dir.path(), 3);
        assert!(
            !apps
                .iter()
                .any(|p| p.file_name().unwrap().to_string_lossy() == "TooDeep.app")
        );
    }

    #[test]
    fn build_finding_carries_bundle_id() {
        let f = build_finding(
            PathBuf::from("/Volumes/USB/X.app"),
            Some("com.bad.x".into()),
        );
        assert_eq!(f.bundle_id.as_deref(), Some("com.bad.x"));
    }
}
