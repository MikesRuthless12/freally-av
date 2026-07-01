//! `node_modules/` package walker (TASK-306).
//!
//! Walks every `node_modules/<scope?>/<pkg>/package.json` under
//! caller-supplied project roots and emits one
//! [`InstalledPackage`] row per `(name, version)`. Scoped
//! packages (`@scope/name`) are handled.

use std::path::Path;

use super::{Ecosystem, InstalledPackage};

/// Maximum directory-recursion depth for the `node_modules`
/// walker. pnpm-style isolated installs can reach ~10; the
/// 32-deep cap defends against symlink loops without rejecting
/// legitimate trees.
const MAX_DEPTH: usize = 32;

/// Walk one project root, returning every `node_modules`
/// package discovered.
pub fn walk(project_root: &Path) -> Vec<InstalledPackage> {
    let mut out = Vec::new();
    walk_node_modules(&project_root.join("node_modules"), &mut out, 0);
    out
}

fn walk_node_modules(dir: &Path, out: &mut Vec<InstalledPackage>, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        // Reject symlinks before recursing — npm + pnpm both ship
        // symlinks in their isolated stores, and a malicious
        // package can drop `node_modules/evil/node_modules -> ..`
        // to create an infinite cycle.
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if !ft.is_dir() {
            continue;
        }
        if name.starts_with('@') {
            // Scoped namespace; recurse one level.
            walk_node_modules(&path, out, depth + 1);
            continue;
        }
        if let Some(pkg) = read_package_json(&path) {
            out.push(pkg);
        }
        // Nested node_modules (npm dedupes; pnpm-style isolated
        // installs always have nested trees).
        let nested = path.join("node_modules");
        if let Ok(nested_ft) = std::fs::symlink_metadata(&nested) {
            if nested_ft.is_dir() {
                walk_node_modules(&nested, out, depth + 1);
            }
        }
    }
}

fn read_package_json(pkg_dir: &Path) -> Option<InstalledPackage> {
    let manifest = pkg_dir.join("package.json");
    let body = std::fs::read_to_string(&manifest).ok()?;
    let json: serde_json::Value = serde_json::from_str(&body).ok()?;
    let name = json.get("name")?.as_str()?.to_string();
    let version = json.get("version")?.as_str()?.to_string();
    Some(InstalledPackage {
        ecosystem: Ecosystem::Npm,
        name,
        version,
        install_path: pkg_dir.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(p: &Path, body: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    #[test]
    fn finds_top_level_package() {
        let dir = tempdir().unwrap();
        write(
            &dir.path().join("node_modules/lodash/package.json"),
            r#"{"name":"lodash","version":"4.17.21"}"#,
        );
        let out = walk(dir.path());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "lodash");
        assert_eq!(out[0].version, "4.17.21");
        assert_eq!(out[0].ecosystem, Ecosystem::Npm);
    }

    #[test]
    fn finds_scoped_packages() {
        let dir = tempdir().unwrap();
        write(
            &dir.path().join("node_modules/@scope/foo/package.json"),
            r#"{"name":"@scope/foo","version":"1.0.0"}"#,
        );
        let out = walk(dir.path());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "@scope/foo");
    }

    #[test]
    fn recurses_into_nested_node_modules() {
        let dir = tempdir().unwrap();
        write(
            &dir.path().join("node_modules/parent/package.json"),
            r#"{"name":"parent","version":"1.0.0"}"#,
        );
        write(
            &dir.path()
                .join("node_modules/parent/node_modules/child/package.json"),
            r#"{"name":"child","version":"2.0.0"}"#,
        );
        let out = walk(dir.path());
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn malformed_manifest_silently_skipped() {
        let dir = tempdir().unwrap();
        write(
            &dir.path().join("node_modules/bad/package.json"),
            "not json {{",
        );
        assert!(walk(dir.path()).is_empty());
    }

    #[test]
    fn missing_node_modules_returns_empty() {
        let dir = tempdir().unwrap();
        assert!(walk(dir.path()).is_empty());
    }
}
