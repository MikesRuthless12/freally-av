//! `~/.cargo/registry/cache` + `Cargo.lock` walker (TASK-307).
//!
//! Two complementary inventories:
//!
//!   * [`walk_registry_cache`] — scans
//!     `~/.cargo/registry/cache/<registry>/<name>-<version>.crate`
//!     filenames. This is the "every crate ever downloaded for
//!     any project on this host" view.
//!   * [`walk_cargo_lock`] — parses a project root's
//!     `Cargo.lock` for the authoritative `(name, version)` set
//!     of dependencies that project actually resolves.

use std::path::Path;

use super::{Ecosystem, InstalledPackage};

/// Walk one cargo registry-cache root (typically
/// `~/.cargo/registry/cache`).
pub fn walk_registry_cache(cache_root: &Path) -> Vec<InstalledPackage> {
    let mut out = Vec::new();
    let Ok(registries) = std::fs::read_dir(cache_root) else {
        return out;
    };
    for registry in registries.flatten() {
        let path = registry.path();
        if !path.is_dir() {
            continue;
        }
        let Ok(crates) = std::fs::read_dir(&path) else {
            continue;
        };
        for c in crates.flatten() {
            let cp = c.path();
            let Some(stem) = cp.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let Some(stem) = stem.strip_suffix(".crate") else {
                continue;
            };
            if let Some((name, version)) = split_crate_filename(stem) {
                out.push(InstalledPackage {
                    ecosystem: Ecosystem::Cargo,
                    name,
                    version,
                    install_path: cp,
                });
            }
        }
    }
    out
}

/// Walk one project's `Cargo.lock`. Returns the
/// `[[package]]` entries verbatim.
pub fn walk_cargo_lock(project_root: &Path) -> Vec<InstalledPackage> {
    let lockfile = project_root.join("Cargo.lock");
    let Ok(body) = std::fs::read_to_string(&lockfile) else {
        return Vec::new();
    };
    parse_cargo_lock(&body, &lockfile)
}

fn parse_cargo_lock(body: &str, lockfile: &Path) -> Vec<InstalledPackage> {
    let mut out = Vec::new();
    let mut cur_name: Option<String> = None;
    let mut cur_version: Option<String> = None;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if let (Some(n), Some(v)) = (cur_name.take(), cur_version.take()) {
                out.push(InstalledPackage {
                    ecosystem: Ecosystem::Cargo,
                    name: n,
                    version: v,
                    install_path: lockfile.to_path_buf(),
                });
            }
            continue;
        }
        if let Some(val) = trimmed.strip_prefix("name = ") {
            cur_name = Some(val.trim_matches('"').to_string());
        } else if let Some(val) = trimmed.strip_prefix("version = ") {
            cur_version = Some(val.trim_matches('"').to_string());
        }
    }
    if let (Some(n), Some(v)) = (cur_name, cur_version) {
        out.push(InstalledPackage {
            ecosystem: Ecosystem::Cargo,
            name: n,
            version: v,
            install_path: lockfile.to_path_buf(),
        });
    }
    out
}

/// Split `<name>-<version>` where the version starts with a
/// digit. Cargo's filename convention is unambiguous because
/// crate names cannot contain a hyphen-followed-by-digit
/// fragment that would shadow the version (crates.io enforces
/// names match `[a-zA-Z0-9_-]+` and the parser picks the
/// last `-<digit>...` boundary).
fn split_crate_filename(stem: &str) -> Option<(String, String)> {
    let bytes = stem.as_bytes();
    for (i, _) in bytes.iter().enumerate() {
        if i == 0 || bytes[i - 1] != b'-' {
            continue;
        }
        if bytes[i].is_ascii_digit() {
            let name = &stem[..i - 1];
            let version = &stem[i..];
            return Some((name.to_string(), version.to_string()));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn splits_simple_crate_filename() {
        let (name, version) = split_crate_filename("serde-1.0.197").unwrap();
        assert_eq!(name, "serde");
        assert_eq!(version, "1.0.197");
    }

    #[test]
    fn splits_hyphenated_crate_filename() {
        let (name, version) = split_crate_filename("tokio-stream-0.1.15").unwrap();
        assert_eq!(name, "tokio-stream");
        assert_eq!(version, "0.1.15");
    }

    #[test]
    fn walk_registry_cache_finds_crates() {
        let dir = tempdir().unwrap();
        let registry = dir.path().join("github.com-1ecc6299db9ec823");
        std::fs::create_dir_all(&registry).unwrap();
        std::fs::write(registry.join("serde-1.0.197.crate"), b"x").unwrap();
        std::fs::write(registry.join("anyhow-1.0.80.crate"), b"x").unwrap();
        let out = walk_registry_cache(dir.path());
        assert_eq!(out.len(), 2);
        assert!(
            out.iter()
                .any(|p| p.name == "serde" && p.version == "1.0.197")
        );
        assert!(
            out.iter()
                .any(|p| p.name == "anyhow" && p.version == "1.0.80")
        );
    }

    #[test]
    fn walk_cargo_lock_extracts_packages() {
        let dir = tempdir().unwrap();
        let lock = r#"
# Auto-generated.
version = 3

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.36.0"
"#;
        std::fs::write(dir.path().join("Cargo.lock"), lock).unwrap();
        let out = walk_cargo_lock(dir.path());
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|p| p.name == "serde"));
        assert!(out.iter().any(|p| p.name == "tokio"));
    }
}
