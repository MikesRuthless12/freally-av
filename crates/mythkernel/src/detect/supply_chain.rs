//! Supply-chain package scan (TASK-147, FR-143, Phase 10).
//!
//! Walks developer-ecosystem package caches and surface them as
//! `PackageRef` rows that downstream code matches against the OSV.dev
//! malicious-package feed (loaded via [`crate::updater::osv`]).
//!
//! Phase 10 wave 1 covers the four highest-volume ecosystems:
//!
//!   * **npm** — every `node_modules/<name>/package.json`
//!   * **PyPI** — every `<site-packages>/<dist-info>/METADATA`
//!   * **Cargo** — every `~/.cargo/registry/cache/*/<name>-<version>.crate`
//!   * **RubyGems** — every `~/.gem/specs/*.gemspec` + bundle-cached
//!     `<vendor>/cache/<name>-<version>.gem`
//!
//! Deferred to later waves: Composer (PHP), Maven (Java), Gradle, NuGet,
//! Conda, Hex (Elixir). The `PackageEcosystem` enum already includes
//! placeholders so the walker is the only extension surface.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Closed enum of package ecosystems Mythodikal can identify. The
/// values match OSV.dev's ecosystem keys (`"npm"`, `"PyPI"`, …) so the
/// match against the malicious-package feed can be done by direct
/// string equality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageEcosystem {
    Npm,
    PyPI,
    CratesIo,
    RubyGems,
    Maven,
    NuGet,
    Composer,
    Go,
    Hex,
}

impl PackageEcosystem {
    pub fn osv_key(self) -> &'static str {
        match self {
            PackageEcosystem::Npm => "npm",
            PackageEcosystem::PyPI => "PyPI",
            PackageEcosystem::CratesIo => "crates.io",
            PackageEcosystem::RubyGems => "RubyGems",
            PackageEcosystem::Maven => "Maven",
            PackageEcosystem::NuGet => "NuGet",
            PackageEcosystem::Composer => "Packagist",
            PackageEcosystem::Go => "Go",
            PackageEcosystem::Hex => "Hex",
        }
    }
}

/// One installed package observed on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRef {
    pub ecosystem: PackageEcosystem,
    pub name: String,
    pub version: String,
    /// Absolute path the package's metadata was read from
    /// (`package.json`, `METADATA`, `.crate`, `.gemspec`, …). Used for
    /// the "where is this installed?" column in findings.
    pub manifest_path: PathBuf,
}

/// Where on disk to look for each ecosystem's cache. Caller supplies
/// the per-host paths so this module stays pure-logic + testable
/// without env-var probing.
#[derive(Debug, Clone, Default)]
pub struct ScanRoots {
    pub node_modules: Vec<PathBuf>,
    pub site_packages: Vec<PathBuf>,
    pub cargo_registry: Vec<PathBuf>,
    pub gem_specs: Vec<PathBuf>,
}

/// Walk every supplied root and yield the union of detected packages.
pub fn enumerate(roots: &ScanRoots) -> Vec<PackageRef> {
    let mut out = Vec::new();
    for r in &roots.node_modules {
        walk_node_modules(r, &mut out);
    }
    for r in &roots.site_packages {
        walk_site_packages(r, &mut out);
    }
    for r in &roots.cargo_registry {
        walk_cargo_registry(r, &mut out);
    }
    for r in &roots.gem_specs {
        walk_gem_specs(r, &mut out);
    }
    out
}

fn walk_node_modules(dir: &Path, out: &mut Vec<PackageRef>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        // Handle scoped packages: `@scope/<name>`.
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) if n.starts_with('@') => {
                // Recurse one level into the scope directory.
                if let Ok(scope_read) = std::fs::read_dir(&path) {
                    for inner in scope_read.flatten() {
                        let inner_path = inner.path();
                        if inner_path.is_dir() {
                            try_read_npm_pkg(&inner_path, n, out);
                        }
                    }
                }
                continue;
            }
            Some(n) => n.to_string(),
            None => continue,
        };
        try_read_npm_pkg(&path, &name, out);
    }
}

fn try_read_npm_pkg(pkg_dir: &Path, scope_prefix: &str, out: &mut Vec<PackageRef>) {
    let manifest = pkg_dir.join("package.json");
    let Ok(body) = std::fs::read_to_string(&manifest) else {
        return;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) else {
        return;
    };
    let name = json
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let version = json
        .get("version")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if let (Some(n), Some(v)) = (name, version) {
        let qualified = if scope_prefix.starts_with('@') && !n.starts_with('@') {
            format!("{scope_prefix}/{n}")
        } else {
            n
        };
        out.push(PackageRef {
            ecosystem: PackageEcosystem::Npm,
            name: qualified,
            version: v,
            manifest_path: manifest,
        });
    }
}

fn walk_site_packages(dir: &Path, out: &mut Vec<PackageRef>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let file = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        // PyPI installed-distribution dirs end with `.dist-info` or
        // legacy `.egg-info`. Both carry a METADATA file.
        if !file.ends_with(".dist-info") && !file.ends_with(".egg-info") {
            continue;
        }
        let metadata_path = path.join("METADATA");
        let Ok(body) = std::fs::read_to_string(&metadata_path) else {
            continue;
        };
        let (mut name, mut version) = (None, None);
        for line in body.lines().take(40) {
            if let Some(rest) = line.strip_prefix("Name: ") {
                name = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("Version: ") {
                version = Some(rest.trim().to_string());
            }
            if name.is_some() && version.is_some() {
                break;
            }
        }
        if let (Some(n), Some(v)) = (name, version) {
            out.push(PackageRef {
                ecosystem: PackageEcosystem::PyPI,
                name: n,
                version: v,
                manifest_path: metadata_path,
            });
        }
    }
}

fn walk_cargo_registry(dir: &Path, out: &mut Vec<PackageRef>) {
    // Cargo stores cached crates at
    //   <cargo>/registry/cache/<index>/<name>-<version>.crate
    // The index dir has a fingerprint suffix; the filename split occurs
    // at the FIRST dash followed by an ASCII digit so a pre-release
    // version like `serde-1.0.100-rc.1` keeps the `-rc.1` as part of
    // the version rather than splitting at the last dash (which would
    // give `name=serde-1.0.100-rc`, `version=1`).
    fn walk_inner(dir: &Path, out: &mut Vec<PackageRef>) {
        let Ok(read) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in read.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk_inner(&path, out);
                continue;
            }
            let file = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            let Some(stem) = file.strip_suffix(".crate") else {
                continue;
            };
            let Some((name, version)) = split_name_version(stem) else {
                continue;
            };
            out.push(PackageRef {
                ecosystem: PackageEcosystem::CratesIo,
                name: name.to_string(),
                version: version.to_string(),
                manifest_path: path,
            });
        }
    }
    walk_inner(dir, out);
}

fn walk_gem_specs(dir: &Path, out: &mut Vec<PackageRef>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let file = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let Some(stem) = file.strip_suffix(".gemspec") else {
            continue;
        };
        // `<name>-<version>.gemspec` — split at the FIRST dash-then-digit
        // so `*-1.0.0-beta.gemspec` keeps `-beta` in the version rather
        // than dropping it to the name.
        let Some((name, version)) = split_name_version(stem) else {
            continue;
        };
        out.push(PackageRef {
            ecosystem: PackageEcosystem::RubyGems,
            name: name.to_string(),
            version: version.to_string(),
            manifest_path: path,
        });
    }
}

/// Split a `<name>-<version>` filename stem at the first `-` whose
/// following character is an ASCII digit. Returns `None` when no such
/// separator exists (the filename doesn't carry a version).
///
/// Handles semver pre-release suffixes correctly: `serde-1.0.100-rc.1`
/// returns `("serde", "1.0.100-rc.1")`, not `("serde-1.0.100-rc", "1")`.
fn split_name_version(stem: &str) -> Option<(&str, &str)> {
    let bytes = stem.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'-' && bytes[i + 1].is_ascii_digit() {
            let name = &stem[..i];
            let version = &stem[i + 1..];
            if name.is_empty() || version.is_empty() {
                return None;
            }
            return Some((name, version));
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn osv_key_matches_documented_strings() {
        assert_eq!(PackageEcosystem::Npm.osv_key(), "npm");
        assert_eq!(PackageEcosystem::PyPI.osv_key(), "PyPI");
        assert_eq!(PackageEcosystem::CratesIo.osv_key(), "crates.io");
        assert_eq!(PackageEcosystem::RubyGems.osv_key(), "RubyGems");
    }

    fn write(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn npm_walker_picks_up_packages_and_scoped_packages() {
        let dir = tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        write(
            &nm.join("react/package.json"),
            r#"{"name":"react","version":"18.2.0"}"#,
        );
        write(
            &nm.join("@scope/utils/package.json"),
            r#"{"name":"utils","version":"1.2.3"}"#,
        );
        let mut out = Vec::new();
        walk_node_modules(&nm, &mut out);
        assert_eq!(out.len(), 2);
        let react = out.iter().find(|p| p.name == "react").unwrap();
        assert_eq!(react.version, "18.2.0");
        let scoped = out.iter().find(|p| p.name == "@scope/utils").unwrap();
        assert_eq!(scoped.version, "1.2.3");
    }

    #[test]
    fn pypi_walker_reads_dist_info_metadata() {
        let dir = tempdir().unwrap();
        let sp = dir.path().join("site-packages");
        write(
            &sp.join("requests-2.31.0.dist-info/METADATA"),
            "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\nSummary: HTTP for Humans.\n",
        );
        let mut out = Vec::new();
        walk_site_packages(&sp, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "requests");
        assert_eq!(out[0].version, "2.31.0");
        assert_eq!(out[0].ecosystem, PackageEcosystem::PyPI);
    }

    #[test]
    fn cargo_walker_extracts_name_and_version_from_crate_filename() {
        let dir = tempdir().unwrap();
        let reg = dir
            .path()
            .join("registry/cache/github.com-1ecc6299db9ec823");
        std::fs::create_dir_all(&reg).unwrap();
        std::fs::write(reg.join("serde-1.0.100.crate"), b"x").unwrap();
        std::fs::write(reg.join("tokio-1.43.0.crate"), b"x").unwrap();
        let mut out = Vec::new();
        walk_cargo_registry(dir.path(), &mut out);
        assert_eq!(out.len(), 2);
        let serde = out.iter().find(|p| p.name == "serde").unwrap();
        assert_eq!(serde.version, "1.0.100");
    }

    #[test]
    fn gem_walker_extracts_name_and_version_from_filename() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("rails-7.1.3.gemspec"), b"x").unwrap();
        let mut out = Vec::new();
        walk_gem_specs(dir.path(), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "rails");
        assert_eq!(out[0].version, "7.1.3");
    }

    #[test]
    fn split_name_version_keeps_pre_release_suffix_with_version() {
        // Regression: rfind('-') would have split `serde-1.0.100-rc.1` at
        // the last dash, giving name=`serde-1.0.100-rc` version=`1`,
        // which never matches an OSV.dev advisory filed against `serde`.
        assert_eq!(
            split_name_version("serde-1.0.100-rc.1"),
            Some(("serde", "1.0.100-rc.1"))
        );
        assert_eq!(
            split_name_version("rocksdb-0.21.0-rc.4"),
            Some(("rocksdb", "0.21.0-rc.4"))
        );
        assert_eq!(split_name_version("rails-7.1.3"), Some(("rails", "7.1.3")));
        // Name with embedded dashes (no version part following a digit)
        // — no separator yet, returns None.
        assert!(split_name_version("foo-bar-baz").is_none());
        // Empty name or empty version → None.
        assert!(split_name_version("-1.0.0").is_none());
    }

    #[test]
    fn cargo_walker_handles_pre_release_filenames() {
        let dir = tempdir().unwrap();
        let reg = dir
            .path()
            .join("registry/cache/github.com-1ecc6299db9ec823");
        std::fs::create_dir_all(&reg).unwrap();
        std::fs::write(reg.join("serde-1.0.100-rc.1.crate"), b"x").unwrap();
        let mut out = Vec::new();
        walk_cargo_registry(dir.path(), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "serde");
        assert_eq!(out[0].version, "1.0.100-rc.1");
    }

    #[test]
    fn enumerate_unions_every_root() {
        let dir = tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        write(&nm.join("a/package.json"), r#"{"name":"a","version":"1"}"#);
        let sp = dir.path().join("site-packages");
        write(
            &sp.join("b-1.0.dist-info/METADATA"),
            "Name: b\nVersion: 1.0\n",
        );
        let roots = ScanRoots {
            node_modules: vec![nm],
            site_packages: vec![sp],
            cargo_registry: vec![],
            gem_specs: vec![],
        };
        let union = enumerate(&roots);
        assert_eq!(union.len(), 2);
    }

    #[test]
    fn missing_roots_yield_empty_vec() {
        let roots = ScanRoots {
            node_modules: vec![PathBuf::from("/does/not/exist")],
            ..Default::default()
        };
        assert!(enumerate(&roots).is_empty());
    }
}
