//! Supply-chain & developer-ecosystem coverage
//! (Phase 10 Wave 3 — TASK-306..325).
//!
//! Pure-local walkers and analyzers across the ecosystems a
//! developer machine carries: npm / cargo / gem / composer /
//! maven / pypi (TASK-306..309), editor extensions (TASK-310,
//! 311), git hooks (TASK-312), npm preinstall scripts
//! (TASK-314), `curl | sh` interception (TASK-315), containers
//! / compose / kube (TASK-316..318), `direnv` (TASK-319), SSH
//! `Match` blocks (TASK-320), SBOM emit + diff (TASK-321, 322),
//! VS-Code-Server / JetBrains-Gateway listener detection
//! (TASK-323), `.npmrc` / `pip.conf` registry overrides
//! (TASK-324), and `.pypirc` token-leak scoring (TASK-325).
//!
//! Every walker is **pure-local** — no network at scan time.
//! Vulnerable-package joins use the on-disk OSV cache the
//! updater channel maintains under `updater::engine`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Ecosystems the supply-chain walkers cover.
///
/// Held in `snake_case` for the OSV advisory cache lookup —
/// `npm`, `cargo`, `pypi`, … — which matches the OSV.dev
/// ecosystem identifiers verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    Npm,
    Cargo,
    Gem,
    Composer,
    Maven,
    PyPI,
    VsCodeExtension,
    JetBrainsPlugin,
}

impl Ecosystem {
    pub fn as_osv_str(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Cargo => "crates.io",
            Ecosystem::Gem => "RubyGems",
            Ecosystem::Composer => "Packagist",
            Ecosystem::Maven => "Maven",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::VsCodeExtension => "VSCode",
            Ecosystem::JetBrainsPlugin => "JetBrains",
        }
    }
}

/// One installed dependency, ecosystem-tagged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub install_path: PathBuf,
}

/// One row from the cached OSV advisory set — the columns we
/// actually join on.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OsvAdvisoryKey {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnerablePackageFinding {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub install_path: PathBuf,
    pub advisory_ids: Vec<String>,
}

/// Per-ecosystem name normalization.
///
///   * **npm** — names are required to be lowercase; we lowercase
///     here defensively in case a `package.json` "name" carries
///     stray uppercase.
///   * **PyPI** — PEP 503 normalization: lowercase, replace runs
///     of `_`, `-`, `.` with a single `-`.
///   * Everything else passes through verbatim (cargo names are
///     already canonicalized by crates.io; gem / composer /
///     maven preserve case).
pub fn normalize_package_name(ecosystem: Ecosystem, name: &str) -> String {
    match ecosystem {
        Ecosystem::Npm => name.to_ascii_lowercase(),
        Ecosystem::PyPI => {
            let lower = name.to_ascii_lowercase();
            let mut out = String::with_capacity(lower.len());
            let mut prev_sep = false;
            for c in lower.chars() {
                if matches!(c, '_' | '-' | '.') {
                    if !prev_sep && !out.is_empty() {
                        out.push('-');
                        prev_sep = true;
                    }
                } else {
                    out.push(c);
                    prev_sep = false;
                }
            }
            while out.ends_with('-') {
                out.pop();
            }
            out
        }
        _ => name.to_string(),
    }
}

/// Join an inventory of [`InstalledPackage`] rows against the
/// `OsvAdvisoryKey` -> advisory-ids cache. Pure-function so
/// every per-ecosystem walker can pipe through this same join.
///
/// Name comparison applies [`normalize_package_name`] on each
/// lookup so a PyPI installation recording `Requests` matches an
/// advisory cached under `requests`. The raw key is also tried
/// (in case the caller pre-normalized the advisory cache).
pub fn join_advisories(
    inventory: &[InstalledPackage],
    advisories: &std::collections::HashMap<OsvAdvisoryKey, Vec<String>>,
) -> Vec<VulnerablePackageFinding> {
    let mut out = Vec::new();
    for pkg in inventory {
        let raw_key = OsvAdvisoryKey {
            ecosystem: pkg.ecosystem,
            name: pkg.name.clone(),
            version: pkg.version.clone(),
        };
        let normalized = normalize_package_name(pkg.ecosystem, &pkg.name);
        let norm_key = OsvAdvisoryKey {
            ecosystem: pkg.ecosystem,
            name: normalized.clone(),
            version: pkg.version.clone(),
        };
        let ids = advisories
            .get(&raw_key)
            .or_else(|| advisories.get(&norm_key));
        if let Some(ids) = ids {
            out.push(VulnerablePackageFinding {
                ecosystem: pkg.ecosystem,
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                install_path: pkg.install_path.clone(),
                advisory_ids: ids.clone(),
            });
        }
    }
    out
}

pub mod cargo;
pub mod compose;
pub mod composer;
pub mod container;
pub mod direnv;
pub mod editor_ext;
pub mod gem;
pub mod git_hooks;
pub mod kube;
pub mod maven;
pub mod npm;
pub mod npm_scripts;
pub mod pipe_guard;
pub mod pypi;
pub mod pypirc;
pub mod registry_override;
pub mod remote_dev_listener;
pub mod sbom;
pub mod sbom_diff;
pub mod ssh_config;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn osv_ecosystem_strings_match_spec() {
        assert_eq!(Ecosystem::Npm.as_osv_str(), "npm");
        assert_eq!(Ecosystem::Cargo.as_osv_str(), "crates.io");
        assert_eq!(Ecosystem::PyPI.as_osv_str(), "PyPI");
    }

    #[test]
    fn pypi_name_normalization_per_pep_503() {
        assert_eq!(
            normalize_package_name(Ecosystem::PyPI, "Requests"),
            "requests"
        );
        assert_eq!(
            normalize_package_name(Ecosystem::PyPI, "Foo_Bar.Baz"),
            "foo-bar-baz"
        );
        assert_eq!(normalize_package_name(Ecosystem::PyPI, "a..b"), "a-b");
    }

    #[test]
    fn npm_name_normalization_lowercases() {
        assert_eq!(normalize_package_name(Ecosystem::Npm, "Lodash"), "lodash");
    }

    #[test]
    fn join_matches_pypi_via_normalized_name() {
        let inv = vec![InstalledPackage {
            ecosystem: Ecosystem::PyPI,
            name: "Requests".to_string(),
            version: "2.31.0".to_string(),
            install_path: PathBuf::from("/"),
        }];
        let mut adv = HashMap::new();
        adv.insert(
            OsvAdvisoryKey {
                ecosystem: Ecosystem::PyPI,
                name: "requests".to_string(),
                version: "2.31.0".to_string(),
            },
            vec!["PYSEC-2024-X".to_string()],
        );
        let out = join_advisories(&inv, &adv);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].advisory_ids, vec!["PYSEC-2024-X"]);
    }

    #[test]
    fn join_pairs_inventory_against_advisories() {
        let inv = vec![
            InstalledPackage {
                ecosystem: Ecosystem::Npm,
                name: "lodash".to_string(),
                version: "4.17.20".to_string(),
                install_path: PathBuf::from("/proj/node_modules/lodash"),
            },
            InstalledPackage {
                ecosystem: Ecosystem::Npm,
                name: "express".to_string(),
                version: "4.18.0".to_string(),
                install_path: PathBuf::from("/proj/node_modules/express"),
            },
        ];
        let mut adv = HashMap::new();
        adv.insert(
            OsvAdvisoryKey {
                ecosystem: Ecosystem::Npm,
                name: "lodash".to_string(),
                version: "4.17.20".to_string(),
            },
            vec!["GHSA-29mw-wpgm-hmr9".to_string()],
        );
        let out = join_advisories(&inv, &adv);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "lodash");
        assert_eq!(out[0].advisory_ids, vec!["GHSA-29mw-wpgm-hmr9"]);
    }
}
