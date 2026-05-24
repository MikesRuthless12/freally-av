//! TASK-188 — Cargo / PyPI / npm publisher-key allowlist.
//!
//! Local `publisher_keys.toml` mapping `(ecosystem, package,
//! version_range)` → `(publisher_id, key_fingerprint)`. The
//! scanner queries this allowlist for files under known dev-tool
//! install roots (`~/.cargo/`, `~/.local/lib/python*/site-packages/`,
//! `node_modules/`); on match the file is treated as trusted
//! provided the per-ecosystem provenance attestation also verifies.
//!
//! ## Scope for Wave 2 Phase A
//!
//! Ships the TOML loader + the path-shape classifier (which
//! ecosystem does the file belong to?). Per-ecosystem attestation
//! verification (`cargo vet`-style audit.toml for Cargo, PEP 740
//! attestations for PyPI, npm provenance manifest for npm) is wired
//! in a follow-up — for v0.7.x the path classifier + toml lookup
//! are the v1 cut.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{Detector, DetectorVerdict, FileCtx};

pub const DETECTOR_ID: &str = "dev_publisher_allowlist";
pub const PRIORITY: u32 = 13;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Cargo,
    PyPi,
    Npm,
}

impl Ecosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Ecosystem::Cargo => "cargo",
            Ecosystem::PyPi => "pypi",
            Ecosystem::Npm => "npm",
        }
    }
}

/// Detect which dev-tool ecosystem a path belongs to. Returns
/// `(ecosystem, package_name)` when the path is recognisable as
/// living under a known install root.
pub fn classify_dev_path(path: &Path) -> Option<(Ecosystem, String)> {
    let s = path.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    // Cargo: `~/.cargo/registry/src/index.crates.io-<hash>/<crate>-<ver>/...`
    if let Some(idx) = s.find("/.cargo/registry/src/")
        && let Some(after) = s.get(idx..)
        && let Some(crate_seg) = after.split('/').nth(5)
        && !crate_seg.is_empty()
    {
        return Some((Ecosystem::Cargo, strip_version_suffix(crate_seg)));
    }
    // PyPI: `.../site-packages/<package>/...`
    if let Some(idx) = s.find("/site-packages/")
        && let Some(after) = s.get(idx + "/site-packages/".len()..)
        && let Some(pkg_seg) = after.split('/').next()
        && !pkg_seg.is_empty()
    {
        return Some((Ecosystem::PyPi, pkg_seg.to_string()));
    }
    // npm: `.../node_modules/<package>/...` (handle scoped @org/pkg).
    if let Some(idx) = s.find("/node_modules/")
        && let Some(after) = s.get(idx + "/node_modules/".len()..)
    {
        let mut parts = after.split('/');
        if let Some(first) = parts.next() {
            if first.starts_with('@') {
                if let Some(second) = parts.next() {
                    return Some((Ecosystem::Npm, format!("{first}/{second}")));
                }
            } else if !first.is_empty() {
                return Some((Ecosystem::Npm, first.to_string()));
            }
        }
    }
    None
}

/// Strip the trailing `-x.y.z[-suffix]` from a Cargo crate dir name.
fn strip_version_suffix(crate_dir: &str) -> String {
    // Find the last '-' followed by a digit.
    let bytes = crate_dir.as_bytes();
    for i in (0..bytes.len()).rev() {
        if bytes[i] == b'-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            return crate_dir[..i].to_string();
        }
    }
    crate_dir.to_string()
}

/// One row in `publisher_keys.toml`. Wave 2 Phase A only consults
/// the (ecosystem, package) tuple for an allow-or-not match; the
/// version_range + key_fingerprint fields are loaded but not yet
/// enforced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublisherEntry {
    pub ecosystem: String,
    pub package: String,
    #[serde(default)]
    pub version_range: Option<String>,
    pub publisher_id: String,
    pub key_fingerprint: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PublisherKeysFile {
    #[serde(default)]
    pub publishers: Vec<PublisherEntry>,
}

impl PublisherKeysFile {
    pub fn load_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }
    pub fn is_allowlisted(&self, eco: Ecosystem, package: &str) -> bool {
        self.publishers.iter().any(|p| {
            p.ecosystem.eq_ignore_ascii_case(eco.as_str())
                && p.package.eq_ignore_ascii_case(package)
        })
    }
}

#[derive(Debug)]
pub struct DevPublisherAllowlistDetector {
    keys: PublisherKeysFile,
    by_eco_pkg: HashMap<(String, String), ()>,
}

impl DevPublisherAllowlistDetector {
    pub fn new(keys: PublisherKeysFile) -> Self {
        let mut by_eco_pkg = HashMap::new();
        for p in &keys.publishers {
            by_eco_pkg.insert(
                (p.ecosystem.to_ascii_lowercase(), p.package.to_ascii_lowercase()),
                (),
            );
        }
        Self { keys, by_eco_pkg }
    }
}

impl Detector for DevPublisherAllowlistDetector {
    fn id(&self) -> &str {
        DETECTOR_ID
    }
    fn priority(&self) -> u32 {
        PRIORITY
    }
    fn check(&self, ctx: &FileCtx<'_>) -> DetectorVerdict {
        let Some((eco, pkg)) = classify_dev_path(ctx.path) else {
            return DetectorVerdict::Clean;
        };
        let key = (eco.as_str().to_string(), pkg.to_ascii_lowercase());
        if self.by_eco_pkg.contains_key(&key) {
            DetectorVerdict::SkipFile
        } else {
            DetectorVerdict::Clean
        }
    }
}

#[allow(dead_code)]
fn _ensure_keys_is_used(d: &DevPublisherAllowlistDetector) -> usize {
    d.keys.publishers.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_cargo_path() {
        let p = Path::new(
            "/home/me/.cargo/registry/src/index.crates.io-1cd66030c0c0e765/serde-1.0.193/src/lib.rs",
        );
        let (eco, pkg) = classify_dev_path(p).unwrap();
        assert_eq!(eco, Ecosystem::Cargo);
        assert_eq!(pkg, "serde");
    }

    #[test]
    fn classify_pypi_path() {
        let p = Path::new("/home/me/venv/lib/python3.12/site-packages/requests/__init__.py");
        let (eco, pkg) = classify_dev_path(p).unwrap();
        assert_eq!(eco, Ecosystem::PyPi);
        assert_eq!(pkg, "requests");
    }

    #[test]
    fn classify_npm_path() {
        let p = Path::new("/home/me/proj/node_modules/lodash/index.js");
        let (eco, pkg) = classify_dev_path(p).unwrap();
        assert_eq!(eco, Ecosystem::Npm);
        assert_eq!(pkg, "lodash");
    }

    #[test]
    fn classify_npm_scoped_package() {
        let p = Path::new("/home/me/proj/node_modules/@solid/router/index.js");
        let (eco, pkg) = classify_dev_path(p).unwrap();
        assert_eq!(eco, Ecosystem::Npm);
        assert_eq!(pkg, "@solid/router");
    }

    #[test]
    fn load_toml_and_allowlist_lookup() {
        let text = r#"
            [[publishers]]
            ecosystem = "cargo"
            package = "serde"
            publisher_id = "dtolnay"
            key_fingerprint = "DEADBEEF"

            [[publishers]]
            ecosystem = "npm"
            package = "lodash"
            publisher_id = "jdalton"
            key_fingerprint = "CAFE1234"
        "#;
        let keys = PublisherKeysFile::load_toml(text).unwrap();
        assert!(keys.is_allowlisted(Ecosystem::Cargo, "serde"));
        assert!(keys.is_allowlisted(Ecosystem::Npm, "lodash"));
        assert!(!keys.is_allowlisted(Ecosystem::PyPi, "serde"));
        assert!(!keys.is_allowlisted(Ecosystem::Cargo, "tokio"));
    }

    #[test]
    fn unrecognised_path_returns_none() {
        assert!(classify_dev_path(Path::new("/usr/bin/grep")).is_none());
    }
}
