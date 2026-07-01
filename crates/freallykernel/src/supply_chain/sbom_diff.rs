//! SBOM diff between two snapshots (TASK-322).
//!
//! Produces three per-ecosystem buckets — `added`,
//! `removed`, `version_changed` — when comparing two
//! [`SbomSnapshot`]s. The caller then cross-references the
//! `version_changed` set against the cached OSV advisory keys
//! to highlight which version bumps introduced (or removed)
//! known-vulnerable versions.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::Ecosystem;
use super::sbom::{SbomComponent, SbomSnapshot};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionChange {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub from_version: String,
    pub to_version: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomDiff {
    pub added: Vec<SbomComponent>,
    pub removed: Vec<SbomComponent>,
    pub version_changed: Vec<VersionChange>,
}

pub fn diff(before: &SbomSnapshot, after: &SbomSnapshot) -> SbomDiff {
    let before_by_key = index_by_key(before);
    let after_by_key = index_by_key(after);

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut version_changed = Vec::new();

    // Index by `(ecosystem, name)` to find version changes
    // before we walk the per-version sets.
    let before_by_name = index_by_name(before);
    let after_by_name = index_by_name(after);

    for (key, comp) in &after_by_key {
        if !before_by_key.contains_key(key) {
            // New `(eco, name, version)`. Could be a brand-new
            // dependency OR a version bump of an existing one.
            if let Some(prev) = before_by_name.get(&(comp.ecosystem, comp.name.clone())) {
                if prev.version != comp.version {
                    version_changed.push(VersionChange {
                        ecosystem: comp.ecosystem,
                        name: comp.name.clone(),
                        from_version: prev.version.clone(),
                        to_version: comp.version.clone(),
                    });
                    continue;
                }
            }
            added.push(comp.clone());
        }
    }

    for (key, comp) in &before_by_key {
        if !after_by_key.contains_key(key) {
            // Removed `(eco, name, version)` — but only count
            // as a true removal if there's no successor version
            // for the same `(ecosystem, name)` in the after set.
            if !after_by_name.contains_key(&(comp.ecosystem, comp.name.clone())) {
                removed.push(comp.clone());
            }
        }
    }

    SbomDiff {
        added,
        removed,
        version_changed,
    }
}

fn index_by_key(snap: &SbomSnapshot) -> BTreeMap<(Ecosystem, String, String), SbomComponent> {
    let mut out = BTreeMap::new();
    for c in &snap.components {
        out.insert((c.ecosystem, c.name.clone(), c.version.clone()), c.clone());
    }
    out
}

fn index_by_name(snap: &SbomSnapshot) -> BTreeMap<(Ecosystem, String), SbomComponent> {
    let mut out = BTreeMap::new();
    for c in &snap.components {
        out.insert((c.ecosystem, c.name.clone()), c.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::InstalledPackage;
    use super::*;
    use std::path::PathBuf;

    fn snap(pkgs: &[(Ecosystem, &str, &str)]) -> SbomSnapshot {
        let inv: Vec<InstalledPackage> = pkgs
            .iter()
            .map(|(e, n, v)| InstalledPackage {
                ecosystem: *e,
                name: (*n).to_string(),
                version: (*v).to_string(),
                install_path: PathBuf::from("/"),
            })
            .collect();
        SbomSnapshot::from_inventory(0, &inv)
    }

    #[test]
    fn detects_added_removed_and_version_change() {
        let before = snap(&[
            (Ecosystem::Npm, "lodash", "4.17.20"),
            (Ecosystem::Npm, "removed-pkg", "1.0.0"),
        ]);
        let after = snap(&[
            (Ecosystem::Npm, "lodash", "4.17.21"),
            (Ecosystem::Npm, "brand-new", "0.1.0"),
        ]);
        let d = diff(&before, &after);
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].name, "brand-new");
        assert_eq!(d.removed.len(), 1);
        assert_eq!(d.removed[0].name, "removed-pkg");
        assert_eq!(d.version_changed.len(), 1);
        let vc = &d.version_changed[0];
        assert_eq!(vc.from_version, "4.17.20");
        assert_eq!(vc.to_version, "4.17.21");
    }

    #[test]
    fn identical_snapshots_have_empty_diff() {
        let s = snap(&[(Ecosystem::Cargo, "serde", "1.0.0")]);
        let d = diff(&s, &s);
        assert!(d.added.is_empty());
        assert!(d.removed.is_empty());
        assert!(d.version_changed.is_empty());
    }
}
