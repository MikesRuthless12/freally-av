//! Maven (Java) walker (TASK-308 — maven half).
//!
//! Walks `~/.m2/repository/<groupId path>/<artifactId>/
//! <version>/<artifactId>-<version>.jar`. Maven encodes the
//! Group / Artifact / Version triple in the directory layout,
//! so the walker reconstructs `groupId:artifactId` from the
//! path itself without needing to parse `maven-metadata-*.xml`.

use std::path::{Path, PathBuf};

use super::{Ecosystem, InstalledPackage};

/// Depth cap mirrors the deepest realistic Maven layout
/// (`group.subgroup.subsubgroup/artifact/version`) plus headroom
/// — 32 protects against symlink loops without rejecting any
/// legitimate `~/.m2/repository`.
const MAX_DEPTH: usize = 32;

pub fn walk(repo_root: &Path) -> Vec<InstalledPackage> {
    let mut out = Vec::new();
    walk_recursive(repo_root, repo_root, &mut out, 0);
    out
}

fn walk_recursive(repo_root: &Path, dir: &Path, out: &mut Vec<InstalledPackage>, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    let mut subdirs = Vec::new();
    let mut version_jars = Vec::new();
    for e in read.flatten() {
        let p = e.path();
        let Ok(ft) = e.file_type() else { continue };
        // Reject symlinks at the file-type layer so cyclic
        // junctions inside `~/.m2` (Windows reparse points,
        // hand-made `ln -s` inside Maven caches) don't blow
        // the stack.
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            subdirs.push(p);
        } else if p.extension().and_then(|s| s.to_str()) == Some("jar") {
            version_jars.push(p);
        }
    }
    for jar in version_jars {
        if let Some(pkg) = classify_jar(repo_root, &jar) {
            out.push(pkg);
        }
    }
    for sub in subdirs {
        walk_recursive(repo_root, &sub, out, depth + 1);
    }
}

fn classify_jar(repo_root: &Path, jar: &Path) -> Option<InstalledPackage> {
    let rel = jar.strip_prefix(repo_root).ok()?;
    let mut comps: Vec<&str> = rel.iter().filter_map(|s| s.to_str()).collect();
    if comps.len() < 4 {
        return None;
    }
    let _file_name = comps.pop()?;
    let version = comps.pop()?.to_string();
    let artifact = comps.pop()?.to_string();
    let group = comps.join(".");
    Some(InstalledPackage {
        ecosystem: Ecosystem::Maven,
        name: format!("{group}:{artifact}"),
        version,
        install_path: PathBuf::from(jar),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn walks_repository_layout() {
        let dir = tempdir().unwrap();
        let repo = dir.path();
        let jar = repo.join("org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar");
        std::fs::create_dir_all(jar.parent().unwrap()).unwrap();
        std::fs::write(&jar, b"PK").unwrap();
        let out = walk(repo);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "org.apache.commons:commons-lang3");
        assert_eq!(out[0].version, "3.14.0");
        assert_eq!(out[0].ecosystem, Ecosystem::Maven);
    }

    #[test]
    fn empty_repo_returns_empty() {
        let dir = tempdir().unwrap();
        assert!(walk(dir.path()).is_empty());
    }
}
