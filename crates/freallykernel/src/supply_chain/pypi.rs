//! Python `site-packages` audit (TASK-309).
//!
//! Walks one `site-packages` root for every `*.dist-info/METADATA`
//! file. Each METADATA is RFC-822-style with `Name:` and
//! `Version:` headers — those are all we need to join against
//! the cached PyPI advisory set. No network.

use std::path::Path;

use super::{Ecosystem, InstalledPackage};

pub fn walk(site_packages: &Path) -> Vec<InstalledPackage> {
    let mut out = Vec::new();
    let Ok(read) = std::fs::read_dir(site_packages) else {
        return out;
    };
    for entry in read.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.ends_with(".dist-info") {
            continue;
        }
        let metadata = p.join("METADATA");
        if let Some(pkg) = read_metadata(&metadata) {
            out.push(pkg);
        }
    }
    out
}

fn read_metadata(path: &Path) -> Option<InstalledPackage> {
    let body = std::fs::read_to_string(path).ok()?;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    for line in body.lines() {
        if line.is_empty() {
            break; // headers end at first blank line
        }
        if let Some(rest) = line.strip_prefix("Name:") {
            name = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Version:") {
            version = Some(rest.trim().to_string());
        }
    }
    Some(InstalledPackage {
        ecosystem: Ecosystem::PyPI,
        name: name?,
        version: version?,
        install_path: path.parent()?.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn reads_dist_info_metadata() {
        let dir = tempdir().unwrap();
        let dist = dir.path().join("requests-2.31.0.dist-info");
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::write(
            dist.join("METADATA"),
            "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n\nFull text body…",
        )
        .unwrap();
        let out = walk(dir.path());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "requests");
        assert_eq!(out[0].version, "2.31.0");
        assert_eq!(out[0].ecosystem, Ecosystem::PyPI);
    }

    #[test]
    fn empty_dir_returns_empty() {
        let dir = tempdir().unwrap();
        assert!(walk(dir.path()).is_empty());
    }
}
