//! `~/.gem/specs/*` Ruby gem walker (TASK-308 — gem half).
//!
//! Reads each installed gem's `<name>-<version>.gemspec`
//! filename from the user's gem specs root. RubyGems stores
//! gemspec filenames as `<name>-<version>` for vanilla gems and
//! `<name>-<version>-<platform>` for platform-specific gems.

use std::path::Path;

use super::{Ecosystem, InstalledPackage};

pub fn walk(specs_root: &Path) -> Vec<InstalledPackage> {
    let mut out = Vec::new();
    let Ok(versions) = std::fs::read_dir(specs_root) else {
        return out;
    };
    for v in versions.flatten() {
        let vp = v.path();
        if !vp.is_dir() {
            continue;
        }
        let Ok(specs) = std::fs::read_dir(&vp) else {
            continue;
        };
        for spec in specs.flatten() {
            let sp = spec.path();
            let Some(stem) = sp.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let Some(stem) = stem.strip_suffix(".gemspec") else {
                continue;
            };
            if let Some((name, version)) = split_gem_filename(stem) {
                out.push(InstalledPackage {
                    ecosystem: Ecosystem::Gem,
                    name,
                    version,
                    install_path: sp,
                });
            }
        }
    }
    out
}

fn split_gem_filename(stem: &str) -> Option<(String, String)> {
    // Anchor on the FIRST `-<digit>` boundary so platform /
    // revision tails (`pg-1.5.4-x86_64-linux`,
    // `rake-13.0.6-1`) stay attached to the version rather
    // than being misclassified as part of the name.
    let bytes = stem.as_bytes();
    let mut split: Option<usize> = None;
    for i in 1..bytes.len() {
        if bytes[i - 1] == b'-' && bytes[i].is_ascii_digit() {
            split = Some(i);
            break;
        }
    }
    let split = split?;
    let name = stem[..split - 1].to_string();
    let version = stem[split..].to_string();
    if name.is_empty() {
        return None;
    }
    Some((name, version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn splits_gem_filename() {
        let (n, v) = split_gem_filename("rails-7.1.3").unwrap();
        assert_eq!(n, "rails");
        assert_eq!(v, "7.1.3");
    }

    #[test]
    fn splits_with_hyphenated_name() {
        let (n, v) = split_gem_filename("rack-protection-3.1.0").unwrap();
        assert_eq!(n, "rack-protection");
        assert_eq!(v, "3.1.0");
    }

    #[test]
    fn keeps_platform_suffix_attached_to_version() {
        let (n, v) = split_gem_filename("pg-1.5.4-x86_64-linux").unwrap();
        assert_eq!(n, "pg");
        assert_eq!(v, "1.5.4-x86_64-linux");
    }

    #[test]
    fn keeps_revision_suffix_attached_to_version() {
        let (n, v) = split_gem_filename("rake-13.0.6-1").unwrap();
        assert_eq!(n, "rake");
        assert_eq!(v, "13.0.6-1");
    }

    #[test]
    fn rejects_leading_dash_digit() {
        assert!(split_gem_filename("-1.0.0").is_none());
    }

    #[test]
    fn walk_returns_inventory() {
        let dir = tempdir().unwrap();
        let v = dir.path().join("3.2.0");
        std::fs::create_dir_all(&v).unwrap();
        std::fs::write(v.join("rails-7.1.3.gemspec"), b"x").unwrap();
        let out = walk(dir.path());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "rails");
        assert_eq!(out[0].ecosystem, Ecosystem::Gem);
    }
}
