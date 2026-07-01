//! Composer (PHP) walker (TASK-308 — composer half).
//!
//! Reads `composer.lock` for a project. The lockfile is JSON
//! with a `packages` array of objects carrying `name` and
//! `version`. Pure JSON parsing — no PHP runtime touched.

use std::path::Path;

use super::{Ecosystem, InstalledPackage};

pub fn walk(project_root: &Path) -> Vec<InstalledPackage> {
    let lock = project_root.join("composer.lock");
    let Ok(body) = std::fs::read_to_string(&lock) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    // `composer install` installs both the prod (`packages`) and
    // dev (`packages-dev`) arrays by default, so both go into the
    // OSV-joinable inventory.
    for key in ["packages", "packages-dev"] {
        if let Some(pkgs) = json.get(key).and_then(|v| v.as_array()) {
            for p in pkgs {
                if let (Some(name), Some(version)) = (
                    p.get("name").and_then(|v| v.as_str()),
                    p.get("version").and_then(|v| v.as_str()),
                ) {
                    out.push(InstalledPackage {
                        ecosystem: Ecosystem::Composer,
                        name: name.to_string(),
                        version: version.to_string(),
                        install_path: lock.clone(),
                    });
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn reads_packages_array() {
        let dir = tempdir().unwrap();
        let body = r#"
            {
                "packages": [
                    {"name":"symfony/console","version":"v6.4.0"},
                    {"name":"laravel/framework","version":"v10.0.0"}
                ]
            }
        "#;
        std::fs::write(dir.path().join("composer.lock"), body).unwrap();
        let out = walk(dir.path());
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].ecosystem, Ecosystem::Composer);
    }

    #[test]
    fn reads_packages_dev_too() {
        let dir = tempdir().unwrap();
        let body = r#"
            {
                "packages": [{"name":"symfony/console","version":"v6.4.0"}],
                "packages-dev": [{"name":"phpunit/phpunit","version":"10.5.0"}]
            }
        "#;
        std::fs::write(dir.path().join("composer.lock"), body).unwrap();
        let out = walk(dir.path());
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|p| p.name == "phpunit/phpunit"));
    }

    #[test]
    fn missing_lockfile_returns_empty() {
        let dir = tempdir().unwrap();
        assert!(walk(dir.path()).is_empty());
    }
}
