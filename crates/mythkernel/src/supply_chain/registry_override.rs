//! `.npmrc` / `.yarnrc` / `pip.conf` registry-override detector
//! (TASK-324).
//!
//! Walks the caller-supplied set of config-file paths
//! (the daemon assembles the combined list from
//! `~/.npmrc`, `~/.yarnrc`, `~/.yarnrc.yml`, project-root
//! `.npmrc`, `~/.pip/pip.conf`, `~/.config/pip/pip.conf`).
//!
//! Flags:
//!
//!   * `registry = http://...` or `index-url = http://...`
//!     (cleartext HTTP — P0)
//!   * `registry = https://<host>` where `<host>` is not in
//!     the bundled trusted-host allowlist
//!
//! Pure key-value scan; YAML inside `.yarnrc.yml` is handled
//! line-by-line.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryOverrideKind {
    PlaintextHttp,
    UnknownHost,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryOverrideFinding {
    pub kind: RegistryOverrideKind,
    pub source: PathBuf,
    pub key: String,
    pub url: String,
}

const TRUSTED_NPM_HOSTS: &[&str] = &["registry.npmjs.org", "registry.yarnpkg.com"];
const TRUSTED_PYPI_HOSTS: &[&str] = &["pypi.org", "files.pythonhosted.org", "pypi.python.org"];

pub fn audit(config_path: &Path) -> Vec<RegistryOverrideFinding> {
    let Ok(body) = std::fs::read_to_string(config_path) else {
        return Vec::new();
    };
    audit_body(config_path, &body)
}

fn audit_body(source: &Path, body: &str) -> Vec<RegistryOverrideFinding> {
    let mut out = Vec::new();
    let is_pip = source
        .file_name()
        .and_then(|s| s.to_str())
        .map(|n| n.eq_ignore_ascii_case("pip.conf"))
        .unwrap_or(false);
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        // INI / npmrc form: key = value
        // yarnrc.yml form: key: value
        let kv = line.split_once('=').or_else(|| line.split_once(':'));
        let Some((k, v)) = kv else {
            continue;
        };
        let key = k.trim().to_string();
        let value = v.trim().trim_matches(['"', '\'']).to_string();
        let key_lower = key.to_ascii_lowercase();
        let is_registry_key = matches!(
            key_lower.as_str(),
            "registry" | "index-url" | "npmregistryserver" | "extra-index-url"
        );
        if !is_registry_key {
            continue;
        }
        if value.starts_with("http://") {
            out.push(RegistryOverrideFinding {
                kind: RegistryOverrideKind::PlaintextHttp,
                source: source.to_path_buf(),
                key,
                url: value,
            });
            continue;
        }
        if let Some(host) = extract_host(&value) {
            let trusted = if is_pip {
                TRUSTED_PYPI_HOSTS
                    .iter()
                    .any(|h| h.eq_ignore_ascii_case(host))
            } else {
                TRUSTED_NPM_HOSTS
                    .iter()
                    .any(|h| h.eq_ignore_ascii_case(host))
                    || TRUSTED_PYPI_HOSTS
                        .iter()
                        .any(|h| h.eq_ignore_ascii_case(host))
            };
            if !trusted {
                out.push(RegistryOverrideFinding {
                    kind: RegistryOverrideKind::UnknownHost,
                    source: source.to_path_buf(),
                    key,
                    url: value,
                });
            }
        }
    }
    out
}

fn extract_host(url: &str) -> Option<&str> {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host_end = after_scheme
        .find(['/', ':', '?', '#'])
        .unwrap_or(after_scheme.len());
    Some(&after_scheme[..host_end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn flags_http_registry() {
        let dir = tempdir().unwrap();
        let p = dir.path().join(".npmrc");
        std::fs::write(&p, "registry=http://malicious.example/npm/\n").unwrap();
        let out = audit(&p);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, RegistryOverrideKind::PlaintextHttp);
    }

    #[test]
    fn flags_unknown_https_host() {
        let dir = tempdir().unwrap();
        let p = dir.path().join(".npmrc");
        std::fs::write(&p, "registry=https://npm.attacker.example/\n").unwrap();
        let out = audit(&p);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, RegistryOverrideKind::UnknownHost);
    }

    #[test]
    fn allows_trusted_npm_host() {
        let dir = tempdir().unwrap();
        let p = dir.path().join(".npmrc");
        std::fs::write(&p, "registry=https://registry.npmjs.org/\n").unwrap();
        assert!(audit(&p).is_empty());
    }

    #[test]
    fn pip_conf_uses_pypi_allowlist() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("pip.conf");
        std::fs::write(&p, "[global]\nindex-url = https://pypi.org/simple\n").unwrap();
        assert!(audit(&p).is_empty());
    }

    #[test]
    fn pip_conf_flags_unknown_host() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("pip.conf");
        std::fs::write(&p, "[global]\nindex-url = https://evil.example/simple\n").unwrap();
        let out = audit(&p);
        assert!(
            out.iter()
                .any(|f| f.kind == RegistryOverrideKind::UnknownHost)
        );
    }
}
