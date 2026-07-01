//! `docker-compose.yml` / `compose.yaml` static analyzer
//! (TASK-317).
//!
//! Walks user-configured project roots for compose files and
//! flags risky shapes:
//!
//!   * `image: <repo>:latest` (or no tag) — unpinned base
//!   * `privileged: true`
//!   * `volumes:` entry referencing `/var/run/docker.sock`
//!   * `cap_add:` containing `SYS_ADMIN`
//!   * `network_mode: host`
//!
//! Pure line-oriented YAML scan — no `serde_yaml` dependency
//! (it's not in the workspace). The rules trigger on the
//! literal substring after stripping comments and quoting; any
//! oddly-formatted YAML will fail-open (no finding) rather than
//! crash the scan.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComposeFindingKind {
    UnpinnedImageTag,
    PrivilegedContainer,
    DockerSockMount,
    SysAdminCapability,
    HostNetworkMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposeFinding {
    pub kind: ComposeFindingKind,
    pub source: PathBuf,
    pub line_number: usize,
    pub raw_line: String,
}

pub fn analyze(compose_path: &Path) -> Vec<ComposeFinding> {
    let Ok(body) = std::fs::read_to_string(compose_path) else {
        return Vec::new();
    };
    analyze_body(compose_path, &body)
}

fn analyze_body(source: &Path, body: &str) -> Vec<ComposeFinding> {
    let mut out = Vec::new();
    for (idx, raw) in body.lines().enumerate() {
        let line_number = idx + 1;
        let stripped = strip_yaml_comment(raw).trim();
        if stripped.is_empty() {
            continue;
        }
        if let Some(kind) = classify_line(stripped) {
            out.push(ComposeFinding {
                kind,
                source: source.to_path_buf(),
                line_number,
                raw_line: raw.to_string(),
            });
        }
    }
    out
}

fn strip_yaml_comment(line: &str) -> &str {
    // Comment marker preceded by whitespace; we do not try to
    // handle '#' inside quoted strings — the rule lines we
    // detect never quote their values.
    if let Some(idx) = line.find(" #") {
        &line[..idx]
    } else if let Some(idx) = line.find("\t#") {
        &line[..idx]
    } else {
        line
    }
}

fn classify_line(line: &str) -> Option<ComposeFindingKind> {
    let lower = line.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("image:") {
        let value = rest.trim().trim_matches(['"', '\'']);
        if value.is_empty() {
            return None;
        }
        // Strip any registry+port prefix (`host:5000/repo`) before
        // looking for the version tag — otherwise the port colon
        // is mistaken for the tag delimiter and an unpinned
        // private-registry image is silently passed.
        let after_registry = value.rsplit_once('/').map(|(_, t)| t).unwrap_or(value);
        // Digest-pinned images (`image@sha256:...`) are pinned even
        // without a tag.
        if after_registry.contains('@') {
            return None;
        }
        let tag = after_registry
            .rsplit_once(':')
            .map(|(_, t)| t)
            .unwrap_or("");
        if tag.is_empty() || tag == "latest" {
            return Some(ComposeFindingKind::UnpinnedImageTag);
        }
    }
    if lower.contains("privileged: true") || lower.contains("privileged:true") {
        return Some(ComposeFindingKind::PrivilegedContainer);
    }
    if lower.contains("/var/run/docker.sock") {
        return Some(ComposeFindingKind::DockerSockMount);
    }
    if lower.contains("sys_admin") {
        return Some(ComposeFindingKind::SysAdminCapability);
    }
    if lower.contains("network_mode: host")
        || lower.contains("network_mode: \"host\"")
        || lower.contains("network_mode: 'host'")
    {
        return Some(ComposeFindingKind::HostNetworkMode);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn flags_latest_tag() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("compose.yaml");
        std::fs::write(&p, "services:\n  web:\n    image: nginx:latest\n").unwrap();
        let out = analyze(&p);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, ComposeFindingKind::UnpinnedImageTag);
    }

    #[test]
    fn flags_unpinned_image_without_tag() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("compose.yaml");
        std::fs::write(&p, "services:\n  web:\n    image: nginx\n").unwrap();
        let out = analyze(&p);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, ComposeFindingKind::UnpinnedImageTag);
    }

    #[test]
    fn flags_unpinned_private_registry_image() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("compose.yaml");
        std::fs::write(
            &p,
            "services:\n  api:\n    image: registry.example.com:5000/repo\n",
        )
        .unwrap();
        let out = analyze(&p);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, ComposeFindingKind::UnpinnedImageTag);
    }

    #[test]
    fn digest_pinned_image_is_silent() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("compose.yaml");
        std::fs::write(&p, "services:\n  api:\n    image: nginx@sha256:abc123def\n").unwrap();
        assert!(analyze(&p).is_empty());
    }

    #[test]
    fn pinned_tag_is_silent() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("compose.yaml");
        std::fs::write(&p, "services:\n  web:\n    image: nginx:1.25.3\n").unwrap();
        assert!(analyze(&p).is_empty());
    }

    #[test]
    fn flags_docker_sock_mount_and_privileged() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("compose.yaml");
        std::fs::write(
            &p,
            "services:\n  api:\n    image: foo:1.0\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
        )
        .unwrap();
        let out = analyze(&p);
        assert!(
            out.iter()
                .any(|f| f.kind == ComposeFindingKind::PrivilegedContainer)
        );
        assert!(
            out.iter()
                .any(|f| f.kind == ComposeFindingKind::DockerSockMount)
        );
    }

    #[test]
    fn flags_sys_admin_and_host_network() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("compose.yaml");
        std::fs::write(
            &p,
            "services:\n  api:\n    image: x:1\n    network_mode: host\n    cap_add: [SYS_ADMIN]\n",
        )
        .unwrap();
        let out = analyze(&p);
        assert!(
            out.iter()
                .any(|f| f.kind == ComposeFindingKind::SysAdminCapability)
        );
        assert!(
            out.iter()
                .any(|f| f.kind == ComposeFindingKind::HostNetworkMode)
        );
    }
}
