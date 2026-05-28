//! Kubernetes context credential detector (TASK-318).
//!
//! Reads `~/.kube/config` plus any `$KUBECONFIG` paths the
//! caller assembles. Flags credentials sitting in plaintext
//! and config files whose POSIX mode is more permissive than
//! `0600`.
//!
//! Pure line-scan — yaml parsing kept lightweight because the
//! flagged keys are simple key-value pairs that don't need a
//! full YAML AST.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KubeFindingKind {
    PlaintextToken,
    PlaintextPassword,
    EmbeddedClientCert,
    WorldReadableConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubeFinding {
    pub kind: KubeFindingKind,
    pub source: PathBuf,
    pub line_number: Option<usize>,
    pub detail: String,
}

pub fn audit(config_path: &Path) -> Vec<KubeFinding> {
    let mut out = Vec::new();
    if let Ok(body) = std::fs::read_to_string(config_path) {
        audit_body(config_path, &body, &mut out);
    }
    if let Some(mode) = posix_mode(config_path) {
        if (mode & 0o077) != 0 {
            out.push(KubeFinding {
                kind: KubeFindingKind::WorldReadableConfig,
                source: config_path.to_path_buf(),
                line_number: None,
                detail: format!("mode={:04o}", mode),
            });
        }
    }
    out
}

fn audit_body(source: &Path, body: &str, out: &mut Vec<KubeFinding>) {
    for (idx, raw) in body.lines().enumerate() {
        let line_number = idx + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let kind = if trimmed.starts_with("token:") {
            Some(KubeFindingKind::PlaintextToken)
        } else if trimmed.starts_with("password:") {
            Some(KubeFindingKind::PlaintextPassword)
        } else if trimmed.starts_with("client-certificate-data:")
            || trimmed.starts_with("client-key-data:")
        {
            Some(KubeFindingKind::EmbeddedClientCert)
        } else {
            None
        };
        if let Some(kind) = kind {
            out.push(KubeFinding {
                kind,
                source: source.to_path_buf(),
                line_number: Some(line_number),
                detail: trimmed.to_string(),
            });
        }
    }
}

#[cfg(unix)]
fn posix_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).ok().map(|m| m.permissions().mode())
}

#[cfg(not(unix))]
fn posix_mode(_path: &Path) -> Option<u32> {
    // Windows ACLs are evaluated by a separate Windows-only
    // audit; the unix-mode check is silent on non-unix hosts.
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn flags_plaintext_token() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("config");
        std::fs::write(&p, "users:\n- name: dev\n  user:\n    token: abc.def.ghi\n").unwrap();
        let out = audit(&p);
        assert!(
            out.iter()
                .any(|f| f.kind == KubeFindingKind::PlaintextToken)
        );
    }

    #[test]
    fn flags_plaintext_password() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("config");
        std::fs::write(&p, "users:\n- name: dev\n  user:\n    password: secret\n").unwrap();
        let out = audit(&p);
        assert!(
            out.iter()
                .any(|f| f.kind == KubeFindingKind::PlaintextPassword)
        );
    }

    #[test]
    fn flags_embedded_client_cert() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("config");
        std::fs::write(
            &p,
            "users:\n- name: dev\n  user:\n    client-certificate-data: AAAA\n",
        )
        .unwrap();
        let out = audit(&p);
        assert!(
            out.iter()
                .any(|f| f.kind == KubeFindingKind::EmbeddedClientCert)
        );
    }

    #[cfg(unix)]
    #[test]
    fn flags_world_readable_config() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let p = dir.path().join("config");
        std::fs::write(&p, "apiVersion: v1\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let out = audit(&p);
        assert!(
            out.iter()
                .any(|f| f.kind == KubeFindingKind::WorldReadableConfig)
        );
    }
}
