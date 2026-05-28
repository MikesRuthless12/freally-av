//! SSH `Match` block scanner (TASK-320).
//!
//! Reads `~/.ssh/config` plus any `/etc/ssh/ssh_config(.d/*)`
//! files the caller assembles. Inside each `Match` block, flags
//! `ProxyCommand` / `ProxyJump` whose argument resolves into a
//! user-writable path (`$TMPDIR`, `~/Downloads`, `/tmp`,
//! `/var/folders/`).
//!
//! Pure line scan — ssh-config is a single-line directive
//! format with optional indentation under each `Host` /
//! `Match` block.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshConfigFindingKind {
    SuspiciousProxyCommand,
    SuspiciousProxyJump,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshConfigFinding {
    pub kind: SshConfigFindingKind,
    pub source: PathBuf,
    pub block: String,
    pub line_number: usize,
    pub raw_line: String,
}

pub fn audit(config_path: &Path) -> Vec<SshConfigFinding> {
    let Ok(body) = std::fs::read_to_string(config_path) else {
        return Vec::new();
    };
    audit_body(config_path, &body)
}

fn audit_body(source: &Path, body: &str) -> Vec<SshConfigFinding> {
    let mut out = Vec::new();
    let mut current_block: String = "<global>".to_string();
    for (idx, raw) in body.lines().enumerate() {
        let line_number = idx + 1;
        let line = raw.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("host ") || lower.starts_with("match ") {
            current_block = line.to_string();
            continue;
        }
        // ssh_config keywords are case-insensitive (see `man 5
        // ssh_config`), so match the lowered prefix and recover the
        // original-case argument via byte-offset slicing.
        if let Some(value) = strip_ci_keyword(line, "ProxyCommand") {
            if has_user_writable_path(value) {
                out.push(SshConfigFinding {
                    kind: SshConfigFindingKind::SuspiciousProxyCommand,
                    source: source.to_path_buf(),
                    block: current_block.clone(),
                    line_number,
                    raw_line: raw.to_string(),
                });
            }
        } else if let Some(value) = strip_ci_keyword(line, "ProxyJump") {
            if has_user_writable_path(value) {
                out.push(SshConfigFinding {
                    kind: SshConfigFindingKind::SuspiciousProxyJump,
                    source: source.to_path_buf(),
                    block: current_block.clone(),
                    line_number,
                    raw_line: raw.to_string(),
                });
            }
        }
    }
    out
}

/// Case-insensitive `strip_prefix` for ssh_config keywords. Returns
/// the trimmed argument when the keyword matches and is followed by
/// whitespace (or `=` for the `Keyword=Value` shorthand `ssh` also
/// honors).
fn strip_ci_keyword<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    if line.len() < keyword.len() {
        return None;
    }
    let head = &line[..keyword.len()];
    if !head.eq_ignore_ascii_case(keyword) {
        return None;
    }
    let rest = &line[keyword.len()..];
    let first = rest.chars().next()?;
    if first.is_whitespace() || first == '=' {
        Some(rest.trim_start_matches(['=', ' ', '\t']).trim_end())
    } else {
        None
    }
}

fn has_user_writable_path(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("/tmp/")
        || lower.contains("/var/tmp/")
        || lower.contains("/downloads/")
        || lower.contains("/var/folders/")
        || lower.contains("$tmpdir")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn flags_proxycommand_in_tmp() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("config");
        std::fs::write(
            &p,
            "Host attacker\n    ProxyCommand /tmp/evil-proxy %h %p\n",
        )
        .unwrap();
        let out = audit(&p);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, SshConfigFindingKind::SuspiciousProxyCommand);
    }

    #[test]
    fn flags_proxyjump_under_downloads() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("config");
        std::fs::write(
            &p,
            "Match all\n    ProxyJump /Users/alice/Downloads/jump.sh\n",
        )
        .unwrap();
        let out = audit(&p);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, SshConfigFindingKind::SuspiciousProxyJump);
        assert!(out[0].block.to_ascii_lowercase().starts_with("match"));
    }

    #[test]
    fn case_insensitive_keyword_match() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("config");
        std::fs::write(&p, "Host attacker\n    PROXYCOMMAND /tmp/x.sh %h %p\n").unwrap();
        let out = audit(&p);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, SshConfigFindingKind::SuspiciousProxyCommand);
    }

    #[test]
    fn silent_on_safe_paths() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("config");
        std::fs::write(
            &p,
            "Host work\n    ProxyCommand /usr/bin/ssh -W %h:%p bastion\n",
        )
        .unwrap();
        assert!(audit(&p).is_empty());
    }
}
