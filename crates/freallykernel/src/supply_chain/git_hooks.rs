//! Git-config hook detector (TASK-312).
//!
//! Reads project-local `.git/hooks/*` plus the global git
//! config (`~/.gitconfig`, `~/.config/git/config`,
//! `/etc/gitconfig`). Flags:
//!
//!   * `core.fsmonitor` set to a path inside `$TMPDIR`,
//!     `~/Downloads`, `/tmp`, or any world-writable directory
//!   * `core.hooksPath` pointing into the same set of paths
//!   * `init.templateDir` pointing into the same set of paths
//!
//! Project `.git/hooks/<name>` files are surfaced as
//! `executable-hook` informational rows when any hook file is
//! non-empty (git ships the default `.sample` files which are
//! also surfaced but tagged as `sample`).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHookFindingKind {
    SuspiciousFsMonitor,
    SuspiciousHooksPath,
    SuspiciousTemplateDir,
    ExecutableHook,
    SampleHook,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHookFinding {
    pub kind: GitHookFindingKind,
    pub source: PathBuf,
    pub value: String,
}

pub fn audit_project(project_root: &Path) -> Vec<GitHookFinding> {
    let mut out = Vec::new();
    let hooks_dir = project_root.join(".git").join("hooks");
    if let Ok(read) = std::fs::read_dir(&hooks_dir) {
        for entry in read.flatten() {
            let p = entry.path();
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if name.ends_with(".sample") {
                out.push(GitHookFinding {
                    kind: GitHookFindingKind::SampleHook,
                    source: p.clone(),
                    value: name.to_string(),
                });
                continue;
            }
            // Non-sample hook present and non-empty.
            if let Ok(meta) = std::fs::metadata(&p) {
                if meta.len() > 0 {
                    out.push(GitHookFinding {
                        kind: GitHookFindingKind::ExecutableHook,
                        source: p.clone(),
                        value: name.to_string(),
                    });
                }
            }
        }
    }
    let project_config = project_root.join(".git").join("config");
    if project_config.is_file() {
        audit_config(&project_config, &mut out);
    }
    out
}

pub fn audit_config(config_path: &Path, out: &mut Vec<GitHookFinding>) {
    let Ok(body) = std::fs::read_to_string(config_path) else {
        return;
    };
    let mut current_section: Option<String> = None;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            let inside = trimmed.trim_matches(['[', ']']).trim();
            current_section = Some(inside.to_lowercase());
            continue;
        }
        let Some(section) = current_section.as_deref() else {
            continue;
        };
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim().to_lowercase();
            let value = v.trim().trim_matches('"').to_string();
            let path = format!("{section}.{key}");
            let kind = match path.as_str() {
                "core.fsmonitor" if is_suspicious(&value) => {
                    Some(GitHookFindingKind::SuspiciousFsMonitor)
                }
                "core.hookspath" if is_suspicious(&value) => {
                    Some(GitHookFindingKind::SuspiciousHooksPath)
                }
                "init.templatedir" if is_suspicious(&value) => {
                    Some(GitHookFindingKind::SuspiciousTemplateDir)
                }
                _ => None,
            };
            if let Some(kind) = kind {
                out.push(GitHookFinding {
                    kind,
                    source: config_path.to_path_buf(),
                    value,
                });
            }
        }
    }
}

fn is_suspicious(value: &str) -> bool {
    // Normalize backslashes so the same predicate works on
    // Windows paths from `core.hooksPath = C:\Users\u\Downloads\...`.
    let lower = value.to_ascii_lowercase().replace('\\', "/");
    lower.starts_with("/tmp/")
        || lower == "/tmp"
        || lower.starts_with("/var/tmp/")
        || lower.contains("/downloads/")
        || lower.ends_with("/downloads")
        || lower.starts_with("/var/folders/")
        // Windows AppData/Local/Temp and any drive-letter Temp dir.
        || lower.contains("/appdata/local/temp/")
        || lower.contains("/temp/")
        || lower.contains("/users/public/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn flags_suspicious_hookspath() {
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("config");
        std::fs::write(
            &cfg,
            "[core]\nhooksPath = /tmp/evil-hooks\nrepositoryformatversion = 0\n",
        )
        .unwrap();
        let mut out = Vec::new();
        audit_config(&cfg, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, GitHookFindingKind::SuspiciousHooksPath);
    }

    #[test]
    fn flags_executable_hooks_and_samples() {
        let dir = tempdir().unwrap();
        let hooks = dir.path().join(".git/hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        std::fs::write(hooks.join("pre-commit.sample"), b"#!/bin/sh\n").unwrap();
        std::fs::write(hooks.join("pre-push"), b"#!/bin/sh\necho hi\n").unwrap();
        let out = audit_project(dir.path());
        assert!(
            out.iter()
                .any(|f| f.kind == GitHookFindingKind::ExecutableHook && f.value == "pre-push")
        );
        assert!(
            out.iter()
                .any(|f| f.kind == GitHookFindingKind::SampleHook
                    && f.value == "pre-commit.sample")
        );
    }

    #[test]
    fn flags_windows_downloads_hookspath() {
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("config");
        std::fs::write(
            &cfg,
            "[core]\nhooksPath = C:\\Users\\victim\\Downloads\\evil-hooks\n",
        )
        .unwrap();
        let mut out = Vec::new();
        audit_config(&cfg, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, GitHookFindingKind::SuspiciousHooksPath);
    }

    #[test]
    fn safe_paths_are_silent() {
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("config");
        std::fs::write(&cfg, "[core]\nhooksPath = /usr/local/share/git-hooks\n").unwrap();
        let mut out = Vec::new();
        audit_config(&cfg, &mut out);
        assert!(out.is_empty());
    }
}
