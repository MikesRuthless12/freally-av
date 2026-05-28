//! Suspicious environment-variable detector (TASK-304,
//! Phase 10 Wave 3, Linux + macOS).
//!
//! The daemon reads `/proc/<pid>/environ` on Linux and
//! `KERN_PROCARGS2` on macOS, then hands the resulting
//! `(name, value)` pairs to [`audit`]. Findings are read-only
//! and opt-in — the prd's "no kernel driver" rule means we
//! cannot block `LD_PRELOAD`-tainted spawns; we just surface
//! them.
//!
//! Detected hijack-class env vars:
//!
//! * `LD_AUDIT` (Linux), `LD_PRELOAD` (Linux) — runtime linker
//!   library injection.
//! * `DYLD_INSERT_LIBRARIES`, `DYLD_FRAMEWORK_PATH`,
//!   `DYLD_LIBRARY_PATH` (macOS) — dyld injection / search-order
//!   hijack. SIP scrubs these for protected binaries; for
//!   user-space binaries they still flow through.
//! * `PYTHONPATH` pointing into `$TMPDIR`, `/tmp`, or any
//!   `Downloads/` segment.
//! * `PERL5OPT`, `RUBYOPT` — `-Mevil` / `-r evil.rb` style
//!   pre-execution module loading.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvAuditKind {
    LdPreload,
    LdAudit,
    DyldInsertLibraries,
    DyldFrameworkPath,
    DyldLibraryPath,
    PythonPathUserWritable,
    Perl5Opt,
    RubyOpt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvAuditFinding {
    pub kind: EnvAuditKind,
    pub variable: String,
    pub value: String,
}

/// Audit one process's environment block.
pub fn audit(env: &[(String, String)]) -> Vec<EnvAuditFinding> {
    let mut out = Vec::new();
    for (name, value) in env {
        if value.is_empty() {
            continue;
        }
        if let Some(kind) = classify(name, value) {
            out.push(EnvAuditFinding {
                kind,
                variable: name.clone(),
                value: value.clone(),
            });
        }
    }
    out
}

fn classify(name: &str, value: &str) -> Option<EnvAuditKind> {
    match name {
        "LD_PRELOAD" => Some(EnvAuditKind::LdPreload),
        "LD_AUDIT" => Some(EnvAuditKind::LdAudit),
        "DYLD_INSERT_LIBRARIES" => Some(EnvAuditKind::DyldInsertLibraries),
        "DYLD_FRAMEWORK_PATH" => Some(EnvAuditKind::DyldFrameworkPath),
        "DYLD_LIBRARY_PATH" => Some(EnvAuditKind::DyldLibraryPath),
        "PYTHONPATH" => {
            if value.split(':').any(is_user_writable_temp_or_downloads) {
                Some(EnvAuditKind::PythonPathUserWritable)
            } else {
                None
            }
        }
        "PERL5OPT" => Some(EnvAuditKind::Perl5Opt),
        "RUBYOPT" => Some(EnvAuditKind::RubyOpt),
        _ => None,
    }
}

fn is_user_writable_temp_or_downloads(seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }
    let lower = seg.to_ascii_lowercase();
    lower == "/tmp"
        || lower.starts_with("/tmp/")
        || lower.starts_with("/var/tmp/")
        || lower.starts_with("/var/folders/")
        || lower.contains("/downloads/")
        || lower.ends_with("/downloads")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn flags_ld_preload() {
        let f = audit(&env(&[("LD_PRELOAD", "/tmp/evil.so")]));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, EnvAuditKind::LdPreload);
    }

    #[test]
    fn flags_dyld_insert_libraries() {
        let f = audit(&env(&[(
            "DYLD_INSERT_LIBRARIES",
            "/Users/alice/Downloads/inject.dylib",
        )]));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, EnvAuditKind::DyldInsertLibraries);
    }

    #[test]
    fn pythonpath_only_flags_user_writable() {
        let safe = audit(&env(&[("PYTHONPATH", "/usr/lib/python3.11")]));
        assert!(safe.is_empty());
        let bad = audit(&env(&[(
            "PYTHONPATH",
            "/usr/lib/python3.11:/Users/alice/Downloads/payload",
        )]));
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].kind, EnvAuditKind::PythonPathUserWritable);
    }

    #[test]
    fn flags_perl5opt_and_rubyopt() {
        let f = audit(&env(&[("PERL5OPT", "-Mevil"), ("RUBYOPT", "-revil")]));
        assert_eq!(f.len(), 2);
        assert!(f.iter().any(|x| x.kind == EnvAuditKind::Perl5Opt));
        assert!(f.iter().any(|x| x.kind == EnvAuditKind::RubyOpt));
    }

    #[test]
    fn empty_values_are_silent() {
        let f = audit(&env(&[("LD_PRELOAD", "")]));
        assert!(f.is_empty());
    }
}
