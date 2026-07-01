//! Suspicious DLL-search-path detector (TASK-305, Phase 10
//! Wave 3, Windows-only).
//!
//! For each running process, the daemon enumerates loaded
//! modules via `EnumProcessModules` and resolves each module's
//! load path. Loads that originated outside of `KnownDLLs` /
//! `%SystemRoot%\System32` and instead resolved against the
//! process's current working directory (or an attacker-writable
//! search-order entry) raise a `dll-search-hijack` finding.
//!
//! Foundation here owns the analysis function — the caller
//! supplies a [`LoadedModule`] list. Platform code lives in the
//! Windows daemon.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadedModule {
    /// Just the file name, e.g. `wininet.dll`. Case is preserved
    /// for the finding; comparison is ASCII-insensitive.
    pub module_name: String,
    /// Absolute path the module actually loaded from.
    pub loaded_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DllHijackFinding {
    pub module_name: String,
    pub loaded_path: String,
    /// `loaded_path` parent — preserved for UI presentation.
    pub loaded_dir: String,
}

/// Inputs the caller has assembled per-process before invoking
/// the rule.
pub struct DllSearchContext<'a> {
    /// Module table from `EnumProcessModules`.
    pub modules: &'a [LoadedModule],
    /// Working directory of the process (`GetCurrentDirectoryW`
    /// inside the target via remote call, or the snapshot the
    /// daemon already records at exec time).
    pub current_directory: &'a str,
    /// Whether the OS protected this load through `KnownDLLs`.
    /// Caller (the Windows daemon) tracks this by querying
    /// `HKLM\System\CurrentControlSet\Control\Session Manager\KnownDLLs`
    /// at start-up.
    pub known_dlls: &'a [String],
}

/// Returns every loaded module that resolved into the process's
/// CWD instead of `System32` / a known protected DLL location.
pub fn evaluate(ctx: &DllSearchContext<'_>) -> Vec<DllHijackFinding> {
    let mut out = Vec::new();
    let cwd_lower = ctx.current_directory.to_ascii_lowercase();
    for m in ctx.modules {
        if ctx
            .known_dlls
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&m.module_name))
        {
            continue;
        }
        let path_lower = m.loaded_path.to_ascii_lowercase();
        if path_lower.starts_with("c:\\windows\\system32\\")
            || path_lower.starts_with("c:\\windows\\syswow64\\")
        {
            continue;
        }
        if path_lower.starts_with(&cwd_lower) {
            let loaded_dir = parent_dir(&m.loaded_path).to_string();
            out.push(DllHijackFinding {
                module_name: m.module_name.clone(),
                loaded_path: m.loaded_path.clone(),
                loaded_dir,
            });
        }
    }
    out
}

fn parent_dir(p: &str) -> &str {
    p.rsplit_once(['\\', '/'])
        .map(|(parent, _)| parent)
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_dll_loaded_from_cwd() {
        let mods = vec![LoadedModule {
            module_name: "wininet.dll".to_string(),
            loaded_path: "C:\\Users\\alice\\Downloads\\app\\wininet.dll".to_string(),
        }];
        let ctx = DllSearchContext {
            modules: &mods,
            current_directory: "C:\\Users\\alice\\Downloads\\app",
            known_dlls: &["kernel32.dll".to_string()],
        };
        let f = evaluate(&ctx);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].module_name, "wininet.dll");
        assert_eq!(f[0].loaded_dir, "C:\\Users\\alice\\Downloads\\app");
    }

    #[test]
    fn silent_when_loaded_from_system32() {
        let mods = vec![LoadedModule {
            module_name: "wininet.dll".to_string(),
            loaded_path: "C:\\Windows\\System32\\wininet.dll".to_string(),
        }];
        let ctx = DllSearchContext {
            modules: &mods,
            current_directory: "C:\\Users\\alice\\Downloads\\app",
            known_dlls: &[],
        };
        assert!(evaluate(&ctx).is_empty());
    }

    #[test]
    fn known_dlls_are_skipped_even_when_path_unusual() {
        let mods = vec![LoadedModule {
            module_name: "kernel32.dll".to_string(),
            loaded_path: "C:\\Users\\alice\\app\\kernel32.dll".to_string(),
        }];
        let ctx = DllSearchContext {
            modules: &mods,
            current_directory: "C:\\Users\\alice\\app",
            known_dlls: &["kernel32.dll".to_string()],
        };
        // KnownDLLs is the OS-level loader allowlist; the
        // process can't actually have substituted kernel32
        // from CWD, so the rule trusts the daemon's snapshot.
        assert!(evaluate(&ctx).is_empty());
    }

    #[test]
    fn case_insensitive_path_compare() {
        let mods = vec![LoadedModule {
            module_name: "Wininet.DLL".to_string(),
            loaded_path: "C:\\USERS\\alice\\Downloads\\app\\Wininet.DLL".to_string(),
        }];
        let ctx = DllSearchContext {
            modules: &mods,
            current_directory: "c:\\users\\alice\\downloads\\app",
            known_dlls: &[],
        };
        assert_eq!(evaluate(&ctx).len(), 1);
    }
}
