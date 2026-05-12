//! macOS autostart enumeration (TASK-138).
//!
//! Returns the set of paths the file-mutation baseline detector
//! (`detect/file_mutation.rs`) should snapshot every scan. macOS
//! persistence surfaces are concentrated in launchd plist trees + shell
//! rc files; per FR-131 we collect:
//!
//! - **System-wide launchd**: `/Library/LaunchAgents/`,
//!   `/Library/LaunchDaemons/`, `/System/Library/LaunchAgents/`, and
//!   `/System/Library/LaunchDaemons/`. We surface the plist itself; the
//!   target binary is whichever `ProgramArguments[0]` references — not
//!   resolved here to keep the enumerator boundary clean. Hash drift on
//!   the plist still flags a tampered launch item.
//! - **Per-user launchd**: `~/Library/LaunchAgents/`.
//! - **Login items (sandboxed location)**: `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/`
//!   (`BackgroundItems.btm`). Single file; mutations are noteworthy.
//! - **Shell rc files**: `~/.bashrc`, `~/.bash_profile`, `~/.zshrc`,
//!   `~/.zprofile`, `~/.profile`.
//!
//! `$PATH` binaries flow through the cross-platform shim in
//! `crate::detect::file_mutation::path_binaries`.

use std::path::PathBuf;

/// Collect every autostart-class path on this macOS host. Best-effort —
/// missing directories are silently skipped.
pub fn enumerate_autostart() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let home = std::env::var_os("HOME").map(PathBuf::from);

    let system_dirs = [
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/System/Library/LaunchAgents",
        "/System/Library/LaunchDaemons",
    ];
    for dir in system_dirs {
        push_dir_contents(std::path::Path::new(dir), "plist", &mut out);
    }
    if let Some(h) = home.as_ref() {
        push_dir_contents(&h.join("Library/LaunchAgents"), "plist", &mut out);

        // BackgroundItems.btm — single file in a sandboxed dir.
        let btm = h.join(
            "Library/Application Support/com.apple.backgroundtaskmanagementagent/BackgroundItems.btm",
        );
        if btm.is_file() {
            out.push(btm);
        }

        for rc in [
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".zshrc",
            ".zprofile",
        ] {
            let p = h.join(rc);
            if p.is_file() {
                out.push(p);
            }
        }
    }

    out
}

fn push_dir_contents(dir: &std::path::Path, ext: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        if p.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case(ext))
            .unwrap_or(false)
        {
            out.push(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerator_returns_files_only() {
        let paths = enumerate_autostart();
        for p in paths {
            assert!(p.is_file(), "enumerator surfaced non-file: {}", p.display());
        }
    }
}
