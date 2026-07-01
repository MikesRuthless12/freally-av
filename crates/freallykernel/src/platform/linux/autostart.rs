//! Linux autostart enumeration (TASK-138).
//!
//! Returns the set of paths the file-mutation baseline detector
//! (`detect/file_mutation.rs`) should snapshot every scan. Mutations to
//! these files are the highest-leverage post-compromise persistence
//! signal on Linux. Per FR-131 we collect:
//!
//! - **XDG autostart desktop entries** — every `.desktop` file under
//!   `/etc/xdg/autostart/`, `$XDG_CONFIG_HOME/autostart/`, and per-user
//!   `~/.config/autostart/`.
//! - **systemd unit symlink targets** — `/etc/systemd/system/*.service`
//!   plus `$XDG_CONFIG_HOME/systemd/user/*.service` and `~/.config/systemd/user/*.service`.
//! - **Shell rc files** — `~/.bashrc`, `~/.bash_profile`, `~/.profile`,
//!   `~/.zshrc`, `~/.zprofile`. Scripts the user reads on every shell.
//!
//! `$PATH` binaries are surfaced through the cross-platform shim in
//! `crate::detect::file_mutation::path_binaries` so the same enumerator
//! works on every host.

use std::path::PathBuf;

/// Collect every autostart-class path on this Linux host. Best-effort —
/// missing directories are silently skipped. The caller dedupes.
pub fn enumerate_autostart() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let home = std::env::var_os("HOME").map(PathBuf::from);

    // XDG autostart directories.
    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|h| h.join(".config")));
    let xdg_dirs = [
        Some(PathBuf::from("/etc/xdg/autostart")),
        xdg_config_home.clone().map(|p| p.join("autostart")),
        home.as_ref().map(|h| h.join(".config/autostart")),
    ];
    for dir in xdg_dirs.into_iter().flatten() {
        push_dir_contents(&dir, "desktop", &mut out);
    }

    // systemd units (service files; honor enabled symlinks first, fall
    // through to the unit files themselves).
    let systemd_dirs = [
        Some(PathBuf::from("/etc/systemd/system")),
        xdg_config_home.map(|p| p.join("systemd/user")),
        home.as_ref().map(|h| h.join(".config/systemd/user")),
    ];
    for dir in systemd_dirs.into_iter().flatten() {
        push_dir_contents(&dir, "service", &mut out);
    }

    // Shell rc files.
    if let Some(h) = home {
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

/// Push every regular file under `dir` whose extension matches `ext`
/// (case-insensitive) into `out`. Silently skips missing directories
/// and unreadable entries.
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

    /// On any Linux developer host, at least one XDG / systemd directory
    /// will exist — but on CI containers many may be empty. The test
    /// only asserts the enumerator returns without panicking and never
    /// produces a non-file entry; an empty Vec is acceptable.
    #[test]
    fn enumerator_returns_files_only() {
        let paths = enumerate_autostart();
        for p in paths {
            assert!(p.is_file(), "enumerator surfaced non-file: {}", p.display());
        }
    }
}
