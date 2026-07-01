//! Windows autostart enumeration (TASK-138).
//!
//! Returns the set of paths the file-mutation baseline detector
//! (`detect/file_mutation.rs`) should snapshot every scan. Windows
//! persistence surfaces are spread across Start Menu / Startup folders
//! plus registry `Run` keys. Per FR-131 the static-file portion is:
//!
//! - **Startup folder (per-user)**:
//!   `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`
//! - **Startup folder (all users)**:
//!   `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp\`
//! - **Common shell config**: `%USERPROFILE%\Documents\PowerShell\profile.ps1`
//!   and `%USERPROFILE%\Documents\WindowsPowerShell\profile.ps1`.
//!
//! Registry `Run` / `RunOnce` keys aren't filesystem entries — the
//! Phase 12 ETW + WDAC enforcement stack (TASK-098) covers them via the
//! ETW Threat Intelligence subscriber. We deliberately scope this
//! enumerator to *files* so the mutation detector's hash-drift contract
//! holds without an extra registry-snapshot layer.
//!
//! `$PATH` binaries flow through the cross-platform shim in
//! `crate::detect::file_mutation::path_binaries`.

use std::path::PathBuf;

/// Collect every autostart-class file path on this Windows host.
/// Best-effort — missing directories are silently skipped.
pub fn enumerate_autostart() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();

    // Per-user Startup folder.
    if let Some(appdata) = std::env::var_os("APPDATA") {
        let p = PathBuf::from(appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup");
        push_dir_contents(&p, &mut out);
    }

    // All-users Startup folder.
    if let Some(programdata) = std::env::var_os("ProgramData") {
        let p =
            PathBuf::from(programdata).join("Microsoft\\Windows\\Start Menu\\Programs\\StartUp");
        push_dir_contents(&p, &mut out);
    }

    // PowerShell profile.ps1 (PowerShell 7 + Windows PowerShell 5.1).
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        let base = PathBuf::from(profile);
        for sub in [
            "Documents\\PowerShell\\profile.ps1",
            "Documents\\WindowsPowerShell\\profile.ps1",
        ] {
            let p = base.join(sub);
            if p.is_file() {
                out.push(p);
            }
        }
    }

    out
}

/// Push every regular file under `dir` into `out`. We don't filter by
/// extension here — Startup folders accept .lnk shortcuts, .bat scripts,
/// .exe files, .cmd scripts, and more; the mutation detector compares
/// the hash regardless of type.
fn push_dir_contents(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_file() {
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
