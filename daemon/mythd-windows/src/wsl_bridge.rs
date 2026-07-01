//! WSL distro auto-discover (TASK-240, Phase 8 Wave 2).
//!
//! Windows-host half of the cross-host real-time bridge. Enumerates
//! WSL2 distros via `wsl.exe --list --verbose`, offers to install a
//! `freallyd-linux` daemon companion inside each, and aggregates findings
//! through the per-distro `\\wsl.localhost\<distro>\run\freallyd\freallyd.sock`
//! UNIX socket bridge.
//!
//! No kernel driver, no Hyper-V escape — all communication is via the
//! documented `\\wsl.localhost` path. Install path is opt-in per distro.

pub use freallykernel::platform::wsl::{WslDistroRow, parse_wsl_list_text, parse_wsl_list_utf16le};

/// Build the argv for `wsl.exe --list --verbose`. Returned instead of
/// executed so unit tests don't spawn a subprocess.
pub fn list_distros_argv() -> Vec<String> {
    vec![
        "wsl.exe".to_string(),
        "--list".to_string(),
        "--verbose".to_string(),
    ]
}

/// Build the argv for `wsl.exe -d <distro> -- <cmd>...`.
pub fn run_in_distro_argv(distro: &str, cmd: &[&str]) -> Vec<String> {
    let mut argv = vec![
        "wsl.exe".to_string(),
        "-d".to_string(),
        distro.to_string(),
        "--".to_string(),
    ];
    for c in cmd {
        argv.push((*c).to_string());
    }
    argv
}

/// Per-distro IPC socket path under `\\wsl.localhost\<distro>`.
/// Returns the canonical path the Windows-side bridge `connect`s to.
pub fn distro_socket_path(distro: &str) -> String {
    format!(r"\\wsl.localhost\{distro}\run\freallyd\freallyd.sock")
}

/// Spawn `wsl.exe --list --verbose` and parse the output. Returns
/// the list of distros, or an empty list if `wsl.exe` is missing.
#[cfg(target_os = "windows")]
pub fn list_distros() -> Vec<WslDistroRow> {
    let out = std::process::Command::new("wsl.exe")
        .arg("--list")
        .arg("--verbose")
        .output();
    match out {
        Ok(o) => parse_wsl_list_utf16le(&o.stdout),
        Err(_) => Vec::new(),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn list_distros() -> Vec<WslDistroRow> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_argv_is_canonical() {
        let argv = list_distros_argv();
        assert_eq!(argv, vec!["wsl.exe", "--list", "--verbose"]);
    }

    #[test]
    fn run_in_distro_threads_command() {
        let argv = run_in_distro_argv("Ubuntu", &["sudo", "install", "freallyd"]);
        assert_eq!(
            argv,
            vec!["wsl.exe", "-d", "Ubuntu", "--", "sudo", "install", "freallyd"]
        );
    }

    #[test]
    fn socket_path_is_canonical() {
        let p = distro_socket_path("Ubuntu");
        assert_eq!(p, r"\\wsl.localhost\Ubuntu\run\freallyd\freallyd.sock");
    }
}
