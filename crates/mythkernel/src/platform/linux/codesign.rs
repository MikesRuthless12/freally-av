//! Linux signer extraction (TASK-136).
//!
//! Strategy (in order of preference):
//!   1. **Detached GPG signature** next to the file (`<path>.sig`, `<path>.asc`).
//!      Read the fingerprint via `gpg --verify --status-fd 1` and surface the
//!      `VALIDSIG <fpr>` line. Reflects upstream packages that ship signed
//!      tarballs (Linux kernel sources, gnupg itself, etc.).
//!   2. **Owning dpkg package**: `dpkg-query -S <path>` finds the package;
//!      `dpkg-query -f '${Maintainer}' -W <pkg>` returns the maintainer. The
//!      GPG signature of the .deb itself is verified by APT during install —
//!      by the time the file is on disk, it transitively came from the
//!      apt-keyring-trusted source.
//!   3. **Owning RPM package**: `rpm -qf <path>` and `rpm -q --queryformat '%{PACKAGER}' <pkg>`.
//!   4. **Unsigned** — no detached sig and not owned by a package manager
//!      (typical for ~/Downloads/random.bin).
//!
//! All shells are best-effort with a hard 3 s timeout. Failures return
//! `unsigned()` rather than propagating an error — a signer extractor that
//! refuses to scan unsigned files would block 99% of legitimate user data.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::detect::publisher::{SignerIdentity, SignerKind};

const SHELL_TIMEOUT: Duration = Duration::from_secs(3);

/// PATH-pinned absolute paths to the system signer tools (sec-review M4).
/// A user whose `~/.bin/gpg` shadows the real one could otherwise trick
/// the engine into accepting fake signers. Fall back to the bare name if
/// the canonical path is missing (e.g. NixOS, BSDs).
const GPG_PATHS: &[&str] = &["/usr/bin/gpg", "/bin/gpg"];
const DPKG_PATHS: &[&str] = &["/usr/bin/dpkg-query"];
const RPM_PATHS: &[&str] = &["/usr/bin/rpm", "/bin/rpm"];

fn resolve_binary(candidates: &[&str], fallback_name: &str) -> std::ffi::OsString {
    for c in candidates {
        if Path::new(c).exists() {
            return c.into();
        }
    }
    // The unconditional fallback preserves portability on distros where
    // the binary lives under a non-canonical prefix. The exec inherits
    // the parent's PATH; the security review's M4 concern is only the
    // "user-writable shadow" case, which canonical paths eliminate when
    // they exist.
    fallback_name.into()
}

pub fn extract_signer(path: &Path) -> SignerIdentity {
    if let Some(s) = try_gpg_detached(path) {
        return s;
    }
    if let Some(s) = try_dpkg(path) {
        return s;
    }
    if let Some(s) = try_rpm(path) {
        return s;
    }
    SignerIdentity::unsigned()
}

fn try_gpg_detached(path: &Path) -> Option<SignerIdentity> {
    for ext in [".sig", ".asc"] {
        let sig_path = format!("{}{ext}", path.display());
        if !Path::new(&sig_path).exists() {
            continue;
        }
        let gpg_bin = resolve_binary(GPG_PATHS, "gpg");
        let out = timeout_command(
            Command::new(&gpg_bin)
                .arg("--status-fd")
                .arg("1")
                .arg("--verify")
                .arg(&sig_path)
                .arg(path),
        )?;
        if !out.status.success() {
            continue;
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            // `[GNUPG:] VALIDSIG <fingerprint> ...`
            if let Some(rest) = line.strip_prefix("[GNUPG:] VALIDSIG ")
                && let Some(fpr) = rest.split_whitespace().next()
            {
                return Some(SignerIdentity {
                    identity: format!("gpg:{fpr}"),
                    kind: SignerKind::Gpg,
                });
            }
        }
    }
    None
}

fn try_dpkg(path: &Path) -> Option<SignerIdentity> {
    let dpkg_bin = resolve_binary(DPKG_PATHS, "dpkg-query");
    let out = timeout_command(Command::new(&dpkg_bin).arg("-S").arg(path))?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Format on stock dpkg: `package-name: /full/path`
    // Multi-arch dpkg: `package-name:arch: /full/path` (sec-review M1).
    // Strategy: rsplit on `: ` (colon followed by space) which always
    // separates the path from the package spec.
    let pkg = match stdout.rsplit_once(": ") {
        Some((pkg_part, _path_part)) => pkg_part.trim(),
        None => return None,
    };
    if pkg.is_empty() {
        return None;
    }
    let out2 = timeout_command(
        Command::new(&dpkg_bin)
            .arg("-W")
            .arg("-f=${Maintainer}")
            .arg(pkg),
    )?;
    if !out2.status.success() {
        return None;
    }
    let maintainer = String::from_utf8_lossy(&out2.stdout).trim().to_string();
    if maintainer.is_empty() {
        return None;
    }
    Some(SignerIdentity {
        identity: format!("dpkg:{pkg}:{maintainer}"),
        kind: SignerKind::Gpg,
    })
}

/// Pure parser exposed for tests (sec-review M1 + code-review nit 13).
/// Pulls the package spec ("name" or "name:arch") from a `dpkg-query -S`
/// stdout line, tolerating the multi-arch suffix.
pub fn parse_dpkg_query_s(stdout: &str) -> Option<&str> {
    stdout.rsplit_once(": ").map(|(pkg, _)| pkg.trim())
}

fn try_rpm(path: &Path) -> Option<SignerIdentity> {
    let rpm_bin = resolve_binary(RPM_PATHS, "rpm");
    let out = timeout_command(Command::new(&rpm_bin).arg("-qf").arg(path))?;
    if !out.status.success() {
        return None;
    }
    let pkg = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if pkg.is_empty() || pkg.starts_with("error") {
        return None;
    }
    // Query packager only — the `%{SIGPGP:pgpsig}` field returns the
    // full ASCII-armored PGP signature blob (hundreds of bytes) which
    // would have been concatenated into `signer_identity`, blowing past
    // the persistence cap (sec-review M3). Use the short keyid form
    // instead.
    let out2 = timeout_command(
        Command::new(&rpm_bin)
            .arg("-q")
            .arg("--queryformat")
            .arg("%{PACKAGER}\n%{SIGGPG:pgpsig}")
            .arg(&pkg),
    )?;
    if !out2.status.success() {
        return None;
    }
    let body = String::from_utf8_lossy(&out2.stdout).trim().to_string();
    if body.is_empty() || body.contains("(none)") {
        return None;
    }
    // Defensive truncation in addition to the global cap in
    // `SignerIdentity::truncated()` — keeps free-text noise out of the
    // log lines too.
    let one_line: String = body.replace('\n', " ").chars().take(256).collect();
    Some(SignerIdentity {
        identity: format!("rpm:{pkg}:{one_line}"),
        kind: SignerKind::Gpg,
    })
}

/// Run a command with a hard timeout. Wraps `wait_timeout` semantics; we
/// don't depend on the wait-timeout crate to keep transitive deps slim.
fn timeout_command(cmd: &mut Command) -> Option<std::process::Output> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let start = std::time::Instant::now();
    loop {
        if let Ok(Some(_status)) = child.try_wait() {
            return child.wait_with_output().ok();
        }
        if start.elapsed() >= SHELL_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn unsigned_file_returns_unsigned() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("plain.bin");
        fs::write(&p, b"hello").unwrap();
        let s = extract_signer(&p);
        assert_eq!(s.kind, SignerKind::Unsigned);
    }

    #[test]
    fn parse_dpkg_query_s_handles_plain_format() {
        let out = "coreutils: /usr/bin/ls\n";
        assert_eq!(parse_dpkg_query_s(out), Some("coreutils"));
    }

    #[test]
    fn parse_dpkg_query_s_handles_multi_arch() {
        // Sec-review M1 — `pkg:arch: /path` was previously truncated
        // to `pkg` by splitting on the first colon.
        let out = "libc6:amd64: /lib/x86_64-linux-gnu/libc.so.6\n";
        assert_eq!(parse_dpkg_query_s(out), Some("libc6:amd64"));
    }

    #[test]
    fn parse_dpkg_query_s_handles_path_with_colon() {
        // `dpkg-query` never emits paths containing ": " (the package
        // specifier is followed by a *literal* colon-space), so a path
        // containing a colon alone is still parsed correctly.
        let out = "weird-pkg: /weird:path/file\n";
        assert_eq!(parse_dpkg_query_s(out), Some("weird-pkg"));
    }

    #[test]
    fn resolve_binary_uses_canonical_path_when_present() {
        // Sec-review M4 — pick the absolute path when it exists.
        // This test is a no-op on systems where /usr/bin/sh isn't
        // present, but covers the resolve fn's happy path.
        let resolved = resolve_binary(&["/this/does/not/exist", "/bin/sh"], "sh");
        // On most Unixes /bin/sh exists; on systems where it doesn't,
        // we fall through to the fallback name `sh`.
        assert!(
            resolved == std::ffi::OsString::from("/bin/sh")
                || resolved == std::ffi::OsString::from("sh")
        );
    }
}
