//! macOS signer extraction (TASK-136).
//!
//! Shells out to `codesign -dv --verbose=4 <path>` and parses
//! `TeamIdentifier=<XXXXXXXXXX>` from stderr (where codesign writes its
//! detail output). Unsigned binaries print `code object is not signed at all`
//! and return non-zero; we surface those as `SignerIdentity::unsigned()`.
//!
//! No Apple Developer Program / notarization dependency — `codesign -dv`
//! reads from the binary's embedded code-signature blob without contacting
//! Apple. Per `docs/prd.md` § 1.5.3 the engine never makes paid Apple
//! services part of the build pipeline.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::detect::publisher::{SignerIdentity, SignerKind};

const SHELL_TIMEOUT: Duration = Duration::from_secs(3);
/// Canonical Apple-shipped `codesign` location (sec-review M4). PATH-
/// shadowing this with a user-writable binary would let an attacker
/// declare malware as Apple-signed.
const CODESIGN_PATH: &str = "/usr/bin/codesign";

pub fn extract_signer(path: &Path) -> SignerIdentity {
    let bin: std::ffi::OsString = if Path::new(CODESIGN_PATH).exists() {
        CODESIGN_PATH.into()
    } else {
        "codesign".into()
    };
    let mut child = match Command::new(&bin)
        .arg("-dv")
        .arg("--verbose=4")
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return SignerIdentity::unsigned(),
    };
    let start = std::time::Instant::now();
    loop {
        if let Ok(Some(_status)) = child.try_wait() {
            break;
        }
        if start.elapsed() >= SHELL_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return SignerIdentity::unsigned();
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(_) => return SignerIdentity::unsigned(),
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stderr}\n{stdout}");
    if combined.contains("not signed at all") || combined.contains("does not appear to be signed") {
        return SignerIdentity::unsigned();
    }
    parse_codesign_output(&combined)
}

/// Pure parser — exposed for tests. Looks for `TeamIdentifier=...`,
/// `Authority=...`, and (where present) `Identifier=...` lines and
/// produces a stable identity string.
pub fn parse_codesign_output(s: &str) -> SignerIdentity {
    let mut team_id: Option<String> = None;
    let mut authority: Option<String> = None;
    let mut bundle_identifier: Option<String> = None;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("TeamIdentifier=") {
            team_id = Some(rest.trim().to_string());
        }
        if authority.is_none()
            && let Some(rest) = line.strip_prefix("Authority=")
        {
            authority = Some(rest.trim().to_string());
        }
        if bundle_identifier.is_none()
            && let Some(rest) = line.strip_prefix("Identifier=")
        {
            bundle_identifier = Some(rest.trim().to_string());
        }
    }
    let identity = match (team_id, authority, bundle_identifier) {
        (Some(t), Some(a), _) => format!("codesign:{t}:{a}"),
        (Some(t), None, Some(b)) => format!("codesign:{t}:{b}"),
        (Some(t), None, None) => format!("codesign:{t}"),
        (None, Some(a), _) => format!("codesign::{a}"),
        _ => return SignerIdentity::unsigned(),
    };
    SignerIdentity {
        identity,
        kind: SignerKind::Codesign,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_extracts_team_id_and_authority() {
        let s = "\
Executable=/Applications/Safari.app/Contents/MacOS/Safari
Identifier=com.apple.Safari
Format=app bundle with Mach-O thin (arm64)
TeamIdentifier=APPLECOMPUTER
Authority=Software Signing
Authority=Apple Code Signing Certification Authority
Authority=Apple Root CA
";
        let id = parse_codesign_output(s);
        assert_eq!(id.kind, SignerKind::Codesign);
        assert!(id.identity.contains("APPLECOMPUTER"));
        assert!(id.identity.contains("Software Signing"));
    }

    #[test]
    fn parse_falls_back_to_bundle_id_when_authority_missing() {
        let s = "Identifier=com.example.thing\nTeamIdentifier=ABC123XYZW\n";
        let id = parse_codesign_output(s);
        assert!(id.identity.contains("ABC123XYZW"));
        assert!(id.identity.contains("com.example.thing"));
    }

    #[test]
    fn parse_returns_unsigned_when_no_signer_fields() {
        let s = "Executable=/bin/ls\nFormat=Mach-O thin\n";
        let id = parse_codesign_output(s);
        assert_eq!(id.kind, SignerKind::Unsigned);
    }
}
