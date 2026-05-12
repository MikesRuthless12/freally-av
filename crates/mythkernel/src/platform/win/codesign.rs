//! Windows Authenticode signer extraction (TASK-136).
//!
//! Shells out to PowerShell's `Get-AuthenticodeSignature` cmdlet
//! (ships on every supported Windows; no extra install) and parses the
//! `SignerCertificate.Subject` distinguished name. The DN is the canonical
//! Authenticode identity surfaced everywhere else (`signtool verify`,
//! Sigcheck, certmgr) — using it keeps the user-facing string consistent.
//!
//! Per `docs/prd.md` § 1.5.3 the engine **does not** ship its own OV / EV
//! cert and **does not** call `WinVerifyTrust` to assert trust; we read
//! Authenticode metadata only to identify the signer. The user's exclusions
//! page lets them whitelist by identity — they're trusting the certificate
//! chain themselves, not the engine.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::detect::publisher::{SignerIdentity, SignerKind};

const SHELL_TIMEOUT: Duration = Duration::from_secs(8);
/// Poll interval while waiting for PowerShell to exit (sec-review R-I9).
/// 25 ms × N files added measurable overhead; 100 ms is still well below
/// the user-visible threshold for the operator-mode scan.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

pub fn extract_signer(path: &Path) -> SignerIdentity {
    let script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $sig = Get-AuthenticodeSignature -FilePath {}; \
         if ($sig.Status -ne 'Valid' -and $sig.Status -ne 'UnknownError') {{ Write-Output 'STATUS:UNSIGNED'; exit 0 }}; \
         if ($sig.SignerCertificate -eq $null) {{ Write-Output 'STATUS:UNSIGNED'; exit 0 }}; \
         Write-Output ('STATUS:' + $sig.Status); \
         Write-Output ('SUBJECT:' + $sig.SignerCertificate.Subject); \
         Write-Output ('ISSUER:' + $sig.SignerCertificate.Issuer); \
         Write-Output ('THUMBPRINT:' + $sig.SignerCertificate.Thumbprint)",
        powershell_quote(&path.to_string_lossy())
    );

    let mut child = match Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(&script)
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
        std::thread::sleep(POLL_INTERVAL);
    }
    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(_) => return SignerIdentity::unsigned(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    parse_powershell_output(&text)
}

/// Parser exposed for tests. Reads the four `KEY:value` lines and synthesizes
/// a `codesign:thumbprint:subject` identity.
pub fn parse_powershell_output(s: &str) -> SignerIdentity {
    let mut status = "";
    let mut subject = "";
    let mut thumbprint = "";
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("STATUS:") {
            status = v.trim();
        } else if let Some(v) = line.strip_prefix("SUBJECT:") {
            subject = v.trim();
        } else if let Some(v) = line.strip_prefix("THUMBPRINT:") {
            thumbprint = v.trim();
        }
    }
    if status == "UNSIGNED" || subject.is_empty() {
        return SignerIdentity::unsigned();
    }
    let identity = if thumbprint.is_empty() {
        format!("authenticode:{subject}")
    } else {
        format!("authenticode:{thumbprint}:{subject}")
    };
    SignerIdentity {
        identity,
        kind: SignerKind::Authenticode,
    }
}

/// Conservative PowerShell single-quote escaper. PowerShell uses doubled
/// single quotes for literal single quotes inside `'...'`.
fn powershell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_extracts_authenticode_subject_and_thumbprint() {
        let s = "\
STATUS:Valid
SUBJECT:CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
ISSUER:CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
THUMBPRINT:ABCDEF0123456789ABCDEF0123456789ABCDEF01
";
        let id = parse_powershell_output(s);
        assert_eq!(id.kind, SignerKind::Authenticode);
        assert!(id.identity.contains("Microsoft Corporation"));
        assert!(id.identity.contains("ABCDEF"));
    }

    #[test]
    fn parse_unsigned_status_returns_unsigned() {
        let s = "STATUS:UNSIGNED\n";
        let id = parse_powershell_output(s);
        assert_eq!(id.kind, SignerKind::Unsigned);
    }

    #[test]
    fn parse_missing_subject_returns_unsigned() {
        let s = "STATUS:Valid\n";
        let id = parse_powershell_output(s);
        assert_eq!(id.kind, SignerKind::Unsigned);
    }

    #[test]
    fn powershell_quote_doubles_single_quotes() {
        assert_eq!(powershell_quote("a'b"), "'a''b'");
        assert_eq!(powershell_quote("plain"), "'plain'");
    }
}
