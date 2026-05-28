//! Suspicious-MIME save detection (TASK-268, FEAT-213, Phase 10 Wave 2).
//!
//! Reads Chromium download metadata's declared MIME plus the saved
//! file's first bytes, then flags any pair where the declared text
//! type masks an executable payload. Hand-rolled magic-byte sniffer
//! keeps the engine dep tree tight (no `infer` crate).

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SniffedKind {
    /// Windows PE (`MZ`) — DLL or EXE.
    Pe,
    /// ELF (`\x7fELF`).
    Elf,
    /// Mach-O 32 / 64 / fat. Any of `0xFEEDFACE`, `0xFEEDFACF`,
    /// `0xCAFEBABE` (fat), little- or big-endian.
    MachO,
    /// Shell script (`#!`).
    Shell,
    /// JAR / ZIP container — Java executable etc.
    Zip,
    /// Anything we can recognise but isn't dangerous on its own
    /// (e.g. HTML, plain text, image magics). The detector still
    /// flags if the **declared** MIME claims this kind but the
    /// bytes say otherwise.
    Benign,
    /// Unknown / unrecognised. Used as a quiet default so the
    /// detector doesn't fire on every random file.
    Unknown,
}

/// Sniff the first ~16 bytes of `bytes` and return the kind it
/// matches. Returns [`SniffedKind::Unknown`] on no match.
pub fn sniff(bytes: &[u8]) -> SniffedKind {
    if bytes.len() >= 2 && &bytes[..2] == b"MZ" {
        return SniffedKind::Pe;
    }
    if bytes.len() >= 4 && &bytes[..4] == b"\x7fELF" {
        return SniffedKind::Elf;
    }
    if bytes.len() >= 4 {
        let m = &bytes[..4];
        if m == [0xFE, 0xED, 0xFA, 0xCE]
            || m == [0xCE, 0xFA, 0xED, 0xFE]
            || m == [0xFE, 0xED, 0xFA, 0xCF]
            || m == [0xCF, 0xFA, 0xED, 0xFE]
            || m == [0xCA, 0xFE, 0xBA, 0xBE]
            || m == [0xBE, 0xBA, 0xFE, 0xCA]
        {
            return SniffedKind::MachO;
        }
    }
    if bytes.len() >= 2 && &bytes[..2] == b"#!" {
        return SniffedKind::Shell;
    }
    if bytes.len() >= 4 && &bytes[..4] == b"PK\x03\x04" {
        return SniffedKind::Zip;
    }
    if is_textish_prefix(bytes) {
        return SniffedKind::Benign;
    }
    SniffedKind::Unknown
}

fn is_textish_prefix(bytes: &[u8]) -> bool {
    // Treat the first 32 bytes as ASCII-printable + whitespace
    // → benign-looking text. Used so the detector doesn't yell
    // when the declared MIME and the actual bytes both say "text."
    if bytes.is_empty() {
        return false;
    }
    let span = &bytes[..bytes.len().min(32)];
    span.iter()
        .all(|b| matches!(*b, 0x09 | 0x0A | 0x0D | 0x20..=0x7E))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MimeMismatchFinding {
    pub path: std::path::PathBuf,
    pub declared_mime: String,
    pub sniffed: SniffedKind,
}

/// Decide whether `(declared_mime, sniffed)` is a mismatch worth
/// surfacing. Treats anything declared as text/plain / text/html /
/// application/javascript / application/octet-stream-unknown that
/// sniffs as a recognised executable kind as a P1 finding.
pub fn evaluate(declared_mime: &str, sniffed: SniffedKind) -> bool {
    let lc = declared_mime.trim().to_ascii_lowercase();
    let claims_text = lc.starts_with("text/")
        || lc == "application/javascript"
        || lc == "application/json"
        || lc == "application/x-empty";
    let executable = matches!(
        sniffed,
        SniffedKind::Pe
            | SniffedKind::Elf
            | SniffedKind::MachO
            | SniffedKind::Shell
            | SniffedKind::Zip
    );
    claims_text && executable
}

/// End-to-end helper: read the first `peek_bytes` of the file, sniff
/// it, and produce a finding if the declared MIME mismatches.
pub fn check_file(
    path: &Path,
    declared_mime: &str,
    peek_bytes: usize,
) -> Option<MimeMismatchFinding> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; peek_bytes];
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);
    let sniffed = sniff(&buf);
    if evaluate(declared_mime, sniffed) {
        Some(MimeMismatchFinding {
            path: path.to_path_buf(),
            declared_mime: declared_mime.to_string(),
            sniffed,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_recognises_pe() {
        let bytes = b"MZ\x90\x00...";
        assert_eq!(sniff(bytes), SniffedKind::Pe);
    }

    #[test]
    fn sniff_recognises_elf_and_macho() {
        assert_eq!(sniff(b"\x7fELFblah"), SniffedKind::Elf);
        assert_eq!(sniff(&[0xCF, 0xFA, 0xED, 0xFE, 0]), SniffedKind::MachO);
        assert_eq!(sniff(&[0xCA, 0xFE, 0xBA, 0xBE, 0]), SniffedKind::MachO);
    }

    #[test]
    fn sniff_recognises_zip_and_shell() {
        assert_eq!(sniff(b"PK\x03\x04..."), SniffedKind::Zip);
        assert_eq!(sniff(b"#!/bin/bash\necho"), SniffedKind::Shell);
    }

    #[test]
    fn sniff_classifies_text_prefix_as_benign() {
        assert_eq!(sniff(b"hello world\n"), SniffedKind::Benign);
    }

    #[test]
    fn sniff_unknown_for_garbage() {
        assert_eq!(sniff(&[0xFF, 0xFE, 0xFD, 0xFC]), SniffedKind::Unknown);
    }

    #[test]
    fn text_plain_with_pe_bytes_is_mismatch() {
        assert!(evaluate("text/plain", SniffedKind::Pe));
        assert!(evaluate("text/html", SniffedKind::Elf));
        assert!(evaluate("application/javascript", SniffedKind::MachO));
    }

    #[test]
    fn declared_executable_with_executable_bytes_is_not_mismatch() {
        assert!(!evaluate("application/x-msdownload", SniffedKind::Pe));
        assert!(!evaluate("application/x-mach-binary", SniffedKind::MachO));
    }

    #[test]
    fn text_with_text_bytes_is_not_mismatch() {
        assert!(!evaluate("text/plain", SniffedKind::Benign));
    }

    #[test]
    fn empty_payload_is_unknown_and_not_mismatch() {
        assert_eq!(sniff(&[]), SniffedKind::Unknown);
        assert!(!evaluate("text/plain", SniffedKind::Unknown));
    }

    #[test]
    fn check_file_finds_pe_masquerading_as_text() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("notes.txt");
        std::fs::write(&p, b"MZ\x90\x00...padding").unwrap();
        let hit = check_file(&p, "text/plain", 16).unwrap();
        assert_eq!(hit.sniffed, SniffedKind::Pe);
    }

    #[test]
    fn check_file_returns_none_when_bytes_match_declared_type() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("notes.txt");
        std::fs::write(&p, b"Hello world").unwrap();
        assert!(check_file(&p, "text/plain", 16).is_none());
    }
}
