//! `autorun.inf` flag (TASK-246, Phase 8 Wave 2).
//!
//! Tiny `[autorun]` INI reader for the USB-insert auto-scan. Reads at
//! most 4 KiB from the volume root, parses `open=`, `shellexecute=`,
//! `icon=` entries, and returns a finding shape.
//!
//! Read-only — never modifies the file. Fail-safe parser: a malformed
//! INI produces an `AutorunFinding` with `parse_error = Some(...)`
//! rather than panicking or skipping.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Read cap. autorun.inf files in the wild are typically < 1 KiB; 4 KiB
/// is a generous ceiling that prevents a hostile USB from streaming a
/// multi-MB file into the parser.
pub const READ_CAP_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AutorunFinding {
    pub open: Option<String>,
    pub shellexecute: Option<String>,
    pub icon: Option<String>,
    pub parse_error: Option<String>,
    /// Raw bytes the parser saw (capped at [`READ_CAP_BYTES`]).
    pub raw_len: usize,
}

impl AutorunFinding {
    /// True iff the finding contains any actionable target — meaning
    /// the daemon should surface it as a P1 finding to the user.
    pub fn is_actionable(&self) -> bool {
        self.open.is_some() || self.shellexecute.is_some()
    }
}

/// Try to read `<mountpoint>/autorun.inf` (case-insensitive on Linux
/// because removable volumes there are typically FAT/exFAT and the
/// OS preserves case). Returns `None` when the file does not exist;
/// returns `Some(AutorunFinding)` otherwise.
pub fn inspect(mountpoint: &Path) -> Option<AutorunFinding> {
    let candidate = locate_case_insensitive(mountpoint, "autorun.inf")?;
    let bytes = read_capped(&candidate).ok()?;
    Some(parse(&bytes))
}

/// Pure parser — exposed for unit tests. Accepts bytes (not a path).
pub fn parse(bytes: &[u8]) -> AutorunFinding {
    let raw_len = bytes.len();
    // INI files in the wild are CRLF + Windows-1252; we read as UTF-8
    // lossy so a stray non-UTF-8 byte does not panic.
    let text = String::from_utf8_lossy(bytes);
    let mut in_autorun = false;
    let mut out = AutorunFinding {
        raw_len,
        ..Default::default()
    };
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(name) = section_name(line) {
            in_autorun = name.eq_ignore_ascii_case("autorun");
            continue;
        }
        if !in_autorun {
            continue;
        }
        let Some(eq) = line.find('=') else { continue };
        let key = line[..eq].trim();
        let value = line[eq + 1..].trim().to_string();
        match key.to_ascii_lowercase().as_str() {
            "open" => out.open = Some(value),
            "shellexecute" => out.shellexecute = Some(value),
            "icon" => out.icon = Some(value),
            _ => {}
        }
    }
    out
}

fn section_name(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'[' && bytes[bytes.len() - 1] == b']' {
        Some(&line[1..line.len() - 1])
    } else {
        None
    }
}

fn read_capped(p: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(p)?;
    let mut buf = Vec::with_capacity(READ_CAP_BYTES);
    f.by_ref()
        .take(READ_CAP_BYTES as u64)
        .read_to_end(&mut buf)?;
    Ok(buf)
}

fn locate_case_insensitive(dir: &Path, name: &str) -> Option<std::path::PathBuf> {
    let direct = dir.join(name);
    if direct.exists() {
        return Some(direct);
    }
    // Cheap case-insensitive scan — autorun.inf is at the volume root
    // so the dir has tens-not-thousands of entries.
    let entries = std::fs::read_dir(dir).ok()?;
    for ent in entries.flatten() {
        if let Some(s) = ent.file_name().to_str() {
            if s.eq_ignore_ascii_case(name) {
                return Some(ent.path());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parses_open_and_shellexecute_and_icon() {
        let body = b"[autorun]\nopen=evil.exe\nshellexecute=launcher.bat\nicon=disk.ico\n";
        let f = parse(body);
        assert_eq!(f.open.as_deref(), Some("evil.exe"));
        assert_eq!(f.shellexecute.as_deref(), Some("launcher.bat"));
        assert_eq!(f.icon.as_deref(), Some("disk.ico"));
        assert!(f.is_actionable());
    }

    #[test]
    fn ignores_other_sections() {
        let body = b"[other]\nopen=ok.exe\n[autorun]\nopen=bad.exe\n";
        let f = parse(body);
        assert_eq!(f.open.as_deref(), Some("bad.exe"));
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let body = b"; comment\n# also comment\n[autorun]\n\nopen=x.exe\n";
        let f = parse(body);
        assert_eq!(f.open.as_deref(), Some("x.exe"));
    }

    #[test]
    fn case_insensitive_keys_and_section() {
        let body = b"[AutoRun]\nOPEN=x.exe\nShellExecute=y.bat\n";
        let f = parse(body);
        assert_eq!(f.open.as_deref(), Some("x.exe"));
        assert_eq!(f.shellexecute.as_deref(), Some("y.bat"));
    }

    #[test]
    fn empty_input_is_not_actionable() {
        let f = parse(b"");
        assert!(!f.is_actionable());
    }

    #[test]
    fn inspect_locates_file_case_insensitively() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("AUTORUN.INF");
        std::fs::write(&p, b"[autorun]\nopen=run.exe\n").unwrap();
        let f = inspect(dir.path()).expect("expected to find autorun.inf");
        assert_eq!(f.open.as_deref(), Some("run.exe"));
    }

    #[test]
    fn inspect_returns_none_when_absent() {
        let dir = tempdir().unwrap();
        assert!(inspect(dir.path()).is_none());
    }
}
