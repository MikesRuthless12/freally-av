//! WSL distro parsing (shared, cross-platform — TASK-240, Phase 8 Wave 2).
//!
//! The Windows host shells out to `wsl.exe --list --verbose`; the
//! Linux peer (when running inside a WSL2 distro) tags emitted events
//! with `WSL_DISTRO_NAME`. Both halves consume the same parser, so it
//! lives here in mythkernel rather than in either daemon crate. The
//! `daemon/mythd-{linux,windows}/` re-export from here.
//!
//! Pure parsing — no syscalls, no shell-outs. The actual `wsl.exe`
//! invocation lives in `daemon/mythd-windows/src/wsl_bridge.rs::list_distros`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WslDistroRow {
    pub name: String,
    pub state: String,
    pub version: u8,
}

/// Parse the `wsl.exe --list --verbose` UTF-16 LE output the Windows-
/// side bridge captures. Strips the BOM, decodes via
/// `String::from_utf16_lossy`, then delegates to [`parse_wsl_list_text`].
pub fn parse_wsl_list_utf16le(bytes: &[u8]) -> Vec<WslDistroRow> {
    if bytes.len() < 2 {
        return Vec::new();
    }
    let mut start = 0usize;
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        start = 2;
    }
    let words: Vec<u16> = bytes[start..]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let text = String::from_utf16_lossy(&words);
    parse_wsl_list_text(&text)
}

/// Parse the rendered text form. Tolerates the leading `*` marker
/// `wsl.exe` puts next to the default distro.
pub fn parse_wsl_list_text(text: &str) -> Vec<WslDistroRow> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let trimmed = line.trim_start().trim_start_matches('*').trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(name) = parts.next() else { continue };
        let state = parts.next().unwrap_or("Unknown").to_string();
        let version = parts.next().and_then(|s| s.parse::<u8>().ok()).unwrap_or(0);
        out.push(WslDistroRow {
            name: name.to_string(),
            state,
            version,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_text_skips_header_and_default_marker() {
        let text = "  NAME            STATE           VERSION\n* Ubuntu          Running         2\n  Debian          Stopped         2\n";
        let rows = parse_wsl_list_text(text);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "Ubuntu");
        assert_eq!(rows[0].state, "Running");
        assert_eq!(rows[0].version, 2);
        assert_eq!(rows[1].name, "Debian");
    }

    #[test]
    fn parse_utf16le_handles_bom() {
        let text = "  NAME    STATE    VERSION\n* Ubuntu  Running  2\n";
        let mut bytes = vec![0xFF, 0xFE];
        for c in text.encode_utf16() {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        let rows = parse_wsl_list_utf16le(&bytes);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "Ubuntu");
    }

    #[test]
    fn parse_empty_returns_empty() {
        assert!(parse_wsl_list_text("").is_empty());
        assert!(parse_wsl_list_utf16le(&[]).is_empty());
    }
}
