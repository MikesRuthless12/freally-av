//! RTF object-package scanner (TASK-278).
//!
//! Detects two RTF abuses:
//!
//!   * `\objdata` blocks (embedded OLE objects) — historically
//!     used to drop Equation Editor exploits (CVE-2017-11882,
//!     CVE-2018-0802) and HTA loaders.
//!   * `\object` + `\objupdate` and `\objemb` + `\objautlink`
//!     control words — the auto-update + embedded markers that
//!     cause Word to instantiate the object without user
//!     interaction.
//!
//! The extractor returns each `\objdata` hex blob's *decoded
//! bytes* (RTF hex stream stripped of whitespace and braces).
//! Downstream YARA can then run against the OLE header (`D0 CF
//! 11 E0`) that almost always sits at offset 0 of these blobs.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RtfObjectFinding {
    /// Byte offset of `\objdata` inside the RTF stream.
    pub offset: usize,
    /// Decoded payload (hex → bytes). Empty when the blob was
    /// malformed.
    pub decoded: Vec<u8>,
    /// `true` if the object was annotated `\objupdate` or
    /// `\objautlink` (auto-update markers).
    pub auto_update: bool,
    /// `true` if the embedded object is OLE (decoded payload
    /// starts with the CFB magic `D0 CF 11 E0`).
    pub is_ole_compound: bool,
}

/// Scan an RTF document. Returns one finding per `\objdata`
/// hex block.
pub fn scan(raw: &[u8]) -> Vec<RtfObjectFinding> {
    if !is_rtf(raw) {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(raw);
    let mut out = Vec::new();
    let mut search_from = 0;
    while let Some(rel) = text[search_from..].find("\\objdata") {
        let abs = search_from + rel;
        let payload_start = abs + "\\objdata".len();
        // Look ahead for auto-update / autolink markers within
        // the enclosing object group (up to 512 bytes of slack
        // to either side covers virtually every legitimate
        // case).
        let window_start = abs.saturating_sub(512);
        let window_end = (payload_start + 512).min(text.len());
        let window = &text[window_start..window_end];
        let auto_update = window.contains("\\objupdate") || window.contains("\\objautlink");

        // Decode hex stream. The hex spans from `payload_start`
        // until the matching `}` that closes the object group.
        let close_rel = text[payload_start..]
            .find('}')
            .unwrap_or(text.len() - payload_start);
        let hex_block = &text[payload_start..payload_start + close_rel];
        let decoded = decode_hex_stream(hex_block.as_bytes());
        let is_ole_compound = decoded.starts_with(&[0xD0, 0xCF, 0x11, 0xE0]);

        out.push(RtfObjectFinding {
            offset: abs,
            decoded,
            auto_update,
            is_ole_compound,
        });
        search_from = payload_start + close_rel;
    }
    out
}

fn is_rtf(raw: &[u8]) -> bool {
    raw.starts_with(b"{\\rtf")
}

fn decode_hex_stream(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut nibble: Option<u8> = None;
    for &b in bytes {
        let v = match b {
            b'0'..=b'9' => b - b'0',
            b'A'..=b'F' => b - b'A' + 10,
            b'a'..=b'f' => b - b'a' + 10,
            _ => continue, // skip whitespace, braces, control words
        };
        match nibble {
            Some(hi) => {
                out.push((hi << 4) | v);
                nibble = None;
            }
            None => nibble = Some(v),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_rtf() {
        assert!(scan(b"not rtf").is_empty());
    }

    #[test]
    fn detects_objdata_with_ole_magic() {
        let rtf =
            b"{\\rtf1\\ansi\n{\\object\\objemb\\objupdate{\\*\\objdata d0cf11e0a1b11ae10000\n}}}";
        let findings = scan(rtf);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].is_ole_compound);
        assert!(findings[0].auto_update);
        assert_eq!(&findings[0].decoded[..4], &[0xD0, 0xCF, 0x11, 0xE0]);
    }

    #[test]
    fn benign_rtf_yields_no_findings() {
        let rtf = b"{\\rtf1\\ansi\n{\\b Hello}\n}";
        assert!(scan(rtf).is_empty());
    }

    #[test]
    fn multiple_objdata_blocks_each_emit() {
        let rtf = b"{\\rtf1\\ansi{\\object\\objemb{\\*\\objdata AAAA}}{\\object\\objemb{\\*\\objdata BBBB}}}";
        let findings = scan(rtf);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].decoded, vec![0xAA, 0xAA]);
        assert_eq!(findings[1].decoded, vec![0xBB, 0xBB]);
    }

    #[test]
    fn auto_update_flag_is_set_only_when_marker_present() {
        let rtf_no_update = b"{\\rtf1\\ansi{\\object\\objemb{\\*\\objdata 4D5A9000}}}";
        let findings = scan(rtf_no_update);
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].auto_update);
        // Decoded `4D5A9000` should be the MZ header bytes.
        assert_eq!(&findings[0].decoded[..4], &[0x4D, 0x5A, 0x90, 0x00]);
    }

    #[test]
    fn malformed_hex_yields_partial_decode() {
        // Odd-numbered hex digits — the last nibble is dropped.
        let rtf = b"{\\rtf1{\\object\\objemb{\\*\\objdata DEAD0}}}";
        let findings = scan(rtf);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].decoded, vec![0xDE, 0xAD]);
    }
}
