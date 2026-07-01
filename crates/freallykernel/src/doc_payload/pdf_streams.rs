//! PDF stream-object scanner (TASK-277).
//!
//! Enumerates `stream` … `endstream` regions in a PDF and surfaces:
//!
//!   * the byte range of each stream's encoded payload
//!   * its declared `/Filter` (FlateDecode, ASCIIHexDecode,
//!     ASCII85Decode, LZWDecode, RunLengthDecode, CCITTFaxDecode,
//!     DCTDecode, JBIG2Decode, JPXDecode, Crypt)
//!   * whether the stream uses multiple chained filters (a
//!     classic obfuscation marker — `/Filter [/ASCIIHexDecode
//!     /FlateDecode]`)
//!
//! Filter decoding itself lands at closeout (FlateDecode reuses
//! `flate2` already in the workspace). The foundation here gives
//! the scan-row the inventory + chained-filter heuristic.

use serde::{Deserialize, Serialize};

use crate::util::bytes::find_subslice;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdfStreamInfo {
    /// Byte offset of the literal `stream` token.
    pub stream_token_offset: usize,
    /// Byte offset of the payload's first byte (after the
    /// `stream\r?\n` newline).
    pub payload_offset: usize,
    /// Byte length of the payload.
    pub payload_length: usize,
    /// List of `/Filter` names declared in the stream dict. An
    /// empty list means no filter (raw uncompressed stream).
    pub filters: Vec<String>,
}

/// Enumerate every `stream` … `endstream` region. Malformed
/// streams (missing `endstream`) are skipped silently.
pub fn enumerate(raw: &[u8]) -> Vec<PdfStreamInfo> {
    if !raw.starts_with(b"%PDF-") {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(start_rel) = find_subslice(&raw[cursor..], b"stream") {
        let start = cursor + start_rel;
        // Require that `stream` be either at start-of-file (won't
        // happen — `%PDF-` prefix) or preceded by whitespace —
        // distinguishes `stream` from `endstream`.
        if start > 0 && !raw[start - 1].is_ascii_whitespace() {
            cursor = start + 6;
            continue;
        }
        // Payload begins after the newline.
        let after_token = start + 6;
        let payload_start = after_newline(raw, after_token);
        // Locate matching `endstream`.
        let Some(end_rel) = find_subslice(&raw[payload_start..], b"endstream") else {
            cursor = after_token;
            continue;
        };
        let mut payload_end = payload_start + end_rel;
        // Strip the preceding newline byte(s) per the PDF spec.
        while payload_end > payload_start
            && (raw[payload_end - 1] == b'\n' || raw[payload_end - 1] == b'\r')
        {
            payload_end -= 1;
        }
        let filters = extract_filters(raw, start);
        out.push(PdfStreamInfo {
            stream_token_offset: start,
            payload_offset: payload_start,
            payload_length: payload_end.saturating_sub(payload_start),
            filters,
        });
        cursor = payload_start + end_rel + 9; // past `endstream`
    }
    out
}

fn after_newline(raw: &[u8], from: usize) -> usize {
    let mut i = from;
    // PDF spec: `stream` keyword must be followed by EITHER
    // CRLF or a single LF (not a bare CR).
    if i < raw.len() && raw[i] == b'\r' && i + 1 < raw.len() && raw[i + 1] == b'\n' {
        return i + 2;
    }
    if i < raw.len() && raw[i] == b'\n' {
        return i + 1;
    }
    // Permissive fallback: skip whitespace.
    while i < raw.len() && raw[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn extract_filters(raw: &[u8], stream_token_at: usize) -> Vec<String> {
    // Look backwards from `stream` for the dict (`<<` … `>>`).
    // Bound the search to the byte after the most-recent
    // `endstream` (or `endobj`) so we don't accidentally pick
    // up a previous object's `/Filter` declaration.
    let cap = 4096.min(stream_token_at);
    let mut lower = stream_token_at - cap;
    if let Some(rel) = raw[lower..stream_token_at]
        .windows(b"endstream".len())
        .rposition(|w| w == b"endstream")
    {
        lower = lower + rel + b"endstream".len();
    } else if let Some(rel) = raw[lower..stream_token_at]
        .windows(b"endobj".len())
        .rposition(|w| w == b"endobj")
    {
        lower = lower + rel + b"endobj".len();
    }
    let slice = &raw[lower..stream_token_at];
    // PDF dictionary keys are ASCII; walk the byte slice directly
    // instead of cloning into a `String` (4 KiB × N streams).
    let Some(filter_pos) = slice
        .windows(b"/Filter".len())
        .rposition(|w| w == b"/Filter")
    else {
        return Vec::new();
    };
    let after = &slice[filter_pos + b"/Filter".len()..];
    let trimmed = trim_ascii_start(after);
    if let Some(after_bracket) = trimmed.strip_prefix(b"[") {
        // Array form: `[ /FlateDecode /ASCIIHexDecode ]`.
        let close = after_bracket
            .iter()
            .position(|&b| b == b']')
            .unwrap_or(after_bracket.len());
        return parse_filter_names(&after_bracket[..close]);
    }
    if let Some(after_slash) = trimmed.strip_prefix(b"/") {
        let end = after_slash
            .iter()
            .position(|&b| b.is_ascii_whitespace() || matches!(b, b'/' | b'>' | b'['))
            .unwrap_or(after_slash.len());
        return vec![String::from_utf8_lossy(&after_slash[..end]).into_owned()];
    }
    Vec::new()
}

fn trim_ascii_start(bytes: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    &bytes[i..]
}

fn parse_filter_names(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'/' {
            // Skip token without leading slash.
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            continue;
        }
        i += 1; // skip '/'
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'/' {
            i += 1;
        }
        if start < i {
            out.push(String::from_utf8_lossy(&bytes[start..i]).into_owned());
        }
    }
    out
}

/// Detect chained-filter obfuscation. Returns `true` when any
/// stream lists two or more `/Filter` names.
pub fn has_chained_filters(streams: &[PdfStreamInfo]) -> bool {
    streams.iter().any(|s| s.filters.len() >= 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerates_single_stream() {
        let pdf = b"%PDF-1.4\n4 0 obj\n<< /Length 4 /Filter /FlateDecode >>\nstream\nDATA\nendstream\nendobj";
        let streams = enumerate(pdf);
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].filters, vec!["FlateDecode"]);
        assert_eq!(streams[0].payload_length, 4);
    }

    #[test]
    fn handles_chained_filters_array() {
        let pdf = b"%PDF-1.4\n<< /Filter [/ASCIIHexDecode /FlateDecode] /Length 6 >>\nstream\nABCDEF\nendstream\n";
        let streams = enumerate(pdf);
        assert_eq!(streams.len(), 1);
        assert_eq!(
            streams[0].filters,
            vec!["ASCIIHexDecode".to_string(), "FlateDecode".to_string()]
        );
        assert!(has_chained_filters(&streams));
    }

    #[test]
    fn missing_endstream_is_skipped() {
        let pdf = b"%PDF-1.4\n<< /Length 99 >>\nstream\nDATA";
        assert!(enumerate(pdf).is_empty());
    }

    #[test]
    fn rejects_non_pdf_input() {
        assert!(enumerate(b"not a pdf").is_empty());
    }

    #[test]
    fn no_filter_stream_yields_empty_filter_vec() {
        let pdf = b"%PDF-1.4\n<< /Length 4 >>\nstream\nDATA\nendstream\n";
        let streams = enumerate(pdf);
        assert_eq!(streams.len(), 1);
        assert!(streams[0].filters.is_empty());
        assert!(!has_chained_filters(&streams));
    }

    #[test]
    fn multiple_streams_in_one_pdf() {
        let pdf = b"%PDF-1.5\n<< /Filter /FlateDecode /Length 4 >>\nstream\nAAAA\nendstream\n<< /Length 3 >>\nstream\nBBB\nendstream\n";
        let streams = enumerate(pdf);
        assert_eq!(streams.len(), 2);
        assert_eq!(streams[0].filters, vec!["FlateDecode"]);
        assert!(streams[1].filters.is_empty());
    }

    #[test]
    fn endstream_keyword_doesnt_match_as_stream_start() {
        // The `stream` substring inside `endstream` should not
        // produce a phantom finding.
        let pdf = b"%PDF-1.4\n<< /Length 3 >>\nstream\nABC\nendstream\n";
        let streams = enumerate(pdf);
        assert_eq!(streams.len(), 1, "got {streams:?}");
    }
}
