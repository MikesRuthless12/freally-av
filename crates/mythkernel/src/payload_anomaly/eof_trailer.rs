//! Hidden-data-after-EOF detector (TASK-287).
//!
//! Many file formats define a hard end-of-file marker. Bytes
//! present *after* that marker are out-of-spec — sometimes
//! benign (e.g. a CDN that appends a Last-Modified comment),
//! sometimes a smuggled payload. This module classifies each
//! supported container into one of three states:
//!
//!   * `Clean` — no trailer
//!   * `TrailerBenign` — trailer is short (< 64 bytes) and
//!     stays inside an ignorable region
//!   * `TrailerSuspect` — trailer is large or contains another
//!     file-format magic (PE, ZIP, OLE, etc.)
//!
//! Supported formats:
//!
//!   * PNG  — IEND chunk terminates the stream
//!   * JPEG — `FF D9` end-of-image marker
//!   * GIF  — `;` (0x3B) trailer
//!   * PDF  — `%%EOF`

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrailerVerdict {
    Clean,
    TrailerBenign,
    TrailerSuspect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrailerFinding {
    pub format: &'static str,
    pub verdict: TrailerVerdict,
    pub trailer_offset: usize,
    pub trailer_bytes: usize,
}

const APPENDED_MAGICS: &[&[u8]] = &[
    b"MZ",                                 // PE
    b"\x7FELF",                            // ELF
    &[0xCF, 0xFA, 0xED, 0xFE],             // Mach-O 64
    &[0xFE, 0xED, 0xFA, 0xCE],             // Mach-O 32 BE
    &[0xCA, 0xFE, 0xBA, 0xBE],             // Mach-O fat
    b"PK\x03\x04",                         // ZIP
    &[0xD0, 0xCF, 0x11, 0xE0],             // OLE CFB
    &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], // 7z
    b"%PDF-",                              // PDF
];

pub fn evaluate(raw: &[u8]) -> Option<TrailerFinding> {
    if let Some(off) = png_eof(raw) {
        return Some(classify("png", raw, off));
    }
    if let Some(off) = jpeg_eof(raw) {
        return Some(classify("jpeg", raw, off));
    }
    if let Some(off) = gif_eof(raw) {
        return Some(classify("gif", raw, off));
    }
    if let Some(off) = pdf_eof(raw) {
        return Some(classify("pdf", raw, off));
    }
    None
}

fn classify(format: &'static str, raw: &[u8], eof_at: usize) -> TrailerFinding {
    let trailer_bytes = raw.len().saturating_sub(eof_at);
    let verdict = if trailer_bytes == 0 {
        TrailerVerdict::Clean
    } else {
        let after = &raw[eof_at..];
        if has_appended_magic(after) || trailer_bytes >= 64 {
            TrailerVerdict::TrailerSuspect
        } else {
            TrailerVerdict::TrailerBenign
        }
    };
    TrailerFinding {
        format,
        verdict,
        trailer_offset: eof_at,
        trailer_bytes,
    }
}

fn has_appended_magic(after: &[u8]) -> bool {
    for magic in APPENDED_MAGICS {
        if after.len() >= magic.len() && &after[..magic.len()] == *magic {
            return true;
        }
        // Magic doesn't have to be exactly at offset 0 — some
        // formats pad. Search in the first 256 bytes.
        let scan_limit = after.len().min(256);
        if scan_limit >= magic.len()
            && after[..scan_limit]
                .windows(magic.len())
                .any(|w| w == *magic)
        {
            return true;
        }
    }
    false
}

fn png_eof(raw: &[u8]) -> Option<usize> {
    const PNG_HEAD: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if raw.len() < PNG_HEAD.len() || raw[..8] != PNG_HEAD {
        return None;
    }
    // IEND chunk = 12 bytes: 00 00 00 00 49 45 4E 44 AE 42 60 82.
    const IEND: [u8; 8] = [b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82];
    let rel = raw.windows(IEND.len()).position(|w| w == IEND)?;
    Some(rel + IEND.len())
}

fn jpeg_eof(raw: &[u8]) -> Option<usize> {
    if raw.len() < 2 || raw[0] != 0xFF || raw[1] != 0xD8 {
        return None;
    }
    // Walk backwards for the last FF D9 — that's the canonical EOI.
    for i in (1..raw.len()).rev() {
        if raw[i] == 0xD9 && raw[i - 1] == 0xFF {
            return Some(i + 1);
        }
    }
    None
}

fn gif_eof(raw: &[u8]) -> Option<usize> {
    if raw.len() < 6 || (&raw[..6] != b"GIF87a" && &raw[..6] != b"GIF89a") {
        return None;
    }
    // Trailer byte 0x3B sits at the end of the GIF stream.
    let pos = raw.iter().rposition(|&b| b == 0x3B)?;
    Some(pos + 1)
}

fn pdf_eof(raw: &[u8]) -> Option<usize> {
    if !raw.starts_with(b"%PDF-") {
        return None;
    }
    let needle = b"%%EOF";
    let rel = raw.windows(needle.len()).rposition(|w| w == needle)?;
    let mut end = rel + needle.len();
    // PDF spec allows an optional trailing newline.
    while end < raw.len() && (raw[end] == b'\r' || raw[end] == b'\n') {
        end += 1;
    }
    Some(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_with_trailer(trailer: &[u8]) -> Vec<u8> {
        let mut out = vec![0x89u8, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        // Empty IHDR + IDAT chunks — only IEND matters for the test.
        out.extend_from_slice(&[0, 0, 0, 0, b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82]);
        out.extend_from_slice(trailer);
        out
    }

    #[test]
    fn clean_png_yields_clean_verdict() {
        let png = png_with_trailer(&[]);
        let f = evaluate(&png).unwrap();
        assert_eq!(f.format, "png");
        assert_eq!(f.verdict, TrailerVerdict::Clean);
        assert_eq!(f.trailer_bytes, 0);
    }

    #[test]
    fn small_benign_trailer_is_flagged_benign() {
        let png = png_with_trailer(b"// CDN footer");
        let f = evaluate(&png).unwrap();
        assert_eq!(f.verdict, TrailerVerdict::TrailerBenign);
        assert_eq!(f.trailer_bytes, 13);
    }

    #[test]
    fn appended_pe_in_trailer_flagged_suspect() {
        let png = png_with_trailer(b"MZ\x90\0\x03\0\0");
        let f = evaluate(&png).unwrap();
        assert_eq!(f.verdict, TrailerVerdict::TrailerSuspect);
    }

    #[test]
    fn long_trailer_flagged_suspect_even_without_magic() {
        let trailer: Vec<u8> = (0..2048).map(|i| (i & 0xFF) as u8).collect();
        let png = png_with_trailer(&trailer);
        let f = evaluate(&png).unwrap();
        assert_eq!(f.verdict, TrailerVerdict::TrailerSuspect);
    }

    #[test]
    fn jpeg_trailer_is_detected() {
        let mut jpg = vec![0xFFu8, 0xD8];
        // Minimal JPEG: SOI, then EOI, with trailer.
        jpg.extend_from_slice(&[0xFF, 0xD9]);
        jpg.extend_from_slice(b"PK\x03\x04");
        let f = evaluate(&jpg).unwrap();
        assert_eq!(f.format, "jpeg");
        assert_eq!(f.verdict, TrailerVerdict::TrailerSuspect);
    }

    #[test]
    fn gif_trailer_is_detected() {
        let mut gif = Vec::from(*b"GIF89a");
        gif.extend(std::iter::repeat(0u8).take(100));
        gif.push(0x3B);
        gif.extend_from_slice(b"appended-content");
        let f = evaluate(&gif).unwrap();
        assert_eq!(f.format, "gif");
        assert_eq!(f.verdict, TrailerVerdict::TrailerBenign);
    }

    #[test]
    fn pdf_with_trailing_payload_is_detected() {
        let mut pdf = Vec::from(*b"%PDF-1.4\n");
        pdf.extend_from_slice(b"%%EOF\n");
        pdf.extend(std::iter::repeat(0u8).take(2000));
        let f = evaluate(&pdf).unwrap();
        assert_eq!(f.format, "pdf");
        assert_eq!(f.verdict, TrailerVerdict::TrailerSuspect);
    }

    #[test]
    fn non_image_input_returns_none() {
        assert!(evaluate(b"not an image").is_none());
    }
}
