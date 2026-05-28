//! RFC 5322 `.eml` parser (TASK-271).
//!
//! Best-effort parser that handles the three things the engine cares
//! about: structured headers (`From`, `Subject`, `Date`,
//! `Message-ID`), a flat list of MIME body parts with per-part
//! `Content-Type` + decoded body, and attachments with filename and
//! decoded bytes.
//!
//! ### What this is NOT
//!
//! This is not a strict RFC 5322 / 2045 / 2046 / 2047 implementation.
//! It does not unfold encoded-word RFC 2047 headers, does not handle
//! 8BITMIME, and does not normalize line endings beyond CRLF/LF
//! tolerance. The closeout pass swaps in `mail-parser` (Apache-2.0)
//! for full compliance once the dep gate is cleared. The minimal
//! shape here is enough to drive the YARA scan + attachment-extract
//! flow described in `docs/product-roadmap.md` § Phase 10 Wave 2.

use serde::{Deserialize, Serialize};

use crate::util::bytes::find_subslice;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmlMessage {
    pub from: Option<String>,
    pub to: Option<String>,
    pub subject: Option<String>,
    pub date: Option<String>,
    pub message_id: Option<String>,
    pub headers: Vec<(String, String)>,
    pub parts: Vec<MimePart>,
    pub attachments: Vec<EmlAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MimePart {
    pub content_type: String,
    pub charset: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmlAttachment {
    pub filename: Option<String>,
    pub content_type: String,
    pub decoded_bytes: Vec<u8>,
}

/// Parse a single `.eml` message. Always returns a populated
/// [`EmlMessage`] even when parts of the input are malformed — the
/// scan row needs partial output more than a hard error.
pub fn parse_eml(raw: &[u8]) -> EmlMessage {
    let raw = strip_trailing_nul(raw);
    let (header_block, body) = split_header_body(raw);
    let headers = parse_headers(header_block);

    let mut msg = EmlMessage {
        headers: headers.clone(),
        ..Default::default()
    };
    for (k, v) in &headers {
        let lk = k.to_ascii_lowercase();
        match lk.as_str() {
            "from" => msg.from = Some(v.clone()),
            "to" => msg.to = Some(v.clone()),
            "subject" => msg.subject = Some(v.clone()),
            "date" => msg.date = Some(v.clone()),
            "message-id" => msg.message_id = Some(v.clone()),
            _ => {}
        }
    }

    let ct = header_value(&headers, "content-type").unwrap_or_default();
    let cte = header_value(&headers, "content-transfer-encoding").unwrap_or_default();
    let disposition = header_value(&headers, "content-disposition").unwrap_or_default();

    if let Some(boundary) = mime_boundary(&ct) {
        for sub in split_multipart(body, &boundary) {
            walk_part(&sub, &mut msg);
        }
    } else if !headers.is_empty() {
        // Single-part message — body is the whole thing. Skip
        // when no headers parsed (truly malformed input — keeps
        // the partial-output contract from emitting noise).
        consume_part(&headers, &ct, &cte, &disposition, body, &mut msg);
    }

    msg
}

fn walk_part(part: &[u8], msg: &mut EmlMessage) {
    let (hdr_block, body) = split_header_body(part);
    let headers = parse_headers(hdr_block);
    let ct = header_value(&headers, "content-type").unwrap_or_default();
    let cte = header_value(&headers, "content-transfer-encoding").unwrap_or_default();
    let disposition = header_value(&headers, "content-disposition").unwrap_or_default();

    if let Some(boundary) = mime_boundary(&ct) {
        for sub in split_multipart(body, &boundary) {
            walk_part(&sub, msg);
        }
    } else {
        consume_part(&headers, &ct, &cte, &disposition, body, msg);
    }
}

fn consume_part(
    headers: &[(String, String)],
    ct: &str,
    cte: &str,
    disposition: &str,
    body: &[u8],
    msg: &mut EmlMessage,
) {
    let decoded = decode_transfer(body, cte);
    let mime_type = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let charset = param(ct, "charset");

    if is_attachment(disposition, ct) {
        let filename = param(disposition, "filename").or_else(|| param(ct, "name"));
        msg.attachments.push(EmlAttachment {
            filename,
            content_type: if mime_type.is_empty() {
                "application/octet-stream".to_string()
            } else {
                mime_type
            },
            decoded_bytes: decoded,
        });
        return;
    }

    let content_type = if mime_type.is_empty() {
        "text/plain".to_string()
    } else {
        mime_type
    };
    msg.parts.push(MimePart {
        content_type,
        charset,
        body: decoded,
    });
    // Headers from inner parts aren't promoted into the top-level
    // headers map; that field already reflects the outer message.
    let _ = headers;
}

fn is_attachment(disposition: &str, ct: &str) -> bool {
    let lc_disp = disposition.to_ascii_lowercase();
    if lc_disp.starts_with("attachment") || lc_disp.starts_with("inline; filename") {
        return true;
    }
    // `name=` parameter on Content-Type is the legacy attachment
    // marker pre-RFC 2183.
    if param(ct, "name").is_some() && !ct.to_ascii_lowercase().starts_with("multipart/") {
        return true;
    }
    false
}

fn strip_trailing_nul(raw: &[u8]) -> &[u8] {
    let mut end = raw.len();
    while end > 0 && raw[end - 1] == 0 {
        end -= 1;
    }
    &raw[..end]
}

fn split_header_body(raw: &[u8]) -> (&[u8], &[u8]) {
    // Look for CRLF CRLF first, fall back to LF LF.
    if let Some(pos) = find_subslice(raw, b"\r\n\r\n") {
        return (&raw[..pos], &raw[pos + 4..]);
    }
    if let Some(pos) = find_subslice(raw, b"\n\n") {
        return (&raw[..pos], &raw[pos + 2..]);
    }
    (raw, &[])
}

fn parse_headers(block: &[u8]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let text = String::from_utf8_lossy(block);
    for raw_line in text.split('\n') {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation of previous header per RFC 5322 §3.2.2.
            if let Some(last) = out.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
            continue;
        }
        if let Some(colon) = line.find(':') {
            let (k, v) = line.split_at(colon);
            out.push((k.trim().to_string(), v[1..].trim().to_string()));
        }
    }
    out
}

fn header_value(headers: &[(String, String)], key: &str) -> Option<String> {
    let target = key.to_ascii_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&target))
        .map(|(_, v)| v.clone())
}

fn mime_boundary(content_type: &str) -> Option<String> {
    let lc = content_type.to_ascii_lowercase();
    if !lc.starts_with("multipart/") {
        return None;
    }
    param(content_type, "boundary")
}

/// Extract `param=value` (with or without quoting) from a
/// header-value line. Case-insensitive on the param name; quoted
/// values keep their interior whitespace.
pub fn param(line: &str, name: &str) -> Option<String> {
    let lc = line.to_ascii_lowercase();
    let needle = format!("{}=", name.to_ascii_lowercase());
    let mut search_from = 0;
    while let Some(start) = lc[search_from..].find(&needle) {
        let abs = search_from + start;
        // Must be preceded by `;` or start-of-string-after-`;`.
        if abs != 0 {
            let prev_char_idx = lc[..abs].rfind(|c: char| !c.is_whitespace());
            if let Some(pi) = prev_char_idx {
                if lc.as_bytes()[pi] != b';' {
                    search_from = abs + needle.len();
                    continue;
                }
            }
        }
        let rest = &line[abs + needle.len()..];
        let val = if let Some(stripped) = rest.strip_prefix('"') {
            let end = stripped.find('"')?;
            stripped[..end].to_string()
        } else {
            rest.split([';', '\r', '\n'])
                .next()
                .unwrap_or("")
                .trim()
                .to_string()
        };
        return Some(val);
    }
    None
}

fn split_multipart(body: &[u8], boundary: &str) -> Vec<Vec<u8>> {
    let mid = format!("--{}", boundary);
    let mut parts = Vec::new();
    let text = body;
    let needle = mid.as_bytes();
    let mut idx = 0;
    let mut starts: Vec<usize> = Vec::new();
    while let Some(rel) = find_subslice(&text[idx..], needle) {
        starts.push(idx + rel);
        idx = idx + rel + needle.len();
    }
    // Append a sentinel at text.len() so the final part is
    // emitted even when the canonical `--boundary--` closing
    // marker is missing (truncated / malformed MIME). The
    // module contract is "always return what we could read"
    // — silently dropping the last attachment is a real-world
    // false-negative trigger.
    if !starts.is_empty() {
        starts.push(text.len());
    }
    for window in starts.windows(2) {
        let begin = window[0] + needle.len();
        let end = window[1];
        if begin > end || end > text.len() {
            continue;
        }
        let chunk = trim_part(&text[begin..end]);
        if !chunk.is_empty() {
            parts.push(chunk.to_vec());
        }
    }
    parts
}

fn trim_part(s: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < s.len() && (s[start] == b'\r' || s[start] == b'\n') {
        start += 1;
    }
    let mut end = s.len();
    while end > start && (s[end - 1] == b'\r' || s[end - 1] == b'\n' || s[end - 1] == b'-') {
        end -= 1;
    }
    &s[start..end]
}

fn decode_transfer(body: &[u8], encoding: &str) -> Vec<u8> {
    match encoding.trim().to_ascii_lowercase().as_str() {
        "base64" => decode_base64_loose(body),
        "quoted-printable" => decode_quoted_printable(body),
        _ => body.to_vec(), // 7bit / 8bit / binary all map to identity.
    }
}

fn decode_base64_loose(body: &[u8]) -> Vec<u8> {
    // Strip whitespace + non-alphabet bytes so MIME folding / CRLF
    // gaps don't trip the strict decoder, then hand off to the
    // workspace `base64` crate (already a dep via the engine-bundle
    // signature path).
    let mut cleaned: Vec<u8> = body
        .iter()
        .copied()
        .filter(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        .collect();
    // Some MIME generators emit non-padded base64. Drop padding
    // before handing to the URL-safe variant so we don't fail
    // when the input is missing trailing `=`.
    while cleaned.last() == Some(&b'=') {
        cleaned.pop();
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(&cleaned)
        .unwrap_or_default()
}

fn decode_quoted_printable(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        let b = body[i];
        if b == b'=' && i + 2 < body.len() {
            let h1 = body[i + 1];
            let h2 = body[i + 2];
            if h1 == b'\r' && h2 == b'\n' {
                // Soft line break.
                i += 3;
                continue;
            }
            if h1 == b'\n' {
                i += 2;
                continue;
            }
            if let (Some(d1), Some(d2)) = (hex_val(h1), hex_val(h2)) {
                out.push((d1 << 4) | d2);
                i += 3;
                continue;
            }
        }
        out.push(b);
        i += 1;
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_eml_headers() {
        let raw = b"From: alice@example.com\r\n\
                    To: bob@example.com\r\n\
                    Subject: Hello there\r\n\
                    Date: Mon, 28 May 2026 12:00:00 +0000\r\n\
                    Message-ID: <abc@example>\r\n\
                    \r\n\
                    Body text here.\r\n";
        let msg = parse_eml(raw);
        assert_eq!(msg.from.as_deref(), Some("alice@example.com"));
        assert_eq!(msg.to.as_deref(), Some("bob@example.com"));
        assert_eq!(msg.subject.as_deref(), Some("Hello there"));
        assert_eq!(msg.message_id.as_deref(), Some("<abc@example>"));
        assert_eq!(msg.parts.len(), 1);
        assert_eq!(msg.parts[0].content_type, "text/plain");
        assert!(String::from_utf8_lossy(&msg.parts[0].body).contains("Body text here."));
        assert!(msg.attachments.is_empty());
    }

    #[test]
    fn folds_continuation_lines_into_one_header() {
        let raw = b"Subject: foo\r\n bar\r\n\tbaz\r\n\r\nbody";
        let msg = parse_eml(raw);
        assert_eq!(msg.subject.as_deref(), Some("foo bar baz"));
    }

    #[test]
    fn lf_only_separator_is_tolerated() {
        let raw = b"From: a\nSubject: b\n\nbody";
        let msg = parse_eml(raw);
        assert_eq!(msg.subject.as_deref(), Some("b"));
        assert_eq!(msg.parts.len(), 1);
    }

    #[test]
    fn multipart_alternative_splits_into_two_parts() {
        let raw = b"From: a@b\r\n\
                    Content-Type: multipart/alternative; boundary=\"BB\"\r\n\
                    \r\n\
                    --BB\r\n\
                    Content-Type: text/plain\r\n\r\n\
                    plain text body\r\n\
                    --BB\r\n\
                    Content-Type: text/html\r\n\r\n\
                    <p>html body</p>\r\n\
                    --BB--\r\n";
        let msg = parse_eml(raw);
        assert_eq!(msg.parts.len(), 2);
        assert_eq!(msg.parts[0].content_type, "text/plain");
        assert_eq!(msg.parts[1].content_type, "text/html");
        assert!(String::from_utf8_lossy(&msg.parts[0].body).contains("plain text body"));
        assert!(String::from_utf8_lossy(&msg.parts[1].body).contains("html body"));
    }

    #[test]
    fn base64_attachment_is_decoded() {
        // "Mythodikal\n" in base64 = "TXl0aG9kaWthbAo="
        let raw = b"From: a@b\r\n\
                    Content-Type: multipart/mixed; boundary=BD\r\n\
                    \r\n\
                    --BD\r\n\
                    Content-Type: text/plain\r\n\r\n\
                    see attachment\r\n\
                    --BD\r\n\
                    Content-Type: application/octet-stream; name=\"payload.bin\"\r\n\
                    Content-Disposition: attachment; filename=\"payload.bin\"\r\n\
                    Content-Transfer-Encoding: base64\r\n\r\n\
                    TXl0aG9kaWthbAo=\r\n\
                    --BD--\r\n";
        let msg = parse_eml(raw);
        assert_eq!(msg.attachments.len(), 1);
        assert_eq!(msg.attachments[0].filename.as_deref(), Some("payload.bin"));
        assert_eq!(&msg.attachments[0].decoded_bytes, b"Mythodikal\n");
        assert_eq!(msg.attachments[0].content_type, "application/octet-stream");
    }

    #[test]
    fn quoted_printable_body_decodes() {
        let raw = b"From: a@b\r\n\
                    Content-Type: text/plain; charset=utf-8\r\n\
                    Content-Transfer-Encoding: quoted-printable\r\n\
                    \r\n\
                    Hello=20world=21\r\n";
        let msg = parse_eml(raw);
        assert_eq!(msg.parts.len(), 1);
        assert!(String::from_utf8_lossy(&msg.parts[0].body).starts_with("Hello world!"));
    }

    #[test]
    fn multipart_without_closing_boundary_still_emits_final_part() {
        // Adversarial / truncated MIME: only the opening
        // `--BB` markers, no `--BB--` terminator. The final
        // part must still be parsed — otherwise the attacker
        // can smuggle an attachment past the scanner just by
        // truncating the trailer.
        let raw = b"From: a@b\r\n\
                    Content-Type: multipart/mixed; boundary=BB\r\n\
                    \r\n\
                    --BB\r\n\
                    Content-Type: text/plain\r\n\r\n\
                    cover text\r\n\
                    --BB\r\n\
                    Content-Type: application/octet-stream; name=\"payload.bin\"\r\n\
                    Content-Disposition: attachment; filename=\"payload.bin\"\r\n\
                    Content-Transfer-Encoding: base64\r\n\r\n\
                    TXl0aG9kaWthbAo=\r\n";
        let msg = parse_eml(raw);
        assert_eq!(msg.attachments.len(), 1, "final part must not be dropped");
        assert_eq!(msg.attachments[0].filename.as_deref(), Some("payload.bin"));
        assert_eq!(&msg.attachments[0].decoded_bytes, b"Mythodikal\n");
    }

    #[test]
    fn nested_multipart_walks_recursively() {
        let raw = b"From: a@b\r\n\
                    Content-Type: multipart/mixed; boundary=OUT\r\n\
                    \r\n\
                    --OUT\r\n\
                    Content-Type: multipart/alternative; boundary=IN\r\n\r\n\
                    --IN\r\n\
                    Content-Type: text/plain\r\n\r\nplain\r\n\
                    --IN\r\n\
                    Content-Type: text/html\r\n\r\n<b>html</b>\r\n\
                    --IN--\r\n\
                    --OUT\r\n\
                    Content-Type: application/zip; name=\"x.zip\"\r\n\
                    Content-Disposition: attachment; filename=\"x.zip\"\r\n\r\n\
                    raw zip bytes here\r\n\
                    --OUT--\r\n";
        let msg = parse_eml(raw);
        assert_eq!(msg.parts.len(), 2, "nested parts found");
        assert_eq!(msg.attachments.len(), 1);
        assert_eq!(msg.attachments[0].content_type, "application/zip");
    }

    #[test]
    fn malformed_input_yields_partial_message() {
        let msg = parse_eml(b"not even close to RFC 5322");
        // No headers parsed, no body parts. The contract is "always
        // return *something*"; this asserts no panic + sane defaults.
        assert!(msg.from.is_none());
        assert!(msg.parts.is_empty());
        assert!(msg.attachments.is_empty());
    }

    #[test]
    fn param_extracts_quoted_and_unquoted() {
        assert_eq!(
            param("multipart/mixed; boundary=\"XYZ\"", "boundary"),
            Some("XYZ".to_string())
        );
        assert_eq!(
            param("multipart/mixed; boundary=plain", "boundary"),
            Some("plain".to_string())
        );
        assert_eq!(param("multipart/mixed; foo=bar", "boundary"), None);
    }
}
