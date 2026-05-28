//! `.mbox` walker (TASK-271).
//!
//! mbox is a flat concatenation of RFC 5322 messages separated by
//! lines that start with `From ` (with a trailing space — distinct
//! from the `From:` header). This walker splits on the separator
//! and feeds each chunk through [`crate::email::eml::parse_eml`].
//!
//! Both `mboxo` and `mboxrd` quoting variants of in-body `From `
//! lines are tolerated transparently — we only split on `From ` at
//! the *start of a line*, so a quoted body line `>From ` doesn't
//! produce a false split.

use super::eml::{parse_eml, EmlMessage};

/// Split an `.mbox` file into individual [`EmlMessage`] entries.
/// Malformed entries are still emitted with whatever the per-message
/// parser could recover.
pub fn parse_mbox(raw: &[u8]) -> Vec<EmlMessage> {
    let mut out = Vec::new();
    for chunk in split_mbox(raw) {
        out.push(parse_eml(chunk));
    }
    out
}

fn split_mbox(raw: &[u8]) -> Vec<&[u8]> {
    let mut parts: Vec<&[u8]> = Vec::new();
    let mut starts: Vec<usize> = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        if at_line_start(raw, i) && starts_with(&raw[i..], b"From ") {
            starts.push(i);
        }
        // Advance to next newline.
        match raw[i..].iter().position(|&b| b == b'\n') {
            Some(rel) => i = i + rel + 1,
            None => break,
        }
    }
    for window in starts.windows(2) {
        parts.push(&raw[window[0]..window[1]]);
    }
    if let Some(&last) = starts.last() {
        parts.push(&raw[last..]);
    }
    if parts.is_empty() && !raw.is_empty() {
        // No separator at all — treat as a single message.
        parts.push(raw);
    }
    // Drop the leading `From ...\n` envelope line from each part
    // so the parser sees a clean header block.
    parts
        .into_iter()
        .map(|p| {
            if starts_with(p, b"From ") {
                match p.iter().position(|&b| b == b'\n') {
                    Some(nl) => &p[nl + 1..],
                    None => &p[5..],
                }
            } else {
                p
            }
        })
        .collect()
}

fn at_line_start(raw: &[u8], i: usize) -> bool {
    i == 0 || raw[i - 1] == b'\n'
}

fn starts_with(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && &haystack[..needle.len()] == needle
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_three_message_mbox() {
        let raw = b"From alice@example Mon May 28 12:00:00 2026\n\
                    From: alice@example.com\n\
                    Subject: One\n\n\
                    body one\n\
                    From bob@example Mon May 28 12:05:00 2026\n\
                    From: bob@example.com\n\
                    Subject: Two\n\n\
                    body two\n\
                    From carol@example Mon May 28 12:10:00 2026\n\
                    From: carol@example.com\n\
                    Subject: Three\n\n\
                    body three\n";
        let msgs = parse_mbox(raw);
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].subject.as_deref(), Some("One"));
        assert_eq!(msgs[1].subject.as_deref(), Some("Two"));
        assert_eq!(msgs[2].subject.as_deref(), Some("Three"));
    }

    #[test]
    fn from_in_body_doesnt_split() {
        // The body line `>From ` (mboxrd quoting) must not create
        // an extra message.
        let raw = b"From sender Mon May 28 12:00:00 2026\n\
                    Subject: only\n\n\
                    >From the office\n\
                    body line two\n";
        let msgs = parse_mbox(raw);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].subject.as_deref(), Some("only"));
    }

    #[test]
    fn empty_input_yields_empty_vec() {
        assert!(parse_mbox(b"").is_empty());
    }

    #[test]
    fn single_message_without_separator_is_returned() {
        let raw = b"Subject: bare\n\nbody";
        let msgs = parse_mbox(raw);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].subject.as_deref(), Some("bare"));
    }
}
