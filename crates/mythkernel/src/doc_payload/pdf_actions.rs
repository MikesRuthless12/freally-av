//! PDF JavaScript + launch-action extractor (TASK-276).
//!
//! Scans a `.pdf` byte buffer for the four high-risk action
//! primitives:
//!
//!   * `/JS` and `/JavaScript` — JavaScript actions
//!   * `/Launch` — launches an external program
//!   * `/OpenAction` — fires on document open
//!   * `/AA` — additional-actions dictionary (mouse-over, form
//!     focus, page-open …)
//!
//! Detection is presence-based: the parser doesn't follow
//! indirect-object refs, so a hit means "the document contains
//! the keyword in a place where the PDF spec defines it". Final
//! semantic resolution happens in the closeout pass; this
//! foundation gives the scan-row badge.

use serde::{Deserialize, Serialize};

use crate::util::bytes::find_subslice;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PdfActionKind {
    JavaScript,
    Launch,
    OpenAction,
    AdditionalAction,
    GoToRemote,
    SubmitForm,
    ImportData,
}

impl PdfActionKind {
    pub fn label(self) -> &'static str {
        match self {
            PdfActionKind::JavaScript => "JavaScript",
            PdfActionKind::Launch => "Launch",
            PdfActionKind::OpenAction => "OpenAction",
            PdfActionKind::AdditionalAction => "AdditionalAction",
            PdfActionKind::GoToRemote => "GoToRemote",
            PdfActionKind::SubmitForm => "SubmitForm",
            PdfActionKind::ImportData => "ImportData",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdfActionFinding {
    pub kind: PdfActionKind,
    pub offset: usize,
    /// Up to 200 bytes of surrounding context for UI display.
    pub context: String,
}

const KEYWORDS: &[(&[u8], PdfActionKind)] = &[
    (b"/JavaScript", PdfActionKind::JavaScript),
    (b"/JS", PdfActionKind::JavaScript),
    (b"/Launch", PdfActionKind::Launch),
    (b"/OpenAction", PdfActionKind::OpenAction),
    (b"/AA", PdfActionKind::AdditionalAction),
    (b"/GoToR", PdfActionKind::GoToRemote),
    (b"/SubmitForm", PdfActionKind::SubmitForm),
    (b"/ImportData", PdfActionKind::ImportData),
];

/// Scan a PDF byte buffer and return one finding per **first**
/// occurrence of each action keyword. Returns an empty vec for
/// non-PDF input (no `%PDF-` header).
pub fn scan(raw: &[u8]) -> Vec<PdfActionFinding> {
    if !raw.starts_with(b"%PDF-") {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut seen: Vec<PdfActionKind> = Vec::new();
    for (needle, kind) in KEYWORDS {
        if seen.contains(kind) {
            continue;
        }
        if let Some(off) = find_subslice(raw, needle) {
            // Reject substring overlap: `/AA` shouldn't match
            // `/AAccept` (unusual but possible custom dict keys).
            // The PDF spec defines name objects as ending at the
            // first non-regular character; we approximate with
            // "next byte must be `\s` / `[` / `(` / `<` / `]` /
            // `>` / `/`".
            if !is_name_terminator(raw, off + needle.len()) {
                continue;
            }
            out.push(PdfActionFinding {
                kind: *kind,
                offset: off,
                context: extract_context(raw, off, needle.len()),
            });
            seen.push(*kind);
        }
    }
    out
}

fn is_name_terminator(raw: &[u8], pos: usize) -> bool {
    if pos >= raw.len() {
        return true; // EOF terminates
    }
    let b = raw[pos];
    b.is_ascii_whitespace() || matches!(b, b'/' | b'[' | b'(' | b'<' | b']' | b'>' | b'{' | b'}')
}

fn extract_context(raw: &[u8], offset: usize, needle_len: usize) -> String {
    let start = offset.saturating_sub(40);
    let end = (offset + needle_len + 80).min(raw.len());
    String::from_utf8_lossy(&raw[start..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pdf_input() {
        assert!(scan(b"this is not a PDF").is_empty());
    }

    #[test]
    fn flags_open_action_javascript() {
        let pdf = b"%PDF-1.5\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert('x');) >> >>\nendobj\n%%EOF";
        let findings = scan(pdf);
        let kinds: Vec<PdfActionKind> = findings.iter().map(|f| f.kind).collect();
        assert!(kinds.contains(&PdfActionKind::OpenAction));
        assert!(kinds.contains(&PdfActionKind::JavaScript));
    }

    #[test]
    fn flags_launch_action() {
        let pdf = b"%PDF-1.4\n2 0 obj\n<< /Type /Action /S /Launch /F (cmd.exe) >>\nendobj";
        let findings = scan(pdf);
        assert!(findings.iter().any(|f| f.kind == PdfActionKind::Launch));
    }

    #[test]
    fn flags_aa_dict() {
        let pdf = b"%PDF-1.7\n<< /AA << /O << /S /JavaScript >> >> >>";
        let findings = scan(pdf);
        let kinds: Vec<PdfActionKind> = findings.iter().map(|f| f.kind).collect();
        assert!(kinds.contains(&PdfActionKind::AdditionalAction));
    }

    #[test]
    fn benign_pdf_returns_empty() {
        let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF";
        assert!(scan(pdf).is_empty());
    }

    #[test]
    fn name_object_terminator_rejects_extended_keyword() {
        // `/AAccept` shouldn't match `/AA`.
        let pdf = b"%PDF-1.5\n<< /AAccept (foo) >>";
        assert!(scan(pdf).is_empty());
    }

    #[test]
    fn context_window_includes_surrounding_bytes() {
        let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Action /S /Launch /F (calc.exe) >>\nendobj";
        let findings = scan(pdf);
        let launch = findings
            .iter()
            .find(|f| f.kind == PdfActionKind::Launch)
            .unwrap();
        assert!(launch.context.contains("calc.exe"));
    }

    #[test]
    fn one_finding_per_kind_even_with_duplicates() {
        let pdf = b"%PDF-1.4\n/JavaScript (a) /JavaScript (b) /JavaScript (c)\n%%EOF";
        let findings = scan(pdf);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, PdfActionKind::JavaScript);
    }
}
