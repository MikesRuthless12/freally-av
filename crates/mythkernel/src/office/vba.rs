//! VBA auto-execute macro detector (TASK-273).
//!
//! Once the Phase 10 closeout pass adds the VBA RLE-decompressor
//! (lifted from `oletools`-style permissive crates), the daemon
//! hands the *decompressed* VBA source for each macro module into
//! [`scan_vba_modules`]. This function regex-scans for any of the
//! four canonical auto-exec triggers Microsoft documents:
//!
//!   * `Sub Auto_Open` / `Sub AutoOpen` — Word + Excel pre-2007
//!   * `Sub Document_Open` — Word 2007+
//!   * `Sub Workbook_Open` — Excel 2007+
//!   * `Sub AutoExec` — Word global template auto-exec
//!
//! Each hit becomes a [`VbaAutoExecFinding`] that the scan-row UI
//! shows with a red `auto-exec macro` badge.

use serde::{Deserialize, Serialize};

/// Decompressed source of a single VBA module. `source` is the
/// post-RLE-decompression UTF-8 text; binary modules and the
/// PerformanceCache stream are excluded by the daemon-side
/// extractor before calling [`scan_vba_modules`].
#[derive(Debug, Clone)]
pub struct VbaModule<'a> {
    pub name: &'a str,
    pub source: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VbaTrigger {
    AutoOpen,
    DocumentOpen,
    WorkbookOpen,
    AutoExec,
    AutoClose,
    DocumentClose,
    WorkbookActivate,
}

impl VbaTrigger {
    pub fn label(self) -> &'static str {
        match self {
            VbaTrigger::AutoOpen => "Auto_Open",
            VbaTrigger::DocumentOpen => "Document_Open",
            VbaTrigger::WorkbookOpen => "Workbook_Open",
            VbaTrigger::AutoExec => "AutoExec",
            VbaTrigger::AutoClose => "AutoClose",
            VbaTrigger::DocumentClose => "Document_Close",
            VbaTrigger::WorkbookActivate => "Workbook_Activate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VbaAutoExecFinding {
    pub module_name: String,
    pub trigger: VbaTrigger,
    /// Byte offset of the `Sub …` declaration inside the module.
    pub offset: usize,
    /// Lower-case canonical name as it appeared in the source,
    /// preserved for UI display (`auto_open` vs `AutoOpen`).
    pub display_name: String,
}

const TRIGGERS: &[(VbaTrigger, &[&str])] = &[
    (VbaTrigger::AutoOpen, &["auto_open", "autoopen"]),
    (VbaTrigger::DocumentOpen, &["document_open"]),
    (VbaTrigger::WorkbookOpen, &["workbook_open"]),
    (VbaTrigger::AutoExec, &["autoexec"]),
    (VbaTrigger::AutoClose, &["auto_close", "autoclose"]),
    (VbaTrigger::DocumentClose, &["document_close"]),
    (VbaTrigger::WorkbookActivate, &["workbook_activate"]),
];

/// Scan a slice of decompressed VBA modules for the canonical
/// auto-exec entrypoints. Match is case-insensitive and skips
/// `Private Sub` re-declarations the same as `Sub` because both
/// fire on the host event.
pub fn scan_vba_modules(modules: &[VbaModule<'_>]) -> Vec<VbaAutoExecFinding> {
    let mut out = Vec::new();
    for m in modules {
        let lc = m.source.to_ascii_lowercase();
        for (trigger, needles) in TRIGGERS {
            for needle in *needles {
                let mut search_from = 0;
                while let Some(rel) = lc[search_from..].find(needle) {
                    let abs = search_from + rel;
                    search_from = abs + needle.len();
                    if !is_sub_declaration(&lc, abs) {
                        continue;
                    }
                    let display = capture_display(m.source, abs, needle.len());
                    out.push(VbaAutoExecFinding {
                        module_name: m.name.to_string(),
                        trigger: *trigger,
                        offset: abs,
                        display_name: display,
                    });
                    break; // one finding per trigger per module
                }
            }
        }
    }
    out
}

fn is_sub_declaration(lc: &str, name_off: usize) -> bool {
    // Walk backwards from `name_off` skipping whitespace, then
    // confirm we hit `sub` (with optional `private` / `public`
    // / `static` keywords). The needle has to be preceded by
    // whitespace; otherwise `MyAuto_Open` substring would fire.
    let bytes = lc.as_bytes();
    if name_off == 0 {
        return false;
    }
    let prev = bytes[name_off - 1];
    if !prev.is_ascii_whitespace() {
        return false;
    }
    // Skip whitespace backwards.
    let mut i = name_off;
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    // Read the preceding word.
    let word_end = i;
    while i > 0 && (bytes[i - 1].is_ascii_alphabetic() || bytes[i - 1] == b'_') {
        i -= 1;
    }
    let word = &lc[i..word_end];
    matches!(word, "sub" | "function")
}

fn capture_display(source: &str, abs: usize, len: usize) -> String {
    let end = abs + len;
    if end > source.len() {
        return String::new();
    }
    source[abs..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_auto_open_in_word_macro() {
        let source = "\
Attribute VB_Name = \"ThisDocument\"
Sub Auto_Open()
  MsgBox \"hi\"
End Sub
";
        let m = VbaModule {
            name: "ThisDocument",
            source,
        };
        let findings = scan_vba_modules(&[m]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].trigger, VbaTrigger::AutoOpen);
        assert_eq!(findings[0].module_name, "ThisDocument");
        assert_eq!(findings[0].display_name, "Auto_Open");
    }

    #[test]
    fn detects_workbook_open() {
        let m = VbaModule {
            name: "ThisWorkbook",
            source: "Private Sub Workbook_Open()\nEnd Sub",
        };
        let findings = scan_vba_modules(&[m]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].trigger, VbaTrigger::WorkbookOpen);
    }

    #[test]
    fn skips_substring_in_identifier() {
        // `MyAuto_Open` shouldn't fire — it's a different identifier.
        let m = VbaModule {
            name: "Mod1",
            source: "Sub MyAuto_Open()\nEnd Sub",
        };
        let findings = scan_vba_modules(&[m]);
        assert!(findings.is_empty(), "found: {findings:?}");
    }

    #[test]
    fn flags_both_auto_open_and_auto_close_in_same_module() {
        let source = "Sub Auto_Open()\nEnd Sub\nSub Auto_Close()\nEnd Sub";
        let m = VbaModule {
            name: "Mod1",
            source,
        };
        let findings = scan_vba_modules(&[m]);
        let triggers: Vec<VbaTrigger> = findings.iter().map(|f| f.trigger).collect();
        assert!(triggers.contains(&VbaTrigger::AutoOpen));
        assert!(triggers.contains(&VbaTrigger::AutoClose));
    }

    #[test]
    fn case_insensitive_match_preserves_display_case() {
        let m = VbaModule {
            name: "Mod1",
            source: "sub AUTOEXEC()\nEnd Sub",
        };
        let findings = scan_vba_modules(&[m]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].trigger, VbaTrigger::AutoExec);
        assert_eq!(findings[0].display_name, "AUTOEXEC");
    }

    #[test]
    fn function_keyword_also_counts() {
        let m = VbaModule {
            name: "Mod1",
            source: "Public Function Auto_Open()\nEnd Function",
        };
        let findings = scan_vba_modules(&[m]);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn empty_modules_yield_no_findings() {
        let findings = scan_vba_modules(&[]);
        assert!(findings.is_empty());
    }
}
