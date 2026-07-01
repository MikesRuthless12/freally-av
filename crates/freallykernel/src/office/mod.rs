//! Office-forensics module (Phase 10 Wave 2 — TASK-272..275).
//!
//! In-tree, read-only parsers for the four Office artefacts the
//! roadmap calls out without forcing an Office or LibreOffice
//! install:
//!
//!   * `cfb`     — Microsoft Compound File Binary directory walker
//!                 used by Office 97-2003 binary formats and `.msg`
//!                 (TASK-272)
//!   * `vba`     — Auto_Open / Document_Open / AutoExec /
//!                 Workbook_Open detector (TASK-273)
//!   * `excel`   — WEBSERVICE / DDE / IMPORTDATA / RTD / CALL /
//!                 REGISTER cell-formula flag (TASK-274)
//!   * `crypto`  — MS-OFFCRYPTO encrypted-document fingerprint
//!                 (TASK-275)
//!
//! Each submodule is pure-logic over caller-supplied byte slices
//! so the test surface stays in-process and deterministic. The
//! CFB walker handles the on-disk format directly; the VBA /
//! Excel scanners assume the daemon-side extractor has already
//! teased out the macro modules + cell formulas (the heavy
//! `decompress` step lands at Phase 10 closeout once the chosen
//! dependency lands).

pub mod cfb;
pub mod crypto;
pub mod excel;
pub mod vba;

pub use cfb::{CfbDirectoryEntry, CfbObjectType, parse_cfb};
pub use crypto::{OfficeEncryption, detect_encryption};
pub use excel::{XlFormulaFinding, XlSuspiciousFn, scan_formulas};
pub use vba::{VbaAutoExecFinding, VbaTrigger, scan_vba_modules};
