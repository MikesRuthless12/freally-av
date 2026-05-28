//! Document-payload extractors (Phase 10 Wave 2 — TASK-276..279).
//!
//! Four small in-tree parsers for the document formats that
//! routinely carry second-stage payloads:
//!
//!   * `pdf_actions`  — `/JavaScript`, `/Launch`, `/OpenAction`,
//!                      `/AA` (additional-action) extractor
//!                      (TASK-276)
//!   * `pdf_streams`  — stream-object enumerator (`stream` …
//!                      `endstream`) with `FlateDecode` /
//!                      `ASCIIHexDecode` filter normalization
//!                      (TASK-277)
//!   * `rtf_obj`      — `\objdata` / `\objupdate` /
//!                      `\objemb` hex-blob extractor (TASK-278)
//!   * `lnk`          — Microsoft Shell Link (`.lnk`) header +
//!                      LinkTargetIDList + LinkInfo parser
//!                      (TASK-279)
//!
//! All parsing is structural — heuristics that flag the
//! *presence* of dangerous primitives, not full semantic
//! validation. Each module returns a flat list of findings
//! ready for the scan-row UI.

pub mod lnk;
pub mod pdf_actions;
pub mod pdf_streams;
pub mod rtf_obj;
