//! Payload-anomaly detectors (Phase 10 Wave 2 — TASK-286..290).
//!
//! Cross-cutting heuristics that don't fit cleanly under a
//! container-specific module:
//!
//!   * `stego`          — chi-square LSB heuristic over image
//!                        pixel data (TASK-286)
//!   * `eof_trailer`    — hidden-data-after-EOF detector for
//!                        PNG / JPEG / GIF / PDF / ZIP
//!                        (TASK-287)
//!   * `iso_autorun`    — ISO/IMG autorun.inf root presence
//!                        (TASK-288)
//!   * `lnk_anomaly`    — LNK working-directory anomaly checker
//!                        (TASK-289 — composes
//!                        `doc_payload::lnk`)
//!   * `office_template`— Word `attachedTemplate` external-URL
//!                        detector — the remote-template
//!                        injection shape (TASK-290)
//!
//! All read-only. Every detector returns a typed finding the
//! daemon promotes into a scan row.

pub mod eof_trailer;
pub mod iso_autorun;
pub mod lnk_anomaly;
pub mod office_template;
pub mod stego;
