//! Email-forensics module (Phase 10 Wave 2 — TASK-271).
//!
//! In-tree, read-only parsers for the three on-disk mail formats
//! Mythodikal surfaces in scan rows: RFC 5322 `.eml`, `.mbox` (one
//! file = many `From ` -separated messages), and Outlook `.msg`
//! (Microsoft Compound File Binary — the OLE walker lives in
//! `office::cfb`, this module just consumes the resulting streams).
//!
//! ## Scope split
//!
//! This commit lands the **`.eml` foundation**: RFC 5322 header
//! parser, MIME-multipart splitter, and base64 + quoted-printable
//! transfer decoders. The walker emits an [`EmlMessage`] with one
//! decoded body part per `Content-Type` plus a flat
//! `Vec<EmlAttachment>`. Callers (the engine-side YARA pass) run
//! yara-x over each text/html body and each attachment's decoded
//! bytes after this returns.
//!
//! `.mbox` reuses the same parser — split on lines beginning with
//! `From ` (the mbox separator) and feed each chunk through
//! [`parse_eml`].
//!
//! `.msg` is a Microsoft Compound File. The dispatch lives in
//! [`office::cfb`](crate::office::cfb); this module exposes a
//! convenience wrapper [`parse_msg_streams`] that joins
//! `__substg1.0_*` property streams (PR_SUBJECT / PR_BODY /
//! PR_SENDER_EMAIL_ADDRESS / PR_ATTACH_FILENAME) into the same
//! [`EmlMessage`] shape so downstream code is single-path.
//!
//! All parsing is best-effort; malformed input yields the partial
//! [`EmlMessage`] populated up to the point of failure rather than
//! a hard error — scan rows want "what we could read", not "the
//! file was rejected".

pub mod eml;
pub mod mbox;
pub mod msg;

pub use eml::{parse_eml, EmlAttachment, EmlMessage, MimePart};
pub use mbox::parse_mbox;
pub use msg::parse_msg_streams;
