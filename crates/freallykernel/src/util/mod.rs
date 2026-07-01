//! Internal helpers shared across freallykernel parsers.

pub mod bytes;
/// Path-canonicalisation helpers for attacker-supplied filenames
/// (TASK-271..279 follow-up from the Phase 10 Wave 2 security
/// review). `safe_filename` / `is_safe_relative` / `safe_join`
/// are the defenses any consumer of `EmlAttachment.filename`,
/// `MsgAttachmentStream.filename_w`, or `DownloadRecord.target_path`
/// must apply before turning the value into a real path.
pub mod paths;
/// Shell-quote helpers for log/UI rendering of strings extracted
/// from attacker-controlled files (LNK arguments, Excel formulas,
/// autorun.inf directives). `quote_for_log` is display-safe;
/// `poisoned_for_exec` makes accidental shell invocation fail loud.
pub mod shell;
