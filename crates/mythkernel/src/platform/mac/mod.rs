//! macOS-specific platform glue (TASK-136 Phase 4, Phase 9+ daemon hooks).

pub mod codesign;
/// FSEvents journal subscriber (vendored from sister project Sourcerer).
/// Used by [`crate::walker::ntfs::NtfsWalker`]'s non-Windows fallback for
/// fast bootstrap walks; the real-time subscribe stream backs the Phase 9
/// macOS real-time daemon.
pub mod journal;
