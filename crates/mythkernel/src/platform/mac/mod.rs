//! macOS-specific platform glue (TASK-136 Phase 4, Phase 9+ daemon hooks).

/// Autostart-class path enumeration (TASK-138). Launchd plists, login
/// items, shell rc files. Drives the file-mutation baseline detector
/// at scan time.
pub mod autostart;
pub mod codesign;
/// FSEvents journal subscriber (vendored from sister project Sourcerer).
/// Used by [`crate::walker::ntfs::NtfsWalker`]'s non-Windows fallback for
/// fast bootstrap walks; the real-time subscribe stream backs the Phase 9
/// macOS real-time daemon.
pub mod journal;
