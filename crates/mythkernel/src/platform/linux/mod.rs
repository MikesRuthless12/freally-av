//! Linux-specific platform glue (TASK-136 Phase 4, Phase 8+ daemon hooks).

/// Autostart-class path enumeration (TASK-138). XDG `.desktop` files,
/// systemd units, shell rc files. Drives the file-mutation baseline
/// detector at scan time.
pub mod autostart;
pub mod codesign;
/// inotify+fanotify journal subscriber (vendored from sister project Sourcerer).
/// Used by [`crate::walker::ntfs::NtfsWalker`]'s Linux path for fast bootstrap
/// walks via raw `getdents64`; the real-time subscribe stream backs the
/// Phase 8 Linux real-time daemon.
pub mod journal;
