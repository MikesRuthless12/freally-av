//! Linux-specific platform glue (TASK-136 Phase 4, Phase 8+ daemon hooks).

pub mod codesign;
/// inotify+fanotify journal subscriber (vendored from sister project Sourcerer).
/// Used by [`crate::walker::ntfs::NtfsWalker`]'s Linux path for fast bootstrap
/// walks via raw `getdents64`; the real-time subscribe stream backs the
/// Phase 8 Linux real-time daemon.
pub mod journal;
