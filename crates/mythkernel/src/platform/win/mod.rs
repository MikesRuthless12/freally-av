//! Windows-specific platform glue (TASK-136 Phase 4, Phase 5 MFT walker,
//! Phase 12 ETW/AMSI/WDAC daemon).

/// Autostart-class path enumeration (TASK-138). Startup folders (per-user
/// and all-users) + PowerShell profile scripts. Drives the file-mutation
/// baseline detector at scan time. Registry `Run`/`RunOnce` keys are
/// covered by Phase 12 ETW (TASK-098), not this enumerator.
pub mod autostart;
pub mod codesign;
/// USN journal subscriber (vendored from sister project Sourcerer). Shared
/// between TASK-050's MFT bootstrap walker and TASK-051's USN incremental
/// walker.
pub mod journal;
/// Volume detection + enumeration (TASK-052). Used by TASK-053's
/// [`crate::walker::multi_volume::MultiVolumeWalker`] to fan out one
/// bootstrap walk per detected volume.
pub mod volumes;
