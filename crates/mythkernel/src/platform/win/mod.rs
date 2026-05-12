//! Windows-specific platform glue (TASK-136 Phase 4, Phase 5 MFT walker,
//! Phase 12 ETW/AMSI/WDAC daemon).

pub mod codesign;
/// USN journal subscriber (vendored from sister project Sourcerer). Shared
/// between TASK-050's MFT bootstrap walker and TASK-051's USN incremental
/// walker.
pub mod journal;
/// Volume detection + enumeration (TASK-052). Used by TASK-053's
/// [`crate::walker::multi_volume::MultiVolumeWalker`] to fan out one
/// bootstrap walk per detected volume.
pub mod volumes;
