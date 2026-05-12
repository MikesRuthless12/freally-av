//! Windows-specific platform glue (TASK-136 Phase 4, Phase 5 MFT walker,
//! Phase 12 ETW/AMSI/WDAC daemon).

pub mod codesign;
/// USN journal subscriber (vendored from sister project Sourcerer). Shared
/// between TASK-050's MFT bootstrap walker and TASK-051's USN incremental
/// walker.
pub mod journal;
