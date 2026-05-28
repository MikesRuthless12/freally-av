//! Process-hollowing detector (TASK-296).
//!
//! Process hollowing creates a suspended process from a benign
//! image, then overwrites the original PE in memory with a
//! second-stage image before resuming. Daemon-side code feeds
//! this module two artefacts:
//!
//!   * the *path* the kernel reports as the process image
//!   * a hash (BLAKE3) of the **first PE section header** as
//!     read from the **in-memory image** AND from the on-disk
//!     image referenced by the path
//!
//! When those two hashes disagree, the in-memory image was
//! replaced — the canonical hollowing signature. An optional
//! `imagebase_relocated` flag promotes the finding to high
//! confidence because legitimate ASLR doesn't relocate the
//! PE-section-header bytes.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HollowingFinding {
    pub reason: HollowingReason,
    pub on_disk_image_path: String,
    pub on_disk_section_hash: String,
    pub in_memory_section_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HollowingReason {
    SectionHashMismatch,
    SectionHashMismatchAndRelocated,
}

/// Compare the hashes. `None` when they match (no finding).
pub fn detect_hollowing(
    on_disk_image_path: &str,
    on_disk_section_hash: &str,
    in_memory_section_hash: &str,
    imagebase_relocated: bool,
) -> Option<HollowingFinding> {
    if on_disk_section_hash.eq_ignore_ascii_case(in_memory_section_hash) {
        return None;
    }
    let reason = if imagebase_relocated {
        HollowingReason::SectionHashMismatchAndRelocated
    } else {
        HollowingReason::SectionHashMismatch
    };
    Some(HollowingFinding {
        reason,
        on_disk_image_path: on_disk_image_path.to_string(),
        on_disk_section_hash: on_disk_section_hash.to_string(),
        in_memory_section_hash: in_memory_section_hash.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_hashes_yield_no_finding() {
        let r = detect_hollowing(
            "C:\\Windows\\notepad.exe",
            "deadbeef",
            "DEADBEEF",
            false,
        );
        assert!(r.is_none());
    }

    #[test]
    fn mismatch_fires_with_section_hash_mismatch_reason() {
        let f = detect_hollowing(
            "C:\\Windows\\notepad.exe",
            "deadbeef",
            "feedface",
            false,
        )
        .unwrap();
        assert_eq!(f.reason, HollowingReason::SectionHashMismatch);
    }

    #[test]
    fn relocated_flag_promotes_reason() {
        let f = detect_hollowing(
            "C:\\Windows\\notepad.exe",
            "deadbeef",
            "feedface",
            true,
        )
        .unwrap();
        assert_eq!(f.reason, HollowingReason::SectionHashMismatchAndRelocated);
    }

    #[test]
    fn hash_comparison_is_case_insensitive() {
        let r = detect_hollowing("/usr/bin/ls", "AbCdEf12", "abcdef12", false);
        assert!(r.is_none());
    }
}
