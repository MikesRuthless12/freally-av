//! YARA pass over per-process memory regions (TASK-291).
//!
//! Foundation lands a structured request shape — the daemon
//! enqueues these and the engine's existing
//! [`crate::detect::yara_engine`] consumes them. Actual
//! `yara-x` integration reuses the production scan path and
//! lands at Phase 10 closeout, so this module just owns the
//! type that gets serialised across the IPC boundary.

use serde::{Deserialize, Serialize};

use super::Pid;
use super::regions::MemoryRegion;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum YaraRegionRequestKind {
    /// Run the full ruleset.
    FullRuleSet,
    /// Run only the in-memory rules under
    /// `rules/memory/*.yar` — faster + less false-positive
    /// noise on high-volume scans.
    InMemoryOnly,
    /// Caller-supplied rule ID set; daemon resolves to the
    /// compiled subset.
    Subset(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct YaraRegionRequest {
    pub pid: Pid,
    pub region: MemoryRegion,
    pub kind: YaraRegionRequestKind,
}

impl YaraRegionRequest {
    pub fn full(pid: Pid, region: MemoryRegion) -> Self {
        Self {
            pid,
            region,
            kind: YaraRegionRequestKind::FullRuleSet,
        }
    }

    pub fn in_memory(pid: Pid, region: MemoryRegion) -> Self {
        Self {
            pid,
            region,
            kind: YaraRegionRequestKind::InMemoryOnly,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_scan::regions::MemoryProtection;

    #[test]
    fn full_request_round_trips() {
        let req = YaraRegionRequest::full(
            Pid(4321),
            MemoryRegion {
                base: 0x10000,
                size: 0x1000,
                protection: MemoryProtection::READ | MemoryProtection::EXECUTE,
                mapped_path: None,
            },
        );
        assert_eq!(req.pid, Pid(4321));
        assert_eq!(req.kind, YaraRegionRequestKind::FullRuleSet);
    }

    #[test]
    fn in_memory_request_distinct_kind() {
        let req = YaraRegionRequest::in_memory(
            Pid(1),
            MemoryRegion {
                base: 0x20000,
                size: 0x2000,
                protection: MemoryProtection::READ
                    | MemoryProtection::WRITE
                    | MemoryProtection::EXECUTE,
                mapped_path: None,
            },
        );
        assert_eq!(req.kind, YaraRegionRequestKind::InMemoryOnly);
    }

    #[test]
    fn subset_kind_carries_id() {
        let req = YaraRegionRequest {
            pid: Pid(2),
            region: MemoryRegion {
                base: 0,
                size: 0,
                protection: MemoryProtection::READ,
                mapped_path: None,
            },
            kind: YaraRegionRequestKind::Subset(42),
        };
        assert_eq!(req.kind, YaraRegionRequestKind::Subset(42));
    }
}
