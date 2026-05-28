//! Per-process memory-sweep foundations (Phase 10 Wave 2 —
//! TASK-291..295).
//!
//! Daemon-side platform code (Windows `ReadProcessMemory`,
//! macOS `mach_vm_read`, Linux `process_vm_readv`) snapshots
//! the per-process region list and the page bytes themselves;
//! the engine consumes those snapshots through this module.
//!
//! Five detectors:
//!
//!   * `regions`     — `MemoryRegion` shape + suspicious-region
//!                     heuristic (TASK-292)
//!   * `yara_sweep`  — YARA pass over each region's bytes
//!                     (TASK-291 — composes the existing
//!                     `detect::yara_engine`)
//!   * `shellcode`   — pre-disassembly shape detector for
//!                     egg-hunter / GetPC / common Metasploit
//!                     prefixes (TASK-293)
//!   * `reflective`  — reflective-DLL detection (Windows)
//!                     (TASK-294)
//!   * `macho_load`  — in-memory Mach-O image detector
//!                     (TASK-295)
//!
//! Every check is pure-logic over caller-supplied bytes / metadata.
//! Read-only — no `WriteProcessMemory`, no `ptrace POKE`.

use serde::{Deserialize, Serialize};

pub mod macho_load;
pub mod reflective;
pub mod regions;
pub mod shellcode;
pub mod yara_sweep;

pub use macho_load::{MachOInMemoryFinding, is_macho_in_memory};
pub use reflective::{ReflectiveFinding, detect_reflective_dll};
pub use regions::{MemoryProtection, MemoryRegion, SuspiciousRegionFinding, is_suspicious_region};
pub use shellcode::{ShellcodeShape, ShellcodeShapeFinding, scan_shellcode_shapes};
pub use yara_sweep::{YaraRegionRequest, YaraRegionRequestKind};

/// Identifier the daemon uses to attribute findings back to a
/// process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Pid(pub u32);

impl Pid {
    pub fn raw(self) -> u32 {
        self.0
    }
}
