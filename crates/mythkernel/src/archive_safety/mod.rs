//! Archive-safety module (Phase 10 Wave 2 — TASK-280..285).
//!
//! Defense-in-depth checks that wrap the existing archive walker
//! (`archive_scan`) with explicit safety primitives:
//!
//!   * `bomb_guard` — compression-ratio cap (TASK-281)
//!   * `password`   — encrypted-entry surfacing (TASK-282)
//!   * `magic`      — extended-format magic-byte sniffer
//!                    (TASK-283 — 7z / rar / dmg / iso / udf /
//!                    vhdx / wim / tar.zst / tar.xz)
//!   * `recursion`  — nested-archive recursion-depth limit
//!                    (TASK-284)
//!   * `sfx`        — self-extracting PE heuristic (TASK-285)
//!   * `detonate`   — opt-in detonate-in-VM coordination stub
//!                    (TASK-280)
//!
//! Every check is pure-logic over caller-supplied bytes /
//! metadata so the engine can chain them in any order. The
//! existing native ZIP path in `archive_scan` already enforces
//! per-entry byte caps; this module adds the ratio + depth +
//! magic dimensions without disturbing that hot path.

pub mod bomb_guard;
pub mod detonate;
pub mod magic;
pub mod password;
pub mod recursion;
pub mod sfx;

pub use bomb_guard::{is_zip_bomb_ratio, BombFinding, BombGuardConfig};
pub use detonate::{DetonationDecision, DetonationPolicy};
pub use magic::{detect_archive_kind, ExtendedArchiveKind};
pub use password::{is_encrypted_zip_entry, PasswordFinding};
pub use recursion::{ArchiveDepthGuard, DepthExceededError};
pub use sfx::{detect_sfx, SfxFinding, SfxKind};
