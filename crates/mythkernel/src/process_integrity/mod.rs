//! Process-integrity detectors (Phase 10 Wave 2 — TASK-296..300).
//!
//! Five complementary checks running over caller-supplied
//! per-process snapshots:
//!
//!   * `hollowing`     — process-hollowing detector (TASK-296)
//!   * `thread_hijack` — hijacked thread-start detector
//!                       (TASK-297)
//!   * `image_hash`    — per-process image-hash integrity
//!                       (TASK-298)
//!   * `autopsy`       — killed-process autopsy log shape +
//!                       ring-buffer (TASK-299)
//!   * `core_dump`     — crashed-process core-dump YARA pass
//!                       (TASK-300)
//!
//! Pure-logic — daemon-side platform code feeds the structs.

pub mod autopsy;
pub mod core_dump;
pub mod hollowing;
pub mod image_hash;
pub mod thread_hijack;

pub use autopsy::{AutopsyEntry, AutopsyLog, ExitReason};
pub use core_dump::{CoreDumpYaraRequest, CoreDumpYaraVerdict};
pub use hollowing::{HollowingFinding, HollowingReason, detect_hollowing};
pub use image_hash::{ImageHashFinding, ImageHashStatus, evaluate_image_hash};
pub use thread_hijack::{ThreadHijackFinding, detect_hijacked_thread};
