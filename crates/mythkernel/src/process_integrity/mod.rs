//! Process-integrity detectors (Phase 10 Wave 2 — TASK-296..300;
//! Wave 3 — TASK-301..305).
//!
//! Wave 2 (per-process integrity at exec / death time):
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
//! Wave 3 (per-process forensic surface):
//!
//!   * `net_counters`      — per-pid network byte counters
//!                           + rate computation (TASK-301)
//!   * `io_counters`       — per-pid file-write counters
//!                           + heavy-writer threshold (TASK-302)
//!   * `ancestry`          — PPID chain walker + first-
//!                           observation cache (TASK-303)
//!   * `env_audit`         — suspicious env-var detector
//!                           (TASK-304, Linux + macOS)
//!   * `dll_search_order`  — DLL search-hijack detector
//!                           (TASK-305, Windows)
//!
//! Pure-logic — daemon-side platform code feeds the structs.

pub mod ancestry;
pub mod autopsy;
pub mod core_dump;
pub mod dll_search_order;
pub mod env_audit;
pub mod hollowing;
pub mod image_hash;
pub mod io_counters;
pub mod net_counters;
pub mod thread_hijack;

pub use ancestry::{AncestryCache, AncestryChain, ProcessNode, build_chain};
pub use autopsy::{AutopsyEntry, AutopsyLog, ExitReason};
pub use core_dump::{CoreDumpYaraRequest, CoreDumpYaraVerdict};
pub use dll_search_order::{
    DllHijackFinding, DllSearchContext, LoadedModule, evaluate as evaluate_dll_search,
};
pub use env_audit::{EnvAuditFinding, EnvAuditKind, audit as audit_env};
pub use hollowing::{HollowingFinding, HollowingReason, detect_hollowing};
pub use image_hash::{ImageHashFinding, ImageHashStatus, evaluate_image_hash};
pub use io_counters::{
    DEFAULT_DAILY_WRITE_ALERT_BYTES, HeavyWriterFinding, IoCounterSnapshot,
    evaluate as evaluate_heavy_writer, is_system_writer,
};
pub use net_counters::{NetCounterRate, NetCounterSnapshot, rate as net_counter_rate};
pub use thread_hijack::{ThreadHijackFinding, detect_hijacked_thread};
