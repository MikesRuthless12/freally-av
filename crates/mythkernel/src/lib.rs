//! Mythodikal Anti-Virus engine core (`mythkernel`).
//!
//! Module structure mirrors `docs/prd.md` § 2.3. Most modules are stubs in
//! Phase 0 / TASK-004 and are filled in by later tasks (TASK-009 onward).

#![allow(dead_code)]

pub mod archive_scan;
pub mod config;
pub mod db;
pub mod engine;
pub mod error;
pub mod eta;
pub mod exclusions;
pub mod findings;
pub mod hasher;
pub mod heuristics_scan;
pub mod history;
pub mod logging;
pub mod process_scan;
pub mod quarantine;
pub mod registry_scan;
pub mod scan;
pub mod scheduler;
pub mod sysload;
pub mod telemetry;
pub mod throttle;

pub mod detect;
/// Phase 9 Wave 2 — per-app real-time exemption registry (TASK-253).
/// macOS backend is Keychain-backed and biometric-gated; the
/// cross-platform shape and in-memory registry live here.
pub mod exempt;
pub mod ipc;
pub mod platform;
pub mod realtime;
pub mod updater;
/// Phase 8 Wave 2 — cross-platform USB / removable-media surface
/// (TASK-241..250). Per-OS daemon glue (udev / IOKit / SetupDi) lives
/// under `daemon/mythd-{linux,macos,windows}/src/usb.rs`; the shared
/// types, allowlist, BadUSB detector, RTL-override heuristic, and
/// per-device scan history all live here.
pub mod usb;
pub mod walker;

pub use error::EngineError;
