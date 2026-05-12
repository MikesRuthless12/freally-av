//! Mythodikal Anti-Virus engine core (`mythkernel`).
//!
//! Module structure mirrors `docs/prd.md` § 2.3. Most modules are stubs in
//! Phase 0 / TASK-004 and are filled in by later tasks (TASK-009 onward).

#![allow(dead_code)]

pub mod config;
pub mod db;
pub mod engine;
pub mod error;
pub mod eta;
pub mod exclusions;
pub mod findings;
pub mod hasher;
pub mod history;
pub mod logging;
pub mod quarantine;
pub mod scan;
pub mod scheduler;
pub mod sysload;
pub mod telemetry;
pub mod throttle;

pub mod detect;
pub mod ipc;
pub mod realtime;
pub mod updater;
pub mod walker;

pub use error::EngineError;
