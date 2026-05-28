//! Mythodikal Anti-Virus Tauri command bridge.
//!
//! Re-exports `#[tauri::command]` wrappers from `commands` and IPC types from
//! `types`. Phase 0 / TASK-004 ships stubs; commands are filled in by TASK-028
//! (Phase 3) and extended by TASK-130/131/132 (Phase 4) and TASK-156/157/158.

#![allow(dead_code)]

pub mod commands;
/// Phase 9 Wave 2 — macOS-specific commands: per-app exemptions
/// (TASK-253) + launchd heartbeat (TASK-254).
pub mod commands_mac;
/// Phase 8 Wave 2 — per-mount real-time toggle (TASK-238).
pub mod commands_mount;
/// Phase 8 Wave 2 — USB stack Tauri commands (TASK-242/244/249/250).
pub mod commands_usb;
pub mod types;
