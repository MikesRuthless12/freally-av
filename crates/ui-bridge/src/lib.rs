//! Mythodikal Anti-Virus Tauri command bridge.
//!
//! Re-exports `#[tauri::command]` wrappers from `commands` and IPC types from
//! `types`. Phase 0 / TASK-004 ships stubs; commands are filled in by TASK-028
//! (Phase 3) and extended by TASK-130/131/132 (Phase 4) and TASK-156/157/158.

#![allow(dead_code)]

pub mod commands;
pub mod types;
