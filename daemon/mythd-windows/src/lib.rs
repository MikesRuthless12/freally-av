//! `mythd-windows` library surface (Phase 12 scaffold + Phase 8 Wave 2 plumbing).
//!
//! Windows real-time (ETW + AMSI + WDAC + Defender bridge) lands in
//! Phase 12 (TASK-096..108). This Phase-8 crate ships the
//! cross-platform USB watcher (TASK-241..250) glue + the WSL bridge
//! (TASK-240) so `cargo build --workspace` produces a `mythd` binary
//! on Windows hosts at the Phase-8 boundary.
//!
//! Per `docs/prd.md` § 1.5.4: **no kernel driver**. Every Windows
//! surface here is user-mode (`SetupDi*`, `RegisterDeviceNotification`,
//! `wsl.exe` shell-out). The "block-on-detected" decision on Windows
//! lands in Phase 12 via WDAC policy regeneration + Defender push,
//! **not** a Mythodikal kernel filter.

#![allow(dead_code)]

pub mod usb;
pub mod wsl_bridge;
