//! `mythd-macos` library surface (Phase 9 stub + Phase 8 Wave 2 USB).
//!
//! macOS real-time landing in Phase 9 (TASK-079..083); the Wave 2 USB
//! plumbing (TASK-241/243/244/245/247/249) has its **cross-platform**
//! portion in `mythkernel::usb::*` and its macOS-specific glue here.
//!
//! Per `docs/prd.md` § 1.5.4: NOTIFY-only on macOS. No
//! `com.apple.developer.endpoint-security.client` entitlement — that
//! requires the paid Apple Developer Program forbidden by § 1.5.
//! Phase 9 wires FSEvents as the primary surface; this Phase 8 crate
//! exists so `cargo build --workspace` produces a `mythd` binary on
//! the macOS host that the USB / autorun.inf / .app-on-USB plumbing
//! can be wired into without a follow-up workspace edit.

#![allow(dead_code)]

pub mod rules;
pub mod usb;
pub mod usb_ro;
