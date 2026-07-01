//! `freallyd-macos` library surface (Phase 9 + Phase 8 Wave 2 USB).
//!
//! macOS real-time lands in Phase 9 (TASK-079..083 Wave 1,
//! TASK-251..255 Wave 2); the Wave 2 USB plumbing has its
//! **cross-platform** portion in `freallykernel::usb::*` and its
//! macOS-specific glue here.
//!
//! Per `docs/prd.md` § 1.5.4: NOTIFY-only on macOS. No
//! `com.apple.developer.endpoint-security.client` entitlement — that
//! requires the paid Apple Developer Program forbidden by § 1.5.
//! Phase 9 wires FSEvents as the primary surface; ESF NOTIFY layers
//! opportunistically on top when the system extension loads without
//! an entitlement.

#![allow(dead_code)]

/// FSEvents ↔ ESF NOTIFY failover (TASK-252).
pub mod esf_failover;
/// Opportunistic ESF NOTIFY system extension wrapper (TASK-080).
pub mod esf_notify;
/// Per-app real-time exemption store (Keychain-backed, TASK-253).
pub mod exemption_keychain;
/// FSEvents listener (TASK-079) — primary mac real-time surface.
pub mod fsevents;
/// launchd heartbeat / watchdog (TASK-254).
pub mod launchd;
pub mod rules;
pub mod usb;
pub mod usb_ro;
