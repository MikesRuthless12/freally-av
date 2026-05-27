//! `mythd-linux` library surface.
//!
//! The binary at `bin/mythd` is a thin wrapper that wires the modules
//! below into a tokio runtime; this lib.rs exists so the unit tests
//! for each module run on every platform without depending on the
//! binary entry point.
//!
//! Phase 8 task coverage in this crate:
//!
//! | TASK    | Module                          |
//! |---------|---------------------------------|
//! | 073     | `fanotify`, `main.rs`           |
//! | 076     | `watchdog`, `../../packaging/`  |
//! | 077     | `inotify_fallback`              |
//! | 140     | `block`                         |
//! | 141     | `rules::browser_creds`          |
//! | 142     | `rules::honey`                  |
//! | 236     | `ebpf`                          |
//! | 237     | `audit`                         |
//! | 238     | `mounts`                        |
//! | 239     | `container_dedupe`              |
//! | 240     | `wsl_peer`                      |
//! | 241     | `usb`                           |
//! | 242     | (re-exports `mythkernel::usb::allowlist`) |
//! | 243     | (re-exports `mythkernel::usb::hid_anomaly`) |
//! | 244     | `usb::power_only_apply`         |
//! | 245     | `usb_ro`                        |
//! | 246–250 | (re-exports `mythkernel::usb::*`)|
//!
//! Per `docs/prd.md` § 1.5.4: no kernel driver, no LSM hooks. Every
//! Linux syscall surface (fanotify, inotify, audit, eBPF, udev) is
//! `#[cfg(target_os = "linux")]`-gated; on other hosts the modules
//! compile but their `start()` returns `Unsupported`.

#![allow(dead_code)]

pub mod audit;
pub mod block;
pub mod container_dedupe;
pub mod ebpf;
pub mod fanotify;
pub mod inotify_fallback;
pub mod ipc_client;
pub mod mounts;
pub mod rules;
pub mod usb;
pub mod usb_ro;
pub mod watchdog;
pub mod wsl_peer;
