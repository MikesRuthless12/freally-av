//! Cross-platform USB / removable-media surface (TASK-241..250,
//! Phase 8 Wave 2).
//!
//! Owns the **shared types + pure logic** every per-OS daemon
//! consumes:
//!
//!  * [`UsbInsertEvent`] / [`UsbInterface`] — the unified shape per-OS
//!    listeners (udev / IOKit / SetupDi) fold into. Lives here so the
//!    engine's USB-insert auto-scan never branches on the source OS.
//!  * [`UsbWatcher`] — the trait every per-OS listener implements.
//!  * [`allowlist`] — VID:PID:Serial allowlist (TASK-242).
//!  * [`hid_anomaly`] — BadUSB composite-device detector (TASK-243).
//!  * [`power_only`] — per-port "power-only" toggle store (TASK-244).
//!  * [`autorun`] — `autorun.inf` reader + finding shape (TASK-246).
//!  * [`rtl_override`] — RTL-override hidden-exec heuristic (TASK-248).
//!  * [`write_log`] — removable-volume write event log (TASK-249).
//!  * [`device_history`] — per-device first-/last-seen + scan-count
//!    history (TASK-250).
//!
//! Per § 1.5.4 every listener is **read-only / user-mode** — no
//! kernel driver, no filter driver. The daemon side just observes
//! device arrivals and prompts the user; the engine decides.

pub mod allowlist;
pub mod autorun;
pub mod device_history;
pub mod hid_anomaly;
pub mod power_only;
pub mod rtl_override;
pub mod write_log;

use serde::{Deserialize, Serialize};

/// One USB interface descriptor as seen by the OS-level enumerator.
/// `bInterfaceClass` and `bInterfaceProtocol` are the canonical USB
/// spec bytes; `interface_id` is the OS's stable identifier for the
/// interface (sysfs path on Linux, IOService entry id on macOS,
/// SetupDi instance id on Windows).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbInterface {
    pub interface_id: String,
    /// USB `bInterfaceClass` byte.
    pub class: u8,
    /// USB `bInterfaceSubClass` byte.
    pub subclass: u8,
    /// USB `bInterfaceProtocol` byte.
    pub protocol: u8,
    /// Unix milliseconds when the interface enumerated. Used by the
    /// BadUSB detector's 2 s window check (TASK-243).
    pub enumerated_at_ms: i64,
}

impl UsbInterface {
    pub const CLASS_HID: u8 = 0x03;
    pub const CLASS_MASS_STORAGE: u8 = 0x08;
    /// HID protocol byte for a keyboard (`bInterfaceProtocol = 1`).
    pub const HID_PROTO_KEYBOARD: u8 = 0x01;
}

/// One device-arrival event the engine consumes. Cross-platform shape
/// — per-OS listeners fold their native event into this struct via
/// the [`UsbWatcher`] trait.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbInsertEvent {
    /// Vendor id as a 4-char lowercase hex string ("0951" for
    /// Kingston). String form keeps comparisons trivial and avoids
    /// per-OS numeric width drama.
    pub vid: String,
    pub pid: String,
    pub serial: String,
    /// Human label (e.g. "Kingston DataTraveler 3.0"). Optional —
    /// some USB devices return an empty descriptor.
    pub label: Option<String>,
    /// Mountpoint exposed to the OS, if the device exposes any
    /// filesystem. None for keyboards / charging-only devices.
    pub mountpoint: Option<String>,
    /// Bus + port location string (e.g. "1-3.2" on Linux, "AppleUSB
    /// .../Hub@1d100000" on macOS, "USB\\VID_0951...\\0" on Windows).
    /// Used by the per-port power-only store (TASK-244).
    pub port_path: String,
    pub interfaces: Vec<UsbInterface>,
    /// Unix milliseconds when the daemon first surfaced the device.
    pub first_seen_ms: i64,
}

/// Trait every per-OS listener implements. The daemon side owns a
/// concrete listener; the engine side consumes the event channel via
/// `UsbInsertEvent` only.
pub trait UsbWatcher: Send + Sync {
    /// Starts the listener and returns a channel the caller can read
    /// `UsbInsertEvent`s from. The channel closes when [`UsbWatcher::stop`]
    /// is called.
    fn start(&mut self) -> Result<std::sync::mpsc::Receiver<UsbInsertEvent>, UsbWatcherError>;
    fn stop(&mut self);
}

/// Error every per-OS listener returns.
#[derive(Debug, thiserror::Error)]
pub enum UsbWatcherError {
    #[error("not supported on this host (listener requires {0})")]
    Unsupported(&'static str),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("backend: {0}")]
    Backend(String),
}

/// Default insert-event coalesce window. Multi-interface composite
/// USB devices enumerate their interfaces one at a time over a few
/// hundred milliseconds; without coalescing the same device emits a
/// `UsbInsertEvent` per interface. 500 ms folds the typical composite
/// enumeration into one event (TASK-241).
pub const DEFAULT_DEBOUNCE_MS: i64 = 500;

/// Coalesces a stream of raw single-interface events into one event
/// per `(vid, pid, serial)` within `window_ms`. Pure helper so each
/// per-OS daemon can plug its native event source through the same
/// debouncer.
pub fn coalesce_events(
    raw: impl Iterator<Item = UsbInsertEvent>,
    window_ms: i64,
) -> Vec<UsbInsertEvent> {
    let mut out: Vec<UsbInsertEvent> = Vec::new();
    'event: for ev in raw {
        for existing in out.iter_mut() {
            let same =
                existing.vid == ev.vid && existing.pid == ev.pid && existing.serial == ev.serial;
            let within_window = ev.first_seen_ms - existing.first_seen_ms <= window_ms;
            if same && within_window {
                // Merge interfaces, preserve earliest first_seen_ms,
                // pull in the late-arriving mountpoint if any.
                existing.interfaces.extend(ev.interfaces.into_iter());
                if existing.mountpoint.is_none() && ev.mountpoint.is_some() {
                    existing.mountpoint = ev.mountpoint;
                }
                if existing.label.is_none() && ev.label.is_some() {
                    existing.label = ev.label;
                }
                continue 'event;
            }
        }
        out.push(ev);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(vid: &str, pid: &str, serial: &str, ifc: u8, t: i64) -> UsbInsertEvent {
        UsbInsertEvent {
            vid: vid.into(),
            pid: pid.into(),
            serial: serial.into(),
            label: None,
            mountpoint: None,
            port_path: "1-1".into(),
            interfaces: vec![UsbInterface {
                interface_id: format!("{ifc}"),
                class: ifc,
                subclass: 0,
                protocol: 0,
                enumerated_at_ms: t,
            }],
            first_seen_ms: t,
        }
    }

    #[test]
    fn coalesce_merges_composite_within_window() {
        let raw = vec![
            ev("0951", "1665", "AABB", UsbInterface::CLASS_HID, 100),
            ev(
                "0951",
                "1665",
                "AABB",
                UsbInterface::CLASS_MASS_STORAGE,
                250,
            ),
        ];
        let folded = coalesce_events(raw.into_iter(), DEFAULT_DEBOUNCE_MS);
        assert_eq!(folded.len(), 1);
        assert_eq!(folded[0].interfaces.len(), 2);
        // first_seen_ms is the earliest of the two.
        assert_eq!(folded[0].first_seen_ms, 100);
    }

    #[test]
    fn coalesce_keeps_distinct_devices_separate() {
        let raw = vec![
            ev("0951", "1665", "AAAA", UsbInterface::CLASS_HID, 0),
            ev("0951", "1665", "BBBB", UsbInterface::CLASS_HID, 0),
        ];
        let folded = coalesce_events(raw.into_iter(), DEFAULT_DEBOUNCE_MS);
        assert_eq!(folded.len(), 2);
    }

    #[test]
    fn coalesce_does_not_merge_outside_window() {
        let raw = vec![
            ev("0951", "1665", "AABB", UsbInterface::CLASS_HID, 0),
            ev(
                "0951",
                "1665",
                "AABB",
                UsbInterface::CLASS_MASS_STORAGE,
                DEFAULT_DEBOUNCE_MS + 10,
            ),
        ];
        let folded = coalesce_events(raw.into_iter(), DEFAULT_DEBOUNCE_MS);
        // The late storage interface is treated as a re-insert.
        assert_eq!(folded.len(), 2);
    }
}
