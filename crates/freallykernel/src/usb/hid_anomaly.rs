//! BadUSB HID anomaly detector (TASK-243, Phase 8 Wave 2, FR — § 1.5.4).
//!
//! Flags composite USB devices that enumerate **both** a HID-keyboard
//! interface (`class 0x03`, `protocol 0x01`) AND a mass-storage
//! interface (`class 0x08`) within a 2 s window. That shape matches
//! USB Rubber-Ducky-style attack devices that pose as a flash drive
//! while typing keystrokes.
//!
//! Per § 1.5.4 the verdict is **alert-only** — the daemon never
//! disables the keyboard or unmounts the volume. The user confirms
//! via the modal (TASK-241) and either trusts the device (TASK-242
//! allowlist) or quarantines.
//!
//! Allowlisted (TASK-242) devices skip the check entirely — the
//! caller passes `is_allowlisted` so this module stays decoupled
//! from rusqlite.

use crate::usb::{UsbInsertEvent, UsbInterface};

/// Default HID + mass-storage co-enumeration window. Composite USB
/// devices typically enumerate within a few hundred milliseconds; 2 s
/// is the spec ceiling.
pub const DEFAULT_WINDOW_MS: i64 = 2_000;

/// One BadUSB finding shape — returned by [`inspect`] when an event
/// trips the heuristic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadUsbHidShape {
    pub vid: String,
    pub pid: String,
    pub serial: String,
    pub keyboard_ms: i64,
    pub storage_ms: i64,
    pub gap_ms: i64,
}

/// Inspect one `event` for the BadUSB composite shape. Returns
/// `Some(BadUsbHidShape)` when the device exposes both a
/// HID-keyboard interface and a mass-storage interface within
/// `window_ms` of each other. `None` otherwise.
pub fn inspect(event: &UsbInsertEvent, window_ms: i64) -> Option<BadUsbHidShape> {
    let mut kbd_ms: Option<i64> = None;
    let mut storage_ms: Option<i64> = None;
    for ifc in &event.interfaces {
        let is_kbd = ifc.class == UsbInterface::CLASS_HID
            && ifc.protocol == UsbInterface::HID_PROTO_KEYBOARD;
        let is_storage = ifc.class == UsbInterface::CLASS_MASS_STORAGE;
        if is_kbd && kbd_ms.is_none_or(|t| ifc.enumerated_at_ms < t) {
            kbd_ms = Some(ifc.enumerated_at_ms);
        }
        if is_storage && storage_ms.is_none_or(|t| ifc.enumerated_at_ms < t) {
            storage_ms = Some(ifc.enumerated_at_ms);
        }
    }
    let (k, s) = (kbd_ms?, storage_ms?);
    let gap = (k - s).abs();
    if gap <= window_ms {
        Some(BadUsbHidShape {
            vid: event.vid.clone(),
            pid: event.pid.clone(),
            serial: event.serial.clone(),
            keyboard_ms: k,
            storage_ms: s,
            gap_ms: gap,
        })
    } else {
        None
    }
}

/// Wrapper that consults an allowlist closure first; returns `None`
/// if the device is allowlisted regardless of shape.
pub fn inspect_with_allowlist<F>(
    event: &UsbInsertEvent,
    window_ms: i64,
    is_allowlisted: F,
) -> Option<BadUsbHidShape>
where
    F: FnOnce(&UsbInsertEvent) -> bool,
{
    if is_allowlisted(event) {
        return None;
    }
    inspect(event, window_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::UsbInterface;

    fn ifc(class: u8, proto: u8, t: i64) -> UsbInterface {
        UsbInterface {
            interface_id: format!("if{class}{proto}"),
            class,
            subclass: 0,
            protocol: proto,
            enumerated_at_ms: t,
        }
    }

    fn ev(interfaces: Vec<UsbInterface>) -> UsbInsertEvent {
        UsbInsertEvent {
            vid: "0951".into(),
            pid: "1665".into(),
            serial: "AABB".into(),
            label: None,
            mountpoint: None,
            port_path: "1-1".into(),
            interfaces,
            first_seen_ms: 0,
        }
    }

    #[test]
    fn keyboard_only_no_finding() {
        let event = ev(vec![ifc(
            UsbInterface::CLASS_HID,
            UsbInterface::HID_PROTO_KEYBOARD,
            0,
        )]);
        assert!(inspect(&event, DEFAULT_WINDOW_MS).is_none());
    }

    #[test]
    fn storage_only_no_finding() {
        let event = ev(vec![ifc(UsbInterface::CLASS_MASS_STORAGE, 0, 0)]);
        assert!(inspect(&event, DEFAULT_WINDOW_MS).is_none());
    }

    #[test]
    fn keyboard_plus_storage_within_window_fires() {
        let event = ev(vec![
            ifc(
                UsbInterface::CLASS_HID,
                UsbInterface::HID_PROTO_KEYBOARD,
                100,
            ),
            ifc(UsbInterface::CLASS_MASS_STORAGE, 0, 250),
        ]);
        let f = inspect(&event, DEFAULT_WINDOW_MS).expect("expected finding");
        assert_eq!(f.gap_ms, 150);
    }

    #[test]
    fn outside_window_does_not_fire() {
        let event = ev(vec![
            ifc(UsbInterface::CLASS_HID, UsbInterface::HID_PROTO_KEYBOARD, 0),
            ifc(UsbInterface::CLASS_MASS_STORAGE, 0, DEFAULT_WINDOW_MS + 50),
        ]);
        assert!(inspect(&event, DEFAULT_WINDOW_MS).is_none());
    }

    #[test]
    fn allowlisted_device_skips_check() {
        let event = ev(vec![
            ifc(
                UsbInterface::CLASS_HID,
                UsbInterface::HID_PROTO_KEYBOARD,
                100,
            ),
            ifc(UsbInterface::CLASS_MASS_STORAGE, 0, 250),
        ]);
        let out = inspect_with_allowlist(&event, DEFAULT_WINDOW_MS, |_| true);
        assert!(out.is_none());
        let out = inspect_with_allowlist(&event, DEFAULT_WINDOW_MS, |_| false);
        assert!(out.is_some());
    }

    #[test]
    fn hid_non_keyboard_does_not_fire() {
        let event = ev(vec![
            // HID mouse — class 0x03, protocol 0x02 — should NOT trip.
            ifc(UsbInterface::CLASS_HID, 0x02, 100),
            ifc(UsbInterface::CLASS_MASS_STORAGE, 0, 250),
        ]);
        assert!(inspect(&event, DEFAULT_WINDOW_MS).is_none());
    }
}
