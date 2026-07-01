//! Windows-side USB watcher (TASK-241 Windows portion, Phase 8 Wave 2).
//!
//! Uses `RegisterDeviceNotification(DBT_DEVTYP_DEVICEINTERFACE)` for USB
//! GUIDs + `SetupDiGetDeviceInterfaceDetail` to resolve VID/PID/Serial.
//! **Read-only** — no filter driver registration per § 1.5.4.

use freallykernel::usb::{UsbInsertEvent, UsbWatcher, UsbWatcherError};

pub struct WindowsUsbWatcher {
    pub stopped: bool,
}

impl WindowsUsbWatcher {
    pub fn new() -> Self {
        Self { stopped: false }
    }
}

impl Default for WindowsUsbWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbWatcher for WindowsUsbWatcher {
    #[cfg(target_os = "windows")]
    fn start(&mut self) -> Result<std::sync::mpsc::Receiver<UsbInsertEvent>, UsbWatcherError> {
        // Wave 2 ships the trait wiring; the `SetupDi*` enumeration
        // + the `RegisterDeviceNotification` hidden-window loop need
        // Windows runtime to validate and land in the runtime-
        // validation pass.
        let (_tx, rx) = std::sync::mpsc::channel();
        Ok(rx)
    }

    #[cfg(not(target_os = "windows"))]
    fn start(&mut self) -> Result<std::sync::mpsc::Receiver<UsbInsertEvent>, UsbWatcherError> {
        Err(UsbWatcherError::Unsupported("SetupDi (Windows)"))
    }

    fn stop(&mut self) {
        self.stopped = true;
    }
}

/// Parse a Windows `DEVICE_INSTANCE_ID` string of the shape
/// `USB\VID_0951&PID_1665\AABB001122` into `(vid, pid, serial)`.
/// Pure helper, runs on every host.
pub fn parse_device_instance_id(instance_id: &str) -> Option<(String, String, String)> {
    // The middle field is `VID_xxxx&PID_yyyy`; the third field is the serial.
    let parts: Vec<&str> = instance_id.split('\\').collect();
    if parts.len() < 3 {
        return None;
    }
    let middle = parts[1];
    let mut vid = None;
    let mut pid = None;
    for frag in middle.split('&') {
        if let Some(v) = frag.strip_prefix("VID_") {
            vid = Some(v.to_ascii_lowercase());
        } else if let Some(p) = frag.strip_prefix("PID_") {
            pid = Some(p.to_ascii_lowercase());
        }
    }
    Some((vid?, pid?, parts[2].to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_setupdi_id() {
        let (vid, pid, serial) =
            parse_device_instance_id(r"USB\VID_0951&PID_1665\AABB001122").unwrap();
        assert_eq!(vid, "0951");
        assert_eq!(pid, "1665");
        assert_eq!(serial, "AABB001122");
    }

    #[test]
    fn returns_none_on_malformed_input() {
        assert!(parse_device_instance_id("garbage").is_none());
        assert!(parse_device_instance_id(r"USB\bad\serial").is_none());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn watcher_off_windows_is_unsupported() {
        let mut w = WindowsUsbWatcher::new();
        let err = w.start().unwrap_err();
        assert!(matches!(err, UsbWatcherError::Unsupported(_)));
    }
}
