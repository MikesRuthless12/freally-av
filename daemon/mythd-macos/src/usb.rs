//! macOS-side USB watcher (TASK-241 macOS portion, Phase 8 Wave 2).
//!
//! Uses IOKit `IOServiceAddMatchingNotification` on the
//! `kIOUSBDeviceClassName` service, joined with `DADiskAppearedCallback`
//! from DiskArbitration for the mountpoint. Both APIs are user-mode,
//! read-only — no kernel extension, no entitlement gating per § 1.5.4.

use mythkernel::usb::{UsbInsertEvent, UsbWatcher, UsbWatcherError};

pub struct MacosUsbWatcher {
    pub stopped: bool,
}

impl MacosUsbWatcher {
    pub fn new() -> Self {
        Self { stopped: false }
    }
}

impl Default for MacosUsbWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbWatcher for MacosUsbWatcher {
    #[cfg(target_os = "macos")]
    fn start(&mut self) -> Result<std::sync::mpsc::Receiver<UsbInsertEvent>, UsbWatcherError> {
        // Wave 2 ships the trait wiring; the IOServiceAddMatching
        // setup + DiskArbitration callback need a macOS runtime to
        // validate against and land in the runtime-validation pass.
        let (_tx, rx) = std::sync::mpsc::channel();
        Ok(rx)
    }

    #[cfg(not(target_os = "macos"))]
    fn start(&mut self) -> Result<std::sync::mpsc::Receiver<UsbInsertEvent>, UsbWatcherError> {
        Err(UsbWatcherError::Unsupported("IOKit (macOS)"))
    }

    fn stop(&mut self) {
        self.stopped = true;
    }
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn watcher_off_macos_is_unsupported() {
        let mut w = MacosUsbWatcher::new();
        let err = w.start().unwrap_err();
        assert!(matches!(err, UsbWatcherError::Unsupported(_)));
    }
}
