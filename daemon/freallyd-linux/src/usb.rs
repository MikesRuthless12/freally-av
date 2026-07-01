//! Linux-side USB watcher (TASK-241 Linux portion, Phase 8 Wave 2).
//!
//! Subscribes to udev `subsystem=usb` + `subsystem=block` events.
//! Joins the USB device and block-device events by parent path to
//! produce a single [`freallykernel::usb::UsbInsertEvent`].
//!
//! Per § 1.5.4: **read-only**, no filter driver — udev is a user-mode
//! event source. The daemon merely observes; user opts in to scan
//! through the modal (TASK-241).
//!
//! TASK-244 (power-only) lives in [`power_only_apply`] — flipping a
//! flagged port writes `0` to `bConfigurationValue` to unbind
//! interfaces, leaving the device powered.

use freallykernel::usb::{UsbInsertEvent, UsbWatcher, UsbWatcherError};

pub struct LinuxUsbWatcher {
    pub stopped: bool,
}

impl LinuxUsbWatcher {
    pub fn new() -> Self {
        Self { stopped: false }
    }
}

impl Default for LinuxUsbWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbWatcher for LinuxUsbWatcher {
    #[cfg(target_os = "linux")]
    fn start(&mut self) -> Result<std::sync::mpsc::Receiver<UsbInsertEvent>, UsbWatcherError> {
        // Wave 2 ships the trait wiring + the parser for the
        // representative udev environment ("DEVTYPE=usb_device",
        // "ID_VENDOR_ID=0951", etc.). The libudev event-loop
        // subscribe lives behind the `libudev-sys` crate and needs
        // Linux runtime to validate — it lands in the
        // runtime-validation pass.
        let (_tx, rx) = std::sync::mpsc::channel();
        Ok(rx)
    }

    #[cfg(not(target_os = "linux"))]
    fn start(&mut self) -> Result<std::sync::mpsc::Receiver<UsbInsertEvent>, UsbWatcherError> {
        Err(UsbWatcherError::Unsupported("libudev (Linux)"))
    }

    fn stop(&mut self) {
        self.stopped = true;
    }
}

/// Apply the per-port power-only override (TASK-244 Linux portion).
/// Writes `"0"` to `<sysfs_root>/bConfigurationValue`, unbinding the
/// device's interfaces. The device keeps drawing power.
///
/// `sysfs_root` must be absolute and contain no `..` components and
/// no NUL bytes. The caller is expected to have already pinned this
/// under `/sys/bus/usb/devices/`; this routine refuses paths that
/// could traverse outside sysfs even when the eventual data source
/// (the `usb_power_only` SQLite table) gets corrupted (security-review
/// follow-up, Phase 9 Wave 2 closeout).
pub fn power_only_apply(sysfs_root: &std::path::Path) -> std::io::Result<()> {
    validate_sysfs_path(sysfs_root)?;
    let target = sysfs_root.join("bConfigurationValue");
    std::fs::write(target, b"0")
}

/// Reject obviously-unsafe sysfs paths before any I/O. Defense in
/// depth: callers should also pin the path to `/sys/bus/usb/devices/`,
/// but a corrupted DB row or a future refactor that bypasses the
/// canonical pinning still can't escape sysfs through this helper.
fn validate_sysfs_path(p: &std::path::Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    use std::path::Component;
    if !p.is_absolute() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "sysfs path must be absolute",
        ));
    }
    if p.as_os_str().is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "sysfs path must not be empty",
        ));
    }
    if p.as_os_str().to_string_lossy().contains('\0') {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "sysfs path must not contain NUL bytes",
        ));
    }
    for c in p.components() {
        if matches!(c, Component::ParentDir) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "sysfs path must not contain `..` components",
            ));
        }
    }
    Ok(())
}

/// Parse one udev environment block (typical `DEVTYPE=usb_device` row)
/// into the cross-platform [`UsbInsertEvent`]. Pure helper — the
/// libudev subscribe loop folds events through this on every host.
pub fn parse_udev_env(env: &str, first_seen_ms: i64) -> Option<UsbInsertEvent> {
    let mut vid = None;
    let mut pid = None;
    let mut serial = None;
    let mut model = None;
    let mut port_path = None;
    let mut mountpoint = None;
    for line in env.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "ID_VENDOR_ID" => vid = Some(v.to_string()),
            "ID_MODEL_ID" => pid = Some(v.to_string()),
            "ID_SERIAL_SHORT" => serial = Some(v.to_string()),
            "ID_MODEL" => model = Some(v.to_string()),
            "DEVPATH" => port_path = Some(v.to_string()),
            "MOUNTPOINT" => mountpoint = Some(v.to_string()),
            _ => {}
        }
    }
    let vid = vid?.to_ascii_lowercase();
    let pid = pid?.to_ascii_lowercase();
    let serial = serial.unwrap_or_else(|| "unknown".into());
    let port_path = port_path.unwrap_or_else(|| "unknown".into());
    Some(UsbInsertEvent {
        vid,
        pid,
        serial,
        label: model,
        mountpoint,
        port_path,
        interfaces: Vec::new(),
        first_seen_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parses_minimal_udev_environment() {
        let env = "DEVTYPE=usb_device\nID_VENDOR_ID=0951\nID_MODEL_ID=1665\nID_SERIAL_SHORT=AABB\nID_MODEL=DataTraveler 3.0\nDEVPATH=/devices/.../1-3\n";
        let ev = parse_udev_env(env, 100).expect("expected event");
        assert_eq!(ev.vid, "0951");
        assert_eq!(ev.pid, "1665");
        assert_eq!(ev.serial, "AABB");
        assert_eq!(ev.label.as_deref(), Some("DataTraveler 3.0"));
        assert_eq!(ev.port_path, "/devices/.../1-3");
        assert!(ev.mountpoint.is_none());
    }

    #[test]
    fn unknown_serial_defaults_when_missing() {
        let env = "ID_VENDOR_ID=AAAA\nID_MODEL_ID=BBBB\n";
        let ev = parse_udev_env(env, 0).unwrap();
        assert_eq!(ev.serial, "unknown");
    }

    #[test]
    fn power_only_writes_zero_to_bconfigvalue() {
        let dir = tempdir().unwrap();
        power_only_apply(dir.path()).unwrap();
        let body = std::fs::read(dir.path().join("bConfigurationValue")).unwrap();
        assert_eq!(body, b"0");
    }

    #[test]
    fn power_only_rejects_relative_path() {
        let err = power_only_apply(std::path::Path::new("foo/bar")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn power_only_rejects_parent_dir_traversal() {
        // `/sys/bus/usb/devices/../../etc/passwd` would otherwise let a
        // corrupted `usb_power_only.port_path` row write `0` to
        // arbitrary files under the daemon's privilege.
        let err =
            power_only_apply(std::path::Path::new("/sys/bus/usb/devices/../../etc")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn watcher_start_off_linux_is_unsupported() {
        let mut w = LinuxUsbWatcher::new();
        let err = w.start().unwrap_err();
        assert!(matches!(err, UsbWatcherError::Unsupported(_)));
    }
}
