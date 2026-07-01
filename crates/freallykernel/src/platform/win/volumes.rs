//! Windows volume detection + enumeration (TASK-052).
//!
//! Wraps `FindFirstVolumeW` / `FindNextVolumeW` / `GetVolumePathNamesForVolumeNameW`
//! / `GetVolumeInformationW` / `GetDriveTypeW` to surface every fixed and
//! removable volume on the host. Non-NTFS volumes are kept in the result so
//! the caller (TASK-053's [`crate::walker::multi_volume::MultiVolumeWalker`])
//! can pick `NtfsWalker` for NTFS and `PosixWalker` for everything else
//! (FAT32, exFAT, ReFS, network shares with no drive letter).
//!
//! Volumes without a mounted drive letter or path are skipped — they're
//! either system-reserved (recovery / EFI partitions exposed only via
//! `\\?\Volume{...}\`) or detached. The engine has no UI surface for those,
//! so they don't make it into the per-volume scan fan-out.

#![cfg(target_os = "windows")]

use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetDriveTypeW, GetVolumeInformationW,
    GetVolumePathNamesForVolumeNameW,
};
use windows::core::PCWSTR;

/// `GetDriveTypeW` numeric return values per MSDN. `windows-rs` 0.62
/// only re-exports these as integer constants under
/// `Win32::Storage::FileSystem` for some triples; mirror the canonical
/// values here so the file compiles uniformly.
const DRIVE_REMOVABLE: u32 = 2;

/// RAII wrapper around the `FindFirstVolumeW` search handle. Sec-review L4:
/// previous code closed the handle on the explicit error / EOF arms only,
/// so a panic during volume metadata extraction would leak it. Drop now
/// guarantees `FindVolumeClose` runs on every unwind path.
struct VolumeSearchHandle(HANDLE);

impl Drop for VolumeSearchHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `self.0` is a non-null search handle from
            // `FindFirstVolumeW`. `FindVolumeClose` on a valid handle is
            // documented as idempotent (a second close on the same handle
            // would EBADF, but our `is_invalid` gate prevents that).
            let _ = unsafe { FindVolumeClose(self.0) };
        }
    }
}

/// One volume on the host, after `enumerate_volumes()` has filtered it down
/// to "user-visible" status (has at least one mount path).
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    /// First user-visible mount path (e.g. `C:\`). Volumes mounted at
    /// multiple paths surface only their primary here; the full list is in
    /// [`Self::all_mount_paths`].
    pub mount_path: PathBuf,
    /// Every mount path the volume is reachable through. Always contains
    /// `mount_path` as the first element. Empty volumes (no mount) are
    /// excluded by `enumerate_volumes`.
    pub all_mount_paths: Vec<PathBuf>,
    /// Filesystem name reported by `GetVolumeInformationW` (e.g. `NTFS`,
    /// `FAT32`, `exFAT`, `ReFS`).
    pub fs_name: String,
    /// Serial number from `GetVolumeInformationW`. Same number the
    /// vendored journal subscriber uses to key its cursor file.
    pub serial: u32,
    /// True when `fs_name` is `"NTFS"`. The caller routes NTFS volumes
    /// through `NtfsWalker` and everything else through `PosixWalker`.
    pub is_ntfs: bool,
    /// True when `GetDriveTypeW` reports `DRIVE_REMOVABLE` for the
    /// primary mount path. USB sticks, SD cards.
    pub is_removable: bool,
}

/// Enumerate every volume the host exposes. Returns volumes that have at
/// least one user-visible mount path. Order is host-dependent (the order
/// `FindFirstVolumeW` / `FindNextVolumeW` returns them), not sorted.
pub fn enumerate_volumes() -> io::Result<Vec<VolumeInfo>> {
    let mut volumes: Vec<VolumeInfo> = Vec::new();
    let mut name_buf = vec![0u16; 256];

    // SAFETY: FindFirstVolumeW writes a NUL-terminated wide string into
    // name_buf and returns a search handle owned by the caller. The handle
    // is wrapped in `VolumeSearchHandle` immediately so a panic anywhere
    // in the loop still closes it via Drop (sec-review L4).
    let raw_handle = unsafe { FindFirstVolumeW(&mut name_buf) }.map_err(io::Error::other)?;
    let _search = VolumeSearchHandle(raw_handle);

    loop {
        if let Some(info) = volume_for_guid(&name_buf) {
            volumes.push(info);
        }

        // SAFETY: raw_handle is a non-null search handle from
        // FindFirstVolumeW (still owned by `_search`'s Drop).
        // FindNextVolumeW returns Err with ERROR_NO_MORE_FILES (18) when
        // the enumeration is exhausted; treat that as the loop terminator.
        let next = unsafe { FindNextVolumeW(raw_handle, &mut name_buf) };
        if let Err(e) = next {
            // ERROR_NO_MORE_FILES (18) = clean end of enumeration.
            // `_search`'s Drop closes the handle on every exit path including
            // the early `return Err(...)` below.
            if e.code().0 as u32 & 0xFFFF == 18 {
                break;
            }
            return Err(io::Error::other(e));
        }
    }

    Ok(volumes)
}

/// Resolve one `\\?\Volume{GUID}\`-style name into a [`VolumeInfo`].
/// Returns `None` for volumes without a mounted drive letter / path
/// (system reserved, detached, etc.).
fn volume_for_guid(name_buf: &[u16]) -> Option<VolumeInfo> {
    let guid = nul_terminated_to_string(name_buf);
    let mount_paths = mount_paths_for(&guid)?;
    if mount_paths.is_empty() {
        return None;
    }
    let primary = mount_paths[0].clone();
    let (fs_name, serial) = match volume_information(&guid) {
        Ok((fs, s)) => (fs, s),
        Err(_) => return None,
    };
    let is_ntfs = fs_name.eq_ignore_ascii_case("NTFS");
    let is_removable = drive_type_for(&primary) == DRIVE_REMOVABLE;
    Some(VolumeInfo {
        mount_path: primary,
        all_mount_paths: mount_paths,
        fs_name,
        serial,
        is_ntfs,
        is_removable,
    })
}

/// Returns every user-visible mount path for a volume GUID. Wraps
/// `GetVolumePathNamesForVolumeNameW`'s grow-and-retry idiom: first call
/// with a 256-wchar buffer; on `ERROR_MORE_DATA`, grow to the size the
/// API reported and retry.
fn mount_paths_for(guid: &str) -> Option<Vec<PathBuf>> {
    let guid_w = to_wide_nul(guid);
    let mut buf = vec![0u16; 256];
    let mut needed: u32 = 0;

    // SAFETY: out-buffer length passed in chars; needed receives the
    // length the kernel wants if our buffer was too small.
    let r = unsafe {
        GetVolumePathNamesForVolumeNameW(PCWSTR(guid_w.as_ptr()), Some(&mut buf), &mut needed)
    };
    if let Err(e) = r {
        // ERROR_MORE_DATA (234) = our buffer was too small. Resize and retry.
        if e.code().0 as u32 & 0xFFFF == 234 && needed > 0 {
            buf = vec![0u16; needed as usize];
            // SAFETY: same call shape, larger out-buffer.
            unsafe {
                GetVolumePathNamesForVolumeNameW(
                    PCWSTR(guid_w.as_ptr()),
                    Some(&mut buf),
                    &mut needed,
                )
            }
            .ok()?;
        } else {
            return None;
        }
    }

    // The result is a sequence of NUL-terminated wide strings ended by
    // a double-NUL.
    let mut out: Vec<PathBuf> = Vec::new();
    let mut start = 0usize;
    for i in 0..buf.len() {
        if buf[i] == 0 {
            if start == i {
                break; // Hit the closing double-NUL.
            }
            let path = OsString::from_wide(&buf[start..i]);
            out.push(PathBuf::from(path));
            start = i + 1;
        }
    }
    Some(out)
}

/// Wrapper around `GetVolumeInformationW`. Returns `(fs_name, serial)`.
fn volume_information(guid: &str) -> io::Result<(String, u32)> {
    let guid_w = to_wide_nul(guid);
    let mut name_buf = [0u16; 64];
    let mut serial: u32 = 0;
    let mut max_component: u32 = 0;
    let mut fs_flags: u32 = 0;
    let mut fs_buf = [0u16; 32];
    // SAFETY: all out-buffers are stack-sized; the call writes into them
    // and returns a Result.
    unsafe {
        GetVolumeInformationW(
            PCWSTR(guid_w.as_ptr()),
            Some(&mut name_buf),
            Some(&mut serial),
            Some(&mut max_component),
            Some(&mut fs_flags),
            Some(&mut fs_buf),
        )
    }
    .map_err(io::Error::other)?;
    Ok((nul_terminated_to_string(&fs_buf), serial))
}

/// Wrapper around `GetDriveTypeW`. Returns the raw `u32` constant
/// (DRIVE_REMOVABLE = 2, DRIVE_FIXED = 3, etc.).
fn drive_type_for(mount: &std::path::Path) -> u32 {
    let s = mount.to_string_lossy();
    let w = to_wide_nul(&s);
    // SAFETY: thin syscall wrapper; reads the wide-string root path.
    unsafe { GetDriveTypeW(PCWSTR(w.as_ptr())) }
}

fn nul_terminated_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn to_wide_nul(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke check that `enumerate_volumes` returns at least one entry on
    /// any developer Windows host. The test runs on Windows only via the
    /// outer module's `cfg(target_os = "windows")`. On CI runners this
    /// always reports the C: drive at minimum.
    #[test]
    fn enumerate_volumes_finds_at_least_one_drive() {
        let volumes = enumerate_volumes().expect("enumerate_volumes succeeds");
        assert!(
            !volumes.is_empty(),
            "expected at least one volume on the host"
        );
        // Every reported volume must have at least one mount path.
        for v in &volumes {
            assert!(
                !v.all_mount_paths.is_empty(),
                "volume {v:?} surfaced with no mount paths"
            );
            assert_eq!(v.mount_path, v.all_mount_paths[0]);
        }
    }

    #[test]
    fn enumerate_volumes_includes_c_drive_on_typical_hosts() {
        let volumes = enumerate_volumes().expect("enumerate_volumes succeeds");
        let has_c = volumes.iter().any(|v| {
            v.all_mount_paths.iter().any(|p| {
                let s = p.to_string_lossy().to_ascii_uppercase();
                s.starts_with("C:")
            })
        });
        // CI runners (windows-latest) always have C:; this would only fail
        // on a host whose system drive is mounted somewhere exotic.
        assert!(has_c, "expected C: drive in enumeration: {volumes:?}");
    }

    #[test]
    fn nul_terminated_to_string_stops_at_first_nul() {
        let buf: Vec<u16> = "NTFS\0extra".encode_utf16().collect();
        assert_eq!(nul_terminated_to_string(&buf), "NTFS");
    }

    #[test]
    fn nul_terminated_to_string_handles_unterminated_buffer() {
        let buf: Vec<u16> = "FAT32".encode_utf16().collect();
        assert_eq!(nul_terminated_to_string(&buf), "FAT32");
    }

    #[test]
    fn nul_terminated_to_string_empty_buffer_is_empty_string() {
        let buf: Vec<u16> = Vec::new();
        assert_eq!(nul_terminated_to_string(&buf), "");
    }
}
