//! Thin safe wrappers around the inotify, fanotify, getdents64, statfs,
//! and capability syscalls — vendored from Sourcerer.

#![cfg(target_os = "linux")]

use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

// =====================================================================
// Inotify
// =====================================================================

pub struct InotifyFd {
    inner: OwnedFd,
}

impl InotifyFd {
    pub fn init() -> io::Result<Self> {
        let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let inner = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self { inner })
    }

    pub fn add_watch(&self, path: &Path, mask: u32) -> io::Result<i32> {
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let wd = unsafe { libc::inotify_add_watch(self.inner.as_raw_fd(), c.as_ptr(), mask) };
        if wd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(wd)
    }

    pub fn rm_watch(&self, wd: i32) -> io::Result<()> {
        let r = unsafe { libc::inotify_rm_watch(self.inner.as_raw_fd(), wd) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn read_into(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        let n = unsafe {
            libc::read(
                self.inner.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(libc::EAGAIN)) {
                return Ok(None);
            }
            return Err(err);
        }
        Ok(Some(n as usize))
    }

    pub fn raw(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

#[derive(Debug, Clone)]
pub struct ParsedInotifyEvent {
    pub wd: i32,
    pub mask: u32,
    pub cookie: u32,
    pub name: OsString,
}

pub struct InotifyEventIter<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> InotifyEventIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }
}

impl Iterator for InotifyEventIter<'_> {
    type Item = ParsedInotifyEvent;

    fn next(&mut self) -> Option<ParsedInotifyEvent> {
        const HDR: usize = 16;
        if self.offset + HDR > self.buf.len() {
            return None;
        }
        let hdr = &self.buf[self.offset..self.offset + HDR];
        let wd = i32::from_ne_bytes(hdr[0..4].try_into().ok()?);
        let mask = u32::from_ne_bytes(hdr[4..8].try_into().ok()?);
        let cookie = u32::from_ne_bytes(hdr[8..12].try_into().ok()?);
        let len = u32::from_ne_bytes(hdr[12..16].try_into().ok()?) as usize;

        let total = HDR + len;
        if self.offset + total > self.buf.len() {
            return None;
        }
        let name = if len == 0 {
            OsString::new()
        } else {
            let bytes = &self.buf[self.offset + HDR..self.offset + HDR + len];
            let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            OsString::from_vec(bytes[..nul].to_vec())
        };

        self.offset += total;
        Some(ParsedInotifyEvent {
            wd,
            mask,
            cookie,
            name,
        })
    }
}

// =====================================================================
// Fanotify
// =====================================================================

pub struct FanotifyFd {
    inner: OwnedFd,
    mount: OwnedFd,
}

impl FanotifyFd {
    pub fn init(root: &Path) -> io::Result<Self> {
        let init_flags =
            libc::FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME | libc::FAN_NONBLOCK | libc::FAN_CLOEXEC;
        let raw = unsafe { libc::fanotify_init(init_flags, libc::O_RDONLY as u32) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let inner = unsafe { OwnedFd::from_raw_fd(raw) };

        let c = CString::new(root.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mount_raw = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if mount_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let mount = unsafe { OwnedFd::from_raw_fd(mount_raw) };
        Ok(Self { inner, mount })
    }

    pub fn mark_filesystem(&self, root: &Path, mask: u64) -> io::Result<()> {
        let c = CString::new(root.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let flags: libc::c_uint = libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM;
        let r = unsafe {
            libc::fanotify_mark(
                self.inner.as_raw_fd(),
                flags,
                mask,
                libc::AT_FDCWD,
                c.as_ptr(),
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn read_into(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        let n = unsafe {
            libc::read(
                self.inner.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(libc::EAGAIN)) {
                return Ok(None);
            }
            return Err(err);
        }
        Ok(Some(n as usize))
    }

    pub fn raw(&self) -> RawFd {
        self.inner.as_raw_fd()
    }

    pub fn poll_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }

    pub fn resolve_dfid_name(
        &self,
        handle_bytes: &[u8],
        handle_type: i32,
        name: &OsStr,
    ) -> io::Result<Option<PathBuf>> {
        let total = std::mem::size_of::<u32>() + std::mem::size_of::<i32>() + handle_bytes.len();
        let mut buf = vec![0u8; total];
        buf[0..4].copy_from_slice(&(handle_bytes.len() as u32).to_ne_bytes());
        buf[4..8].copy_from_slice(&handle_type.to_ne_bytes());
        buf[8..].copy_from_slice(handle_bytes);

        let fd = unsafe {
            libc::open_by_handle_at(
                self.mount.as_raw_fd(),
                buf.as_ptr() as *mut _,
                libc::O_PATH | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::ENOENT) | Some(libc::ESTALE) => return Ok(None),
                _ => return Err(err),
            }
        }
        let handle_fd = unsafe { OwnedFd::from_raw_fd(fd) };

        let dir = read_link_proc_self_fd(handle_fd.as_raw_fd())?;
        if name.is_empty() {
            return Ok(Some(dir));
        }
        Ok(Some(dir.join(name)))
    }
}

fn read_link_proc_self_fd(fd: RawFd) -> io::Result<PathBuf> {
    let link = format!("/proc/self/fd/{fd}");
    let c = CString::new(link.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n =
            unsafe { libc::readlink(c.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n < buf.len() {
            buf.truncate(n);
            return Ok(PathBuf::from(OsString::from_vec(buf)));
        }
        buf.resize(buf.len() * 2, 0);
    }
}

const FAN_REPORT_DFID_NAME: libc::c_uint = 0x0000_0c00;

pub const FAN_EVENT_INFO_TYPE_FID: u8 = 1;
pub const FAN_EVENT_INFO_TYPE_DFID_NAME: u8 = 2;
pub const FAN_EVENT_INFO_TYPE_DFID: u8 = 3;
pub const FAN_EVENT_INFO_TYPE_OLD_DFID_NAME: u8 = 10;
pub const FAN_EVENT_INFO_TYPE_NEW_DFID_NAME: u8 = 12;

#[derive(Debug)]
pub struct ParsedFanotifyEvent {
    pub mask: u64,
    pub fd: i32,
    pub pid: i32,
    pub handle_bytes: Vec<u8>,
    pub handle_type: i32,
    pub name: OsString,
    pub old: Option<(Vec<u8>, i32, OsString)>,
}

pub struct FanotifyEventIter<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> FanotifyEventIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }
}

impl Iterator for FanotifyEventIter<'_> {
    type Item = ParsedFanotifyEvent;

    fn next(&mut self) -> Option<ParsedFanotifyEvent> {
        const META: usize = 24;
        if self.offset + META > self.buf.len() {
            return None;
        }
        let meta = &self.buf[self.offset..self.offset + META];
        let event_len = u32::from_ne_bytes(meta[0..4].try_into().ok()?) as usize;
        let metadata_len = u16::from_ne_bytes(meta[6..8].try_into().ok()?) as usize;
        let mask = u64::from_ne_bytes(meta[8..16].try_into().ok()?);
        let fd = i32::from_ne_bytes(meta[16..20].try_into().ok()?);
        let pid = i32::from_ne_bytes(meta[20..24].try_into().ok()?);

        if event_len == 0 || self.offset + event_len > self.buf.len() {
            return None;
        }

        let mut handle_bytes: Vec<u8> = Vec::new();
        let mut handle_type: i32 = 0;
        let mut name = OsString::new();
        let mut old: Option<(Vec<u8>, i32, OsString)> = None;

        let mut info_off = self.offset + metadata_len;
        let event_end = self.offset + event_len;
        while info_off + 4 <= event_end {
            let info_hdr = &self.buf[info_off..info_off + 4];
            let info_type = info_hdr[0];
            let info_len = u16::from_ne_bytes(info_hdr[2..4].try_into().ok()?) as usize;
            if info_len == 0 || info_off + info_len > event_end {
                break;
            }
            const FSID: usize = 8;
            const FH_HDR: usize = 8;
            if matches!(
                info_type,
                FAN_EVENT_INFO_TYPE_FID
                    | FAN_EVENT_INFO_TYPE_DFID
                    | FAN_EVENT_INFO_TYPE_DFID_NAME
                    | FAN_EVENT_INFO_TYPE_OLD_DFID_NAME
                    | FAN_EVENT_INFO_TYPE_NEW_DFID_NAME
            ) && info_len >= 4 + FSID + FH_HDR
            {
                let body_start = info_off + 4 + FSID;
                let hbytes =
                    u32::from_ne_bytes(self.buf[body_start..body_start + 4].try_into().ok()?)
                        as usize;
                let htype =
                    i32::from_ne_bytes(self.buf[body_start + 4..body_start + 8].try_into().ok()?);
                let handle_payload_start = body_start + FH_HDR;
                let handle_payload_end = handle_payload_start + hbytes;
                if handle_payload_end <= info_off + info_len {
                    let payload = self.buf[handle_payload_start..handle_payload_end].to_vec();
                    let n = if matches!(
                        info_type,
                        FAN_EVENT_INFO_TYPE_DFID_NAME
                            | FAN_EVENT_INFO_TYPE_OLD_DFID_NAME
                            | FAN_EVENT_INFO_TYPE_NEW_DFID_NAME
                    ) && handle_payload_end < info_off + info_len
                    {
                        let name_bytes = &self.buf[handle_payload_end..info_off + info_len];
                        let nul = name_bytes
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(name_bytes.len());
                        OsString::from_vec(name_bytes[..nul].to_vec())
                    } else {
                        OsString::new()
                    };

                    if info_type == FAN_EVENT_INFO_TYPE_OLD_DFID_NAME {
                        old = Some((payload, htype, n));
                    } else if handle_bytes.is_empty() {
                        handle_bytes = payload;
                        handle_type = htype;
                        name = n;
                    }
                }
            }
            info_off += info_len;
        }

        self.offset += event_len;
        Some(ParsedFanotifyEvent {
            mask,
            fd,
            pid,
            handle_bytes,
            handle_type,
            name,
            old,
        })
    }
}

// =====================================================================
// getdents64 walker
// =====================================================================

/// Recursive directory walker built on raw `getdents64(2)`. Faster than
/// `std::fs::read_dir` on huge trees because each syscall returns
/// thousands of entries packed into a single buffer instead of one
/// `getdents` call per entry.
///
/// Calls `visit` for every regular file encountered. Symlinks are
/// skipped (not followed). Cycle-safe via `(st_dev, st_ino)` dedup.
pub fn walk_getdents64<F>(root: &Path, mut visit: F) -> io::Result<()>
where
    F: FnMut(&Path, &std::fs::Metadata),
{
    use std::collections::HashSet;
    use std::os::unix::fs::MetadataExt;

    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut visited: HashSet<(u64, u64)> = HashSet::new();
    if let Ok(meta) = std::fs::symlink_metadata(root) {
        visited.insert((meta.dev(), meta.ino()));
    }
    let mut buf = vec![0u8; 64 * 1024];

    while let Some(dir) = stack.pop() {
        let cdir = match CString::new(dir.as_os_str().as_bytes()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let dirfd = unsafe {
            libc::open(
                cdir.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if dirfd < 0 {
            tracing::trace!(dir = %dir.display(), error = %io::Error::last_os_error(),
                "getdents64: skipping unreadable dir");
            continue;
        }
        let dirfd = unsafe { OwnedFd::from_raw_fd(dirfd) };

        loop {
            let n = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    dirfd.as_raw_fd(),
                    buf.as_mut_ptr(),
                    buf.len(),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if n == 0 {
                break;
            }
            let bytes = n as usize;
            let mut off = 0usize;
            while off + 19 <= bytes {
                let reclen =
                    u16::from_ne_bytes(buf[off + 16..off + 18].try_into().unwrap()) as usize;
                if reclen == 0 || off + reclen > bytes {
                    break;
                }
                let d_type = buf[off + 18];
                let name_start = off + 19;
                let name_max_end = off + reclen;
                let nul = buf[name_start..name_max_end]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| name_start + p)
                    .unwrap_or(name_max_end);
                let name_bytes = &buf[name_start..nul];
                off += reclen;

                if name_bytes == b"." || name_bytes == b".." {
                    continue;
                }
                let name_os = OsStr::from_bytes(name_bytes);
                let full = dir.join(name_os);

                match d_type {
                    libc::DT_DIR => match std::fs::symlink_metadata(&full) {
                        Ok(meta) => {
                            let key = (meta.dev(), meta.ino());
                            if visited.insert(key) {
                                stack.push(full);
                            }
                        }
                        Err(_) => stack.push(full),
                    },
                    libc::DT_REG => {
                        if let Ok(meta) = std::fs::symlink_metadata(&full)
                            && meta.is_file()
                        {
                            visit(&full, &meta);
                        }
                    }
                    libc::DT_UNKNOWN => {
                        if let Ok(meta) = std::fs::symlink_metadata(&full) {
                            if meta.is_dir() {
                                let key = (meta.dev(), meta.ino());
                                if visited.insert(key) {
                                    stack.push(full);
                                }
                            } else if meta.is_file() {
                                visit(&full, &meta);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

// =====================================================================
// statfs / stat
// =====================================================================

pub fn device_id(path: &Path) -> io::Result<u64> {
    let meta = std::fs::symlink_metadata(path)?;
    use std::os::unix::fs::MetadataExt;
    Ok(meta.dev())
}

pub fn statfs_name(path: &Path) -> io::Result<String> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::statfs(c.as_ptr(), &mut buf) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fs_magic_name(buf.f_type))
}

pub fn fs_magic_name(magic: i64) -> String {
    match magic as u64 {
        0xEF53 => "ext4".into(),
        0x9123_683E => "btrfs".into(),
        0x2FC1_2FC1 => "zfs".into(),
        0x5846_5342 => "xfs".into(),
        0xF2F5_2010 => "f2fs".into(),
        0x0102_1994 => "tmpfs".into(),
        0x6969 => "nfs".into(),
        0x4d44 => "fat".into(),
        0x5346_4e54 => "ntfs".into(),
        0x6E73_6663 | 0x6573_5546 => "fuse".into(),
        0x794C_7630 => "overlayfs".into(),
        0x9FA0 => "proc".into(),
        0x6273_6473 => "btrfs-test".into(),
        other => format!("unknown:0x{other:x}"),
    }
}

// =====================================================================
// Capability detection
// =====================================================================

pub fn has_cap_sys_admin() -> bool {
    has_capability_bit(CAP_SYS_ADMIN_BIT)
}

const CAP_SYS_ADMIN_BIT: u32 = 21;

fn has_capability_bit(bit: u32) -> bool {
    let bytes = match std::fs::read("/proc/self/status") {
        Ok(b) => b,
        Err(_) => return false,
    };
    let s = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:") {
            let hex = rest.trim();
            if let Ok(mask) = u64::from_str_radix(hex, 16) {
                return (mask >> bit) & 1 == 1;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_inotify_event_with_name() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(&7i32.to_ne_bytes());
        buf[4..8].copy_from_slice(&0x4000_0100u32.to_ne_bytes());
        buf[8..12].copy_from_slice(&0u32.to_ne_bytes());
        buf[12..16].copy_from_slice(&8u32.to_ne_bytes());
        buf[16..21].copy_from_slice(b"child");

        let events: Vec<_> = InotifyEventIter::new(&buf).collect();
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.wd, 7);
        assert_eq!(e.mask, 0x4000_0100);
        assert_eq!(e.cookie, 0);
        assert_eq!(e.name.to_string_lossy(), "child");
    }

    #[test]
    fn parse_inotify_event_with_no_name() {
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&3i32.to_ne_bytes());
        buf[4..8].copy_from_slice(&0x0000_0400u32.to_ne_bytes());
        buf[8..12].copy_from_slice(&0u32.to_ne_bytes());
        buf[12..16].copy_from_slice(&0u32.to_ne_bytes());

        let events: Vec<_> = InotifyEventIter::new(&buf).collect();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].name, OsString::new());
    }

    #[test]
    fn parse_two_back_to_back_inotify_events() {
        let mut buf = Vec::with_capacity(48);

        let mut ev1 = vec![0u8; 24];
        ev1[0..4].copy_from_slice(&1i32.to_ne_bytes());
        ev1[4..8].copy_from_slice(&0x40u32.to_ne_bytes());
        ev1[8..12].copy_from_slice(&0xCAFEu32.to_ne_bytes());
        ev1[12..16].copy_from_slice(&8u32.to_ne_bytes());
        ev1[16..21].copy_from_slice(b"old.x");
        buf.extend_from_slice(&ev1);

        let mut ev2 = vec![0u8; 24];
        ev2[0..4].copy_from_slice(&1i32.to_ne_bytes());
        ev2[4..8].copy_from_slice(&0x80u32.to_ne_bytes());
        ev2[8..12].copy_from_slice(&0xCAFEu32.to_ne_bytes());
        ev2[12..16].copy_from_slice(&8u32.to_ne_bytes());
        ev2[16..21].copy_from_slice(b"new.x");
        buf.extend_from_slice(&ev2);

        let events: Vec<_> = InotifyEventIter::new(&buf).collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].cookie, 0xCAFE);
        assert_eq!(events[0].name.to_string_lossy(), "old.x");
        assert_eq!(events[1].cookie, 0xCAFE);
        assert_eq!(events[1].name.to_string_lossy(), "new.x");
    }

    #[test]
    fn parse_inotify_event_truncated_header_is_none() {
        let buf = vec![0u8; 7];
        let events: Vec<_> = InotifyEventIter::new(&buf).collect();
        assert!(events.is_empty());
    }

    #[test]
    fn fs_magic_name_known_filesystems() {
        assert_eq!(fs_magic_name(0xEF53), "ext4");
        assert_eq!(fs_magic_name(0x9123_683E), "btrfs");
        assert_eq!(fs_magic_name(0x2FC1_2FC1), "zfs");
        assert_eq!(fs_magic_name(0x5846_5342), "xfs");
        assert_eq!(fs_magic_name(0x0102_1994), "tmpfs");
    }

    #[test]
    fn fs_magic_name_unknown_renders_hex() {
        let s = fs_magic_name(0xDEAD_BEEF);
        assert!(s.starts_with("unknown:0x"));
        assert!(s.contains("deadbeef"));
    }

    #[test]
    fn parse_fanotify_event_with_dfid_name() {
        let info_payload_len = 8usize;
        let name = b"f.txt\0";
        let info_len = 4 + 8 + 4 + 4 + info_payload_len + name.len();
        let event_len = 24 + info_len;

        let mut buf = vec![0u8; event_len];
        buf[0..4].copy_from_slice(&(event_len as u32).to_ne_bytes());
        buf[4] = 3;
        buf[5] = 0;
        buf[6..8].copy_from_slice(&24u16.to_ne_bytes());
        buf[8..16].copy_from_slice(&(0x100u64).to_ne_bytes());
        buf[16..20].copy_from_slice(&(-1i32).to_ne_bytes());
        buf[20..24].copy_from_slice(&12345i32.to_ne_bytes());

        let info_off = 24usize;
        buf[info_off] = FAN_EVENT_INFO_TYPE_DFID_NAME;
        buf[info_off + 1] = 0;
        buf[info_off + 2..info_off + 4].copy_from_slice(&(info_len as u16).to_ne_bytes());
        buf[info_off + 4..info_off + 12].copy_from_slice(&[0u8; 8]);
        buf[info_off + 12..info_off + 16].copy_from_slice(&(info_payload_len as u32).to_ne_bytes());
        buf[info_off + 16..info_off + 20].copy_from_slice(&1i32.to_ne_bytes());
        for i in 0..info_payload_len {
            buf[info_off + 20 + i] = 0xAA;
        }
        buf[info_off + 20 + info_payload_len..event_len].copy_from_slice(name);

        let events: Vec<_> = FanotifyEventIter::new(&buf).collect();
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.mask, 0x100);
        assert_eq!(e.handle_type, 1);
        assert_eq!(e.handle_bytes.len(), info_payload_len);
        assert!(e.handle_bytes.iter().all(|&b| b == 0xAA));
        assert_eq!(e.name.to_string_lossy(), "f.txt");
        assert!(e.old.is_none());
    }
}
