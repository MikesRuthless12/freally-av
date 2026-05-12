//! Fast platform-native walker (TASK-050).
//!
//! The name is historical — "NtfsWalker" called it that when Windows was
//! the only platform with a fast path. Today the type uses **the fastest
//! enumeration primitive available on each OS**:
//!
//! - **Windows**: NTFS MFT walk via `FSCTL_ENUM_USN_DATA` + parent-FRN
//!   path resolution. See [`crate::platform::win::journal::JournalSubscriber`].
//! - **macOS**: APFS `read_dir`-based recursive walk (Sourcerer's
//!   Phase-2 implementation; Phase-13 will swap to `getattrlistbulk(2)`).
//!   See [`crate::platform::mac::journal::JournalSubscriber`].
//! - **Linux**: raw `getdents64(2)` recursive walk with `(st_dev, st_ino)`
//!   cycle dedup. Far faster than `std::fs::read_dir` on huge trees.
//!   See [`crate::platform::linux::journal::JournalSubscriber`].
//! - **Anywhere else** (or when the platform's volume open fails — e.g.
//!   non-NTFS on Windows, non-admin on Linux fanotify, dropped permissions
//!   on macOS): transparently delegates to [`super::PosixWalker`] so the
//!   `FileWalker` contract still holds.
//!
//! All three platforms drain the same vendored Sourcerer
//! `JournalSubscriber` bootstrap stream into the existing
//! [`crate::walker::FileWalker`] crossbeam-channel shape, so the rest of
//! the engine — ETA, throttle, hash, detect, record, history — sees the
//! same `WalkEvent::File` events regardless of platform.

use std::path::Path;

use super::{FileWalker, PosixWalker, WalkEvent, WalkOpts};

/// Fast platform-native walker. Behavior is platform-conditional; see the
/// module-level doc for the per-OS primitive.
#[derive(Debug, Default, Clone, Copy)]
pub struct NtfsWalker;

impl NtfsWalker {
    pub fn new() -> Self {
        Self
    }
}

impl FileWalker for NtfsWalker {
    fn walk(&self, root: &Path, opts: WalkOpts) -> crossbeam_channel::Receiver<WalkEvent> {
        #[cfg(windows)]
        {
            windows_impl::walk(root, opts)
        }
        #[cfg(target_os = "macos")]
        {
            macos_impl::walk(root, opts)
        }
        #[cfg(target_os = "linux")]
        {
            linux_impl::walk(root, opts)
        }
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            PosixWalker::new().walk(root, opts)
        }
    }
}

// ---------------------------------------------------------------------
// Cross-platform helper: translate a JournalEvent::Create → WalkEvent::File
// honoring WalkOpts (max_depth, skip_hidden). Each platform calls into
// this from its own `windows_impl` / `macos_impl` / `linux_impl` module.
// ---------------------------------------------------------------------

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
fn path_is_under_root(path: &Path, root: &Path) -> bool {
    // Fast path: byte-for-byte component prefix match works for every
    // sane case-sensitive comparison (Linux + macOS native, Windows
    // when the cases happen to line up).
    if path.starts_with(root) {
        return true;
    }
    // Windows drive-root case: `C:\` is the prefix of every path on the
    // volume but `path.starts_with("C:\\")` may return false for some
    // path forms (8.3 names, mixed-case). Use a wide-char case-folded
    // comparison rather than `to_string_lossy()` so non-UTF-16 bytes
    // can't confuse the prefix check (sec-review L1).
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let p_wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .map(|c| {
                // Windows path comparison is ASCII-case-insensitive on
                // drive letters and POSIX path separators; we lowercase
                // ASCII range only and leave higher code points alone
                // so non-ASCII path segments remain byte-exact.
                if (b'A' as u16..=b'Z' as u16).contains(&c) {
                    c + 32
                } else {
                    c
                }
            })
            .collect();
        let r_wide: Vec<u16> = root
            .as_os_str()
            .encode_wide()
            .map(|c| {
                if (b'A' as u16..=b'Z' as u16).contains(&c) {
                    c + 32
                } else {
                    c
                }
            })
            .collect();
        let r_norm: &[u16] = match r_wide.split_last() {
            Some((last, head)) if *last == b'\\' as u16 || *last == b'/' as u16 => head,
            _ => &r_wide,
        };
        if r_norm.is_empty() {
            return true;
        }
        // Drive root case: `c:` matches everything on the drive.
        if r_norm.len() == 2 && r_norm[1] == b':' as u16 && p_wide.starts_with(r_norm) {
            return true;
        }
        if !p_wide.starts_with(r_norm) {
            return false;
        }
        if p_wide.len() == r_norm.len() {
            return true;
        }
        let next = p_wide[r_norm.len()];
        next == b'\\' as u16 || next == b'/' as u16
    }
    #[cfg(not(windows))]
    {
        // Non-Windows: paths are case-sensitive and `Path::starts_with`
        // already handled the only correct match. Anything that fell
        // through is not under root.
        let _ = (path, root);
        false
    }
}

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
fn depth_under_root(path: &Path, root: &Path) -> usize {
    let stripped = path
        .strip_prefix(root)
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|_| path.to_path_buf());
    stripped.components().count().saturating_sub(1)
}

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
fn path_has_hidden_segment(path: &Path) -> bool {
    path.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        s.starts_with('.') && s != "." && s != ".."
    })
}

#[cfg(windows)]
mod windows_impl {
    use super::*;

    use futures::StreamExt;

    use crate::platform::win::journal::{JournalEvent, JournalSubscriber, open as open_subscriber};

    pub fn walk(root: &Path, opts: WalkOpts) -> crossbeam_channel::Receiver<WalkEvent> {
        let (tx, rx) = crossbeam_channel::unbounded();
        let root = root.to_path_buf();

        std::thread::Builder::new()
            .name("mythkernel/ntfs-walker".into())
            .spawn(move || match open_subscriber(&root) {
                Ok(sub) => run_bootstrap(sub, &root, &opts, &tx),
                Err(err) => {
                    tracing::info!(
                        volume = %root.display(),
                        error = %err,
                        "NTFS MFT walker unavailable; falling back to PosixWalker"
                    );
                    run_posix_fallback(&root, opts, &tx);
                }
            })
            .expect("spawn ntfs-walker thread");

        rx
    }

    fn run_bootstrap(
        sub: JournalSubscriber,
        root: &Path,
        opts: &WalkOpts,
        tx: &crossbeam_channel::Sender<WalkEvent>,
    ) {
        let stream = sub.bootstrap();
        let max_depth = opts.max_depth;
        let skip_hidden = opts.skip_hidden;
        futures::executor::block_on(async move {
            let mut stream = Box::pin(stream);
            while let Some(event) = stream.next().await {
                if !translate_and_send(event, root, max_depth, skip_hidden, tx) {
                    break;
                }
            }
        });
    }

    fn run_posix_fallback(root: &Path, opts: WalkOpts, tx: &crossbeam_channel::Sender<WalkEvent>) {
        let inner_rx = PosixWalker::new().walk(root, opts);
        for ev in inner_rx.iter() {
            if tx.send(ev).is_err() {
                return;
            }
        }
    }

    fn translate_and_send(
        event: JournalEvent,
        root: &Path,
        max_depth: Option<usize>,
        skip_hidden: bool,
        tx: &crossbeam_channel::Sender<WalkEvent>,
    ) -> bool {
        let JournalEvent::Create {
            path,
            size,
            mtime_ns,
            ..
        } = event
        else {
            return true;
        };

        if !path_is_under_root(&path, root) {
            return true;
        }
        if let Some(limit) = max_depth
            && depth_under_root(&path, root) > limit
        {
            return true;
        }
        if skip_hidden && path_has_hidden_segment(&path) {
            return true;
        }

        let mtime_secs = if mtime_ns >= 0 {
            (mtime_ns / 1_000_000_000) as i64
        } else {
            0
        };
        tx.send(WalkEvent::File {
            path,
            size,
            mtime: mtime_secs,
        })
        .is_ok()
    }
}

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;

    use futures::StreamExt;

    use crate::platform::mac::journal::{JournalEvent, JournalSubscriber, open as open_subscriber};

    pub fn walk(root: &Path, opts: WalkOpts) -> crossbeam_channel::Receiver<WalkEvent> {
        let (tx, rx) = crossbeam_channel::unbounded();
        let root = root.to_path_buf();

        std::thread::Builder::new()
            .name("mythkernel/macos-walker".into())
            .spawn(move || match open_subscriber(&root) {
                Ok(sub) => run_bootstrap(sub, &root, &opts, &tx),
                Err(err) => {
                    tracing::info!(
                        root = %root.display(),
                        error = %err,
                        "macOS journal walker unavailable; falling back to PosixWalker"
                    );
                    run_posix_fallback(&root, opts, &tx);
                }
            })
            .expect("spawn macos-walker thread");

        rx
    }

    fn run_bootstrap(
        sub: JournalSubscriber,
        root: &Path,
        opts: &WalkOpts,
        tx: &crossbeam_channel::Sender<WalkEvent>,
    ) {
        let stream = sub.bootstrap();
        let max_depth = opts.max_depth;
        let skip_hidden = opts.skip_hidden;
        futures::executor::block_on(async move {
            let mut stream = Box::pin(stream);
            while let Some(event) = stream.next().await {
                if !translate_and_send(event, root, max_depth, skip_hidden, tx) {
                    break;
                }
            }
        });
    }

    fn run_posix_fallback(root: &Path, opts: WalkOpts, tx: &crossbeam_channel::Sender<WalkEvent>) {
        let inner_rx = PosixWalker::new().walk(root, opts);
        for ev in inner_rx.iter() {
            if tx.send(ev).is_err() {
                return;
            }
        }
    }

    fn translate_and_send(
        event: JournalEvent,
        root: &Path,
        max_depth: Option<usize>,
        skip_hidden: bool,
        tx: &crossbeam_channel::Sender<WalkEvent>,
    ) -> bool {
        let JournalEvent::Create {
            path,
            size,
            mtime_ns,
            ..
        } = event
        else {
            return true;
        };

        if !path_is_under_root(&path, root) {
            return true;
        }
        if let Some(limit) = max_depth
            && depth_under_root(&path, root) > limit
        {
            return true;
        }
        if skip_hidden && path_has_hidden_segment(&path) {
            return true;
        }

        let mtime_secs = if mtime_ns >= 0 {
            (mtime_ns / 1_000_000_000) as i64
        } else {
            0
        };
        tx.send(WalkEvent::File {
            path,
            size,
            mtime: mtime_secs,
        })
        .is_ok()
    }
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;

    use futures::StreamExt;

    use crate::platform::linux::journal::{
        JournalEvent, JournalSubscriber, open as open_subscriber,
    };

    pub fn walk(root: &Path, opts: WalkOpts) -> crossbeam_channel::Receiver<WalkEvent> {
        let (tx, rx) = crossbeam_channel::unbounded();
        let root = root.to_path_buf();

        std::thread::Builder::new()
            .name("mythkernel/linux-walker".into())
            .spawn(move || match open_subscriber(&root) {
                Ok(sub) => run_bootstrap(sub, &root, &opts, &tx),
                Err(err) => {
                    tracing::info!(
                        root = %root.display(),
                        error = %err,
                        "Linux journal walker unavailable; falling back to PosixWalker"
                    );
                    run_posix_fallback(&root, opts, &tx);
                }
            })
            .expect("spawn linux-walker thread");

        rx
    }

    fn run_bootstrap(
        sub: JournalSubscriber,
        root: &Path,
        opts: &WalkOpts,
        tx: &crossbeam_channel::Sender<WalkEvent>,
    ) {
        let stream = sub.bootstrap();
        let max_depth = opts.max_depth;
        let skip_hidden = opts.skip_hidden;
        futures::executor::block_on(async move {
            let mut stream = Box::pin(stream);
            while let Some(event) = stream.next().await {
                if !translate_and_send(event, root, max_depth, skip_hidden, tx) {
                    break;
                }
            }
        });
    }

    fn run_posix_fallback(root: &Path, opts: WalkOpts, tx: &crossbeam_channel::Sender<WalkEvent>) {
        let inner_rx = PosixWalker::new().walk(root, opts);
        for ev in inner_rx.iter() {
            if tx.send(ev).is_err() {
                return;
            }
        }
    }

    fn translate_and_send(
        event: JournalEvent,
        root: &Path,
        max_depth: Option<usize>,
        skip_hidden: bool,
        tx: &crossbeam_channel::Sender<WalkEvent>,
    ) -> bool {
        let JournalEvent::Create {
            path,
            size,
            mtime_ns,
            ..
        } = event
        else {
            return true;
        };

        if !path_is_under_root(&path, root) {
            return true;
        }
        if let Some(limit) = max_depth
            && depth_under_root(&path, root) > limit
        {
            return true;
        }
        if skip_hidden && path_has_hidden_segment(&path) {
            return true;
        }

        let mtime_secs = if mtime_ns >= 0 {
            (mtime_ns / 1_000_000_000) as i64
        } else {
            0
        };
        tx.send(WalkEvent::File {
            path,
            size,
            mtime: mtime_secs,
        })
        .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use tempfile::tempdir;

    /// On non-Windows hosts the NtfsWalker must transparently fall back to
    /// PosixWalker so the engine, scan tests, and CI on Linux/macOS keep
    /// working with the same `FileWalker` interface. On Windows hosts we
    /// also exercise the fallback path because the test temp dir is
    /// (almost certainly) not a drive root — so `JournalSubscriber::open`
    /// will reject it and `windows_impl::run_posix_fallback` kicks in.
    #[test]
    fn falls_back_to_posix_walker_on_a_tempdir() {
        let dir = tempdir().unwrap();
        for i in 0..6 {
            let p = dir.path().join(format!("file_{i}.txt"));
            fs::write(&p, format!("content {i}")).unwrap();
        }

        let walker = NtfsWalker::new();
        let rx = walker.walk(dir.path(), WalkOpts::default());

        let mut files = 0;
        for event in rx.iter() {
            if matches!(event, WalkEvent::File { .. }) {
                files += 1;
            }
        }
        assert_eq!(files, 6);
    }

    #[test]
    fn respects_max_depth_via_fallback_path() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        fs::create_dir_all(&nested).unwrap();
        fs::write(dir.path().join("top.txt"), "top").unwrap();
        fs::write(nested.join("deep.txt"), "deep").unwrap();

        let walker = NtfsWalker::new();
        let rx = walker.walk(
            dir.path(),
            WalkOpts {
                max_depth: Some(1),
                ..WalkOpts::default()
            },
        );

        let count = rx
            .iter()
            .filter(|e| matches!(e, WalkEvent::File { .. }))
            .count();
        assert_eq!(count, 1, "max_depth=1 keeps the top-level file only");
    }

    /// Live MFT walk against `C:\`. Windows-only, requires admin, so it's
    /// `#[ignore]`d by default. Run explicitly via
    /// `cargo test --release -p mythkernel ntfs_walker_live -- --ignored --nocapture`.
    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "live MFT walk; requires admin"]
    fn ntfs_walker_live_walks_c_drive() {
        let walker = NtfsWalker::new();
        let rx = walker.walk(Path::new("C:\\"), WalkOpts::default());
        let mut files = 0_usize;
        for event in rx.iter() {
            if matches!(event, WalkEvent::File { .. }) {
                files += 1;
                if files >= 1000 {
                    break;
                }
            }
        }
        assert!(
            files >= 1000,
            "expected ≥ 1000 files in MFT walk, saw {files}"
        );
    }
}
