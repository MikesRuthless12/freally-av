//! USN incremental scan (TASK-051).
//!
//! On Windows: opens the same vendored Sourcerer `JournalSubscriber`
//! [`crate::walker::ntfs::NtfsWalker`] uses, drains the USN journal from
//! the persisted cursor up to a live snapshot point, and translates each
//! settled `JournalEvent::{Create, Modify, Rename}` into a
//! [`crate::walker::WalkEvent::File`]. Drops `Delete`, `RenameOld`, and
//! `AttrChange` — the engine's findings layer reconciles deleted files
//! against past scans separately, and an attribute change with no data
//! change isn't worth a re-hash.
//!
//! Rotation handling: if the USN journal was deleted/recreated since the
//! cursor was minted (or the cursor's `next_usn` fell off the front of the
//! journal), the walker transparently falls back to
//! [`crate::walker::ntfs::NtfsWalker`] for a full MFT walk so the engine
//! still gets a complete file list.
//!
//! On non-Windows hosts, this delegates to [`super::PosixWalker`] so the
//! cross-platform `FileWalker` contract holds.

use std::path::Path;

use super::{FileWalker, PosixWalker, WalkEvent, WalkOpts};
// NtfsWalker only exists / is consumed on Windows. Importing it
// unconditionally trips `unused_imports` on non-Windows builds.
#[cfg(windows)]
use super::NtfsWalker;

#[derive(Debug, Default, Clone, Copy)]
pub struct IncrementalWalker;

impl IncrementalWalker {
    pub fn new() -> Self {
        Self
    }
}

impl FileWalker for IncrementalWalker {
    fn walk(&self, root: &Path, opts: WalkOpts) -> crossbeam_channel::Receiver<WalkEvent> {
        #[cfg(windows)]
        {
            windows_impl::walk(root, opts)
        }
        #[cfg(not(windows))]
        {
            // No NTFS / no USN journal off-Windows. Delegate to PosixWalker.
            PosixWalker::new().walk(root, opts)
        }
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::*;

    use std::path::PathBuf;
    use std::time::UNIX_EPOCH;

    use futures::StreamExt;

    use crate::platform::win::journal::{JournalEvent, JournalSubscriber, open as open_subscriber};

    pub fn walk(root: &Path, opts: WalkOpts) -> crossbeam_channel::Receiver<WalkEvent> {
        let (tx, rx) = crossbeam_channel::unbounded();
        // JournalSubscriber::open canonicalizes the root; the filter
        // (path_is_under_root) compares against this `root` too, so
        // they must agree. Without canonicalizing up-front, on Windows
        // the verbatim `\\?\` prefix mismatch silently rejects every
        // event. Same fix as NtfsWalker's windows_impl / macos_impl /
        // linux_impl.
        let root_owned = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());

        std::thread::Builder::new()
            .name("freallykernel/incremental-walker".into())
            .spawn(move || {
                match open_subscriber(&root_owned) {
                    Ok(sub) => {
                        let end_usn = sub.journal_state().next_usn;
                        match sub.drain_until(end_usn) {
                            Some(stream) => {
                                drain_into_channel(sub, stream, &root_owned, &opts, &tx);
                            }
                            None => {
                                // Rotation gate refused — the journal_id or
                                // first_usn moved under us. Fall through to a
                                // full MFT walk so the engine gets a complete
                                // file list, not a partial one.
                                tracing::info!(
                                    volume = %root_owned.display(),
                                    "USN journal rotated; falling back to NtfsWalker (full MFT)"
                                );
                                run_ntfs_fallback(&root_owned, opts, &tx);
                            }
                        }
                    }
                    Err(err) => {
                        tracing::info!(
                            volume = %root_owned.display(),
                            error = %err,
                            "incremental walker can't open volume; falling back to PosixWalker"
                        );
                        run_posix_fallback(&root_owned, opts, &tx);
                    }
                }
            })
            .expect("spawn incremental-walker thread");

        rx
    }

    fn drain_into_channel(
        _sub: JournalSubscriber,
        stream: impl futures::Stream<Item = JournalEvent> + Send + 'static,
        root: &Path,
        opts: &WalkOpts,
        tx: &crossbeam_channel::Sender<WalkEvent>,
    ) {
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

    fn run_ntfs_fallback(root: &Path, opts: WalkOpts, tx: &crossbeam_channel::Sender<WalkEvent>) {
        let inner_rx = NtfsWalker::new().walk(root, opts);
        for ev in inner_rx.iter() {
            if tx.send(ev).is_err() {
                return;
            }
        }
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
        let (path, mtime_ns) = match event {
            JournalEvent::Create { path, mtime_ns, .. }
            | JournalEvent::Modify { path, mtime_ns, .. } => (path, mtime_ns),
            // For renames, the new path is what the engine should re-scan.
            JournalEvent::Rename { new_path, .. } => (new_path, 0),
            // The walker only surfaces files that *exist* and have changed.
            // Deletes are reconciled by the engine's findings layer against
            // the prior scan's snapshot (FR-062). AttrChange with no data
            // change isn't worth a re-hash.
            JournalEvent::Delete { .. } | JournalEvent::AttrChange { .. } => return true,
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

        // The journal record may name a file that's already been deleted
        // between the USN event and our drain. Stat to filter out misses.
        let metadata = match std::fs::metadata(&path) {
            Ok(m) if m.is_file() => m,
            _ => return true,
        };

        let mtime_secs = if mtime_ns > 0 {
            (mtime_ns / 1_000_000_000) as i64
        } else {
            metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        };

        let walk_event = WalkEvent::File {
            path,
            size: metadata.len(),
            mtime: mtime_secs,
        };
        tx.send(walk_event).is_ok()
    }

    fn path_is_under_root(path: &Path, root: &Path) -> bool {
        // Fast path: byte-for-byte component prefix match.
        if path.starts_with(root) {
            return true;
        }
        // Windows drive-root fallback — wide-char ASCII-case-fold so non-UTF-16
        // bytes can't confuse the prefix check (sec-review L1).
        use std::os::windows::ffi::OsStrExt;
        let p_wide: Vec<u16> = path
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

    fn depth_under_root(path: &Path, root: &Path) -> usize {
        let stripped: PathBuf = path
            .strip_prefix(root)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| path.to_path_buf());
        stripped.components().count().saturating_sub(1)
    }

    fn path_has_hidden_segment(path: &Path) -> bool {
        path.components().any(|c| {
            let s = c.as_os_str().to_string_lossy();
            s.starts_with('.') && s != "." && s != ".."
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// Cross-platform sanity check: IncrementalWalker on a non-drive-root
    /// path falls back to PosixWalker (Windows) or PosixWalker directly
    /// (non-Windows) and yields every file in the scratch dir.
    #[test]
    fn falls_back_to_posix_walker_on_a_tempdir() {
        let dir = tempdir().unwrap();
        for i in 0..4 {
            fs::write(dir.path().join(format!("f_{i}.txt")), b"x").unwrap();
        }
        let walker = IncrementalWalker::new();
        let rx = walker.walk(dir.path(), WalkOpts::default());
        let count = rx
            .iter()
            .filter(|e| matches!(e, WalkEvent::File { .. }))
            .count();
        assert_eq!(count, 4);
    }

    /// Live USN incremental walk against `C:\`. Windows-only, requires
    /// admin; ignored by default.
    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "live USN incremental walk; requires admin"]
    fn incremental_walker_live_against_c_drive() {
        let walker = IncrementalWalker::new();
        // First call seeds the cursor; second call reads the delta. We
        // assert the second call returns 0 .. (anything bounded) — just
        // proving the bounded drain converged without spinning.
        let rx = walker.walk(Path::new("C:\\"), WalkOpts::default());
        for _ in rx.iter().take(100) {}

        let rx = walker.walk(Path::new("C:\\"), WalkOpts::default());
        let count = rx.iter().count();
        assert!(count < 1_000_000, "bounded drain emitted {count} events");
    }
}
