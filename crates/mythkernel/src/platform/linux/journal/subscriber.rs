//! `JournalSubscriber` — vendored from Sourcerer (Linux / inotify+fanotify).

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use futures::Stream;
use futures::channel::mpsc;

use super::cursor::{WatchBackend, WatchCursor};
use super::event::{JournalError, JournalEvent};
use super::ffi::{
    FanotifyEventIter, FanotifyFd, InotifyEventIter, InotifyFd, ParsedInotifyEvent, device_id,
    statfs_name, walk_getdents64,
};
use super::flags::{
    self, FAN_Q_OVERFLOW, MYTHODIKAL_FANOTIFY_MASK, MYTHODIKAL_INOTIFY_MASK, ReasonKind,
};

const READ_BUFFER_BYTES: usize = 64 * 1024;
const POLL_TIMEOUT_MS: i32 = 100;

pub struct JournalSubscriber {
    root: PathBuf,
    cursor_root: PathBuf,
    cursor: Arc<Mutex<WatchCursor>>,
    stop_flag: Arc<AtomicBool>,
}

impl JournalSubscriber {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn cursor(&self) -> WatchCursor {
        self.cursor.lock().expect("cursor mutex poisoned").clone()
    }
}

impl Drop for JournalSubscriber {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}

pub fn open(root: &Path) -> Result<JournalSubscriber, JournalError> {
    open_with_cursor_root(root, &WatchCursor::default_root())
}

pub fn open_with_cursor_root(
    root: &Path,
    cursor_root: &Path,
) -> Result<JournalSubscriber, JournalError> {
    if !root.is_absolute() {
        return Err(JournalError::InvalidRoot(root.to_path_buf()));
    }
    let canonical =
        std::fs::canonicalize(root).map_err(|e| JournalError::OpenRoot(root.to_path_buf(), e))?;
    if !canonical.is_dir() {
        return Err(JournalError::InvalidRoot(canonical));
    }

    let dev = device_id(&canonical).map_err(|e| JournalError::OpenRoot(canonical.clone(), e))?;
    let fs_name =
        statfs_name(&canonical).map_err(|e| JournalError::Statfs(canonical.clone(), e))?;

    let backend = if super::ffi::has_cap_sys_admin() {
        WatchBackend::Fanotify
    } else {
        WatchBackend::Inotify
    };

    let persisted = WatchCursor::load(cursor_root, &canonical)?;
    let cursor = match persisted {
        Some(c) if c.device == dev => WatchCursor {
            root: canonical.clone(),
            device: c.device,
            fs_name: fs_name.clone(),
            backend,
            bootstrap_complete: c.bootstrap_complete,
            last_event_time_ns: c.last_event_time_ns,
        },
        Some(stale) => {
            tracing::info!(
                root = %canonical.display(),
                old_device = stale.device,
                new_device = dev,
                "persisted cursor is on a different device; resetting bootstrap state",
            );
            WatchCursor {
                root: canonical.clone(),
                device: dev,
                fs_name: fs_name.clone(),
                backend,
                bootstrap_complete: false,
                last_event_time_ns: 0,
            }
        }
        None => WatchCursor {
            root: canonical.clone(),
            device: dev,
            fs_name: fs_name.clone(),
            backend,
            bootstrap_complete: false,
            last_event_time_ns: 0,
        },
    };
    cursor.save(cursor_root)?;

    Ok(JournalSubscriber {
        root: canonical,
        cursor_root: cursor_root.to_path_buf(),
        cursor: Arc::new(Mutex::new(cursor)),
        stop_flag: Arc::new(AtomicBool::new(false)),
    })
}

impl JournalSubscriber {
    pub fn bootstrap(&self) -> impl Stream<Item = JournalEvent> + Send + 'static {
        let (tx, rx) = mpsc::unbounded::<JournalEvent>();
        let root = self.root.clone();
        let cursor = self.cursor.clone();
        let cursor_root = self.cursor_root.clone();

        std::thread::Builder::new()
            .name("mythkernel-journal-lin/bootstrap".into())
            .spawn(move || {
                let res = walk_getdents64(&root, |path, meta| {
                    let ev = file_create_event(path, meta);
                    let _ = tx.unbounded_send(ev);
                });
                if let Err(err) = res {
                    tracing::warn!(error = %err, "bootstrap getdents64 walk failed");
                    return;
                }
                if let Ok(mut c) = cursor.lock() {
                    c.bootstrap_complete = true;
                    let _ = c.save(&cursor_root);
                }
            })
            .expect("spawn bootstrap thread");

        rx
    }

    pub fn subscribe(&self) -> impl Stream<Item = JournalEvent> + Send + 'static {
        let (tx, rx) = mpsc::unbounded::<JournalEvent>();
        let root = self.root.clone();
        let cursor = self.cursor.clone();
        let cursor_root = self.cursor_root.clone();
        let backend = self.cursor.lock().expect("cursor mutex poisoned").backend;
        let stop_flag = self.stop_flag.clone();

        std::thread::Builder::new()
            .name("mythkernel-journal-lin/subscribe".into())
            .spawn(move || {
                let res = match backend {
                    WatchBackend::Fanotify => {
                        subscribe_fanotify(&root, cursor, &cursor_root, stop_flag, tx.clone())
                    }
                    WatchBackend::Inotify => {
                        subscribe_inotify(&root, cursor, &cursor_root, stop_flag, tx.clone())
                    }
                };
                if let Err(err) = res {
                    tracing::warn!(error = %err, "subscribe loop exited");
                }
                drop(tx);
            })
            .expect("spawn subscribe thread");

        rx
    }
}

fn subscribe_inotify(
    root: &Path,
    cursor: Arc<Mutex<WatchCursor>>,
    cursor_root: &Path,
    stop_flag: Arc<AtomicBool>,
    tx: mpsc::UnboundedSender<JournalEvent>,
) -> Result<(), JournalError> {
    let inotify = InotifyFd::init().map_err(JournalError::InotifyInit)?;

    let mut wd_to_path: HashMap<i32, PathBuf> = HashMap::new();
    add_watch_recursive(&inotify, root, &mut wd_to_path)?;

    let mut pending_renames: HashMap<u32, PathBuf> = HashMap::new();

    let mut buf = vec![0u8; READ_BUFFER_BYTES];

    loop {
        if stop_flag.load(Ordering::SeqCst) || tx.is_closed() {
            return Ok(());
        }

        if !poll_for_input(inotify.raw())? {
            continue;
        }

        let n = match inotify
            .read_into(&mut buf)
            .map_err(JournalError::InotifyRead)?
        {
            Some(n) => n,
            None => continue,
        };
        if n == 0 {
            continue;
        }

        let events: Vec<ParsedInotifyEvent> = InotifyEventIter::new(&buf[..n]).collect();
        let mut emitted: usize = 0;

        for ev in &events {
            let kind = flags::classify_inotify(ev.mask);
            let parent = wd_to_path.get(&ev.wd).cloned();

            match kind {
                ReasonKind::QueueOverflow => {
                    tracing::warn!("inotify queue overflow; rescanning watched root");
                    let _ = walk_getdents64(root, |path, meta| {
                        let _ = tx.unbounded_send(file_create_event(path, meta));
                    });
                    let _ = add_watch_recursive(&inotify, root, &mut wd_to_path);
                }
                ReasonKind::Ignored => {
                    wd_to_path.remove(&ev.wd);
                }
                ReasonKind::Create => {
                    let parent = match parent {
                        Some(p) => p,
                        None => continue,
                    };
                    let path = parent.join(&ev.name);
                    if flags::is_dir_inotify(ev.mask) {
                        if let Ok(wd) = inotify.add_watch(&path, MYTHODIKAL_INOTIFY_MASK) {
                            wd_to_path.insert(wd, path.clone());
                            let _ = walk_getdents64(&path, |child, meta| {
                                let _ = tx.unbounded_send(file_create_event(child, meta));
                            });
                        }
                        continue;
                    }
                    if let Ok(meta) = std::fs::symlink_metadata(&path)
                        && meta.is_file()
                    {
                        if tx.unbounded_send(file_create_event(&path, &meta)).is_err() {
                            return Ok(());
                        }
                        emitted = emitted.saturating_add(1);
                    }
                }
                ReasonKind::Modify => {
                    let parent = match parent {
                        Some(p) => p,
                        None => continue,
                    };
                    let path = parent.join(&ev.name);
                    if flags::is_dir_inotify(ev.mask) {
                        continue;
                    }
                    if tx.unbounded_send(modify_event_for(path)).is_err() {
                        return Ok(());
                    }
                    emitted = emitted.saturating_add(1);
                }
                ReasonKind::Delete => {
                    let parent = match parent {
                        Some(p) => p,
                        None => continue,
                    };
                    let path = parent.join(&ev.name);
                    if flags::is_dir_inotify(ev.mask) {
                        continue;
                    }
                    if tx.unbounded_send(JournalEvent::Delete { path }).is_err() {
                        return Ok(());
                    }
                    emitted = emitted.saturating_add(1);
                }
                ReasonKind::AttrChange => {
                    let parent = match parent {
                        Some(p) => p,
                        None => continue,
                    };
                    let path = parent.join(&ev.name);
                    if flags::is_dir_inotify(ev.mask) {
                        continue;
                    }
                    let attrs = std::fs::symlink_metadata(&path)
                        .map(|m| {
                            use std::os::unix::fs::MetadataExt;
                            m.mode()
                        })
                        .unwrap_or(0);
                    if tx
                        .unbounded_send(JournalEvent::AttrChange { path, attrs })
                        .is_err()
                    {
                        return Ok(());
                    }
                    emitted = emitted.saturating_add(1);
                }
                ReasonKind::RenameOld => {
                    let parent = match parent {
                        Some(p) => p,
                        None => continue,
                    };
                    let path = parent.join(&ev.name);
                    if ev.cookie != 0 {
                        pending_renames.insert(ev.cookie, path);
                    } else if !flags::is_dir_inotify(ev.mask) {
                        if tx.unbounded_send(JournalEvent::Delete { path }).is_err() {
                            return Ok(());
                        }
                        emitted = emitted.saturating_add(1);
                    }
                }
                ReasonKind::RenameNew => {
                    let parent = match parent {
                        Some(p) => p,
                        None => continue,
                    };
                    let new_path = parent.join(&ev.name);
                    let is_dir = flags::is_dir_inotify(ev.mask);
                    if let Some(old_path) = pending_renames.remove(&ev.cookie) {
                        if is_dir {
                            if let Some((wd, _)) = wd_to_path
                                .iter()
                                .find(|(_, p)| **p == old_path)
                                .map(|(k, v)| (*k, v.clone()))
                            {
                                wd_to_path.insert(wd, new_path.clone());
                            }
                        } else if tx
                            .unbounded_send(JournalEvent::Rename { old_path, new_path })
                            .is_err()
                        {
                            return Ok(());
                        } else {
                            emitted = emitted.saturating_add(1);
                        }
                    } else if !is_dir
                        && let Ok(meta) = std::fs::symlink_metadata(&new_path)
                        && meta.is_file()
                    {
                        let _ = tx.unbounded_send(file_create_event(&new_path, &meta));
                        emitted = emitted.saturating_add(1);
                    }
                }
                ReasonKind::Pending | ReasonKind::Other => {}
            }
        }

        if !pending_renames.is_empty() {
            for (_cookie, old_path) in pending_renames.drain() {
                let _ = tx.unbounded_send(JournalEvent::Delete { path: old_path });
                emitted = emitted.saturating_add(1);
            }
        }

        if emitted > 0 {
            if let Ok(mut c) = cursor.lock() {
                c.last_event_time_ns = now_unix_ns();
            }
            let snapshot = cursor.lock().expect("cursor mutex poisoned").clone();
            let _ = snapshot.save(cursor_root);
        }
    }
}

fn add_watch_recursive(
    inotify: &InotifyFd,
    root: &Path,
    wd_to_path: &mut HashMap<i32, PathBuf>,
) -> Result<(), JournalError> {
    match inotify.add_watch(root, MYTHODIKAL_INOTIFY_MASK) {
        Ok(wd) => {
            wd_to_path.insert(wd, root.to_path_buf());
        }
        Err(e) => {
            return Err(JournalError::InotifyAddWatch {
                path: root.to_path_buf(),
                source: e,
            });
        }
    }

    for sub in collect_subdirs(root) {
        match inotify.add_watch(&sub, MYTHODIKAL_INOTIFY_MASK) {
            Ok(wd) => {
                wd_to_path.insert(wd, sub);
            }
            Err(e) => {
                tracing::trace!(dir = %sub.display(), error = %e,
                    "inotify_add_watch failed; skipping subdir");
            }
        }
    }
    Ok(())
}

fn collect_subdirs(root: &Path) -> Vec<PathBuf> {
    use std::collections::HashSet;
    use std::os::unix::fs::MetadataExt;

    let mut out: Vec<PathBuf> = Vec::new();
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
            if n <= 0 {
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
                let (is_subdir, key) = match d_type {
                    libc::DT_DIR => match std::fs::symlink_metadata(&full) {
                        Ok(m) => (true, Some((m.dev(), m.ino()))),
                        Err(_) => (true, None),
                    },
                    libc::DT_UNKNOWN => match std::fs::symlink_metadata(&full) {
                        Ok(m) if m.is_dir() => (true, Some((m.dev(), m.ino()))),
                        _ => (false, None),
                    },
                    _ => (false, None),
                };
                if is_subdir {
                    if let Some(k) = key
                        && !visited.insert(k)
                    {
                        continue;
                    }
                    out.push(full.clone());
                    stack.push(full);
                }
            }
        }
    }
    out
}

fn subscribe_fanotify(
    root: &Path,
    cursor: Arc<Mutex<WatchCursor>>,
    cursor_root: &Path,
    stop_flag: Arc<AtomicBool>,
    tx: mpsc::UnboundedSender<JournalEvent>,
) -> Result<(), JournalError> {
    let fanotify = match FanotifyFd::init(root) {
        Ok(f) => f,
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::EPERM) | Some(libc::EINVAL) | Some(libc::ENOSYS)
            ) =>
        {
            tracing::warn!(error = %e, "fanotify_init failed; falling back to inotify");
            return subscribe_inotify(root, cursor, cursor_root, stop_flag, tx);
        }
        Err(e) => return Err(JournalError::FanotifyInit(e)),
    };
    fanotify
        .mark_filesystem(root, MYTHODIKAL_FANOTIFY_MASK)
        .map_err(|e| JournalError::FanotifyMark {
            path: root.to_path_buf(),
            source: e,
        })?;

    let mut buf = vec![0u8; READ_BUFFER_BYTES];

    loop {
        if stop_flag.load(Ordering::SeqCst) || tx.is_closed() {
            return Ok(());
        }

        if !poll_for_input(fanotify.poll_fd())? {
            continue;
        }

        let n = match fanotify
            .read_into(&mut buf)
            .map_err(JournalError::InotifyRead)?
        {
            Some(n) => n,
            None => continue,
        };
        if n == 0 {
            continue;
        }

        let mut emitted: usize = 0;
        for ev in FanotifyEventIter::new(&buf[..n]) {
            if ev.mask & FAN_Q_OVERFLOW != 0 {
                tracing::warn!("fanotify queue overflow; rescanning watched root");
                let _ = walk_getdents64(root, |path, meta| {
                    let _ = tx.unbounded_send(file_create_event(path, meta));
                });
                continue;
            }
            let kind = flags::classify_fanotify(ev.mask);

            let path = match fanotify.resolve_dfid_name(&ev.handle_bytes, ev.handle_type, &ev.name)
            {
                Ok(Some(p)) => p,
                Ok(None) => continue,
                Err(e) => {
                    tracing::trace!(error = %e, "fanotify FID resolution failed");
                    continue;
                }
            };
            let is_dir = flags::is_dir_fanotify(ev.mask);

            match kind {
                ReasonKind::Create => {
                    if is_dir {
                        continue;
                    }
                    if let Ok(meta) = std::fs::symlink_metadata(&path)
                        && meta.is_file()
                    {
                        let _ = tx.unbounded_send(file_create_event(&path, &meta));
                        emitted = emitted.saturating_add(1);
                    }
                }
                ReasonKind::Modify => {
                    if is_dir {
                        continue;
                    }
                    let _ = tx.unbounded_send(modify_event_for(path));
                    emitted = emitted.saturating_add(1);
                }
                ReasonKind::Delete => {
                    if is_dir {
                        continue;
                    }
                    let _ = tx.unbounded_send(JournalEvent::Delete { path });
                    emitted = emitted.saturating_add(1);
                }
                ReasonKind::AttrChange => {
                    if is_dir {
                        continue;
                    }
                    let attrs = std::fs::symlink_metadata(&path)
                        .map(|m| {
                            use std::os::unix::fs::MetadataExt;
                            m.mode()
                        })
                        .unwrap_or(0);
                    let _ = tx.unbounded_send(JournalEvent::AttrChange { path, attrs });
                    emitted = emitted.saturating_add(1);
                }
                ReasonKind::RenameOld | ReasonKind::RenameNew => {
                    if is_dir {
                        continue;
                    }
                    let new_path = path;
                    if let Some((old_h, old_t, old_n)) = ev.old.as_ref() {
                        match fanotify.resolve_dfid_name(old_h, *old_t, old_n) {
                            Ok(Some(old_path)) => {
                                let _ =
                                    tx.unbounded_send(JournalEvent::Rename { old_path, new_path });
                                emitted = emitted.saturating_add(1);
                            }
                            _ => {
                                if let Ok(meta) = std::fs::symlink_metadata(&new_path)
                                    && meta.is_file()
                                {
                                    let _ = tx.unbounded_send(file_create_event(&new_path, &meta));
                                    emitted = emitted.saturating_add(1);
                                }
                            }
                        }
                    } else if matches!(kind, ReasonKind::RenameNew) {
                        if let Ok(meta) = std::fs::symlink_metadata(&new_path)
                            && meta.is_file()
                        {
                            let _ = tx.unbounded_send(file_create_event(&new_path, &meta));
                            emitted = emitted.saturating_add(1);
                        }
                    } else {
                        let _ = tx.unbounded_send(JournalEvent::Delete { path: new_path });
                        emitted = emitted.saturating_add(1);
                    }
                }
                ReasonKind::QueueOverflow
                | ReasonKind::Ignored
                | ReasonKind::Pending
                | ReasonKind::Other => {}
            }
        }

        if emitted > 0 {
            if let Ok(mut c) = cursor.lock() {
                c.last_event_time_ns = now_unix_ns();
            }
            let snapshot = cursor.lock().expect("cursor mutex poisoned").clone();
            let _ = snapshot.save(cursor_root);
        }
    }
}

fn poll_for_input(fd: std::os::fd::RawFd) -> Result<bool, JournalError> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let p = unsafe { libc::poll(&mut pfd as *mut _, 1, POLL_TIMEOUT_MS) };
    if p < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            return Ok(false);
        }
        return Err(JournalError::InotifyRead(err));
    }
    Ok(p > 0)
}

fn file_create_event(path: &Path, meta: &std::fs::Metadata) -> JournalEvent {
    use std::os::unix::fs::MetadataExt;
    let mtime_ns = (i128::from(meta.mtime())) * 1_000_000_000 + i128::from(meta.mtime_nsec());
    let ctime_ns = (i128::from(meta.ctime())) * 1_000_000_000 + i128::from(meta.ctime_nsec());
    JournalEvent::Create {
        path: path.to_path_buf(),
        size: meta.len(),
        mtime_ns,
        ctime_ns,
        attrs: meta.mode(),
    }
}

fn modify_event_for(path: PathBuf) -> JournalEvent {
    let meta = std::fs::symlink_metadata(&path).ok();
    let (size, mtime_ns, attrs) = match meta {
        Some(m) => {
            use std::os::unix::fs::MetadataExt;
            let mtime_ns = (i128::from(m.mtime())) * 1_000_000_000 + i128::from(m.mtime_nsec());
            (m.len(), mtime_ns, m.mode())
        }
        None => (0, 0, 0),
    };
    JournalEvent::Modify {
        path,
        size,
        mtime_ns,
        attrs,
    }
}

fn now_unix_ns() -> i128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modify_event_handles_missing_file() {
        let ev = modify_event_for(PathBuf::from("/nonexistent/path/that/should/not/exist"));
        match ev {
            JournalEvent::Modify {
                size,
                mtime_ns,
                attrs,
                ..
            } => {
                assert_eq!(size, 0);
                assert_eq!(mtime_ns, 0);
                assert_eq!(attrs, 0);
            }
            _ => panic!("expected Modify"),
        }
    }
}
