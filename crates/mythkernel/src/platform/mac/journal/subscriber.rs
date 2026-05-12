//! `JournalSubscriber` — vendored from Sourcerer (macOS / FSEvents).

#![cfg(target_os = "macos")]

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use core_foundation::base::TCFType;
use core_foundation::string::CFStringRef;
use core_foundation_sys::array::{
    CFArrayGetCount, CFArrayGetValueAtIndex, CFArrayRef as CfArrayRefRaw,
};

use fsevent_sys::{
    FSEventStreamContext, FSEventStreamEventFlags, FSEventStreamEventId, FSEventStreamRef,
    kFSEventStreamEventIdSinceNow,
};

use futures::Stream;
use futures::channel::mpsc;

use super::cursor::StreamCursor;
use super::event::{JournalError, JournalEvent};
use super::ffi::{
    RunLoopExit, cfstring_to_pathbuf, create_stream, device_id, paths_array_for, run_until_stopped,
    schedule_and_start, signal_stop, statfs_name, teardown_stream,
};
use super::flags::{self, FlagKind};

const FSEVENTS_LATENCY_SECS: f64 = 0.5;
const RUN_LOOP_CYCLE_SECS: f64 = 1.0;

pub struct JournalSubscriber {
    root: PathBuf,
    cursor_root: PathBuf,
    cursor: Arc<Mutex<StreamCursor>>,
    run_loop_ptr: Arc<AtomicUsize>,
    stop_flag: Arc<AtomicBool>,
}

impl JournalSubscriber {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn cursor(&self) -> StreamCursor {
        self.cursor.lock().expect("cursor mutex poisoned").clone()
    }
}

impl Drop for JournalSubscriber {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        let raw = self.run_loop_ptr.load(Ordering::SeqCst);
        if raw == 0 {
            return;
        }
        unsafe { signal_stop(raw as _) }
    }
}

pub fn open(root: &Path) -> Result<JournalSubscriber, JournalError> {
    open_with_cursor_root(root, &StreamCursor::default_root())
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

    let persisted = StreamCursor::load(cursor_root, &canonical)?;
    let cursor = match persisted {
        Some(c) if c.device == dev => StreamCursor {
            root: canonical.clone(),
            device: c.device,
            last_event_id: c.last_event_id,
            fs_name: fs_name.clone(),
            bootstrap_complete: c.bootstrap_complete,
        },
        Some(stale) => {
            tracing::info!(
                root = %canonical.display(),
                old_device = stale.device,
                new_device = dev,
                "persisted FSEvents cursor is on a different device; resetting to SinceNow",
            );
            StreamCursor {
                root: canonical.clone(),
                device: dev,
                last_event_id: 0,
                fs_name: fs_name.clone(),
                bootstrap_complete: false,
            }
        }
        None => StreamCursor {
            root: canonical.clone(),
            device: dev,
            last_event_id: 0,
            fs_name: fs_name.clone(),
            bootstrap_complete: false,
        },
    };
    cursor.save(cursor_root)?;

    Ok(JournalSubscriber {
        root: canonical,
        cursor_root: cursor_root.to_path_buf(),
        cursor: Arc::new(Mutex::new(cursor)),
        run_loop_ptr: Arc::new(AtomicUsize::new(0)),
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
            .name("mythkernel-journal-mac/bootstrap".into())
            .spawn(move || {
                if let Err(err) = bootstrap_thread(&root, &tx) {
                    tracing::warn!(error = %err, "bootstrap walk failed");
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
        let run_loop_ptr = self.run_loop_ptr.clone();
        let stop_flag = self.stop_flag.clone();

        std::thread::Builder::new()
            .name("mythkernel-journal-mac/subscribe".into())
            .spawn(move || {
                if let Err(err) = subscribe_thread(
                    &root,
                    cursor,
                    &cursor_root,
                    run_loop_ptr,
                    stop_flag,
                    tx.clone(),
                ) {
                    tracing::warn!(error = %err, "FSEvents subscribe loop exited");
                }
                drop(tx);
            })
            .expect("spawn subscribe thread");

        rx
    }
}

fn bootstrap_thread(
    root: &Path,
    tx: &mpsc::UnboundedSender<JournalEvent>,
) -> Result<(), JournalError> {
    walk_dir(root, tx).map_err(|e| JournalError::WalkFailed(root.to_path_buf(), e))
}

fn walk_dir(dir: &Path, tx: &mpsc::UnboundedSender<JournalEvent>) -> std::io::Result<()> {
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let read = match std::fs::read_dir(&current) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                tracing::trace!(dir = %current.display(), "skipping unreadable dir");
                continue;
            }
            Err(e) => return Err(e),
        };
        for entry in read {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    tracing::trace!(error = %e, "skipping unreadable entry");
                    continue;
                }
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let ev = file_create_event(&path, &meta);
            if tx.unbounded_send(ev).is_err() {
                return Ok(());
            }
        }
    }
    Ok(())
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
    let meta = std::fs::metadata(&path).ok();
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

struct CtxBoxGuard {
    ptr: *mut CallbackContext,
}

impl CtxBoxGuard {
    fn new(ctx: Box<CallbackContext>) -> Self {
        Self {
            ptr: Box::into_raw(ctx),
        }
    }
    fn raw(&self) -> *mut CallbackContext {
        self.ptr
    }
}

impl Drop for CtxBoxGuard {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            let _ = unsafe { Box::from_raw(self.ptr) };
            self.ptr = std::ptr::null_mut();
        }
    }
}

fn subscribe_thread(
    root: &Path,
    cursor: Arc<Mutex<StreamCursor>>,
    cursor_root: &Path,
    run_loop_ptr: Arc<AtomicUsize>,
    stop_flag: Arc<AtomicBool>,
    tx: mpsc::UnboundedSender<JournalEvent>,
) -> Result<(), JournalError> {
    let paths =
        paths_array_for(root).ok_or_else(|| JournalError::InvalidRoot(root.to_path_buf()))?;

    let ctx_guard = CtxBoxGuard::new(Box::new(CallbackContext::new(tx.clone(), cursor.clone())));

    let mut stream_context = FSEventStreamContext {
        version: 0,
        info: ctx_guard.raw().cast::<c_void>(),
        retain: None,
        release: None,
        copy_description: None,
    };

    let since_when = match cursor.lock() {
        Ok(c) if c.last_event_id != 0 => c.last_event_id,
        _ => kFSEventStreamEventIdSinceNow,
    };

    let run_loop_raw =
        core_foundation::runloop::CFRunLoop::get_current().as_concrete_TypeRef() as usize;
    run_loop_ptr.store(run_loop_raw, Ordering::SeqCst);

    let stream: FSEventStreamRef = unsafe {
        create_stream(
            fsevents_callback,
            &mut stream_context,
            paths.as_concrete_TypeRef(),
            since_when,
            FSEVENTS_LATENCY_SECS,
        )
    };
    if stream.is_null() {
        run_loop_ptr.store(0, Ordering::SeqCst);
        return Err(JournalError::StreamCreateFailed(root.to_path_buf()));
    }

    let started = unsafe { schedule_and_start(stream) };
    if !started {
        unsafe { teardown_stream(stream) };
        run_loop_ptr.store(0, Ordering::SeqCst);
        return Err(JournalError::StreamStartFailed(root.to_path_buf()));
    }

    loop {
        let exit = unsafe { run_until_stopped(RUN_LOOP_CYCLE_SECS) };
        match exit {
            RunLoopExit::Stopped | RunLoopExit::Finished => break,
            RunLoopExit::TimedOut => {
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }
                if tx.is_closed() {
                    break;
                }
                if let Ok(c) = cursor.lock() {
                    let snapshot = c.clone();
                    drop(c);
                    let _ = snapshot.save(cursor_root);
                }
            }
            RunLoopExit::Other(code) => {
                tracing::warn!(code, "CFRunLoopRunInMode returned an unexpected status");
                break;
            }
        }
    }

    unsafe { teardown_stream(stream) };
    run_loop_ptr.store(0, Ordering::SeqCst);

    if let Ok(c) = cursor.lock() {
        let snapshot = c.clone();
        drop(c);
        let _ = snapshot.save(cursor_root);
    }

    drop(ctx_guard);
    Ok(())
}

struct CallbackContext {
    tx: mpsc::UnboundedSender<JournalEvent>,
    cursor: Arc<Mutex<StreamCursor>>,
    known_inodes: HashMap<u64, PathBuf>,
    seen_paths: HashSet<PathBuf>,
}

impl CallbackContext {
    fn new(tx: mpsc::UnboundedSender<JournalEvent>, cursor: Arc<Mutex<StreamCursor>>) -> Self {
        Self {
            tx,
            cursor,
            known_inodes: HashMap::new(),
            seen_paths: HashSet::new(),
        }
    }
}

extern "C" fn fsevents_callback(
    _stream_ref: FSEventStreamRef,
    info: *mut c_void,
    num_events: usize,
    event_paths: *mut c_void,
    event_flags: *const FSEventStreamEventFlags,
    event_ids: *const FSEventStreamEventId,
) {
    if info.is_null() || event_paths.is_null() || num_events == 0 {
        return;
    }
    let ctx: &mut CallbackContext = unsafe { &mut *(info.cast::<CallbackContext>()) };

    if ctx.tx.is_closed() {
        return;
    }

    let paths_arr = event_paths as CfArrayRefRaw;
    let flags_slice: &[FSEventStreamEventFlags] =
        unsafe { std::slice::from_raw_parts(event_flags, num_events) };
    let ids_slice: &[FSEventStreamEventId] =
        unsafe { std::slice::from_raw_parts(event_ids, num_events) };

    let array_len = unsafe { CFArrayGetCount(paths_arr as _) } as usize;
    if array_len != num_events {
        tracing::warn!(
            array_len,
            num_events,
            "FSEvents callback: paths array length disagrees with num_events"
        );
    }
    let len = num_events.min(array_len);

    let mut decoded: Vec<DecodedEvent> = Vec::with_capacity(len);
    let mut rescan_dirs: Vec<PathBuf> = Vec::new();
    let mut max_event_id: u64 = 0;

    for i in 0..len {
        let flags = flags_slice[i];
        let id = ids_slice[i];
        if id > max_event_id {
            max_event_id = id;
        }

        let cf_ptr = unsafe { CFArrayGetValueAtIndex(paths_arr as _, i as isize) };
        let path = match unsafe { cfstring_to_pathbuf(cf_ptr as CFStringRef) } {
            Some(p) => p,
            None => continue,
        };

        let kind = flags::classify(flags);
        match kind {
            FlagKind::MustScanSubDirs => rescan_dirs.push(path),
            FlagKind::RootChanged => {
                tracing::warn!(path = %path.display(), "FSEvents RootChanged");
            }
            FlagKind::Ignore => {}
            other => decoded.push(DecodedEvent {
                kind: other,
                flags,
                path,
            }),
        }
    }

    let mut emit: Vec<JournalEvent> = Vec::with_capacity(decoded.len());

    let rename_idxs: Vec<usize> = decoded
        .iter()
        .enumerate()
        .filter_map(|(i, d)| {
            if d.kind == FlagKind::RenameMaybe && !flags::is_dir(d.flags) {
                Some(i)
            } else {
                None
            }
        })
        .collect();

    let halves: Vec<(usize, bool, Option<u64>)> = rename_idxs
        .iter()
        .map(|&i| {
            let path = &decoded[i].path;
            let exists = path.exists();
            let inode = if exists { inode_of(path) } else { None };
            (i, exists, inode)
        })
        .collect();

    let mut consumed = vec![false; halves.len()];
    for k in 0..halves.len() {
        if consumed[k] {
            continue;
        }
        let (i, exists_i, inode_i) = halves[k];

        let partner = (k + 1..halves.len()).find(|&p| {
            if consumed[p] {
                return false;
            }
            let (_, exists_p, inode_p) = halves[p];
            if exists_i && exists_p {
                inode_p == inode_i && inode_i.is_some()
            } else {
                exists_i != exists_p
            }
        });

        if let Some(p) = partner {
            consumed[k] = true;
            consumed[p] = true;
            let (j, _, _) = halves[p];
            let path_i = decoded[i].path.clone();
            let path_j = decoded[j].path.clone();
            let (old_path, new_path) = if exists_i {
                (path_j, path_i)
            } else {
                (path_i, path_j)
            };
            ctx.known_inodes.retain(|_, p| p != &old_path);
            ctx.seen_paths.remove(&old_path);
            if let Some(ino) = inode_of(&new_path) {
                ctx.known_inodes.insert(ino, new_path.clone());
            }
            ctx.seen_paths.insert(new_path.clone());
            emit.push(JournalEvent::Rename { old_path, new_path });
            continue;
        }

        consumed[k] = true;
        let path = decoded[i].path.clone();
        if exists_i {
            if let Ok(meta) = std::fs::metadata(&path)
                && meta.is_file()
            {
                if let Some(ino) = inode_i {
                    ctx.known_inodes.insert(ino, path.clone());
                }
                if ctx.seen_paths.insert(path.clone()) {
                    emit.push(file_create_event(&path, &meta));
                } else {
                    emit.push(modify_event_for(path.clone()));
                }
            }
        } else {
            ctx.known_inodes.retain(|_, p| p != &path);
            ctx.seen_paths.remove(&path);
            emit.push(JournalEvent::Delete { path });
        }
    }

    for d in decoded.iter() {
        if d.kind == FlagKind::RenameMaybe {
            continue;
        }
        if flags::is_dir(d.flags) && !flags::is_file(d.flags) {
            continue;
        }
        match d.kind {
            FlagKind::Create => {
                if let Ok(meta) = std::fs::metadata(&d.path)
                    && meta.is_file()
                {
                    if let Some(ino) = inode_of(&d.path) {
                        ctx.known_inodes.insert(ino, d.path.clone());
                    }
                    if ctx.seen_paths.insert(d.path.clone()) {
                        emit.push(file_create_event(&d.path, &meta));
                    } else {
                        emit.push(modify_event_for(d.path.clone()));
                    }
                }
            }
            FlagKind::Modify => emit.push(modify_event_for(d.path.clone())),
            FlagKind::Delete => {
                ctx.known_inodes.retain(|_, p| p != &d.path);
                ctx.seen_paths.remove(&d.path);
                emit.push(JournalEvent::Delete {
                    path: d.path.clone(),
                });
            }
            FlagKind::AttrChange => {
                let attrs = std::fs::metadata(&d.path)
                    .map(|m| {
                        use std::os::unix::fs::MetadataExt;
                        m.mode()
                    })
                    .unwrap_or(0);
                emit.push(JournalEvent::AttrChange {
                    path: d.path.clone(),
                    attrs,
                });
            }
            FlagKind::RenameMaybe
            | FlagKind::MustScanSubDirs
            | FlagKind::RootChanged
            | FlagKind::Ignore => {}
        }
    }

    for ev in emit {
        if ctx.tx.unbounded_send(ev).is_err() {
            return;
        }
    }

    for dir in rescan_dirs {
        if !dir.is_dir() {
            continue;
        }
        let _ = walk_dir(&dir, &ctx.tx);
    }

    if max_event_id != 0
        && let Ok(mut c) = ctx.cursor.lock()
        && max_event_id > c.last_event_id
    {
        c.last_event_id = max_event_id;
    }
}

#[derive(Debug, Clone)]
struct DecodedEvent {
    kind: FlagKind,
    flags: FSEventStreamEventFlags,
    path: PathBuf,
}

fn inode_of(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).ok().map(|m| m.ino())
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
