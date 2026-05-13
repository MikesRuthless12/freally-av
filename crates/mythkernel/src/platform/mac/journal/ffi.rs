//! Thin safe wrappers around FSEvents + CoreFoundation + statfs —
//! vendored from Sourcerer.

#![cfg(target_os = "macos")]

use std::ffi::{CStr, CString, c_void};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use core_foundation::array::{CFArray, CFArrayRef};
use core_foundation::base::TCFType;
use core_foundation::runloop::{CFRunLoop, CFRunLoopRef};
use core_foundation::string::{CFString, CFStringRef};

use core_foundation_sys::runloop::{
    CFRunLoopRunInMode, CFRunLoopStop, kCFRunLoopDefaultMode, kCFRunLoopRunFinished,
    kCFRunLoopRunStopped, kCFRunLoopRunTimedOut,
};

use fsevent_sys::{
    FSEventStreamContext, FSEventStreamCreate, FSEventStreamEventFlags, FSEventStreamEventId,
    FSEventStreamInvalidate, FSEventStreamRef, FSEventStreamRelease,
    FSEventStreamScheduleWithRunLoop, FSEventStreamStart, FSEventStreamStop,
    kFSEventStreamCreateFlagFileEvents, kFSEventStreamCreateFlagNoDefer,
    kFSEventStreamCreateFlagUseCFTypes, kFSEventStreamCreateFlagWatchRoot,
};

pub const MYTHODIKAL_STREAM_CREATE_FLAGS: u32 = kFSEventStreamCreateFlagFileEvents
    | kFSEventStreamCreateFlagNoDefer
    | kFSEventStreamCreateFlagUseCFTypes
    | kFSEventStreamCreateFlagWatchRoot;

pub fn paths_array_for(root: &Path) -> Option<CFArray<CFString>> {
    let s = root.to_str()?;
    Some(CFArray::from_CFTypes(&[CFString::new(s)]))
}

/// # Safety
/// `context` must point at a valid `FSEventStreamContext` whose `info`
/// outlives the stream.
pub unsafe fn create_stream(
    callback: extern "C" fn(
        FSEventStreamRef,
        *mut c_void,
        usize,
        *mut c_void,
        *const FSEventStreamEventFlags,
        *const FSEventStreamEventId,
    ),
    context: *mut FSEventStreamContext,
    paths_to_watch: CFArrayRef,
    since_when: u64,
    latency_secs: f64,
) -> FSEventStreamRef {
    unsafe {
        FSEventStreamCreate(
            ptr::null_mut(),
            callback,
            context,
            paths_to_watch as *mut c_void,
            since_when,
            latency_secs,
            MYTHODIKAL_STREAM_CREATE_FLAGS,
        )
    }
}

/// # Safety
/// `stream` must be a non-null, unreleased `FSEventStreamRef`.
pub unsafe fn schedule_and_start(stream: FSEventStreamRef) -> bool {
    unsafe {
        let run_loop = CFRunLoop::get_current();
        FSEventStreamScheduleWithRunLoop(
            stream,
            run_loop.as_concrete_TypeRef() as *mut c_void,
            kCFRunLoopDefaultMode as *mut c_void,
        );
        FSEventStreamStart(stream) != 0
    }
}

/// # Safety
/// If non-null, `stream` must be an unreleased `FSEventStreamRef`.
pub unsafe fn teardown_stream(stream: FSEventStreamRef) {
    if stream.is_null() {
        return;
    }
    unsafe {
        FSEventStreamStop(stream);
        FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
    }
}

/// # Safety
/// `run_loop` must be a `CFRunLoopRef` still alive on its owning thread.
pub unsafe fn signal_stop(run_loop: CFRunLoopRef) {
    unsafe { CFRunLoopStop(run_loop) }
}

/// # Safety
/// Must be called on the thread that scheduled the FSEvents stream onto
/// its run loop.
pub unsafe fn run_until_stopped(cycle_seconds: f64) -> RunLoopExit {
    let status = unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, cycle_seconds, 0) };
    match status {
        x if x == kCFRunLoopRunStopped => RunLoopExit::Stopped,
        x if x == kCFRunLoopRunFinished => RunLoopExit::Finished,
        x if x == kCFRunLoopRunTimedOut => RunLoopExit::TimedOut,
        _ => RunLoopExit::Other(status),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunLoopExit {
    Stopped,
    Finished,
    TimedOut,
    Other(i32),
}

pub fn statfs_name(path: &Path) -> io::Result<String> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::statfs(c.as_ptr(), &mut buf) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    let raw = unsafe { CStr::from_ptr(buf.f_fstypename.as_ptr()) };
    Ok(raw.to_string_lossy().into_owned())
}

pub fn device_id(path: &Path) -> io::Result<u64> {
    let meta = std::fs::symlink_metadata(path)?;
    use std::os::unix::fs::MetadataExt;
    Ok(meta.dev())
}

/// # Safety
/// `cf_str` must be a non-null `CFStringRef` alive for the duration of the call.
pub unsafe fn cfstring_to_pathbuf(cf_str: CFStringRef) -> Option<PathBuf> {
    if cf_str.is_null() {
        return None;
    }
    let owned = unsafe { CFString::wrap_under_get_rule(cf_str) };
    Some(PathBuf::from(owned.to_string()))
}
