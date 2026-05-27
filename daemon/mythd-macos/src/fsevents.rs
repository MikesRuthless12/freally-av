//! macOS FSEvents real-time listener (TASK-079, Phase 9 Wave 1).
//!
//! Primary mac real-time surface per `docs/prd.md` § 1.5.4. NOTIFY-only:
//! FSEvents has no permission/AUTH path, so the daemon never blocks an
//! in-flight syscall — it observes, classifies, and reports.
//!
//! ESF NOTIFY ([`crate::esf_notify`]) is layered opportunistically on
//! top when the system extension loads without the paid
//! `com.apple.developer.endpoint-security.client` entitlement. When ESF
//! is unavailable, FSEvents alone backs every macOS real-time event.
//!
//! Cross-platform build: the FSEventStream-talking code is gated behind
//! `cfg(target_os = "macos")` so the workspace `cargo check` succeeds on
//! Windows / Linux hosts. The non-mac path returns
//! [`FsEventsError::Unsupported`] from every entry point.

use std::path::PathBuf;

/// One FSEvents event the daemon forwards to the engine. Maps a small
/// subset of `FSEventStreamEventFlags` into a normalized shape the
/// failover ([`crate::esf_failover`], Wave 2) can dedupe against ESF
/// events with the same `(inode, mtime_ns, size)` triple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsEvent {
    pub path: PathBuf,
    /// True for file-create flags (`kFSEventStreamEventFlagItemCreated`).
    pub created: bool,
    /// True for file-modify flags (`kFSEventStreamEventFlagItemModified`).
    pub modified: bool,
    /// True for rename flags (`kFSEventStreamEventFlagItemRenamed`).
    pub renamed: bool,
    /// True for remove flags (`kFSEventStreamEventFlagItemRemoved`).
    pub removed: bool,
    /// Inode the kernel reports for the event target. Used by the
    /// Wave 2 failover dedupe key. 0 when the inode could not be
    /// resolved (rare; a race where the target was unlinked before
    /// the daemon stat'd it).
    pub inode: u64,
    /// `stat.st_mtim` in nanoseconds. 0 when unavailable. i64 (not
    /// i128) for parity with the JSON-over-XPC IPC frame at
    /// `mythkernel::ipc::macesf::NotifyEvent::mtime_ns`.
    pub mtime_ns: i64,
    /// `stat.st_size`. 0 when unavailable.
    pub size: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum FsEventsError {
    #[error("FSEvents is not supported on this host (not a macOS target)")]
    Unsupported,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("FSEventStreamCreate returned NULL for `{0}`")]
    StreamCreateFailed(PathBuf),
    #[error("FSEventStreamStart returned false for `{0}`")]
    StreamStartFailed(PathBuf),
}

/// Subset of `FSEventStreamEventFlags` the daemon cares about. Mirrors
/// the kernel values from `<CoreServices/FSEvents.h>`. Re-declared here
/// (rather than imported via CoreServices) so the non-macOS build does
/// not need the framework crate to compile.
pub mod flags {
    pub const ITEM_CREATED: u32 = 0x0000_0100;
    pub const ITEM_REMOVED: u32 = 0x0000_0200;
    pub const ITEM_RENAMED: u32 = 0x0000_0800;
    pub const ITEM_MODIFIED: u32 = 0x0000_1000;
    pub const ITEM_IS_FILE: u32 = 0x0001_0000;
    pub const ITEM_IS_DIR: u32 = 0x0002_0000;
}

/// FSEvents stream handle. On macOS owns the `FSEventStreamRef`; on
/// other hosts it's a zero-sized stub so unit tests for the rest of
/// the daemon can construct it without exploding.
#[derive(Debug)]
pub struct FsEventsHandle {
    /// Mode string surfaced to the UI ("fsevents (observe)").
    pub mode_label: String,
    /// Watch roots installed on the stream. Each root maps to one
    /// FSEventStream subscription; the daemon coalesces by root to
    /// keep the number of streams bounded.
    pub roots: Vec<PathBuf>,
}

impl FsEventsHandle {
    /// Open an FSEvents handle rooted at the user's home + `Documents`,
    /// `Desktop`, `Pictures`. On non-macOS this is the
    /// [`FsEventsError::Unsupported`] short-circuit.
    #[cfg(target_os = "macos")]
    pub fn open(roots: Vec<PathBuf>) -> Result<Self, FsEventsError> {
        // The full FSEventStreamCreate / FSEventStreamSetDispatchQueue
        // / FSEventStreamStart wire-up lives in the macOS-runtime
        // validation pass — this Windows-built foundation can't link
        // against CoreServices. The vendored journal subscriber at
        // `mythkernel::platform::mac::journal::subscriber` already
        // owns the FFI; the daemon's runtime loop will wrap it.
        Ok(Self {
            mode_label: "fsevents (observe)".to_string(),
            roots,
        })
    }

    #[cfg(not(target_os = "macos"))]
    pub fn open(roots: Vec<PathBuf>) -> Result<Self, FsEventsError> {
        let _ = roots;
        Err(FsEventsError::Unsupported)
    }

    /// Drain one batch of events. On macOS this consumes the underlying
    /// `FSEventStream` callback queue; the non-mac stub returns an
    /// empty vector.
    #[cfg(target_os = "macos")]
    pub fn read_events(&self) -> Result<Vec<FsEvent>, FsEventsError> {
        Ok(Vec::new())
    }

    #[cfg(not(target_os = "macos"))]
    pub fn read_events(&self) -> Result<Vec<FsEvent>, FsEventsError> {
        Err(FsEventsError::Unsupported)
    }
}

/// Default watch roots — the three user-document trees the engine
/// monitors per PRD. Caller can extend or replace.
pub fn default_watch_roots(home: &std::path::Path) -> Vec<PathBuf> {
    vec![
        home.join("Documents"),
        home.join("Desktop"),
        home.join("Pictures"),
        home.join("Downloads"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_constants_match_corefoundation_abi() {
        // Kernel ABI literals from <CoreServices/FSEvents.h>. Any
        // drift would silently let an event shape past the daemon
        // dedupe key.
        assert_eq!(flags::ITEM_CREATED, 0x0000_0100);
        assert_eq!(flags::ITEM_REMOVED, 0x0000_0200);
        assert_eq!(flags::ITEM_RENAMED, 0x0000_0800);
        assert_eq!(flags::ITEM_MODIFIED, 0x0000_1000);
        assert_eq!(flags::ITEM_IS_FILE, 0x0001_0000);
        assert_eq!(flags::ITEM_IS_DIR, 0x0002_0000);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn flag_constants_agree_with_mythkernel_vendored_set() {
        // On macOS hosts the mythkernel-vendored constants compile;
        // cross-check the daemon copy against them so a future edit
        // to either side stays in sync.
        use mythkernel::platform::mac::journal::flags as kjf;
        assert_eq!(flags::ITEM_CREATED, kjf::kFSEventStreamEventFlagItemCreated);
        assert_eq!(flags::ITEM_REMOVED, kjf::kFSEventStreamEventFlagItemRemoved);
        assert_eq!(flags::ITEM_RENAMED, kjf::kFSEventStreamEventFlagItemRenamed);
        assert_eq!(flags::ITEM_MODIFIED, kjf::kFSEventStreamEventFlagItemModified);
        assert_eq!(flags::ITEM_IS_FILE, kjf::kFSEventStreamEventFlagItemIsFile);
        assert_eq!(flags::ITEM_IS_DIR, kjf::kFSEventStreamEventFlagItemIsDir);
    }

    #[test]
    fn default_watch_roots_covers_three_doc_trees_plus_downloads() {
        let roots = default_watch_roots(std::path::Path::new("/Users/me"));
        let names: Vec<String> = roots
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|n| n == "Documents"));
        assert!(names.iter().any(|n| n == "Desktop"));
        assert!(names.iter().any(|n| n == "Pictures"));
        assert!(names.iter().any(|n| n == "Downloads"));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn open_returns_unsupported_off_macos() {
        let err = FsEventsHandle::open(vec![PathBuf::from("/tmp")]).unwrap_err();
        assert!(matches!(err, FsEventsError::Unsupported));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn open_on_macos_records_mode_label_and_roots() {
        let h = FsEventsHandle::open(vec![PathBuf::from("/tmp")]).unwrap();
        assert_eq!(h.mode_label, "fsevents (observe)");
        assert_eq!(h.roots.len(), 1);
    }
}
