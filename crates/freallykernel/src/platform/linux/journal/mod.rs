//! Linux inotify+fanotify journal subscriber. **Vendored** from sister
//! project `Sourcerer` (`crates/sourcerer-journal-lin/`) — both projects
//! are owned by Mike Weaver, so the cross-pollination is intentional.
//!
//! Public surface mirrors `platform::win::journal` and
//! `platform::mac::journal`:
//!
//! ```ignore
//! use freallykernel::platform::linux::journal::{open, JournalEvent};
//! use std::path::Path;
//! use futures::StreamExt;
//!
//! # async fn demo() -> Result<(), freallykernel::platform::linux::journal::JournalError> {
//! let sub = open(Path::new("/home/me/Documents"))?;
//! let mut bootstrap = Box::pin(sub.bootstrap());
//! while let Some(ev) = bootstrap.next().await {
//!     // seed the index
//! }
//! let mut realtime = Box::pin(sub.subscribe());
//! while let Some(ev) = realtime.next().await {
//!     // apply the event
//! }
//! # Ok(()) }
//! ```
//!
//! Builds compile cleanly on Windows + macOS too — the inotify /
//! fanotify-backed modules are gated behind `cfg(target_os = "linux")`.
//!
//! ## Backend choice
//!
//! - **inotify** (default): `inotify_add_watch` recursively across every
//!   directory under the root. No privileges required.
//! - **fanotify** (CAP_SYS_ADMIN required): one `fanotify_mark` call
//!   covers the entire mount with `FAN_REPORT_DFID_NAME`, giving correct
//!   rename tracking on overlayfs / Btrfs subvolume crossings.
//!
//! Bootstrap walks via raw `getdents64` on Linux — much faster than
//! `std::fs::read_dir` on huge trees because each syscall returns
//! thousands of entries packed into a single buffer.

pub mod cursor;
pub mod event;
pub mod flags;

#[cfg(target_os = "linux")]
pub mod ffi;
#[cfg(target_os = "linux")]
pub mod subscriber;

pub use cursor::{CursorError, WatchBackend, WatchCursor};
pub use event::{JournalError, JournalEvent};

// `subscribe()` + the non-Create variants of `JournalEvent` aren't consumed
// in Phase 5 wave 1 — only `bootstrap()` powers the fast walker. Phase 8
// (`freallyd-linux` fanotify daemon) will consume `subscribe()`. Intentionally
// retained vendored as-is.
#[cfg(target_os = "linux")]
pub use subscriber::{JournalSubscriber, open, open_with_cursor_root};

#[cfg(not(target_os = "linux"))]
pub fn open(_root: &std::path::Path) -> Result<JournalSubscriber, JournalError> {
    Err(JournalError::UnsupportedPlatform)
}

#[cfg(not(target_os = "linux"))]
pub fn open_with_cursor_root(
    _root: &std::path::Path,
    _cursor_root: &std::path::Path,
) -> Result<JournalSubscriber, JournalError> {
    Err(JournalError::UnsupportedPlatform)
}

#[cfg(not(target_os = "linux"))]
pub struct JournalSubscriber {
    _private: (),
}

#[cfg(not(target_os = "linux"))]
impl JournalSubscriber {
    pub fn bootstrap(&self) -> impl futures::Stream<Item = JournalEvent> + Send + 'static {
        futures::stream::empty()
    }

    pub fn subscribe(&self) -> impl futures::Stream<Item = JournalEvent> + Send + 'static {
        futures::stream::empty()
    }

    pub fn root(&self) -> &std::path::Path {
        std::path::Path::new("")
    }

    pub fn cursor(&self) -> WatchCursor {
        WatchCursor {
            root: std::path::PathBuf::new(),
            device: 0,
            fs_name: String::new(),
            backend: WatchBackend::Inotify,
            bootstrap_complete: false,
            last_event_time_ns: 0,
        }
    }
}
