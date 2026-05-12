//! macOS FSEvents journal subscriber. **Vendored** from sister project
//! `Sourcerer` (`crates/sourcerer-journal-mac/`) — both projects are owned
//! by Mike Weaver, so the cross-pollination is intentional.
//!
//! Public surface mirrors `platform::win::journal` so the engine can pick
//! between the two via `cfg(target_os = ...)`:
//!
//! ```ignore
//! use mythkernel::platform::mac::journal::{open, JournalEvent};
//! use std::path::Path;
//! use futures::StreamExt;
//!
//! # async fn demo() -> Result<(), mythkernel::platform::mac::journal::JournalError> {
//! let sub = open(Path::new("/Users/me/Documents"))?;
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
//! Builds compile cleanly on Windows + Linux too — the FSEvents-backed
//! modules are gated behind `cfg(target_os = "macos")` and the rest of
//! the workspace sees a typed-but-stubbed surface.

pub mod cursor;
pub mod event;
pub mod flags;

#[cfg(target_os = "macos")]
pub mod ffi;
#[cfg(target_os = "macos")]
pub mod subscriber;

pub use cursor::{CursorError, StreamCursor};
pub use event::{JournalError, JournalEvent};

#[cfg(target_os = "macos")]
pub use subscriber::{JournalSubscriber, open, open_with_cursor_root};

/// Stub `open()` for non-macOS hosts so the workspace builds cross-OS.
#[cfg(not(target_os = "macos"))]
pub fn open(_root: &std::path::Path) -> Result<JournalSubscriber, JournalError> {
    Err(JournalError::UnsupportedPlatform)
}

#[cfg(not(target_os = "macos"))]
pub fn open_with_cursor_root(
    _root: &std::path::Path,
    _cursor_root: &std::path::Path,
) -> Result<JournalSubscriber, JournalError> {
    Err(JournalError::UnsupportedPlatform)
}

#[cfg(not(target_os = "macos"))]
pub struct JournalSubscriber {
    _private: (),
}

#[cfg(not(target_os = "macos"))]
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

    pub fn cursor(&self) -> StreamCursor {
        StreamCursor {
            root: std::path::PathBuf::new(),
            device: 0,
            last_event_id: 0,
            fs_name: String::new(),
            bootstrap_complete: false,
        }
    }
}
