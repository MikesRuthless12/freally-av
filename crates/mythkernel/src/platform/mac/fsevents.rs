//! macOS FSEvents real-time facade (TASK-079, Phase 9 Wave 1).
//!
//! Thin re-export of [`crate::platform::mac::journal`] under the
//! FSEvents name. The journal module is the vendored Sourcerer
//! subscriber; "FSEvents" is the name the rest of the codebase + UI
//! string set uses, so callers wanting the macOS real-time stream
//! reach for `platform::mac::fsevents::open()` instead of digging into
//! the journal namespace.
//!
//! Per `docs/prd.md` § 1.5.4: NOTIFY-only on macOS. No paid Apple
//! Developer Program entitlement, no AUTH path. FSEvents is the
//! durable Mythodikal default on macOS; ESF NOTIFY ([`crate::ipc::macesf`])
//! layers opportunistically on top when the system extension loads
//! without an entitlement.

pub use crate::platform::mac::journal::{
    CursorError, JournalError as FsEventsError, JournalEvent as FsEventsEvent, StreamCursor,
    open as open_stream, open_with_cursor_root,
};

#[cfg(target_os = "macos")]
pub use crate::platform::mac::journal::JournalSubscriber as FsEventsSubscriber;

#[cfg(not(target_os = "macos"))]
pub use crate::platform::mac::journal::JournalSubscriber as FsEventsSubscriber;
