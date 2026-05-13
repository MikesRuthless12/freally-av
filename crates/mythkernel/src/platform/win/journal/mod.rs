//! Windows NTFS USN journal subscriber. **Vendored** from sister project
//! `Sourcerer` (`crates/sourcerer-journal-win/`) — both projects are owned by
//! Mike Weaver, so the cross-pollination is intentional.
//!
//! Public surface:
//!
//! ```ignore
//! use mythkernel::platform::win::journal::{open, JournalEvent};
//! use std::path::Path;
//! use futures::StreamExt;
//!
//! # async fn demo() -> Result<(), mythkernel::platform::win::journal::JournalError> {
//! let sub = open(Path::new("C:\\"))?;
//! let mut bootstrap = Box::pin(sub.bootstrap());
//! while let Some(ev) = bootstrap.next().await {
//!     // seed the index / hand to the scan engine
//! }
//! let mut realtime = Box::pin(sub.subscribe());
//! while let Some(ev) = realtime.next().await {
//!     // apply the event
//! }
//! # Ok(()) }
//! ```
//!
//! `bootstrap()` walks the entire MFT once via `FSCTL_ENUM_USN_DATA`. The
//! [`crate::walker::ntfs::NtfsWalker`] adapter (TASK-050) consumes that
//! stream and translates it into the existing [`crate::walker::WalkEvent`]
//! shape so the rest of the engine never learns about the Windows-specific
//! types. `subscribe()` is the live USN journal feed for TASK-051's
//! incremental scan path.

#![cfg(windows)]

pub mod cursor;
pub mod event;
pub mod ffi;
pub mod reasons;
pub mod subscriber;

pub use cursor::{CursorError, VolumeCursor};
pub use event::{JournalError, JournalEvent};
// `subscribe()` + the realtime-event variants of `JournalEvent` aren't yet
// consumed by Mythodikal — Phase 5 wave 1 only uses `bootstrap()` for the
// fast walker. Phase 12 (`mythd-windows` real-time service) will consume
// `subscribe()`. Intentionally retained vendored as-is so the daemon
// pull-up doesn't redo this work.
pub use subscriber::{JournalSubscriber, open, open_with_cursor_root};
