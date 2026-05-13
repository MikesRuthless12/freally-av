//! `JournalEvent` + `JournalError` — vendored from Sourcerer.
//!
//! Mirrored verbatim by the macOS and Linux real-time crates in later
//! Mythodikal phases (8/9/12) so the engine consumes any subscriber
//! through a single shape.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JournalEvent {
    Create {
        path: PathBuf,
        size: u64,
        mtime_ns: i128,
        ctime_ns: i128,
        attrs: u32,
    },
    Modify {
        path: PathBuf,
        size: u64,
        mtime_ns: i128,
        attrs: u32,
    },
    Delete {
        path: PathBuf,
    },
    Rename {
        old_path: PathBuf,
        new_path: PathBuf,
    },
    AttrChange {
        path: PathBuf,
        attrs: u32,
    },
}

impl JournalEvent {
    pub fn primary_path(&self) -> &std::path::Path {
        match self {
            JournalEvent::Create { path, .. }
            | JournalEvent::Modify { path, .. }
            | JournalEvent::Delete { path }
            | JournalEvent::AttrChange { path, .. } => path,
            JournalEvent::Rename { new_path, .. } => new_path,
        }
    }

    pub fn variant_name(&self) -> &'static str {
        match self {
            JournalEvent::Create { .. } => "Create",
            JournalEvent::Modify { .. } => "Modify",
            JournalEvent::Delete { .. } => "Delete",
            JournalEvent::Rename { .. } => "Rename",
            JournalEvent::AttrChange { .. } => "AttrChange",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("volume path is not a Windows drive root (expected e.g. `C:\\`): {0}")]
    InvalidVolumePath(PathBuf),
    #[error("FSCTL_QUERY_USN_JOURNAL failed: {0}")]
    QueryJournal(#[source] std::io::Error),
    #[error("FSCTL_ENUM_USN_DATA failed: {0}")]
    EnumMft(#[source] std::io::Error),
    #[error("FSCTL_READ_USN_JOURNAL failed: {0}")]
    ReadJournal(#[source] std::io::Error),
    #[error("opening volume `{0}` failed: {1}")]
    OpenVolume(PathBuf, #[source] std::io::Error),
    #[error("resolving file `{frn}` to a path failed: {source}")]
    ResolvePath {
        frn: u64,
        #[source]
        source: std::io::Error,
    },
    #[error("cursor persistence error: {0}")]
    Cursor(#[from] crate::platform::win::journal::cursor::CursorError),
    #[error("operation not supported on this platform; the USN journal subscriber is Windows-only")]
    UnsupportedPlatform,
}
