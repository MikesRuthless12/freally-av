//! macOS `JournalEvent` + `JournalError` — vendored from Sourcerer.

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
    #[error("watch root must be an absolute, existing directory: {0}")]
    InvalidRoot(PathBuf),
    #[error("FSEventStreamCreate returned NULL for `{0}`")]
    StreamCreateFailed(PathBuf),
    #[error("FSEventStreamStart returned false for `{0}`")]
    StreamStartFailed(PathBuf),
    #[error("opening watch root `{0}` failed: {1}")]
    OpenRoot(PathBuf, #[source] std::io::Error),
    #[error("statfs(`{0}`) failed: {1}")]
    Statfs(PathBuf, #[source] std::io::Error),
    #[error("filesystem walk of `{0}` failed: {1}")]
    WalkFailed(PathBuf, #[source] std::io::Error),
    #[error("cursor persistence error: {0}")]
    Cursor(#[from] super::cursor::CursorError),
    #[error("operation not supported on this platform; the macOS journal subscriber is macOS-only")]
    UnsupportedPlatform,
}
