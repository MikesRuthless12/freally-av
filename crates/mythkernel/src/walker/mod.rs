//! Cross-platform file walker.
//!
//! Phase 1 ships the [`FileWalker`] trait and the cross-platform posix
//! implementation. The NTFS MFT walker (TASK-050) and the USN incremental
//! walker (TASK-051) live alongside in `ntfs.rs` and `incremental.rs` and
//! also satisfy [`FileWalker`].
//!
//! See `docs/prd.md` § 6.1 (FR-001..FR-007) and § 7 (NFR-001).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub mod incremental;
pub mod multi_volume;
pub mod ntfs;
pub mod posix;

pub use incremental::IncrementalWalker;
pub use multi_volume::MultiVolumeWalker;
pub use ntfs::NtfsWalker;
pub use posix::PosixWalker;

/// Options that govern a single walk.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WalkOpts {
    /// Follow symbolic links during traversal. Default `false` per FR-007.
    pub follow_symlinks: bool,
    /// Skip dot-prefixed entries (`.git`, `.cache`, etc.). Default `false`.
    pub skip_hidden: bool,
    /// Cap traversal depth (root = 0). `None` = unlimited.
    pub max_depth: Option<usize>,
}

/// One observation from the walker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalkEvent {
    /// A regular file the engine should consider for hashing/detection.
    File {
        path: PathBuf,
        size: u64,
        /// Last-modified time as seconds since UNIX epoch.
        mtime: i64,
    },
    /// An entry the walker chose not to descend into (permission, symlink-loop, etc.).
    Skipped { path: PathBuf, reason: String },
    /// A non-fatal error encountered for a single entry.
    Error { path: PathBuf, message: String },
}

/// Implemented by every walker backend (posix, NTFS MFT, USN incremental).
///
/// Phase 1 returns a synchronous receiver of [`WalkEvent`]s. The scan engine
/// (TASK-012) wraps the receiver with `tokio_stream::wrappers` when it needs
/// an `async Stream`. Walkers run their producer on a rayon thread so callers
/// can drain at their own pace.
pub trait FileWalker {
    /// Begin a walk rooted at `root`. The returned receiver yields events
    /// in roughly enumeration order; all sender threads end before the
    /// channel closes.
    fn walk(
        &self,
        root: &std::path::Path,
        opts: WalkOpts,
    ) -> crossbeam_channel::Receiver<WalkEvent>;
}
