//! Cross-platform posix walker.
//!
//! Uses `walkdir` for enumeration and `rayon::par_bridge` so per-entry
//! `metadata()` calls run on the rayon threadpool. Suitable as a fallback
//! on every platform — Windows uses it when the volume is non-NTFS, and
//! macOS/Linux use it everywhere until ESF/fanotify lands.
//!
//! Cancellation: when the caller drops the returned `Receiver`, the
//! first failing `tx.send()` flips a shared `aborted` flag and every
//! other rayon task short-circuits on its next iteration. Without
//! this, the rayon thread pool stays pinned to the cancelled walk for
//! the full enumeration time of the volume — which on a big D:\
//! would starve a subsequent quick-restart scan from making progress.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::UNIX_EPOCH;

use rayon::prelude::*;

use super::{FileWalker, WalkEvent, WalkOpts};

#[derive(Debug, Default, Clone, Copy)]
pub struct PosixWalker;

impl PosixWalker {
    pub fn new() -> Self {
        Self
    }
}

impl FileWalker for PosixWalker {
    fn walk(&self, root: &Path, opts: WalkOpts) -> crossbeam_channel::Receiver<WalkEvent> {
        let (tx, rx) = crossbeam_channel::unbounded();
        let root = root.to_path_buf();
        let aborted = Arc::new(AtomicBool::new(false));

        let aborted_for_iter = aborted.clone();
        let aborted_for_tasks = aborted.clone();
        let log_root = root.clone();
        let sent_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let sent_count_for_log = sent_count.clone();
        let sent_count_for_tasks = sent_count.clone();
        rayon::spawn(move || {
            tracing::info!(root = %log_root.display(), "PosixWalker starting");
            let mut builder = walkdir::WalkDir::new(&log_root).follow_links(opts.follow_symlinks);
            if let Some(max_depth) = opts.max_depth {
                builder = builder.max_depth(max_depth);
            }

            builder
                .into_iter()
                .filter_entry(|entry| {
                    if !opts.skip_hidden {
                        return true;
                    }
                    let name = entry.file_name().to_string_lossy();
                    !(name.starts_with('.') && entry.depth() > 0)
                })
                // Stop pulling from walkdir the moment any task observes
                // the receiver was dropped. Without this the underlying
                // walkdir thread keeps recursing through the volume
                // (descending directories, calling stat on every entry)
                // long after the user cancelled — which is what was
                // starving a quick-restart scan of rayon-walker capacity.
                .take_while(move |_| !aborted_for_iter.load(Ordering::Relaxed))
                .par_bridge()
                .for_each(|res| {
                    // Belt-and-suspenders: once any rayon task has
                    // noticed the receiver was dropped (its send
                    // returned `SendError`), every other task skips
                    // its remaining work — freeing the rayon pool for
                    // the next scan even if some items are mid-flight.
                    if aborted_for_tasks.load(Ordering::Relaxed) {
                        return;
                    }
                    let event = match res {
                        Ok(entry) => {
                            let path = entry.path().to_path_buf();
                            if !entry.file_type().is_file() {
                                return;
                            }
                            match entry.metadata() {
                                Ok(metadata) => {
                                    let mtime = metadata
                                        .modified()
                                        .ok()
                                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                                        .map(|d| d.as_secs() as i64)
                                        .unwrap_or(0);
                                    WalkEvent::File {
                                        path,
                                        size: metadata.len(),
                                        mtime,
                                    }
                                }
                                Err(err) => WalkEvent::Error {
                                    path,
                                    message: err.to_string(),
                                },
                            }
                        }
                        Err(err) => WalkEvent::Error {
                            path: err.path().map(Path::to_path_buf).unwrap_or_default(),
                            message: err.to_string(),
                        },
                    };
                    if tx.send(event).is_err() {
                        aborted.store(true, Ordering::Relaxed);
                    } else {
                        sent_count_for_tasks.fetch_add(1, Ordering::Relaxed);
                    }
                });
            tracing::info!(
                root = %log_root.display(),
                sent = sent_count_for_log.load(Ordering::Relaxed),
                aborted = aborted.load(Ordering::Relaxed),
                "PosixWalker finished"
            );
        });
        let _ = sent_count;

        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn walks_a_flat_directory() {
        let dir = tempdir().unwrap();
        for i in 0..10 {
            let p = dir.path().join(format!("file_{i}.txt"));
            fs::write(&p, format!("content {i}")).unwrap();
        }

        let walker = PosixWalker::new();
        let rx = walker.walk(dir.path(), WalkOpts::default());

        let mut files = 0;
        for event in rx.iter() {
            if matches!(event, WalkEvent::File { .. }) {
                files += 1;
            }
        }
        assert_eq!(files, 10);
    }

    #[test]
    fn respects_max_depth() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("c");
        fs::create_dir_all(&nested).unwrap();
        fs::write(dir.path().join("top.txt"), "top").unwrap();
        fs::write(dir.path().join("a").join("mid.txt"), "mid").unwrap();
        fs::write(nested.join("deep.txt"), "deep").unwrap();

        let walker = PosixWalker::new();
        let rx = walker.walk(
            dir.path(),
            WalkOpts {
                max_depth: Some(1),
                ..WalkOpts::default()
            },
        );

        let files: Vec<_> = rx
            .iter()
            .filter(|e| matches!(e, WalkEvent::File { .. }))
            .collect();
        assert_eq!(files.len(), 1, "only top-level file at max_depth=1");
    }

    #[test]
    fn skip_hidden_excludes_dotfiles() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("visible.txt"), "v").unwrap();
        fs::write(dir.path().join(".hidden"), "h").unwrap();

        let walker = PosixWalker::new();
        let rx = walker.walk(
            dir.path(),
            WalkOpts {
                skip_hidden: true,
                ..WalkOpts::default()
            },
        );

        let files: Vec<_> = rx
            .iter()
            .filter_map(|e| match e {
                WalkEvent::File { path, .. } => Some(path),
                _ => None,
            })
            .collect();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].file_name().unwrap(), "visible.txt");
    }
}
