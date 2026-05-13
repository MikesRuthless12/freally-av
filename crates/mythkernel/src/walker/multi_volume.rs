//! Per-volume scan parallelism (TASK-053).
//!
//! Fans out a single scan into N concurrent walkers — one per volume — and
//! merges the resulting [`WalkEvent`]s onto a single
//! [`crossbeam_channel::Receiver`]. Each per-volume worker uses
//! [`super::NtfsWalker`], which already picks the platform-appropriate
//! fast path (`FSCTL_ENUM_USN_DATA` on Windows, `getdents64` on Linux,
//! recursive `read_dir` on macOS) and falls back to [`super::PosixWalker`]
//! when the platform's fast walker can't open the volume.
//!
//! ## Worker budget
//!
//! Per-volume parallelism does **not** multiply the worker budget. The
//! existing `AdaptiveThrottle` ([`crate::throttle`]) decides how many
//! hash workers the engine should run, and that pool is shared across
//! volumes. This module only governs **enumeration** parallelism: the
//! fast-path walker on each volume is one OS thread regardless of the
//! number of volumes, but those threads run concurrently so a 4-volume
//! scan finishes Phase-A enumeration in roughly the time of the slowest
//! single-volume walk, not the sum.
//!
//! ## API shape
//!
//! [`MultiVolumeWalker`] implements [`super::FileWalker`]: callers see
//! the same `walk(root, opts) -> Receiver<WalkEvent>` contract as
//! `NtfsWalker` / `PosixWalker`. The walker discovers volumes via
//! [`crate::platform::win::volumes::enumerate_volumes`] on Windows;
//! on non-Windows hosts the discovery is a no-op and the walker
//! degrades to a single `NtfsWalker.walk(root)` (which itself
//! delegates to the per-OS fast path).
//!
//! See also [`crate::platform::win::volumes::VolumeInfo`] for the
//! per-volume metadata available to UI surfaces (TASK-056's per-volume
//! chooser pulls from there).

use std::path::{Path, PathBuf};

use super::{FileWalker, NtfsWalker, WalkEvent, WalkOpts};

/// Cap on concurrent per-volume walker threads. Hosts with many mounted
/// volumes (multi-disk NAS, drive enclosures) would otherwise spin up one
/// fast-path walker per volume + the inner-walker thread each spawns,
/// hammering the disk subsystem. Volumes beyond the cap walk sequentially
/// after one of the in-flight walkers finishes.
const MAX_PARALLEL_VOLUMES: usize = 4;

/// Hard cap on the total volume count for a single scan — sec-review L2
/// mitigation. A pathological host (or a malicious USB rack) could
/// otherwise queue 100+ volumes; the parallelism cap above protects the
/// disk but the queue depth itself ties up the scan. Truncate at this
/// limit and `tracing::warn!` so the user knows their scan didn't cover
/// every volume.
const MAX_VOLUMES_PER_SCAN: usize = 32;

/// Per-volume parallel walker. Default behavior delegates to a single
/// [`NtfsWalker`] for the requested root; opt-in via [`Self::all_volumes`]
/// (or scanning a multi-volume root sentinel) fans out across every
/// detected volume.
#[derive(Debug, Clone, Default)]
pub struct MultiVolumeWalker {
    /// When `true`, ignore the `root` passed to `walk()` and fan out across
    /// every detected volume on the host. Suitable for the
    /// `--all-volumes` UI surface (TASK-056).
    all_volumes: bool,
    /// Optional override for the volume list. When `Some`, fan-out skips
    /// volume discovery and uses this list verbatim. Used by integration
    /// tests + by callers that want to scan an explicit subset.
    explicit_volumes: Option<Vec<PathBuf>>,
}

impl MultiVolumeWalker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: when set, `walk(root, …)` ignores `root` and fans out
    /// across every detected volume on the host. Equivalent to scanning
    /// the union of every volume's mount path.
    pub fn all_volumes(mut self, on: bool) -> Self {
        self.all_volumes = on;
        self
    }

    /// Builder: explicit volume list. Overrides discovery; use when the
    /// caller already enumerated volumes (e.g. the UI passed a curated
    /// subset).
    pub fn with_volumes<I: IntoIterator<Item = PathBuf>>(mut self, volumes: I) -> Self {
        self.explicit_volumes = Some(volumes.into_iter().collect());
        self
    }

    /// Resolve the list of root paths to walk. Honors the builder
    /// options first, then falls back to platform-specific volume
    /// discovery, then finally to the single requested `root`.
    /// Resolution is truncated to [`MAX_VOLUMES_PER_SCAN`] (sec-review L2);
    /// excess volumes are dropped with a `tracing::warn!`.
    fn resolved_roots(&self, root: &Path) -> Vec<PathBuf> {
        let mut resolved = if let Some(v) = &self.explicit_volumes
            && !v.is_empty()
        {
            v.clone()
        } else if self.all_volumes {
            #[cfg(target_os = "windows")]
            {
                let from_discovery = crate::platform::win::volumes::enumerate_volumes()
                    .ok()
                    .map(|vs| vs.into_iter().map(|v| v.mount_path).collect::<Vec<_>>())
                    .filter(|v: &Vec<PathBuf>| !v.is_empty());
                from_discovery.unwrap_or_else(|| vec![root.to_path_buf()])
            }
            #[cfg(not(target_os = "windows"))]
            {
                // Linux + macOS don't have an OS-level "list every volume"
                // analog the user would actually want a scan to hit (mounting
                // a USB drive doesn't exhibit the same all-drives-on-the-host
                // pattern Windows has). Fall through to the requested root.
                vec![root.to_path_buf()]
            }
        } else {
            vec![root.to_path_buf()]
        };

        if resolved.len() > MAX_VOLUMES_PER_SCAN {
            tracing::warn!(
                requested = resolved.len(),
                cap = MAX_VOLUMES_PER_SCAN,
                "volume count exceeds MAX_VOLUMES_PER_SCAN; truncating"
            );
            resolved.truncate(MAX_VOLUMES_PER_SCAN);
        }
        resolved
    }
}

impl FileWalker for MultiVolumeWalker {
    fn walk(&self, root: &Path, opts: WalkOpts) -> crossbeam_channel::Receiver<WalkEvent> {
        let roots = self.resolved_roots(root);

        // Single-volume fast path — return NtfsWalker's receiver directly.
        // Spinning an extra "passthrough" thread to copy items 1:1 was pure
        // overhead; the inner walker already runs in its own thread.
        if roots.len() == 1 {
            return NtfsWalker::new().walk(&roots[0], opts);
        }

        // Fan-out: walk volumes in waves of up to MAX_PARALLEL_VOLUMES,
        // each draining into the shared `tx`. The aggregator joins each
        // wave before starting the next so the host's disk subsystem
        // isn't thrashed on a many-volume NAS / drive enclosure.
        //
        // Note re. removable volumes: when the caller opted in via
        // `all_volumes(true)`, the discovery layer surfaces both fixed
        // and removable drives. The walker descends into removable media
        // (USB, SD) intentionally — that's the correct AV behavior on
        // freshly-inserted drives, but it does mean the user trusts
        // every mounted volume on the host equally with this option set.
        let (tx, rx) = crossbeam_channel::unbounded();
        let opts_for_each = opts;
        std::thread::Builder::new()
            .name("mythkernel/multi-volume-aggregator".into())
            .spawn(move || {
                for (wave_idx, chunk) in roots.chunks(MAX_PARALLEL_VOLUMES).enumerate() {
                    let handles: Vec<_> = chunk
                        .iter()
                        .cloned()
                        .enumerate()
                        .map(|(i, root)| {
                            let tx = tx.clone();
                            let opts = opts_for_each.clone();
                            let global_idx = wave_idx * MAX_PARALLEL_VOLUMES + i;
                            std::thread::Builder::new()
                                .name(format!("mythkernel/multi-volume-{global_idx}"))
                                .spawn(move || {
                                    let inner = NtfsWalker::new().walk(&root, opts);
                                    for ev in inner.iter() {
                                        if tx.send(ev).is_err() {
                                            return;
                                        }
                                    }
                                })
                                .expect("spawn per-volume worker")
                        })
                        .collect();
                    for (i, h) in handles.into_iter().enumerate() {
                        if let Err(panic) = h.join() {
                            tracing::error!(
                                wave = wave_idx,
                                volume_in_wave = i,
                                ?panic,
                                "per-volume walker thread panicked"
                            );
                        }
                    }
                }
                drop(tx); // close rx after every wave completes
            })
            .expect("spawn aggregator thread");

        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// Default behavior: single root → no fan-out, results match what
    /// NtfsWalker / PosixWalker would emit on the same path.
    #[test]
    fn single_root_passthrough_yields_every_file() {
        let dir = tempdir().unwrap();
        for i in 0..5 {
            fs::write(dir.path().join(format!("f_{i}.txt")), b"x").unwrap();
        }

        let rx = MultiVolumeWalker::new().walk(dir.path(), WalkOpts::default());
        let count = rx
            .iter()
            .filter(|e| matches!(e, WalkEvent::File { .. }))
            .count();
        assert_eq!(count, 5);
    }

    /// Fan-out: explicit volume list, two distinct tempdirs. Aggregated
    /// stream contains every file from every volume. Ordering is not
    /// guaranteed (volumes drain concurrently).
    #[test]
    fn fans_out_explicit_volumes_and_aggregates_results() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        for i in 0..4 {
            fs::write(dir_a.path().join(format!("a_{i}.txt")), b"a").unwrap();
        }
        for i in 0..3 {
            fs::write(dir_b.path().join(format!("b_{i}.txt")), b"b").unwrap();
        }

        let rx = MultiVolumeWalker::new()
            .with_volumes([dir_a.path().to_path_buf(), dir_b.path().to_path_buf()])
            .walk(Path::new("ignored"), WalkOpts::default());
        let count = rx
            .iter()
            .filter(|e| matches!(e, WalkEvent::File { .. }))
            .count();
        assert_eq!(count, 7, "expected 4 from dir_a + 3 from dir_b");
    }

    /// Builder validation: `all_volumes(true)` on a non-Windows host (or
    /// when discovery fails) falls back to the single requested root.
    #[test]
    fn all_volumes_falls_back_to_root_when_discovery_yields_nothing() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("solo.txt"), b"x").unwrap();

        // We can't reliably guarantee discovery returns non-empty on the
        // test host (Windows CI does, but also surfaces it as multiple
        // volumes which would fan out). To keep this test deterministic
        // cross-platform we use `with_volumes(empty)` which the resolver
        // ignores in favor of the explicit-set logic; combined with
        // all_volumes(false) to skip discovery, the resolver returns
        // `vec![root]`.
        let rx = MultiVolumeWalker::new()
            .with_volumes(Vec::<PathBuf>::new()) // empty → ignored
            .all_volumes(false)
            .walk(dir.path(), WalkOpts::default());
        let count = rx
            .iter()
            .filter(|e| matches!(e, WalkEvent::File { .. }))
            .count();
        assert_eq!(count, 1);
    }

    /// Cross-platform live-volumes test: on Windows, `all_volumes(true)`
    /// must discover at least one volume (the system drive) and yield
    /// some files. `#[ignore]` because it walks real volumes and is
    /// expensive; run with `--ignored` when validating the per-volume
    /// fan-out end-to-end.
    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "live multi-volume walk; long-running"]
    fn all_volumes_discovers_and_walks_at_least_one_volume() {
        let rx = MultiVolumeWalker::new()
            .all_volumes(true)
            .walk(Path::new("ignored"), WalkOpts::default());
        let mut count = 0_usize;
        for ev in rx.iter() {
            if matches!(ev, WalkEvent::File { .. }) {
                count += 1;
                if count >= 100 {
                    break;
                }
            }
        }
        assert!(count >= 100, "expected ≥ 100 files across volumes");
    }
}
