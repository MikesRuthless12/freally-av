//! Ransomware honeyfile tripwires (TASK-142, FR-142, Phase 8).
//!
//! Plant a fixed number of dot-prefixed canary files in user-document
//! trees on first run. The platform real-time daemon watches for any
//! **write** to a canary path; on hit, SIGSTOP the writer's process
//! tree and surface a critical finding.
//!
//! This module is **cross-platform planning logic only** — the
//! actually-watch-and-signal part lives in
//! `daemon/mythd-linux/src/rules/honey.rs` (Linux today),
//! `daemon/mythd-macos/src/rules/honey.rs` (Phase 9, TASK-161), and
//! `daemon/mythd-windows/src/rules/honey.rs` (Phase 12, TASK-162).
//!
//! Planning is shared because every platform follows the same recipe:
//!
//!  1. enumerate user-document roots (`~/Documents`, `~/Desktop`,
//!     `~/Pictures` per the PRD; the caller supplies the list because
//!     "user document tree" varies per platform)
//!  2. for each root, generate a fixed list of dot-prefixed names
//!     spread across deterministic subdirectories so a re-run on the
//!     same user lands on the same set of paths
//!  3. write each canary with a tiny benign payload (~1 KiB of dot
//!     filler) and mark them readable + writable so a ransomware
//!     write hits the watcher
//!
//! Determinism: `plan_canaries(root, seed)` returns the same list
//! whenever called with the same arguments. The `seed` is typically
//! derived from the install ID so two installs on the same machine
//! land on different paths (defeats a ransomware author who memorizes
//! a canonical canary list).

use std::path::{Path, PathBuf};

/// Default canary count per root. Roadmap says "~50" — 48 evenly
/// distributes 16 per subdir × 3 subdirs without an awkward remainder.
pub const DEFAULT_CANARY_COUNT: usize = 48;

/// Tiny benign content written to every canary so the watcher always
/// has a known baseline to compare against. Exactly 1 KiB of dots so
/// the file is small enough to ignore in scan totals.
const CANARY_PAYLOAD: &[u8] = &[b'.'; 1024];

/// Deterministic subdirectory tree the planner spreads canaries
/// across, relative to each user-document root. The names are
/// dot-prefixed so a casual `ls` does not surface them.
const SUBDIRS: &[&str] = &[".cache_index", ".sync_meta", ".thumb_cache"];

/// One planned canary path + its install-time seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryPath {
    pub path: PathBuf,
    /// Stable per-canary id (used in finding rule_id). Two installs
    /// with different seeds get different ids; the SAME install
    /// always gets the SAME id for the same path, so post-write the
    /// daemon can correlate "the file that was written" back to "the
    /// canary slot that was tripped" without a path lookup.
    pub slot: u32,
}

/// Plan `count` canaries under `root` using `seed` as the determinism
/// key. Always returns exactly `count` paths spread evenly across
/// [`SUBDIRS`]. Caller is responsible for actually creating the
/// directories and writing [`CANARY_PAYLOAD`] to each path; this
/// function is pure.
pub fn plan_canaries(root: &Path, count: usize, seed: u64) -> Vec<CanaryPath> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let subdir = SUBDIRS[i % SUBDIRS.len()];
        let slot = i as u32;
        // Name shape: `.canary_<seed8>_<slot4>.bin` — fixed length so
        // a UI inspector sorts them naturally. seed8 / slot4 ensures
        // two installs never collide on the same name.
        let name = format!(
            ".canary_{:08x}_{:04x}.bin",
            (seed as u32) ^ (slot.wrapping_mul(2_654_435_761)),
            slot
        );
        let path = root.join(subdir).join(name);
        out.push(CanaryPath { path, slot });
    }
    out
}

/// Plant `count` canaries under `root` on disk. Creates the
/// subdirectories under [`SUBDIRS`] on demand and writes
/// [`CANARY_PAYLOAD`] to each path. Idempotent — paths that already
/// exist with the correct content are left untouched (writing would
/// itself trip the daemon's watcher if it had already loaded the
/// plan).
pub fn plant_canaries(
    root: &Path,
    count: usize,
    seed: u64,
) -> Result<Vec<CanaryPath>, std::io::Error> {
    let plan = plan_canaries(root, count, seed);
    for c in &plan {
        if let Some(parent) = c.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Re-write only when needed — see doc comment above.
        match std::fs::read(&c.path) {
            Ok(buf) if buf.as_slice() == CANARY_PAYLOAD => continue,
            _ => std::fs::write(&c.path, CANARY_PAYLOAD)?,
        }
    }
    Ok(plan)
}

/// Returns true if `path` matches the canary-name shape under one of
/// the canonical subdirs. Daemons use this as a fast prefilter on
/// every write event before consulting the loaded canary set.
pub fn is_canary_shape(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    if !file_name.starts_with(".canary_") || !file_name.ends_with(".bin") {
        return false;
    }
    let parent_name = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("");
    SUBDIRS.contains(&parent_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn plan_is_deterministic_for_same_seed() {
        let root = Path::new("/tmp/honey");
        let a = plan_canaries(root, 12, 0xdead_beef);
        let b = plan_canaries(root, 12, 0xdead_beef);
        assert_eq!(a, b);
    }

    #[test]
    fn plan_differs_across_seeds() {
        let root = Path::new("/tmp/honey");
        let a = plan_canaries(root, 8, 1);
        let b = plan_canaries(root, 8, 2);
        // Names contain the seed; paths must differ entry-by-entry.
        for (x, y) in a.iter().zip(b.iter()) {
            assert_ne!(x.path, y.path, "seed 1 and 2 produced the same path");
        }
    }

    #[test]
    fn plan_distributes_evenly_across_subdirs() {
        let plan = plan_canaries(Path::new("/r"), 6, 0);
        let mut counts = std::collections::HashMap::new();
        for c in &plan {
            let dir = c.path.parent().unwrap().file_name().unwrap().to_owned();
            *counts.entry(dir).or_insert(0u32) += 1;
        }
        // Six canaries / three subdirs = two per subdir.
        for c in counts.values() {
            assert_eq!(*c, 2);
        }
    }

    #[test]
    fn plant_writes_files_then_is_idempotent() {
        let dir = tempdir().unwrap();
        let plan = plant_canaries(dir.path(), 4, 7).unwrap();
        for c in &plan {
            let body = std::fs::read(&c.path).unwrap();
            assert_eq!(body, CANARY_PAYLOAD);
        }
        // Second call must not rewrite files (would itself trip the
        // watcher). Capture mtime, re-plant, check unchanged.
        let mtime_before = std::fs::metadata(&plan[0].path)
            .unwrap()
            .modified()
            .unwrap();
        let _ = plant_canaries(dir.path(), 4, 7).unwrap();
        let mtime_after = std::fs::metadata(&plan[0].path)
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(mtime_before, mtime_after);
    }

    #[test]
    fn is_canary_shape_recognizes_planned_paths() {
        let plan = plan_canaries(Path::new("/root"), 3, 42);
        for c in &plan {
            assert!(is_canary_shape(&c.path), "expected canary: {:?}", c.path);
        }
    }

    #[test]
    fn is_canary_shape_rejects_unrelated_paths() {
        assert!(!is_canary_shape(Path::new(
            "/home/me/.cache_index/note.txt"
        )));
        assert!(!is_canary_shape(Path::new(
            "/home/me/Documents/.canary_abc.bin"
        )));
        assert!(!is_canary_shape(Path::new("/x/.thumb_cache/y.bin")));
    }
}
