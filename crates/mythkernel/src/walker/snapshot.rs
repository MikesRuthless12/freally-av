//! TASK-215 — Live snapshot scan (VSS / APFS / Btrfs).
//!
//! Scans a *snapshot* of the filesystem rather than the live tree so
//! files modified during the scan are seen as of the snapshot point.
//! Without this, a file we hashed at t=0 and then evaluated at t=10
//! might be different — a moving target that breaks the "every
//! finding row corresponds to one byte-state of one file" invariant.
//!
//! Three backends, all user-mode (per `docs/prd.md` § 1.5 — no
//! kernel drivers):
//!
//! - **Windows VSS** via WMI/COM (`Win32_ShadowCopy.Create`). The
//!   actual COM call lives in the per-OS daemon
//!   (`daemon/mythd-windows/src/snapshot/vss.rs`) so the engine's
//!   dep tree stays slim.
//! - **macOS APFS** via `tmutil localsnapshot` + `mount_apfs -s`.
//!   Shells out to the system binaries.
//! - **Linux Btrfs** via `btrfs subvolume snapshot -r`. Same: shells
//!   out to the system binary.
//!
//! Failure mode is graceful — if snapshot creation fails (no VSS
//! provider, no `tmutil` permission, no `btrfs` binary), the engine
//! logs a warning and scans the live tree. The scan never fails
//! because of a missing snapshot capability.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Which backend produced this snapshot. Read by the engine when
/// surfacing telemetry; informational only at the data layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Vss,
    Apfs,
    Btrfs,
    /// Stub backend — useful for tests and for OSes where no
    /// snapshot capability is available; the snapshot path maps
    /// 1:1 to the live path.
    Passthrough,
}

/// A live-to-snapshot translation table.
///
/// Construct via [`Snapshot::passthrough`] (no-op), or via the
/// per-OS factories (in the daemon crates). The engine consumes the
/// `Snapshot` interface and never cares which backend produced it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub backend: Backend,
    /// Where the snapshot is mounted (or its root for backends that
    /// expose paths directly).
    pub mount_point: PathBuf,
    /// Root the engine is scanning, expressed as a *live* path.
    /// Used for `live_to_snapshot` / `live_path_for` translation.
    pub live_root: PathBuf,
    /// Best-effort label / handle used for teardown (`{c1bbf1c1-…}`
    /// shadow-copy ID on Windows, snapshot name on Btrfs, mount
    /// point ID on macOS).
    pub handle: String,
}

impl Snapshot {
    /// Pass-through snapshot — the "snapshot" path is the live path.
    /// Used when snapshot creation fails or when scanning a tree
    /// that isn't on a snapshotable volume.
    pub fn passthrough<P: Into<PathBuf>>(live_root: P) -> Self {
        let p = live_root.into();
        Self {
            backend: Backend::Passthrough,
            mount_point: p.clone(),
            live_root: p,
            handle: String::new(),
        }
    }

    /// Translate a live path to the equivalent path inside the
    /// snapshot. Returns `None` when `live_path` is outside the
    /// snapshot's `live_root`, or when the relative remainder
    /// contains `..` / root components — those would let a hostile
    /// file name (or buggy caller) escape `mount_point` and target
    /// arbitrary paths outside the snapshot.
    pub fn live_to_snapshot(&self, live_path: &Path) -> Option<PathBuf> {
        let rel = live_path.strip_prefix(&self.live_root).ok()?;
        if !is_safe_relative(rel) {
            return None;
        }
        if matches!(self.backend, Backend::Passthrough) {
            return Some(live_path.to_path_buf());
        }
        let mut p = self.mount_point.clone();
        if rel.as_os_str().is_empty() {
            return Some(p);
        }
        p.push(rel);
        Some(p)
    }

    /// Inverse of [`Self::live_to_snapshot`] — translate a path
    /// inside the snapshot back to its live counterpart. Returns
    /// `None` when `snap_path` is outside the snapshot mount, or
    /// when the relative remainder contains `..` / root components.
    pub fn live_path_for(&self, snap_path: &Path) -> Option<PathBuf> {
        if matches!(self.backend, Backend::Passthrough) {
            return Some(snap_path.to_path_buf());
        }
        let rel = snap_path.strip_prefix(&self.mount_point).ok()?;
        if !is_safe_relative(rel) {
            return None;
        }
        let mut p = self.live_root.clone();
        if rel.as_os_str().is_empty() {
            return Some(p);
        }
        p.push(rel);
        Some(p)
    }

    /// Tear down the snapshot. The host daemon does the actual
    /// `vssadmin delete shadows` / `btrfs subvolume delete` /
    /// `tmutil deletelocalsnapshots`. This is an idempotent stub at
    /// the engine layer; callers invoke it once per Snapshot at end
    /// of scan (or on Drop in the daemon).
    pub fn teardown(&self) -> Result<(), SnapshotError> {
        // Real teardown lives in the daemon's per-OS module. The
        // engine no-ops at this layer so the scan loop can call
        // `snapshot.teardown()` regardless of backend without
        // platform branching.
        Ok(())
    }
}

/// Errors that a backend can surface up to the engine.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    #[error("snapshot provider unavailable: {0}")]
    ProviderUnavailable(String),
    #[error("snapshot creation failed: {0}")]
    CreationFailed(String),
    #[error("snapshot teardown failed: {0}")]
    TeardownFailed(String),
    #[error("snapshot path translation failed: {0}")]
    PathTranslation(String),
}

/// TTL for an auto-cleaned snapshot. Stale snapshots from a crashed
/// scan are cleaned by the daemon's hourly sweep.
pub const DEFAULT_TTL_HOURS: u32 = 24;

/// True iff `rel` is a safe relative path to append to `mount_point` /
/// `live_root`: every component must be `Normal(_)` (no `ParentDir`,
/// no `RootDir`, no absolute prefix). Without this gate, a hostile
/// path like `/snap/2026-05-27/../../etc/passwd` would translate
/// back to `/home/alice/../../etc/passwd` and corrupt finding-row
/// path identity for downstream queries / UI.
fn is_safe_relative(rel: &Path) -> bool {
    use std::path::Component;
    for c in rel.components() {
        match c {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pb(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn passthrough_round_trips_paths() {
        let s = Snapshot::passthrough("/home/alice");
        assert_eq!(
            s.live_to_snapshot(Path::new("/home/alice/work/foo.rs")),
            Some(pb("/home/alice/work/foo.rs"))
        );
        assert_eq!(
            s.live_path_for(Path::new("/home/alice/work/foo.rs")),
            Some(pb("/home/alice/work/foo.rs"))
        );
    }

    #[test]
    fn live_path_to_snapshot_strips_root_and_remaps() {
        let s = Snapshot {
            backend: Backend::Btrfs,
            mount_point: pb("/snap/2026-05-27"),
            live_root: pb("/home/alice"),
            handle: "snap-1".into(),
        };
        assert_eq!(
            s.live_to_snapshot(Path::new("/home/alice/foo.rs")),
            Some(pb("/snap/2026-05-27/foo.rs"))
        );
        assert_eq!(
            s.live_to_snapshot(Path::new("/home/alice")),
            Some(pb("/snap/2026-05-27"))
        );
    }

    #[test]
    fn snapshot_path_back_to_live_for_each_backend() {
        for backend in [Backend::Vss, Backend::Apfs, Backend::Btrfs] {
            let s = Snapshot {
                backend,
                mount_point: pb("/snap/root"),
                live_root: pb("/data"),
                handle: "h".into(),
            };
            assert_eq!(
                s.live_path_for(Path::new("/snap/root/a/b/c.txt")),
                Some(pb("/data/a/b/c.txt")),
                "backend {backend:?}"
            );
        }
    }

    #[test]
    fn outside_root_returns_none() {
        let s = Snapshot {
            backend: Backend::Btrfs,
            mount_point: pb("/snap/2026-05-27"),
            live_root: pb("/home/alice"),
            handle: "snap-1".into(),
        };
        assert_eq!(
            s.live_to_snapshot(Path::new("/etc/passwd")),
            None,
            "paths outside live_root must not translate"
        );
        assert_eq!(
            s.live_path_for(Path::new("/some/other/path")),
            None,
            "paths outside mount_point must not reverse-translate"
        );
    }

    #[test]
    fn teardown_is_idempotent_at_engine_layer() {
        let s = Snapshot::passthrough("/x");
        s.teardown().unwrap();
        s.teardown().unwrap();
    }

    #[test]
    fn serde_round_trip() {
        let s = Snapshot {
            backend: Backend::Vss,
            mount_point: pb(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3"),
            live_root: pb(r"C:\Users\miken"),
            handle: "{1234-abcd}".into(),
        };
        let j = serde_json::to_string(&s).unwrap();
        let s2: Snapshot = serde_json::from_str(&j).unwrap();
        assert_eq!(s.backend, s2.backend);
        assert_eq!(s.mount_point, s2.mount_point);
        assert_eq!(s.live_root, s2.live_root);
        assert_eq!(s.handle, s2.handle);
    }

    #[test]
    fn error_display_strings() {
        let e = SnapshotError::ProviderUnavailable("no VSS service".into());
        assert!(e.to_string().contains("no VSS service"));
    }

    #[test]
    fn ttl_default_24h() {
        assert_eq!(DEFAULT_TTL_HOURS, 24);
    }

    #[test]
    fn translation_rejects_parent_dir_traversal() {
        let s = Snapshot {
            backend: Backend::Btrfs,
            mount_point: pb("/snap/2026-05-27"),
            live_root: pb("/home/alice"),
            handle: "snap-1".into(),
        };
        // A snap_path inside the mount but containing `..` components
        // would let a back-translation escape the live_root.
        assert!(
            s.live_path_for(Path::new("/snap/2026-05-27/../../etc/passwd"))
                .is_none(),
            "back-translation must reject `..` segments"
        );
        // Symmetric: a live_path with `..` would corrupt snapshot
        // translation. (strip_prefix matches the prefix literally and
        // returns `../../etc/passwd` as the remainder.)
        assert!(
            s.live_to_snapshot(Path::new("/home/alice/../../etc/passwd"))
                .is_none(),
            "forward translation must reject `..` segments"
        );
    }

    #[test]
    fn is_safe_relative_accepts_normal_paths() {
        assert!(is_safe_relative(Path::new("foo/bar.rs")));
        assert!(is_safe_relative(Path::new("")));
        assert!(is_safe_relative(Path::new("./foo")));
    }

    #[test]
    fn is_safe_relative_rejects_parent_dir() {
        assert!(!is_safe_relative(Path::new("../etc/passwd")));
        assert!(!is_safe_relative(Path::new("foo/../bar")));
    }

    #[test]
    fn live_root_translation_when_root_is_the_path() {
        let s = Snapshot {
            backend: Backend::Btrfs,
            mount_point: pb("/snap"),
            live_root: pb("/data"),
            handle: String::new(),
        };
        assert_eq!(s.live_to_snapshot(Path::new("/data")), Some(pb("/snap")));
        assert_eq!(s.live_path_for(Path::new("/snap")), Some(pb("/data")));
    }
}
