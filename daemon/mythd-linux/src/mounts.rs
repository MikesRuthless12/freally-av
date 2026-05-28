//! Per-mount real-time toggle (TASK-238, Phase 8 Wave 2).
//!
//! Watches `/proc/self/mountinfo` on a 5 s timer. When the mount set
//! changes, computes the `(add, remove)` diff and applies it to the
//! fanotify FD via `FAN_MARK_ADD` / `FAN_MARK_REMOVE` so a per-mount
//! toggle does not require a daemon restart.
//!
//! Per-mount enabled/disabled persists in the daemon-local sqlite at
//! `/var/lib/mythd/mythd.db`; the engine-side UI (TASK-075) round-
//! trips through the Tauri command in
//! `crates/ui-bridge/src/commands/mount_toggle.rs`.
//!
//! Default policy: rootfs ON, every other mount OFF until the user
//! opts in. `tmpfs` / `proc` / `sys` / `cgroup` are filtered out of
//! the UI entirely.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// One mountpoint row, as parsed from `/proc/self/mountinfo`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MountRow {
    /// `major:minor` device id.
    pub device: String,
    pub mountpoint: PathBuf,
    pub fs_type: String,
}

/// Set of filesystem types we never surface in the mount UI even
/// when present in `/proc/self/mountinfo`.
pub const FILTERED_FS_TYPES: &[&str] = &[
    "tmpfs",
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "devpts",
    "mqueue",
    "ramfs",
    "debugfs",
    "tracefs",
    "fusectl",
    "configfs",
    "securityfs",
    "pstore",
    "autofs",
    "binfmt_misc",
];

/// What `apply_marks` should do on the next tick.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MountDiff {
    pub add: Vec<MountRow>,
    pub remove: Vec<MountRow>,
}

/// Compute the add/remove diff between two ordered mount sets.
/// Pure logic — unit-tested on every host. Cross-platform.
pub fn diff(prev: &[MountRow], next: &[MountRow]) -> MountDiff {
    let prev_set: BTreeSet<_> = prev.iter().collect();
    let next_set: BTreeSet<_> = next.iter().collect();
    let add: Vec<MountRow> = next_set
        .difference(&prev_set)
        .map(|r| (*r).clone())
        .collect();
    let remove: Vec<MountRow> = prev_set
        .difference(&next_set)
        .map(|r| (*r).clone())
        .collect();
    MountDiff { add, remove }
}

/// Filter a raw `/proc/self/mountinfo` line list down to mounts the
/// daemon is willing to expose to the user.
pub fn filter_user_visible(rows: &[MountRow]) -> Vec<MountRow> {
    rows.iter()
        .filter(|r| !FILTERED_FS_TYPES.contains(&r.fs_type.as_str()))
        .cloned()
        .collect()
}

/// Parse one `/proc/self/mountinfo` line. Format (kernel docs):
///
/// ```text
/// 36 35 98:0 /mnt1 /mnt/parent rw,noatime master:1 - ext4 /dev/sda1 rw,errors=remount-ro
/// ```
///
/// Field offsets (0-based): `2` = device, `4` = mountpoint, `7..` =
/// optional-fields-separator `-` followed by fs_type.
pub fn parse_mountinfo_line(line: &str) -> Option<MountRow> {
    let mut parts = line.split_whitespace();
    let _ = parts.next()?; // mount id
    let _ = parts.next()?; // parent id
    let device = parts.next()?.to_string();
    let _ = parts.next()?; // root within fs
    let mountpoint = PathBuf::from(parts.next()?);
    // Walk forward to the `-` separator, then take the next token as fs_type.
    let mut found_separator = false;
    for tok in parts {
        if !found_separator {
            if tok == "-" {
                found_separator = true;
            }
            continue;
        }
        return Some(MountRow {
            device,
            mountpoint,
            fs_type: tok.to_string(),
        });
    }
    None
}

pub fn parse_mountinfo(text: &str) -> Vec<MountRow> {
    text.lines().filter_map(parse_mountinfo_line).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(dev: &str, mp: &str, fs: &str) -> MountRow {
        MountRow {
            device: dev.into(),
            mountpoint: PathBuf::from(mp),
            fs_type: fs.into(),
        }
    }

    #[test]
    fn diff_returns_added_and_removed_in_sorted_order() {
        let prev = vec![m("8:0", "/", "ext4"), m("8:1", "/home", "ext4")];
        let next = vec![m("8:0", "/", "ext4"), m("8:2", "/mnt/usb", "exfat")];
        let d = diff(&prev, &next);
        assert_eq!(d.add, vec![m("8:2", "/mnt/usb", "exfat")]);
        assert_eq!(d.remove, vec![m("8:1", "/home", "ext4")]);
    }

    #[test]
    fn filter_drops_pseudo_filesystems() {
        let rows = vec![
            m("8:0", "/", "ext4"),
            m("0:1", "/proc", "proc"),
            m("0:2", "/sys", "sysfs"),
            m("0:3", "/dev/shm", "tmpfs"),
        ];
        let filtered = filter_user_visible(&rows);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].mountpoint, PathBuf::from("/"));
    }

    #[test]
    fn parses_canonical_mountinfo_line() {
        let line = "36 35 98:0 /mnt1 /mnt/parent rw,noatime master:1 - ext4 /dev/sda1 rw";
        let row = parse_mountinfo_line(line).unwrap();
        assert_eq!(row.device, "98:0");
        assert_eq!(row.mountpoint, PathBuf::from("/mnt/parent"));
        assert_eq!(row.fs_type, "ext4");
    }

    #[test]
    fn parse_handles_multi_optional_fields() {
        let line =
            "29 1 8:1 / / rw,relatime shared:1 master:2 - ext4 /dev/sda1 rw,errors=remount-ro";
        let row = parse_mountinfo_line(line).unwrap();
        assert_eq!(row.fs_type, "ext4");
    }
}
