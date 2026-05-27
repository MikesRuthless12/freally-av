//! TASK-212 — NTFS reparse-point / junction traversal policy.
//!
//! Every NTFS directory entry can carry a *reparse tag* — a 32-bit
//! identifier published in `dwReserved0` of `FILE_ID_BOTH_DIR_INFO`
//! (or in `FindFirstFileEx` results) that tells the walker what kind
//! of indirection the entry represents: symlink, junction, OneDrive
//! cloud-files placeholder, AppExecLink, etc. The decision of whether
//! to follow each tag is policy, not a fixed kernel-level behavior.
//!
//! This module owns the policy:
//!
//! - `ReparseTag` — typed wrapper around the raw `IO_REPARSE_TAG_*`
//!   values published in Microsoft's `ntifs.h`.
//! - `ReparseAction` — three-way choice per tag: `Follow`, `Skip`,
//!   `LogOnly`.
//! - `ReparsePolicy` — per-tag-category defaults plus an optional
//!   per-volume override table loaded from `volumes.toml` (TASK-212).
//!
//! Defaults match the spec's rule of thumb:
//!
//! - OneDrive placeholders (`IO_REPARSE_TAG_CLOUD*`) → `Skip` so we
//!   don't trigger rehydration storms over the user's network.
//! - Mount points / junctions (`IO_REPARSE_TAG_MOUNT_POINT`) →
//!   `Follow` on local volumes, `Skip` on removable media so the
//!   walker doesn't accidentally traverse a USB drive that's
//!   junctioned in.
//! - AppExecLink (`IO_REPARSE_TAG_APPEXECLINK`) → `LogOnly` — the
//!   stub isn't a hashable file in its own right.
//! - Symbolic links (`IO_REPARSE_TAG_SYMLINK`) → `Follow` (matches
//!   the posix walker's `follow_symlinks=true` default for resumable
//!   scans of `~/`).
//!
//! The module is cross-platform (the policy struct compiles on every
//! target); only the actual NTFS dispatch in `walker/ntfs.rs` is
//! cfg-gated. That keeps tests host-portable.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Typed reparse-tag classifier. Wraps the 32-bit IO_REPARSE_TAG
/// constants published by Microsoft. Unknown tags collapse to
/// `Other(tag)` so callers can still log + skip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReparseTag {
    /// `IO_REPARSE_TAG_SYMLINK` (0xA000000C).
    Symlink,
    /// `IO_REPARSE_TAG_MOUNT_POINT` (0xA0000003) — directory junction.
    MountPoint,
    /// `IO_REPARSE_TAG_APPEXECLINK` (0x8000001B) — start-menu UWP stub.
    AppExecLink,
    /// `IO_REPARSE_TAG_CLOUD` (0x9000001A) — OneDrive placeholder.
    /// We collapse the entire `IO_REPARSE_TAG_CLOUD_*` family (0x9000001A
    /// through 0x9000001F) onto this variant because the policy is
    /// identical across them.
    OneDrive,
    /// `IO_REPARSE_TAG_WCI_LINK` / Windows Container Isolation link.
    WciLink,
    /// `IO_REPARSE_TAG_HSM` / HSM2 — legacy Hierarchical Storage.
    Hsm,
    /// `IO_REPARSE_TAG_DEDUP` — NTFS deduplication placeholder.
    Dedup,
    /// Catch-all for tags not specifically enumerated.
    Other(u32),
}

impl ReparseTag {
    /// Decode a raw `dwReserved0` value into our typed enum.
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            0xA000_000C => ReparseTag::Symlink,
            0xA000_0003 => ReparseTag::MountPoint,
            0x8000_001B => ReparseTag::AppExecLink,
            // Cloud Files family.
            0x9000_001A | 0x9000_101A | 0x9000_201A | 0x9000_301A | 0x9000_401A | 0x9000_501A
            | 0x9000_601A | 0x9000_701A => ReparseTag::OneDrive,
            0xA000_0027 => ReparseTag::WciLink,
            0xC000_0004 => ReparseTag::Hsm,
            0x8000_0013 => ReparseTag::Dedup,
            other => ReparseTag::Other(other),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ReparseTag::Symlink => "symlink",
            ReparseTag::MountPoint => "mount_point",
            ReparseTag::AppExecLink => "appexec_link",
            ReparseTag::OneDrive => "onedrive",
            ReparseTag::WciLink => "wci_link",
            ReparseTag::Hsm => "hsm",
            ReparseTag::Dedup => "dedup",
            ReparseTag::Other(_) => "other",
        }
    }
}

/// What the walker should do when it hits a reparse-tagged entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReparseAction {
    /// Treat the reparse-tagged entry like a normal directory / file
    /// and recurse / hash through it.
    Follow,
    /// Don't traverse; emit a `walker:reparse_skipped` event.
    Skip,
    /// Record the entry in the per-scan log (for forensic audit) but
    /// don't descend. Equivalent to `Skip` from the walker's
    /// behavioral perspective; the difference is in the surfaced
    /// telemetry. The engine's audit log carries the tag + path.
    LogOnly,
}

/// Per-volume classification, used to pick the right defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeClass {
    /// Fixed local disk (DRIVE_FIXED on Windows).
    Local,
    /// USB / SD card / removable media (DRIVE_REMOVABLE).
    Removable,
    /// Network share, SMB / NFS (DRIVE_REMOTE).
    Remote,
    /// CD/DVD/Blu-ray (DRIVE_CDROM).
    Optical,
    /// RAM disk (DRIVE_RAMDISK).
    Ram,
}

/// Global policy + optional per-volume override table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReparsePolicy {
    pub symlink: ReparseAction,
    pub mount_point: ReparseAction,
    pub appexec_link: ReparseAction,
    pub onedrive: ReparseAction,
    pub wci_link: ReparseAction,
    pub hsm: ReparseAction,
    pub dedup: ReparseAction,
    /// Action for any tag not specifically enumerated above.
    pub other: ReparseAction,
    /// Per-volume overrides keyed on the volume's mount-point
    /// (e.g. `"C:"`, `"D:"`, `"\\Server\Share"`). Overrides win when
    /// present; missing keys fall through to the default.
    pub per_volume: HashMap<String, PerVolumeOverride>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PerVolumeOverride {
    pub class: Option<VolumeClass>,
    pub symlink: Option<ReparseAction>,
    pub mount_point: Option<ReparseAction>,
    pub appexec_link: Option<ReparseAction>,
    pub onedrive: Option<ReparseAction>,
    pub wci_link: Option<ReparseAction>,
    pub hsm: Option<ReparseAction>,
    pub dedup: Option<ReparseAction>,
    pub other: Option<ReparseAction>,
}

impl Default for ReparsePolicy {
    fn default() -> Self {
        Self {
            symlink: ReparseAction::Follow,
            mount_point: ReparseAction::Follow,
            appexec_link: ReparseAction::LogOnly,
            onedrive: ReparseAction::Skip,
            wci_link: ReparseAction::Skip,
            hsm: ReparseAction::Skip,
            dedup: ReparseAction::Follow, // Dedup placeholders are real files; follow.
            other: ReparseAction::LogOnly,
            per_volume: HashMap::new(),
        }
    }
}

impl ReparsePolicy {
    /// Decide the action for the given tag on the given volume.
    ///
    /// `volume_key` should be the platform-canonical mount-point
    /// identifier — drive letter on Windows (`"C:"`), mount point
    /// on POSIX (`"/mnt/data"`). Empty string is allowed when the
    /// walker hasn't tagged the volume; defaults apply.
    pub fn decide(&self, tag: ReparseTag, volume_key: &str) -> ReparseAction {
        // Single per_volume lookup — hashing the same string twice on
        // every NTFS dir entry was wasted CPU on deep tree walks.
        let over = self.per_volume.get(volume_key);
        if let Some(action) = over.and_then(|o| self.pick_override(o, tag)) {
            return action;
        }
        // Per-volume class can shift the default for some tags
        // (mount-points on removable media skip; same family of
        // tweaks elsewhere as the policy evolves). The "default
        // default" applies otherwise.
        if let Some(class) = over.and_then(|o| o.class)
            && let Some(class_default) = self.class_aware_default(tag, class)
        {
            return class_default;
        }
        self.default_for(tag)
    }

    fn pick_override(&self, over: &PerVolumeOverride, tag: ReparseTag) -> Option<ReparseAction> {
        match tag {
            ReparseTag::Symlink => over.symlink,
            ReparseTag::MountPoint => over.mount_point,
            ReparseTag::AppExecLink => over.appexec_link,
            ReparseTag::OneDrive => over.onedrive,
            ReparseTag::WciLink => over.wci_link,
            ReparseTag::Hsm => over.hsm,
            ReparseTag::Dedup => over.dedup,
            ReparseTag::Other(_) => over.other,
        }
    }

    fn class_aware_default(&self, tag: ReparseTag, class: VolumeClass) -> Option<ReparseAction> {
        match (tag, class) {
            (ReparseTag::MountPoint, VolumeClass::Removable) => Some(ReparseAction::Skip),
            (ReparseTag::MountPoint, VolumeClass::Remote) => Some(ReparseAction::Skip),
            (ReparseTag::MountPoint, VolumeClass::Optical) => Some(ReparseAction::Skip),
            // OneDrive over remote: still skip — caller doesn't want
            // to hydrate placeholders from a network mount.
            (ReparseTag::OneDrive, _) => Some(ReparseAction::Skip),
            _ => None,
        }
    }

    fn default_for(&self, tag: ReparseTag) -> ReparseAction {
        match tag {
            ReparseTag::Symlink => self.symlink,
            ReparseTag::MountPoint => self.mount_point,
            ReparseTag::AppExecLink => self.appexec_link,
            ReparseTag::OneDrive => self.onedrive,
            ReparseTag::WciLink => self.wci_link,
            ReparseTag::Hsm => self.hsm,
            ReparseTag::Dedup => self.dedup,
            ReparseTag::Other(_) => self.other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_raw_recognises_canonical_tags() {
        assert_eq!(ReparseTag::from_raw(0xA000_000C), ReparseTag::Symlink);
        assert_eq!(ReparseTag::from_raw(0xA000_0003), ReparseTag::MountPoint);
        assert_eq!(ReparseTag::from_raw(0x8000_001B), ReparseTag::AppExecLink);
        assert_eq!(ReparseTag::from_raw(0x9000_001A), ReparseTag::OneDrive);
        assert_eq!(ReparseTag::from_raw(0x9000_201A), ReparseTag::OneDrive);
        assert_eq!(
            ReparseTag::from_raw(0x1234_5678),
            ReparseTag::Other(0x1234_5678)
        );
    }

    #[test]
    fn default_policy_matches_spec() {
        let p = ReparsePolicy::default();
        assert_eq!(p.decide(ReparseTag::Symlink, ""), ReparseAction::Follow);
        assert_eq!(p.decide(ReparseTag::MountPoint, ""), ReparseAction::Follow);
        assert_eq!(
            p.decide(ReparseTag::AppExecLink, ""),
            ReparseAction::LogOnly
        );
        assert_eq!(p.decide(ReparseTag::OneDrive, ""), ReparseAction::Skip);
        assert_eq!(
            p.decide(ReparseTag::Other(0xDEAD), ""),
            ReparseAction::LogOnly
        );
    }

    #[test]
    fn per_volume_override_wins() {
        let mut p = ReparsePolicy::default();
        let o = PerVolumeOverride {
            symlink: Some(ReparseAction::Skip),
            ..Default::default()
        };
        p.per_volume.insert("C:".into(), o);
        assert_eq!(p.decide(ReparseTag::Symlink, "C:"), ReparseAction::Skip);
        // Other volume falls back to default.
        assert_eq!(p.decide(ReparseTag::Symlink, "D:"), ReparseAction::Follow);
        // Other tag on the same volume falls back too.
        assert_eq!(p.decide(ReparseTag::OneDrive, "C:"), ReparseAction::Skip);
    }

    #[test]
    fn removable_volume_class_skips_mount_points() {
        let mut p = ReparsePolicy::default();
        p.per_volume.insert(
            "E:".into(),
            PerVolumeOverride {
                class: Some(VolumeClass::Removable),
                ..Default::default()
            },
        );
        assert_eq!(p.decide(ReparseTag::MountPoint, "E:"), ReparseAction::Skip);
        // Fixed disk follows.
        assert_eq!(
            p.decide(ReparseTag::MountPoint, "C:"),
            ReparseAction::Follow
        );
    }

    #[test]
    fn remote_volume_class_skips_mount_points_and_onedrive() {
        let mut p = ReparsePolicy::default();
        p.per_volume.insert(
            r"\\server\share".into(),
            PerVolumeOverride {
                class: Some(VolumeClass::Remote),
                ..Default::default()
            },
        );
        assert_eq!(
            p.decide(ReparseTag::MountPoint, r"\\server\share"),
            ReparseAction::Skip
        );
        assert_eq!(
            p.decide(ReparseTag::OneDrive, r"\\server\share"),
            ReparseAction::Skip
        );
    }

    #[test]
    fn explicit_override_beats_class_default() {
        // Class=Removable would say Skip for MountPoint; an explicit
        // Follow override must win.
        let mut p = ReparsePolicy::default();
        let o = PerVolumeOverride {
            class: Some(VolumeClass::Removable),
            mount_point: Some(ReparseAction::Follow),
            ..Default::default()
        };
        p.per_volume.insert("F:".into(), o);
        assert_eq!(
            p.decide(ReparseTag::MountPoint, "F:"),
            ReparseAction::Follow
        );
    }

    #[test]
    fn unknown_tag_uses_other_default() {
        let p = ReparsePolicy::default();
        assert_eq!(
            p.decide(ReparseTag::Other(0xCAFE_BABE), "C:"),
            ReparseAction::LogOnly
        );
    }

    #[test]
    fn serde_round_trip_preserves_policy() {
        let p = ReparsePolicy::default();
        let s = serde_json::to_string(&p).unwrap();
        let p2: ReparsePolicy = serde_json::from_str(&s).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn tag_names_unique() {
        let names = [
            ReparseTag::Symlink.name(),
            ReparseTag::MountPoint.name(),
            ReparseTag::AppExecLink.name(),
            ReparseTag::OneDrive.name(),
            ReparseTag::WciLink.name(),
            ReparseTag::Hsm.name(),
            ReparseTag::Dedup.name(),
            ReparseTag::Other(0).name(),
        ];
        let mut sorted: Vec<&str> = names.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());
    }
}
