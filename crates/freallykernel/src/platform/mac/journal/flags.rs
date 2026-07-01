//! FSEvents flag bitmask constants + classification — vendored from Sourcerer.

#![allow(non_upper_case_globals)]

pub const kFSEventStreamEventFlagNone: u32 = 0x0000_0000;
pub const kFSEventStreamEventFlagMustScanSubDirs: u32 = 0x0000_0001;
pub const kFSEventStreamEventFlagUserDropped: u32 = 0x0000_0002;
pub const kFSEventStreamEventFlagKernelDropped: u32 = 0x0000_0004;
pub const kFSEventStreamEventFlagEventIdsWrapped: u32 = 0x0000_0008;
pub const kFSEventStreamEventFlagHistoryDone: u32 = 0x0000_0010;
pub const kFSEventStreamEventFlagRootChanged: u32 = 0x0000_0020;
pub const kFSEventStreamEventFlagMount: u32 = 0x0000_0040;
pub const kFSEventStreamEventFlagUnmount: u32 = 0x0000_0080;
pub const kFSEventStreamEventFlagItemCreated: u32 = 0x0000_0100;
pub const kFSEventStreamEventFlagItemRemoved: u32 = 0x0000_0200;
pub const kFSEventStreamEventFlagItemInodeMetaMod: u32 = 0x0000_0400;
pub const kFSEventStreamEventFlagItemRenamed: u32 = 0x0000_0800;
pub const kFSEventStreamEventFlagItemModified: u32 = 0x0000_1000;
pub const kFSEventStreamEventFlagItemFinderInfoMod: u32 = 0x0000_2000;
pub const kFSEventStreamEventFlagItemChangeOwner: u32 = 0x0000_4000;
pub const kFSEventStreamEventFlagItemXattrMod: u32 = 0x0000_8000;
pub const kFSEventStreamEventFlagItemIsFile: u32 = 0x0001_0000;
pub const kFSEventStreamEventFlagItemIsDir: u32 = 0x0002_0000;
pub const kFSEventStreamEventFlagItemIsSymlink: u32 = 0x0004_0000;
pub const kFSEventStreamEventFlagItemIsHardlink: u32 = 0x0010_0000;
pub const kFSEventStreamEventFlagItemIsLastHardlink: u32 = 0x0020_0000;
pub const kFSEventStreamEventFlagItemCloned: u32 = 0x0040_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagKind {
    Create,
    Delete,
    Modify,
    AttrChange,
    RenameMaybe,
    MustScanSubDirs,
    RootChanged,
    Ignore,
}

const FLAG_RENAME: u32 = kFSEventStreamEventFlagItemRenamed;
const FLAG_DELETE: u32 = kFSEventStreamEventFlagItemRemoved;
const FLAG_CREATE: u32 = kFSEventStreamEventFlagItemCreated;
const FLAG_MODIFY: u32 =
    kFSEventStreamEventFlagItemModified | kFSEventStreamEventFlagItemInodeMetaMod;
const FLAG_ATTR: u32 = kFSEventStreamEventFlagItemFinderInfoMod
    | kFSEventStreamEventFlagItemChangeOwner
    | kFSEventStreamEventFlagItemXattrMod;

pub fn classify(flags: u32) -> FlagKind {
    if flags & kFSEventStreamEventFlagMustScanSubDirs != 0 {
        return FlagKind::MustScanSubDirs;
    }
    if flags & kFSEventStreamEventFlagRootChanged != 0 {
        return FlagKind::RootChanged;
    }
    if flags & FLAG_RENAME != 0 {
        return FlagKind::RenameMaybe;
    }
    if flags & FLAG_DELETE != 0 {
        return FlagKind::Delete;
    }
    if flags & FLAG_CREATE != 0 {
        return FlagKind::Create;
    }
    if flags & FLAG_MODIFY != 0 {
        return FlagKind::Modify;
    }
    if flags & FLAG_ATTR != 0 {
        return FlagKind::AttrChange;
    }
    FlagKind::Ignore
}

pub fn is_file(flags: u32) -> bool {
    flags & kFSEventStreamEventFlagItemIsFile != 0
}

pub fn is_dir(flags: u32) -> bool {
    flags & kFSEventStreamEventFlagItemIsDir != 0
}

pub fn is_symlink(flags: u32) -> bool {
    flags & kFSEventStreamEventFlagItemIsSymlink != 0
}

pub fn history_done(flags: u32) -> bool {
    flags & kFSEventStreamEventFlagHistoryDone != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rescan_outranks_everything() {
        let r = kFSEventStreamEventFlagMustScanSubDirs | FLAG_CREATE | FLAG_RENAME;
        assert_eq!(classify(r), FlagKind::MustScanSubDirs);
    }

    #[test]
    fn root_changed_outranks_payload_flags() {
        let r = kFSEventStreamEventFlagRootChanged | FLAG_MODIFY;
        assert_eq!(classify(r), FlagKind::RootChanged);
    }

    #[test]
    fn rename_outranks_create_and_delete() {
        assert_eq!(classify(FLAG_RENAME | FLAG_CREATE), FlagKind::RenameMaybe);
        assert_eq!(classify(FLAG_RENAME | FLAG_DELETE), FlagKind::RenameMaybe);
    }

    #[test]
    fn delete_outranks_create() {
        assert_eq!(classify(FLAG_CREATE | FLAG_DELETE), FlagKind::Delete);
    }

    #[test]
    fn modify_only_paths() {
        assert_eq!(classify(FLAG_MODIFY), FlagKind::Modify);
        assert_eq!(
            classify(kFSEventStreamEventFlagItemInodeMetaMod),
            FlagKind::Modify
        );
        assert_eq!(
            classify(kFSEventStreamEventFlagItemModified),
            FlagKind::Modify
        );
    }

    #[test]
    fn attr_only_paths() {
        assert_eq!(
            classify(kFSEventStreamEventFlagItemFinderInfoMod),
            FlagKind::AttrChange
        );
        assert_eq!(
            classify(kFSEventStreamEventFlagItemChangeOwner),
            FlagKind::AttrChange
        );
        assert_eq!(
            classify(kFSEventStreamEventFlagItemXattrMod),
            FlagKind::AttrChange
        );
    }

    #[test]
    fn no_actionable_bits_is_ignored() {
        assert_eq!(classify(0), FlagKind::Ignore);
        assert_eq!(
            classify(kFSEventStreamEventFlagItemIsFile),
            FlagKind::Ignore
        );
        assert_eq!(classify(kFSEventStreamEventFlagItemIsDir), FlagKind::Ignore);
    }

    #[test]
    fn type_predicates() {
        assert!(is_file(kFSEventStreamEventFlagItemIsFile));
        assert!(!is_file(kFSEventStreamEventFlagItemIsDir));
        assert!(is_dir(kFSEventStreamEventFlagItemIsDir));
        assert!(is_symlink(kFSEventStreamEventFlagItemIsSymlink));
        assert!(history_done(kFSEventStreamEventFlagHistoryDone));
    }
}
