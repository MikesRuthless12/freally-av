//! inotify / fanotify mask → semantic kind mapping — vendored from Sourcerer.

#![allow(non_upper_case_globals)]

pub const IN_ACCESS: u32 = 0x0000_0001;
pub const IN_MODIFY: u32 = 0x0000_0002;
pub const IN_ATTRIB: u32 = 0x0000_0004;
pub const IN_CLOSE_WRITE: u32 = 0x0000_0008;
pub const IN_CLOSE_NOWRITE: u32 = 0x0000_0010;
pub const IN_OPEN: u32 = 0x0000_0020;
pub const IN_MOVED_FROM: u32 = 0x0000_0040;
pub const IN_MOVED_TO: u32 = 0x0000_0080;
pub const IN_CREATE: u32 = 0x0000_0100;
pub const IN_DELETE: u32 = 0x0000_0200;
pub const IN_DELETE_SELF: u32 = 0x0000_0400;
pub const IN_MOVE_SELF: u32 = 0x0000_0800;
pub const IN_UNMOUNT: u32 = 0x0000_2000;
pub const IN_Q_OVERFLOW: u32 = 0x0000_4000;
pub const IN_IGNORED: u32 = 0x0000_8000;
pub const IN_ONLYDIR: u32 = 0x0100_0000;
pub const IN_DONT_FOLLOW: u32 = 0x0200_0000;
pub const IN_EXCL_UNLINK: u32 = 0x0400_0000;
pub const IN_MASK_CREATE: u32 = 0x1000_0000;
pub const IN_MASK_ADD: u32 = 0x2000_0000;
pub const IN_ISDIR: u32 = 0x4000_0000;
pub const IN_ONESHOT: u32 = 0x8000_0000;

pub const FREALLY_INOTIFY_MASK: u32 = IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF
    | IN_EXCL_UNLINK;

pub const FAN_ACCESS: u64 = 0x0000_0001;
pub const FAN_MODIFY: u64 = 0x0000_0002;
pub const FAN_ATTRIB: u64 = 0x0000_0004;
pub const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
pub const FAN_CLOSE_NOWRITE: u64 = 0x0000_0010;
pub const FAN_OPEN: u64 = 0x0000_0020;
pub const FAN_MOVED_FROM: u64 = 0x0000_0040;
pub const FAN_MOVED_TO: u64 = 0x0000_0080;
pub const FAN_CREATE: u64 = 0x0000_0100;
pub const FAN_DELETE: u64 = 0x0000_0200;
pub const FAN_DELETE_SELF: u64 = 0x0000_0400;
pub const FAN_MOVE_SELF: u64 = 0x0000_0800;
pub const FAN_OPEN_EXEC: u64 = 0x0000_1000;
pub const FAN_Q_OVERFLOW: u64 = 0x0000_4000;
pub const FAN_FS_ERROR: u64 = 0x0000_8000;
pub const FAN_ONDIR: u64 = 0x4000_0000_0000_0000;

pub const FREALLY_FANOTIFY_MASK: u64 = FAN_MODIFY
    | FAN_ATTRIB
    | FAN_CLOSE_WRITE
    | FAN_MOVED_FROM
    | FAN_MOVED_TO
    | FAN_CREATE
    | FAN_DELETE
    | FAN_DELETE_SELF
    | FAN_MOVE_SELF
    | FAN_FS_ERROR;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonKind {
    Pending,
    Create,
    Delete,
    RenameOld,
    RenameNew,
    Modify,
    AttrChange,
    QueueOverflow,
    Ignored,
    Other,
}

pub fn classify_inotify(mask: u32) -> ReasonKind {
    if mask & IN_Q_OVERFLOW != 0 {
        return ReasonKind::QueueOverflow;
    }
    if mask & IN_IGNORED != 0 {
        return ReasonKind::Ignored;
    }
    if mask & IN_MOVED_FROM != 0 {
        return ReasonKind::RenameOld;
    }
    if mask & IN_MOVED_TO != 0 {
        return ReasonKind::RenameNew;
    }
    if mask & (IN_DELETE | IN_DELETE_SELF) != 0 {
        return ReasonKind::Delete;
    }
    if mask & IN_CREATE != 0 {
        return ReasonKind::Create;
    }
    if mask & IN_CLOSE_WRITE != 0 {
        return ReasonKind::Modify;
    }
    if mask & IN_ATTRIB != 0 {
        return ReasonKind::AttrChange;
    }
    if mask & IN_MODIFY != 0 {
        return ReasonKind::Pending;
    }
    ReasonKind::Other
}

pub fn classify_fanotify(mask: u64) -> ReasonKind {
    if mask & FAN_Q_OVERFLOW != 0 {
        return ReasonKind::QueueOverflow;
    }
    if mask & FAN_MOVED_FROM != 0 {
        return ReasonKind::RenameOld;
    }
    if mask & FAN_MOVED_TO != 0 {
        return ReasonKind::RenameNew;
    }
    if mask & (FAN_DELETE | FAN_DELETE_SELF) != 0 {
        return ReasonKind::Delete;
    }
    if mask & FAN_CREATE != 0 {
        return ReasonKind::Create;
    }
    if mask & FAN_CLOSE_WRITE != 0 {
        return ReasonKind::Modify;
    }
    if mask & FAN_ATTRIB != 0 {
        return ReasonKind::AttrChange;
    }
    if mask & FAN_MODIFY != 0 {
        return ReasonKind::Pending;
    }
    ReasonKind::Other
}

pub fn is_dir_inotify(mask: u32) -> bool {
    mask & IN_ISDIR != 0
}

pub fn is_dir_fanotify(mask: u64) -> bool {
    mask & FAN_ONDIR != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflow_outranks_everything() {
        let m = IN_Q_OVERFLOW | IN_CREATE | IN_MOVED_FROM;
        assert_eq!(classify_inotify(m), ReasonKind::QueueOverflow);
        let m2 = FAN_Q_OVERFLOW | FAN_CREATE | FAN_MOVED_FROM;
        assert_eq!(classify_fanotify(m2), ReasonKind::QueueOverflow);
    }

    #[test]
    fn ignored_outranks_payload_inotify() {
        let m = IN_IGNORED | IN_DELETE_SELF;
        assert_eq!(classify_inotify(m), ReasonKind::Ignored);
    }

    #[test]
    fn rename_outranks_create_inotify() {
        assert_eq!(
            classify_inotify(IN_CREATE | IN_MOVED_FROM),
            ReasonKind::RenameOld
        );
        assert_eq!(
            classify_inotify(IN_CREATE | IN_MOVED_TO),
            ReasonKind::RenameNew
        );
    }

    #[test]
    fn delete_outranks_create_inotify() {
        assert_eq!(classify_inotify(IN_CREATE | IN_DELETE), ReasonKind::Delete);
    }

    #[test]
    fn close_write_settles_modify_inotify() {
        assert_eq!(classify_inotify(IN_MODIFY), ReasonKind::Pending);
        assert_eq!(classify_inotify(IN_CLOSE_WRITE), ReasonKind::Modify);
        assert_eq!(
            classify_inotify(IN_MODIFY | IN_CLOSE_WRITE),
            ReasonKind::Modify
        );
    }

    #[test]
    fn attrib_only_is_attr_change_inotify() {
        assert_eq!(classify_inotify(IN_ATTRIB), ReasonKind::AttrChange);
    }

    #[test]
    fn unknown_mask_is_other_inotify() {
        assert_eq!(classify_inotify(IN_ACCESS), ReasonKind::Other);
        assert_eq!(classify_inotify(IN_OPEN), ReasonKind::Other);
        assert_eq!(classify_inotify(0), ReasonKind::Other);
    }

    #[test]
    fn rename_outranks_create_fanotify() {
        let m = FAN_CREATE | FAN_MOVED_FROM;
        assert_eq!(classify_fanotify(m), ReasonKind::RenameOld);
    }

    #[test]
    fn delete_outranks_create_fanotify() {
        let m = FAN_CREATE | FAN_DELETE;
        assert_eq!(classify_fanotify(m), ReasonKind::Delete);
    }

    #[test]
    fn close_write_settles_modify_fanotify() {
        assert_eq!(classify_fanotify(FAN_MODIFY), ReasonKind::Pending);
        assert_eq!(classify_fanotify(FAN_CLOSE_WRITE), ReasonKind::Modify);
    }

    #[test]
    fn dir_predicates() {
        assert!(is_dir_inotify(IN_ISDIR | IN_CREATE));
        assert!(!is_dir_inotify(IN_CREATE));
        assert!(is_dir_fanotify(FAN_ONDIR | FAN_CREATE));
        assert!(!is_dir_fanotify(FAN_CREATE));
    }

    #[test]
    fn freally_mask_excludes_read_only_chatter() {
        assert_eq!(FREALLY_INOTIFY_MASK & IN_ACCESS, 0);
        assert_eq!(FREALLY_INOTIFY_MASK & IN_OPEN, 0);
        assert_eq!(FREALLY_INOTIFY_MASK & IN_CLOSE_NOWRITE, 0);
        assert_eq!(FREALLY_FANOTIFY_MASK & FAN_ACCESS, 0);
        assert_eq!(FREALLY_FANOTIFY_MASK & FAN_OPEN, 0);
        assert_eq!(FREALLY_FANOTIFY_MASK & FAN_CLOSE_NOWRITE, 0);
    }
}
