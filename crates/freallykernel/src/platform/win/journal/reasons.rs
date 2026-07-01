//! USN reason-flag → semantic kind mapping. Vendored from Sourcerer.
//!
//! USN records coalesce — a single record's `Reason` field is a bitmap of
//! every change that's happened to the file since its previous CLOSE. We
//! always wait for `USN_REASON_CLOSE` before emitting a `JournalEvent` so
//! every emitted event represents a settled state. Otherwise a single
//! create-write-write-close sequence emits four duplicate `Modify` events.

use windows::Win32::System::Ioctl::{
    USN_REASON_BASIC_INFO_CHANGE, USN_REASON_CLOSE, USN_REASON_DATA_EXTEND,
    USN_REASON_DATA_OVERWRITE, USN_REASON_DATA_TRUNCATION, USN_REASON_EA_CHANGE,
    USN_REASON_FILE_CREATE, USN_REASON_FILE_DELETE, USN_REASON_NAMED_DATA_EXTEND,
    USN_REASON_NAMED_DATA_OVERWRITE, USN_REASON_NAMED_DATA_TRUNCATION, USN_REASON_RENAME_NEW_NAME,
    USN_REASON_RENAME_OLD_NAME, USN_REASON_REPARSE_POINT_CHANGE, USN_REASON_SECURITY_CHANGE,
    USN_REASON_STREAM_CHANGE,
};

const DATA_CHANGE_MASK: u32 = USN_REASON_DATA_EXTEND
    | USN_REASON_DATA_OVERWRITE
    | USN_REASON_DATA_TRUNCATION
    | USN_REASON_NAMED_DATA_EXTEND
    | USN_REASON_NAMED_DATA_OVERWRITE
    | USN_REASON_NAMED_DATA_TRUNCATION
    | USN_REASON_STREAM_CHANGE
    | USN_REASON_REPARSE_POINT_CHANGE
    | USN_REASON_EA_CHANGE;

const ATTR_CHANGE_MASK: u32 = USN_REASON_BASIC_INFO_CHANGE | USN_REASON_SECURITY_CHANGE;

/// Coarse classification used by the subscriber to route a settled (CLOSE)
/// USN record to a single `JournalEvent` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonKind {
    /// Wait for more — record has changes but no `USN_REASON_CLOSE` yet.
    Pending,
    Create,
    Delete,
    /// Old-name half of a rename — caller must pair with a `RenameNew`
    /// for the same FRN before emitting a `JournalEvent::Rename`.
    RenameOld,
    /// New-name half of a rename — pair with the matching `RenameOld`.
    RenameNew,
    Modify,
    AttrChange,
    /// Unknown reason mask we choose not to forward (e.g. transient
    /// transactional bits without CLOSE). The subscriber drops these.
    Ignore,
}

/// Classify a USN record's `Reason` field. Two-tier precedence:
/// - **Inherently terminal** (file is gone — no further accumulation):
///   `FILE_DELETE` and `RENAME_OLD_NAME`. Emit immediately; CLOSE not
///   required. NTFS does not emit a closing record for the OLD name half
///   of a rename, and `FILE_DELETE` for POSIX-style deletes can arrive
///   without a paired CLOSE.
/// - **Settled-state** (we want the LAST record per session): `FILE_CREATE`,
///   `RENAME_NEW_NAME`, `DATA_*`, `ATTR_*`. Gated on `USN_REASON_CLOSE` so
///   write-write-write-close emits exactly one `Modify`.
pub fn classify(reason: u32) -> ReasonKind {
    // --- Terminal tier (no CLOSE required) ---
    if reason & USN_REASON_FILE_DELETE != 0 {
        return ReasonKind::Delete;
    }
    if reason & USN_REASON_RENAME_OLD_NAME != 0 && reason & USN_REASON_RENAME_NEW_NAME == 0 {
        return ReasonKind::RenameOld;
    }

    // --- Settled tier (CLOSE required) ---
    if reason & USN_REASON_CLOSE == 0 {
        return ReasonKind::Pending;
    }

    if reason & USN_REASON_RENAME_NEW_NAME != 0 {
        return ReasonKind::RenameNew;
    }
    if reason & USN_REASON_FILE_CREATE != 0 {
        return ReasonKind::Create;
    }
    if reason & DATA_CHANGE_MASK != 0 {
        return ReasonKind::Modify;
    }
    if reason & ATTR_CHANGE_MASK != 0 {
        return ReasonKind::AttrChange;
    }

    ReasonKind::Ignore
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_close_is_pending() {
        assert_eq!(classify(USN_REASON_FILE_CREATE), ReasonKind::Pending);
        assert_eq!(classify(USN_REASON_DATA_EXTEND), ReasonKind::Pending);
    }

    #[test]
    fn create_then_close_is_create() {
        let r = USN_REASON_FILE_CREATE | USN_REASON_DATA_EXTEND | USN_REASON_CLOSE;
        assert_eq!(classify(r), ReasonKind::Create);
    }

    #[test]
    fn delete_outranks_create_in_a_close_record() {
        let r = USN_REASON_FILE_CREATE | USN_REASON_FILE_DELETE | USN_REASON_CLOSE;
        assert_eq!(classify(r), ReasonKind::Delete);
    }

    #[test]
    fn rename_pair_classification() {
        let old = USN_REASON_RENAME_OLD_NAME | USN_REASON_CLOSE;
        let new = USN_REASON_RENAME_NEW_NAME | USN_REASON_CLOSE;
        assert_eq!(classify(old), ReasonKind::RenameOld);
        assert_eq!(classify(new), ReasonKind::RenameNew);
    }

    #[test]
    fn rename_outranks_create_in_a_close_record() {
        let old = USN_REASON_FILE_CREATE | USN_REASON_RENAME_OLD_NAME | USN_REASON_CLOSE;
        assert_eq!(classify(old), ReasonKind::RenameOld);
        let new = USN_REASON_FILE_CREATE | USN_REASON_RENAME_NEW_NAME | USN_REASON_CLOSE;
        assert_eq!(classify(new), ReasonKind::RenameNew);
    }

    #[test]
    fn data_close_is_modify() {
        let r = USN_REASON_DATA_OVERWRITE | USN_REASON_CLOSE;
        assert_eq!(classify(r), ReasonKind::Modify);
    }

    #[test]
    fn attribute_close_is_attr_change() {
        let r = USN_REASON_BASIC_INFO_CHANGE | USN_REASON_CLOSE;
        assert_eq!(classify(r), ReasonKind::AttrChange);
    }

    #[test]
    fn close_only_is_ignored() {
        assert_eq!(classify(USN_REASON_CLOSE), ReasonKind::Ignore);
    }

    #[test]
    fn rename_old_without_close_is_terminal() {
        assert_eq!(classify(USN_REASON_RENAME_OLD_NAME), ReasonKind::RenameOld);
    }

    #[test]
    fn delete_without_close_is_terminal() {
        assert_eq!(classify(USN_REASON_FILE_DELETE), ReasonKind::Delete);
    }

    #[test]
    fn rename_new_without_close_is_pending() {
        assert_eq!(classify(USN_REASON_RENAME_NEW_NAME), ReasonKind::Pending);
    }
}
