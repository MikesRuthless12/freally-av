//! Password-protected archive surfacing (TASK-282).
//!
//! ZIP entries store an encryption flag in the *General Purpose
//! Bit Flag* (offset +6 of the local file header). When bit 0 is
//! set, the entry is encrypted — the engine cannot scan its
//! contents but the daemon should still tell the user the file
//! reached them.
//!
//! 7z uses a per-entry "is encrypted" boolean in the header.
//! RAR uses bit `0x04` of the file header flags. Both are
//! surfaced via the same [`PasswordFinding`] shape so the UI
//! has one rendering path.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordFinding {
    pub entry_name: String,
    pub archive_kind: &'static str,
    /// Some archive formats (7z, recent ZIP/AES) store an
    /// `aes_strength` byte alongside the encryption flag.
    pub aes_strength: Option<u16>,
}

/// Returns `true` when a ZIP local file header bit-0 (encrypted)
/// is set. `gp_bit_flag` is the raw u16 little-endian field
/// from offset +6 of the local file header.
pub fn is_encrypted_zip_entry(gp_bit_flag: u16) -> bool {
    gp_bit_flag & 0x0001 != 0
}

/// Promote a raw bit-flag into a [`PasswordFinding`] for an
/// engine row. Returns `None` when the entry is not encrypted.
pub fn classify_zip_entry(
    entry_name: &str,
    gp_bit_flag: u16,
    aes_strength: Option<u16>,
) -> Option<PasswordFinding> {
    if !is_encrypted_zip_entry(gp_bit_flag) {
        return None;
    }
    Some(PasswordFinding {
        entry_name: entry_name.to_string(),
        archive_kind: "zip",
        aes_strength,
    })
}

/// 7z password-protected entry promoter. Caller supplies the
/// `is_encrypted` boolean teased out of the 7z header by the
/// `sevenz-rust2` walker.
pub fn classify_seven_z_entry(entry_name: &str, is_encrypted: bool) -> Option<PasswordFinding> {
    if !is_encrypted {
        return None;
    }
    Some(PasswordFinding {
        entry_name: entry_name.to_string(),
        archive_kind: "7z",
        aes_strength: Some(256),
    })
}

/// RAR password-protected entry promoter. RAR file-header bit
/// `0x04` = encrypted.
pub fn classify_rar_entry(entry_name: &str, file_header_flags: u16) -> Option<PasswordFinding> {
    if file_header_flags & 0x0004 == 0 {
        return None;
    }
    Some(PasswordFinding {
        entry_name: entry_name.to_string(),
        archive_kind: "rar",
        aes_strength: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_bit_zero_encrypted() {
        assert!(is_encrypted_zip_entry(0x0001));
        assert!(is_encrypted_zip_entry(0x8001));
        assert!(!is_encrypted_zip_entry(0x0000));
        assert!(!is_encrypted_zip_entry(0x8000));
    }

    #[test]
    fn classify_returns_finding_when_encrypted() {
        let f = classify_zip_entry("locked.bin", 0x0001, Some(256)).expect("flagged");
        assert_eq!(f.entry_name, "locked.bin");
        assert_eq!(f.archive_kind, "zip");
        assert_eq!(f.aes_strength, Some(256));
    }

    #[test]
    fn classify_returns_none_when_plain() {
        assert!(classify_zip_entry("plain.txt", 0x0000, None).is_none());
    }

    #[test]
    fn seven_z_encrypted_marker() {
        let f = classify_seven_z_entry("x", true).expect("flagged");
        assert_eq!(f.archive_kind, "7z");
        let none = classify_seven_z_entry("x", false);
        assert!(none.is_none());
    }

    #[test]
    fn rar_flag_bit_2_encrypted() {
        let f = classify_rar_entry("x", 0x0004).expect("flagged");
        assert_eq!(f.archive_kind, "rar");
        // Other unrelated flag bits don't trip it.
        assert!(classify_rar_entry("x", 0x0001 | 0x0002 | 0x0008).is_none());
    }
}
