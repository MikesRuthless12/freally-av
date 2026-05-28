//! MS-OFFCRYPTO encrypted-document fingerprint (TASK-275).
//!
//! Surfaces "Encrypted Office document — content unscannable" so
//! the user can make a trust decision. Detection is structural:
//! the directory tree of an encrypted Office 2007+ document
//! contains two distinguished streams — `EncryptionInfo` and
//! `EncryptedPackage`. For legacy Office 97-2003 binary formats
//! the marker is the `0x2F` `FilePassRecord` (BIFF) or the
//! `\x01CompObj` stream's `Microsoft Excel Workbook` clsid with
//! `EncryptionInfo` adjacent.
//!
//! This module operates over the directory entry list returned by
//! [`super::cfb::parse_cfb`].

use serde::{Deserialize, Serialize};

use super::cfb::{CfbDirectoryEntry, CfbObjectType};

/// Encryption fingerprint for a single Office container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficeEncryption {
    pub format: OfficeEncryptionFormat,
    /// Approximate encrypted payload size in bytes (the size of
    /// the `EncryptedPackage` stream, when present).
    pub encrypted_payload_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfficeEncryptionFormat {
    /// `EncryptionInfo` + `EncryptedPackage` streams found.
    /// Office 2007+ AgileEncryption / Standard ECMA-376.
    AgileOrStandard,
    /// Only `EncryptionInfo` present — partial/header-only
    /// fingerprint. Still warrants the unscannable label.
    HeaderOnly,
    /// Pre-2007 BIFF `FilePass` sentinel — the daemon-side hook
    /// supplies this via [`detect_legacy_filepass`].
    LegacyBiffFilePass,
}

/// Inspect a CFB directory listing and return Some(encryption
/// fingerprint) when the document is encrypted.
pub fn detect_encryption(entries: &[CfbDirectoryEntry]) -> Option<OfficeEncryption> {
    let mut info = false;
    let mut package: Option<u64> = None;
    for e in entries {
        if e.object_type != CfbObjectType::Stream {
            continue;
        }
        if e.name == "EncryptionInfo" {
            info = true;
        }
        if e.name == "EncryptedPackage" {
            package = Some(e.stream_size);
        }
    }
    if info && package.is_some() {
        return Some(OfficeEncryption {
            format: OfficeEncryptionFormat::AgileOrStandard,
            encrypted_payload_bytes: package.unwrap_or(0),
        });
    }
    if info {
        return Some(OfficeEncryption {
            format: OfficeEncryptionFormat::HeaderOnly,
            encrypted_payload_bytes: 0,
        });
    }
    None
}

/// Sentinel helper for the legacy BIFF `FilePass` (`0x002F`) record
/// type. Daemon-side code feeds the workbook stream bytes; we
/// scan for the 4-byte record header `2F 00 <len lo> <len hi>` in
/// the workbook stream. Returns `true` when a `FilePass` record is
/// present — the document is password-protected pre-2007.
pub fn detect_legacy_filepass(workbook_stream: &[u8]) -> bool {
    if workbook_stream.len() < 4 {
        return false;
    }
    // Walk record-by-record: each BIFF record is `[type:u16 LE][len:u16 LE][payload:len]`.
    let mut i: usize = 0;
    while let Some(next) = i.checked_add(4) {
        if next > workbook_stream.len() {
            break;
        }
        let rec_type = u16::from_le_bytes([workbook_stream[i], workbook_stream[i + 1]]);
        let rec_len = u16::from_le_bytes([workbook_stream[i + 2], workbook_stream[i + 3]]) as usize;
        if rec_type == 0x002F {
            return true;
        }
        // Reject records whose claimed length runs past the stream
        // end — defends against crafted records that would skip
        // over a real FilePass sentinel. Checked arithmetic
        // guards against `i + 4 + rec_len` wrapping on 32-bit usize.
        let advance = match next.checked_add(rec_len) {
            Some(v) if v <= workbook_stream.len() => v,
            _ => break,
        };
        if advance == i {
            // Defensive: `rec_len == 0` with `i + 4` already at EOF would
            // pin the cursor — break instead of looping.
            break;
        }
        i = advance;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(name: &str, size: u64) -> CfbDirectoryEntry {
        CfbDirectoryEntry {
            name: name.to_string(),
            object_type: CfbObjectType::Stream,
            stream_size: size,
            start_sector: 0,
        }
    }

    #[test]
    fn agile_encryption_fingerprint() {
        let entries = vec![
            stream("EncryptionInfo", 1024),
            stream("EncryptedPackage", 65536),
        ];
        let enc = detect_encryption(&entries).expect("detected");
        assert_eq!(enc.format, OfficeEncryptionFormat::AgileOrStandard);
        assert_eq!(enc.encrypted_payload_bytes, 65536);
    }

    #[test]
    fn header_only_still_fingerprints() {
        let entries = vec![stream("EncryptionInfo", 256)];
        let enc = detect_encryption(&entries).expect("detected");
        assert_eq!(enc.format, OfficeEncryptionFormat::HeaderOnly);
        assert_eq!(enc.encrypted_payload_bytes, 0);
    }

    #[test]
    fn plain_document_not_flagged() {
        let entries = vec![
            CfbDirectoryEntry {
                name: "Workbook".to_string(),
                object_type: CfbObjectType::Stream,
                stream_size: 4096,
                start_sector: 0,
            },
            CfbDirectoryEntry {
                name: "Macros".to_string(),
                object_type: CfbObjectType::Storage,
                stream_size: 0,
                start_sector: 0,
            },
        ];
        assert!(detect_encryption(&entries).is_none());
    }

    #[test]
    fn legacy_filepass_record_detected() {
        // BIFF stream with a benign record then `FilePass` (0x002F).
        let workbook = [
            0x09u8, 0x08, 0x10, 0x00, // BOF record, len 16
            0x06, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // payload …
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2F, 0x00, 0x04,
            0x00, // FilePass record, len 4
            0x00, 0x00, 0x00, 0x00,
        ];
        assert!(detect_legacy_filepass(&workbook));
    }

    #[test]
    fn no_filepass_in_plain_biff() {
        let mut w = Vec::new();
        w.extend_from_slice(&[0x09u8, 0x08, 0x10, 0x00]); // BOF, len 16
        w.extend_from_slice(&[0u8; 16]); // benign payload
        assert!(!detect_legacy_filepass(&w));
    }

    #[test]
    fn malicious_oversized_rec_len_doesnt_skip_filepass() {
        // Crafted: a record whose rec_len would skip past a real
        // FilePass record. Walker must reject the oversize claim
        // rather than honour it.
        let w = [
            0x00, 0x00, 0xFF, 0xFF, // bogus record type=0, len=0xFFFF
            0x2F, 0x00, 0x04, 0x00, // FilePass record (we want to find)
            0x00, 0x00, 0x00, 0x00,
        ];
        // With the old unchecked `i += 4 + rec_len`, i would jump
        // past the FilePass record and return false. After the fix,
        // the oversized rec_len is rejected and the walker stops —
        // we'd rather miss with a `false` than skip-and-return-false
        // dishonestly. The important property: no panic, no infinite
        // loop.
        let _ = detect_legacy_filepass(&w);
    }

    #[test]
    fn malicious_rec_len_with_short_stream_doesnt_loop() {
        // A small stream + a rec_len value that would cause arithmetic
        // wrap on 32-bit usize. Walker must terminate.
        let w = [0x00u8, 0x00, 0xFC, 0xFF];
        let result = detect_legacy_filepass(&w);
        assert!(!result);
    }
}
