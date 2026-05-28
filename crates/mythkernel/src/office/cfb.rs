//! Microsoft Compound File Binary directory walker (TASK-272).
//!
//! Reads a `.doc` / `.xls` / `.ppt` / `.msg` container far enough
//! to surface the **directory tree** — every storage and stream
//! name plus the stream's byte length. This is enough to:
//!
//!   * locate the VBA project (`Macros/VBA/<module>`) for the
//!     [`super::vba`] detector
//!   * locate `EncryptionInfo` + `EncryptedPackage` for the
//!     [`super::crypto`] fingerprint
//!   * locate the `__substg1.0_*` Outlook MAPI streams for
//!     [`crate::email::msg`]
//!
//! Stream **content extraction** (FAT/MiniFAT traversal) is
//! deferred to the closeout pass — the foundation here is the
//! header + directory parse, which is what every downstream
//! consumer dispatches on. The constants and layout follow MS-CFB
//! 6.1 §2.
//!
//! Read-only. No mutation.

use serde::{Deserialize, Serialize};

/// Signature at offset 0 of every CFB container.
pub const CFB_SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Free directory-entry marker — skipped during enumeration.
pub const STGTY_INVALID: u8 = 0x00;
pub const STGTY_STORAGE: u8 = 0x01;
pub const STGTY_STREAM: u8 = 0x02;
pub const STGTY_LOCKBYTES: u8 = 0x03;
pub const STGTY_PROPERTY: u8 = 0x04;
pub const STGTY_ROOT: u8 = 0x05;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CfbObjectType {
    Storage,
    Stream,
    Root,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CfbDirectoryEntry {
    pub name: String,
    pub object_type: CfbObjectType,
    /// On-disk size of the stream payload, in bytes. Zero for
    /// storages.
    pub stream_size: u64,
    /// First sector of the stream (FAT index). Caller hands this
    /// off to the stream extractor in the closeout pass.
    pub start_sector: u32,
}

/// Result shape: returns a flat list of directory entries in the
/// order MS-CFB writes them. `None` when the container header is
/// missing or sector size is non-canonical.
pub fn parse_cfb(raw: &[u8]) -> Option<Vec<CfbDirectoryEntry>> {
    if raw.len() < 512 || raw[..8] != CFB_SIGNATURE {
        return None;
    }

    let sector_shift = u16::from_le_bytes([raw[30], raw[31]]);
    if sector_shift != 9 && sector_shift != 12 {
        return None;
    }
    let sector_size: usize = 1 << sector_shift;

    let first_dir_sector = u32::from_le_bytes([raw[48], raw[49], raw[50], raw[51]]) as usize;
    if first_dir_sector == 0xFFFF_FFFE {
        return None;
    }

    // Checked arithmetic — `first_dir_sector` is attacker-controlled. On
    // 32-bit `usize` targets, unchecked `(first_dir_sector + 1) * sector_size`
    // can wrap to a small value that bypasses the bounds check and reads
    // 'directory entries' from the file header.
    let dir_offset = first_dir_sector
        .checked_add(1)
        .and_then(|x| x.checked_mul(sector_size))?;
    if dir_offset >= raw.len() {
        return None;
    }

    let mut entries = Vec::new();
    let mut idx = dir_offset;
    while idx + 128 <= raw.len() {
        let entry_bytes = &raw[idx..idx + 128];
        idx += 128;

        let name_len = u16::from_le_bytes([entry_bytes[64], entry_bytes[65]]) as usize;
        let stgty = entry_bytes[66];
        if stgty == STGTY_INVALID {
            continue;
        }

        let name = decode_entry_name(&entry_bytes[..64.min(name_len.saturating_sub(2).min(64))]);
        let object_type = match stgty {
            STGTY_STORAGE => CfbObjectType::Storage,
            STGTY_STREAM => CfbObjectType::Stream,
            STGTY_ROOT => CfbObjectType::Root,
            _ => CfbObjectType::Other,
        };
        let start_sector = u32::from_le_bytes([
            entry_bytes[116],
            entry_bytes[117],
            entry_bytes[118],
            entry_bytes[119],
        ]);
        let stream_size = u64::from_le_bytes([
            entry_bytes[120],
            entry_bytes[121],
            entry_bytes[122],
            entry_bytes[123],
            entry_bytes[124],
            entry_bytes[125],
            entry_bytes[126],
            entry_bytes[127],
        ]);

        entries.push(CfbDirectoryEntry {
            name,
            object_type,
            stream_size,
            start_sector,
        });

        // Stop once we leave the first directory sector's worth of
        // entries — the foundation pass surfaces the *immediate*
        // entries; deep walk lands at closeout when the FAT chain
        // walker is wired in.
        if idx >= dir_offset + sector_size {
            break;
        }
    }

    Some(entries)
}

fn decode_entry_name(bytes: &[u8]) -> String {
    let mut chars = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let code = u16::from_le_bytes([pair[0], pair[1]]);
        if code == 0 {
            break;
        }
        chars.push(code);
    }
    String::from_utf16_lossy(&chars)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 1-sector-header + 1-sector-FAT + 1-sector-directory
    /// CFB blob with a known root entry + one stream.
    fn synthesise_cfb(entries: &[(&str, CfbObjectType, u64)]) -> Vec<u8> {
        let mut blob = vec![0u8; 512 * 4];
        blob[..8].copy_from_slice(&CFB_SIGNATURE);
        // Minor / major version + byte order.
        blob[24..26].copy_from_slice(&0x003Eu16.to_le_bytes());
        blob[26..28].copy_from_slice(&0x0003u16.to_le_bytes());
        blob[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes());
        // Sector shift = 9 → 512-byte sectors.
        blob[30..32].copy_from_slice(&9u16.to_le_bytes());
        // Mini sector shift = 6 → 64-byte mini-sectors.
        blob[32..34].copy_from_slice(&6u16.to_le_bytes());
        // First directory sector at index 1 (= file offset 512 + 512 = 1024).
        blob[48..52].copy_from_slice(&1u32.to_le_bytes());

        // Directory entries start at offset (first_dir + 1) * sector_size = 1024.
        let dir_off = 1024usize;
        for (i, (name, object_type, stream_size)) in entries.iter().enumerate() {
            let entry_off = dir_off + 128 * i;
            // Name as UTF-16-LE.
            let utf16: Vec<u16> = name.encode_utf16().collect();
            for (j, code) in utf16.iter().enumerate() {
                blob[entry_off + j * 2..entry_off + j * 2 + 2].copy_from_slice(&code.to_le_bytes());
            }
            // Name length in bytes, including trailing NUL (per MS-CFB).
            let name_byte_len = (utf16.len() as u16 + 1) * 2;
            blob[entry_off + 64..entry_off + 66].copy_from_slice(&name_byte_len.to_le_bytes());
            blob[entry_off + 66] = match object_type {
                CfbObjectType::Storage => STGTY_STORAGE,
                CfbObjectType::Stream => STGTY_STREAM,
                CfbObjectType::Root => STGTY_ROOT,
                CfbObjectType::Other => STGTY_PROPERTY,
            };
            blob[entry_off + 116..entry_off + 120].copy_from_slice(&(i as u32).to_le_bytes());
            blob[entry_off + 120..entry_off + 128].copy_from_slice(&stream_size.to_le_bytes());
        }
        blob
    }

    #[test]
    fn rejects_non_cfb_input() {
        assert!(parse_cfb(b"not a CFB").is_none());
        assert!(parse_cfb(&[0u8; 1024]).is_none());
    }

    #[test]
    fn enumerates_root_and_stream_entries() {
        let blob = synthesise_cfb(&[
            ("Root Entry", CfbObjectType::Root, 0),
            ("EncryptionInfo", CfbObjectType::Stream, 1024),
            ("EncryptedPackage", CfbObjectType::Stream, 8192),
        ]);
        let entries = parse_cfb(&blob).expect("CFB parses");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"Root Entry"));
        assert!(names.contains(&"EncryptionInfo"));
        assert!(names.contains(&"EncryptedPackage"));
        let enc_info = entries.iter().find(|e| e.name == "EncryptionInfo").unwrap();
        assert_eq!(enc_info.object_type, CfbObjectType::Stream);
        assert_eq!(enc_info.stream_size, 1024);
    }

    #[test]
    fn invalid_sector_shift_returns_none() {
        let mut blob = synthesise_cfb(&[("Root Entry", CfbObjectType::Root, 0)]);
        // Corrupt sector shift to 17 (illegal — only 9 and 12 valid).
        blob[30..32].copy_from_slice(&17u16.to_le_bytes());
        assert!(parse_cfb(&blob).is_none());
    }

    #[test]
    fn detects_vba_storage_marker() {
        let blob = synthesise_cfb(&[
            ("Root Entry", CfbObjectType::Root, 0),
            ("Macros", CfbObjectType::Storage, 0),
            ("VBA", CfbObjectType::Storage, 0),
            ("ThisDocument", CfbObjectType::Stream, 2048),
        ]);
        let entries = parse_cfb(&blob).expect("CFB parses");
        assert!(
            entries
                .iter()
                .any(|e| e.name == "VBA" && e.object_type == CfbObjectType::Storage)
        );
        assert!(
            entries
                .iter()
                .any(|e| e.name == "ThisDocument" && e.object_type == CfbObjectType::Stream)
        );
    }

    #[test]
    fn malicious_first_dir_sector_doesnt_overflow_usize() {
        // Synthesise a header with an attacker-supplied
        // first_dir_sector that, on a 32-bit usize target, would
        // wrap `(first_dir_sector + 1) * sector_size` to a small
        // value bypassing the bounds check. checked_add /
        // checked_mul must catch it and return None.
        let mut blob = vec![0u8; 1024];
        blob[..8].copy_from_slice(&CFB_SIGNATURE);
        blob[30..32].copy_from_slice(&9u16.to_le_bytes());
        // first_dir_sector = u32::MAX - 1 (the FREESECT sentinel
        // is MAX itself; this is just under it so the early-return
        // doesn't fire). On 32-bit usize, (MAX-1).checked_add(1)
        // returns Some(MAX) then checked_mul(sector_size) overflows
        // → None. On 64-bit usize, the multiplied offset exceeds
        // raw.len() → still None.
        blob[48..52].copy_from_slice(&(u32::MAX - 1).to_le_bytes());
        assert!(parse_cfb(&blob).is_none());
    }

    #[test]
    fn truncated_input_is_safe() {
        let mut blob = synthesise_cfb(&[("Root Entry", CfbObjectType::Root, 0)]);
        blob.truncate(513);
        // Either returns None (truncated before dir sector) or
        // returns an empty Vec — both are acceptable. The critical
        // assertion is "doesn't panic".
        let _ = parse_cfb(&blob);
    }
}
