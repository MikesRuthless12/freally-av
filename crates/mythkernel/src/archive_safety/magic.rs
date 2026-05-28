//! Extended-format archive magic-byte sniffer (TASK-283).
//!
//! When the engine encounters a file whose extension doesn't tell
//! the whole story (downloaded-without-extension, renamed-on-purpose,
//! mailbox attachment), the daemon hands the first 1 KiB to
//! [`detect_archive_kind`] to figure out whether the body is one of
//! the archive containers Mythodikal will eventually mount-and-scan.
//!
//! Recognized:
//!
//!   * ZIP (`PK\x03\x04`, `PK\x05\x06`, `PK\x07\x08`)
//!   * 7-zip (`37 7A BC AF 27 1C`)
//!   * RAR4 (`52 61 72 21 1A 07 00`) / RAR5 (`52 61 72 21 1A 07 01 00`)
//!   * gzip (`1F 8B`)
//!   * bzip2 (`42 5A 68`)
//!   * xz (`FD 37 7A 58 5A 00`)
//!   * zstd (`28 B5 2F FD`)
//!   * lz4 frame (`04 22 4D 18`)
//!   * tar (offset 257 = `ustar`)
//!   * Apple DMG (UDIF Universal Disk Image — checks for trailing
//!     `koly` magic at the *end* of the file; the head probe just
//!     records "could be DMG" if extension/header don't disqualify)
//!   * ISO9660 (`CD001` at offset 0x8001)
//!   * UDF (`BEA01` at offset 0x8001 or near it)
//!   * VHDX (`vhdxfile` at offset 0)
//!   * WIM (`MSWIM\0\0\0` at offset 0)
//!
//! This module is *not* responsible for mounting — only for
//! deciding which extractor crate the daemon should hand the file
//! off to.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtendedArchiveKind {
    Zip,
    SevenZ,
    Rar,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    Lz4,
    Tar,
    Iso9660,
    Udf,
    Vhdx,
    Wim,
    AppleDmg,
}

impl ExtendedArchiveKind {
    pub fn label(self) -> &'static str {
        match self {
            ExtendedArchiveKind::Zip => "zip",
            ExtendedArchiveKind::SevenZ => "7z",
            ExtendedArchiveKind::Rar => "rar",
            ExtendedArchiveKind::Gzip => "gzip",
            ExtendedArchiveKind::Bzip2 => "bzip2",
            ExtendedArchiveKind::Xz => "xz",
            ExtendedArchiveKind::Zstd => "zstd",
            ExtendedArchiveKind::Lz4 => "lz4",
            ExtendedArchiveKind::Tar => "tar",
            ExtendedArchiveKind::Iso9660 => "iso9660",
            ExtendedArchiveKind::Udf => "udf",
            ExtendedArchiveKind::Vhdx => "vhdx",
            ExtendedArchiveKind::Wim => "wim",
            ExtendedArchiveKind::AppleDmg => "dmg",
        }
    }
}

/// Identify an archive container from its leading bytes.
///
/// `head` should be at least 512 bytes for tar detection and at
/// least 32_774 bytes for ISO9660 / UDF detection. Shorter inputs
/// are tolerated — those formats just won't fire.
pub fn detect_archive_kind(head: &[u8]) -> Option<ExtendedArchiveKind> {
    if head.len() >= 8 && &head[0..8] == b"vhdxfile" {
        return Some(ExtendedArchiveKind::Vhdx);
    }
    if head.len() >= 8 && &head[0..8] == b"MSWIM\0\0\0" {
        return Some(ExtendedArchiveKind::Wim);
    }
    if head.len() >= 6 && &head[0..6] == &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        return Some(ExtendedArchiveKind::SevenZ);
    }
    if head.len() >= 7 && head[0..6] == [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07] {
        return Some(ExtendedArchiveKind::Rar);
    }
    if head.len() >= 6 && head[0..6] == [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] {
        return Some(ExtendedArchiveKind::Xz);
    }
    if head.len() >= 4 && head[0..4] == [0x04, 0x22, 0x4D, 0x18] {
        return Some(ExtendedArchiveKind::Lz4);
    }
    if head.len() >= 4 && head[0..4] == [0x28, 0xB5, 0x2F, 0xFD] {
        return Some(ExtendedArchiveKind::Zstd);
    }
    if head.len() >= 4 {
        let p4 = &head[0..4];
        if p4 == b"PK\x03\x04" || p4 == b"PK\x05\x06" || p4 == b"PK\x07\x08" {
            return Some(ExtendedArchiveKind::Zip);
        }
    }
    if head.len() >= 3 && &head[0..3] == b"BZh" {
        return Some(ExtendedArchiveKind::Bzip2);
    }
    if head.len() >= 2 && head[0..2] == [0x1F, 0x8B] {
        return Some(ExtendedArchiveKind::Gzip);
    }
    // ISO9660 / UDF magic lives well into the file (offset 0x8001).
    const SEC_HEAD: usize = 0x8001;
    if head.len() >= SEC_HEAD + 5 {
        if &head[SEC_HEAD..SEC_HEAD + 5] == b"CD001" {
            return Some(ExtendedArchiveKind::Iso9660);
        }
        if &head[SEC_HEAD..SEC_HEAD + 5] == b"BEA01" {
            return Some(ExtendedArchiveKind::Udf);
        }
    }
    // tar: at offset 257, the `ustar` marker (POSIX tar) or
    // `ustar\x00\x30\x30` (gnu tar). 257 + 6 ≤ 512 always when
    // present.
    if head.len() >= 263 && &head[257..262] == b"ustar" {
        return Some(ExtendedArchiveKind::Tar);
    }
    None
}

/// Inspect the *tail* of a file for the Apple DMG `koly` trailer
/// (offset = end - 512, first 4 bytes are `koly`). Caller hands in
/// the last 512 bytes.
pub fn is_apple_dmg_trailer(tail_512: &[u8]) -> bool {
    if tail_512.len() < 512 {
        return false;
    }
    &tail_512[..4] == b"koly"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_zip_central_directory_signature() {
        let head = b"PK\x05\x06ignore the rest";
        assert_eq!(detect_archive_kind(head), Some(ExtendedArchiveKind::Zip));
    }

    #[test]
    fn detects_7z() {
        let head = [0x37u8, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 0];
        assert_eq!(
            detect_archive_kind(&head),
            Some(ExtendedArchiveKind::SevenZ)
        );
    }

    #[test]
    fn detects_xz_zstd_lz4_distinct() {
        assert_eq!(
            detect_archive_kind(&[0xFDu8, 0x37, 0x7A, 0x58, 0x5A, 0x00]),
            Some(ExtendedArchiveKind::Xz)
        );
        assert_eq!(
            detect_archive_kind(&[0x28u8, 0xB5, 0x2F, 0xFD, 0, 0]),
            Some(ExtendedArchiveKind::Zstd)
        );
        assert_eq!(
            detect_archive_kind(&[0x04u8, 0x22, 0x4D, 0x18, 0, 0]),
            Some(ExtendedArchiveKind::Lz4)
        );
    }

    #[test]
    fn detects_vhdx_and_wim() {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"vhdxfile");
        blob.extend(std::iter::repeat(0u8).take(512));
        assert_eq!(detect_archive_kind(&blob), Some(ExtendedArchiveKind::Vhdx));

        let mut wim = Vec::new();
        wim.extend_from_slice(b"MSWIM\0\0\0");
        wim.extend(std::iter::repeat(0u8).take(512));
        assert_eq!(detect_archive_kind(&wim), Some(ExtendedArchiveKind::Wim));
    }

    #[test]
    fn detects_iso9660_magic_at_correct_offset() {
        let mut head = vec![0u8; 0x8001 + 5];
        head[0x8001..0x8001 + 5].copy_from_slice(b"CD001");
        assert_eq!(
            detect_archive_kind(&head),
            Some(ExtendedArchiveKind::Iso9660)
        );
    }

    #[test]
    fn detects_tar_via_ustar_marker() {
        let mut head = vec![0u8; 512];
        head[257..262].copy_from_slice(b"ustar");
        assert_eq!(detect_archive_kind(&head), Some(ExtendedArchiveKind::Tar));
    }

    #[test]
    fn random_bytes_dont_match() {
        let head = [0u8; 1024];
        assert!(detect_archive_kind(&head).is_none());
        let txt = b"this is just a text file, nothing to see";
        assert!(detect_archive_kind(txt).is_none());
    }

    #[test]
    fn apple_dmg_trailer_check() {
        let mut tail = vec![0u8; 512];
        tail[..4].copy_from_slice(b"koly");
        assert!(is_apple_dmg_trailer(&tail));
        let plain = [0u8; 512];
        assert!(!is_apple_dmg_trailer(&plain));
    }
}
