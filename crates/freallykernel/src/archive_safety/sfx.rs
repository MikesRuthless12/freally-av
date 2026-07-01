//! Self-extracting archive heuristic (TASK-285).
//!
//! SFX archives are PE / Mach-O / ELF binaries that carry an
//! archive payload appended after the regular executable image.
//! Three common shapes:
//!
//!   * `PE` + ZIP central directory at end of file
//!   * `PE` + 7z magic bytes after the import table
//!   * `PE` + RAR header following the `.rsrc` section
//!
//! Detection here is the **structural** heuristic: PE / Mach-O /
//! ELF magic at offset 0, then any of the known archive magics
//! appearing after the first 4 KiB. Final disambiguation
//! (which archive crate to mount) reuses [`super::magic`].

use serde::{Deserialize, Serialize};

use super::magic::ExtendedArchiveKind;
use crate::util::bytes::find_subslice;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SfxKind {
    PeZip,
    PeSevenZ,
    PeRar,
    MachZip,
    ElfZip,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SfxFinding {
    pub kind: SfxKind,
    /// Byte offset at which the appended archive payload begins.
    pub payload_offset: usize,
    /// Archive container family of the appended payload.
    pub container: ExtendedArchiveKind,
}

const PE_HEAD: [u8; 2] = [b'M', b'Z'];
const ELF_HEAD: [u8; 4] = [0x7F, b'E', b'L', b'F'];
// Mach-O magic — covers thin Mach-O 32/64 in both byte orders + fat.
const MACHO_MAGICS: &[[u8; 4]] = &[
    [0xFE, 0xED, 0xFA, 0xCE],
    [0xFE, 0xED, 0xFA, 0xCF],
    [0xCE, 0xFA, 0xED, 0xFE],
    [0xCF, 0xFA, 0xED, 0xFE],
    [0xCA, 0xFE, 0xBA, 0xBE],
    [0xCA, 0xFE, 0xBA, 0xBF],
];

const MIN_APPENDED_OFFSET: usize = 4096;

/// Scan a buffer for "PE-host + appended archive" shape.
/// `raw` may be partial — only the *first* MIN_APPENDED_OFFSET +
/// search-window bytes are necessary. The daemon mmap's the
/// whole file in practice.
pub fn detect_sfx(raw: &[u8]) -> Option<SfxFinding> {
    let host = host_kind(raw)?;
    let search_from = MIN_APPENDED_OFFSET.min(raw.len());
    let tail = &raw[search_from..];

    if let Some(rel) = find_subslice(tail, b"PK\x03\x04") {
        return Some(SfxFinding {
            kind: match host {
                Host::Pe => SfxKind::PeZip,
                Host::MachO => SfxKind::MachZip,
                Host::Elf => SfxKind::ElfZip,
            },
            payload_offset: search_from + rel,
            container: ExtendedArchiveKind::Zip,
        });
    }
    if let Some(rel) = find_subslice(tail, &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        if host == Host::Pe {
            return Some(SfxFinding {
                kind: SfxKind::PeSevenZ,
                payload_offset: search_from + rel,
                container: ExtendedArchiveKind::SevenZ,
            });
        }
    }
    if let Some(rel) = find_subslice(tail, &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]) {
        if host == Host::Pe {
            return Some(SfxFinding {
                kind: SfxKind::PeRar,
                payload_offset: search_from + rel,
                container: ExtendedArchiveKind::Rar,
            });
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Host {
    Pe,
    Elf,
    MachO,
}

fn host_kind(raw: &[u8]) -> Option<Host> {
    if raw.len() >= 2 && raw[0..2] == PE_HEAD {
        return Some(Host::Pe);
    }
    if raw.len() >= 4 && raw[0..4] == ELF_HEAD {
        return Some(Host::Elf);
    }
    if raw.len() >= 4 {
        let head: [u8; 4] = [raw[0], raw[1], raw[2], raw[3]];
        if MACHO_MAGICS.contains(&head) {
            return Some(Host::MachO);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_with_appended(payload_magic: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; MIN_APPENDED_OFFSET + 16];
        out[0..2].copy_from_slice(b"MZ");
        // Append payload after the 4 KiB threshold.
        out[MIN_APPENDED_OFFSET..MIN_APPENDED_OFFSET + payload_magic.len()]
            .copy_from_slice(payload_magic);
        out
    }

    #[test]
    fn detects_pe_with_appended_zip() {
        let blob = pe_with_appended(b"PK\x03\x04");
        let f = detect_sfx(&blob).expect("detected");
        assert_eq!(f.kind, SfxKind::PeZip);
        assert_eq!(f.container, ExtendedArchiveKind::Zip);
        assert!(f.payload_offset >= MIN_APPENDED_OFFSET);
    }

    #[test]
    fn detects_pe_with_appended_7z() {
        let blob = pe_with_appended(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
        let f = detect_sfx(&blob).expect("detected");
        assert_eq!(f.kind, SfxKind::PeSevenZ);
        assert_eq!(f.container, ExtendedArchiveKind::SevenZ);
    }

    #[test]
    fn detects_pe_with_appended_rar() {
        let blob = pe_with_appended(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]);
        let f = detect_sfx(&blob).expect("detected");
        assert_eq!(f.kind, SfxKind::PeRar);
    }

    #[test]
    fn benign_pe_yields_nothing() {
        let blob = vec![0u8; MIN_APPENDED_OFFSET + 64];
        let mut blob = blob;
        blob[0..2].copy_from_slice(b"MZ");
        assert!(detect_sfx(&blob).is_none());
    }

    #[test]
    fn plain_zip_isnt_sfx() {
        // A regular zip without a host binary is not SFX.
        let blob = b"PK\x03\x04rest of zip";
        assert!(detect_sfx(blob).is_none());
    }

    #[test]
    fn macho_with_appended_zip() {
        let mut blob = vec![0u8; MIN_APPENDED_OFFSET + 16];
        blob[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
        blob[MIN_APPENDED_OFFSET..MIN_APPENDED_OFFSET + 4].copy_from_slice(b"PK\x03\x04");
        let f = detect_sfx(&blob).expect("detected");
        assert_eq!(f.kind, SfxKind::MachZip);
    }

    #[test]
    fn elf_with_appended_zip() {
        let mut blob = vec![0u8; MIN_APPENDED_OFFSET + 16];
        blob[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        blob[MIN_APPENDED_OFFSET..MIN_APPENDED_OFFSET + 4].copy_from_slice(b"PK\x03\x04");
        let f = detect_sfx(&blob).expect("detected");
        assert_eq!(f.kind, SfxKind::ElfZip);
    }

    #[test]
    fn payload_within_first_4kib_is_ignored() {
        // An archive magic inside the host binary's image (e.g.
        // in the import table) shouldn't be flagged.
        let mut blob = vec![0u8; MIN_APPENDED_OFFSET + 16];
        blob[0..2].copy_from_slice(b"MZ");
        blob[2048..2052].copy_from_slice(b"PK\x03\x04");
        assert!(detect_sfx(&blob).is_none());
    }
}
