//! TASK-209 — Dual-architecture (fat-binary) scan, slice enumeration.
//!
//! `enumerate_slices(bytes) -> Vec<ArchSlice>` yields one slice per
//! architecture in a fat / universal binary so the engine can hash and
//! YARA-scan each independently. Three container shapes are
//! recognised:
//!
//! - **Mach-O Universal (fat)** — `FAT_MAGIC` / `FAT_MAGIC_64`,
//!   `fat_arch` array with `(cputype, offset, size)` per slice.
//! - **PE ARM64X** — a single PE file whose `IMAGE_FILE_MACHINE_ARM64`
//!   carries a hybrid CHPE (Compiled Hybrid PE) table aliasing an
//!   x86_64 view. We surface it as two logical slices (arm64 +
//!   x86_64), each spanning the whole file but tagged with the
//!   `arch_kind` so downstream YARA can run twice with different
//!   architecture-scoped rulesets.
//! - **PE ARM64EC / ARM64** — single-slice fast path; the existing
//!   single-arch hasher is fine.
//!
//! The slice enumeration is deliberately byte-range only — no extra
//! hashing or detection logic here. The fat-binary scan dispatcher
//! (`detect::fat_binary`) consumes the slices and dispatches hashing
//! over each sub-range.

use crate::detect::header_parse::{
    Arch, ExecFormat, FAT_CIGAM, FAT_CIGAM_64, FAT_MAGIC, FAT_MAGIC_64, HeaderSummary, parse_header,
};
use serde::{Deserialize, Serialize};

/// One architecture slice within a multi-arch container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchSlice {
    pub arch: Arch,
    pub offset: u64,
    pub size: u64,
    /// `true` when the slice spans the entire file (single-arch fast
    /// path or hybrid PE that aliases the same bytes under different
    /// arch tags). Hashing a full-file slice once is equivalent to
    /// the legacy single-file hash; the engine de-duplicates by
    /// (offset, size) before issuing additional reads.
    pub full_file: bool,
}

/// Container kind reported alongside the slice list. Lets the engine
/// surface "this binary is x86_64 + arm64" in the finding row without
/// re-parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Container {
    Single,
    MachOFat,
    PeArm64X,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SliceEnumeration {
    pub container: Container,
    pub slices: Vec<ArchSlice>,
}

/// Enumerate slices from a byte buffer. For a sub-MiB prefix this
/// works because the slice table sits at the start of the file
/// (Mach-O `fat_header` + `fat_arch` array; PE optional header).
///
/// Single-arch inputs return one full-file slice.
pub fn enumerate_slices(bytes: &[u8]) -> SliceEnumeration {
    if let Some(e) = enumerate_macho_fat(bytes) {
        return e;
    }
    if let Some(e) = enumerate_pe_hybrid(bytes) {
        return e;
    }
    // Fall through: single-arch fast path.
    let summary = parse_header(bytes).unwrap_or(HeaderSummary::unknown());
    SliceEnumeration {
        container: Container::Single,
        slices: vec![ArchSlice {
            arch: summary.arch,
            offset: 0,
            size: bytes.len() as u64,
            full_file: true,
        }],
    }
}

// -----------------------------------------------------------------------------
// Mach-O fat
// -----------------------------------------------------------------------------

fn enumerate_macho_fat(bytes: &[u8]) -> Option<SliceEnumeration> {
    if bytes.len() < 8 {
        return None;
    }
    let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let (big_endian, is_64) = match magic {
        FAT_MAGIC => (true, false),
        FAT_CIGAM => (false, false),
        FAT_MAGIC_64 => (true, true),
        FAT_CIGAM_64 => (false, true),
        _ => return None,
    };
    let read_u32 = |off: usize| -> Option<u32> {
        if off + 4 > bytes.len() {
            return None;
        }
        let arr = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
        Some(if big_endian {
            u32::from_be_bytes(arr)
        } else {
            u32::from_le_bytes(arr)
        })
    };
    let read_u64 = |off: usize| -> Option<u64> {
        if off + 8 > bytes.len() {
            return None;
        }
        let arr = [
            bytes[off],
            bytes[off + 1],
            bytes[off + 2],
            bytes[off + 3],
            bytes[off + 4],
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
        ];
        Some(if big_endian {
            u64::from_be_bytes(arr)
        } else {
            u64::from_le_bytes(arr)
        })
    };
    let nfat = read_u32(4)?;
    let mut slices = Vec::with_capacity(nfat as usize);
    let entry_size = if is_64 { 32 } else { 20 };
    let mut off = 8;
    for _ in 0..nfat.min(64) {
        if off + entry_size > bytes.len() {
            break;
        }
        let cputype = read_u32(off)?;
        let (offset, size) = if is_64 {
            (read_u64(off + 8)?, read_u64(off + 16)?)
        } else {
            (read_u32(off + 8)? as u64, read_u32(off + 12)? as u64)
        };
        slices.push(ArchSlice {
            arch: macho_arch_from_cputype(cputype),
            offset,
            size,
            full_file: false,
        });
        off += entry_size;
    }
    if slices.is_empty() {
        return None;
    }
    Some(SliceEnumeration {
        container: Container::MachOFat,
        slices,
    })
}

fn macho_arch_from_cputype(cputype: u32) -> Arch {
    const ABI64: u32 = 0x0100_0000;
    match cputype {
        7 => Arch::X86,
        v if v == 7 | ABI64 => Arch::X86_64,
        12 => Arch::Arm,
        v if v == 12 | ABI64 => Arch::Aarch64,
        18 => Arch::PowerPc,
        v if v == 18 | ABI64 => Arch::PowerPc64,
        other => Arch::Other((other & 0xFFFF) as u16),
    }
}

// -----------------------------------------------------------------------------
// PE ARM64X (Hybrid) — alias same bytes as both arm64 + x86_64
// -----------------------------------------------------------------------------

fn enumerate_pe_hybrid(bytes: &[u8]) -> Option<SliceEnumeration> {
    let summary = parse_header(bytes)?;
    if summary.fmt != ExecFormat::Pe {
        return None;
    }
    if summary.arch == Arch::Arm64X {
        let full = bytes.len() as u64;
        return Some(SliceEnumeration {
            container: Container::PeArm64X,
            slices: vec![
                ArchSlice {
                    arch: Arch::Aarch64,
                    offset: 0,
                    size: full,
                    full_file: true,
                },
                ArchSlice {
                    arch: Arch::X86_64,
                    offset: 0,
                    size: full,
                    full_file: true,
                },
            ],
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_macho_fat_32() -> Vec<u8> {
        // 2 slices: x86_64 (cputype 7|ABI64) and arm64 (12|ABI64)
        const ABI64: u32 = 0x0100_0000;
        let mut v = vec![0u8; 8 + 2 * 20 + 64];
        v[..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        v[4..8].copy_from_slice(&2u32.to_be_bytes());
        // slice 0: x86_64
        v[8..12].copy_from_slice(&(7 | ABI64).to_be_bytes());
        v[16..20].copy_from_slice(&100u32.to_be_bytes()); // offset
        v[20..24].copy_from_slice(&50u32.to_be_bytes()); // size
        // slice 1: arm64
        v[28..32].copy_from_slice(&(12u32 | ABI64).to_be_bytes());
        v[36..40].copy_from_slice(&200u32.to_be_bytes());
        v[40..44].copy_from_slice(&60u32.to_be_bytes());
        v
    }

    #[test]
    fn enumerate_macho_fat_two_slices() {
        let bytes = make_macho_fat_32();
        let e = enumerate_slices(&bytes);
        assert_eq!(e.container, Container::MachOFat);
        assert_eq!(e.slices.len(), 2);
        assert_eq!(e.slices[0].arch, Arch::X86_64);
        assert_eq!(e.slices[0].offset, 100);
        assert_eq!(e.slices[0].size, 50);
        assert_eq!(e.slices[1].arch, Arch::Aarch64);
        assert_eq!(e.slices[1].offset, 200);
        assert_eq!(e.slices[1].size, 60);
    }

    fn make_pe_arm64x_header() -> Vec<u8> {
        let mut v = vec![0u8; 0x100];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3c] = 0x40;
        v[0x40] = b'P';
        v[0x41] = b'E';
        // machine = ARM64X (0xA64E)
        v[0x44..0x46].copy_from_slice(&0xA64Eu16.to_le_bytes());
        v[0x46..0x48].copy_from_slice(&3u16.to_le_bytes());
        v[0x54..0x56].copy_from_slice(&224u16.to_le_bytes());
        v[0x58..0x5a].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
        v
    }

    #[test]
    fn enumerate_pe_arm64x_yields_two_slices() {
        let bytes = make_pe_arm64x_header();
        let e = enumerate_slices(&bytes);
        assert_eq!(e.container, Container::PeArm64X);
        assert_eq!(e.slices.len(), 2);
        assert_eq!(e.slices[0].arch, Arch::Aarch64);
        assert_eq!(e.slices[1].arch, Arch::X86_64);
        assert!(e.slices[0].full_file);
        assert!(e.slices[1].full_file);
    }

    #[test]
    fn enumerate_single_arch_fast_path() {
        // ELF64 amd64 — one slice covering the whole buffer.
        let mut v = vec![0u8; 64];
        v[..4].copy_from_slice(b"\x7fELF");
        v[4] = 2; // 64-bit
        v[5] = 1; // LE
        v[16..18].copy_from_slice(&2u16.to_le_bytes());
        v[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86_64
        let e = enumerate_slices(&v);
        assert_eq!(e.container, Container::Single);
        assert_eq!(e.slices.len(), 1);
        assert_eq!(e.slices[0].arch, Arch::X86_64);
        assert!(e.slices[0].full_file);
    }

    #[test]
    fn malformed_fat_falls_back_to_single() {
        // Truncated fat header — should fall back to single (Unknown).
        let v = vec![0xCAu8, 0xFE, 0xBA, 0xBE];
        let e = enumerate_slices(&v);
        assert_eq!(e.container, Container::Single);
    }
}
