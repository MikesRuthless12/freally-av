//! Mach-O in-memory load detector (TASK-295).
//!
//! macOS analogue to [`super::reflective`]. Detects a Mach-O
//! image present in a private executable region that isn't
//! backed by a `.dylib` / `.bundle` / executable file. Five
//! magic numbers cover thin Mach-O (32 / 64 bit, both byte
//! orders) and fat binaries.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachOMagic {
    Thin32Le,
    Thin64Le,
    Thin32Be,
    Thin64Be,
    Fat,
}

impl MachOMagic {
    pub fn label(self) -> &'static str {
        match self {
            MachOMagic::Thin32Le => "macho_thin32_le",
            MachOMagic::Thin64Le => "macho_thin64_le",
            MachOMagic::Thin32Be => "macho_thin32_be",
            MachOMagic::Thin64Be => "macho_thin64_be",
            MachOMagic::Fat => "macho_fat",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachOInMemoryFinding {
    pub offset_in_region: usize,
    pub magic: MachOMagic,
}

/// `is_macho_in_memory` requires both:
///   * region is RX or RWX **and** anonymous (no mapped file)
///   * region's bytes start with a Mach-O magic in the first
///     1 KiB
pub fn is_macho_in_memory(
    bytes: &[u8],
    region_is_anonymous_exec: bool,
) -> Option<MachOInMemoryFinding> {
    if !region_is_anonymous_exec {
        return None;
    }
    let limit = bytes.len().min(1024);
    // Walk every 4-byte window inclusive of the last legal one
    // (`off + 4 <= limit`). The previous `0..limit-4` excluded
    // `off = limit - 4`, missing magic at the final window —
    // e.g. a 4-byte buffer carrying just a Mach-O magic.
    if limit < 4 {
        return None;
    }
    for off in 0..=limit - 4 {
        if let Some(magic) = match_magic(&bytes[off..off + 4]) {
            return Some(MachOInMemoryFinding {
                offset_in_region: off,
                magic,
            });
        }
    }
    None
}

fn match_magic(slice: &[u8]) -> Option<MachOMagic> {
    let arr: [u8; 4] = slice.try_into().ok()?;
    match arr {
        [0xFE, 0xED, 0xFA, 0xCE] => Some(MachOMagic::Thin32Be),
        [0xFE, 0xED, 0xFA, 0xCF] => Some(MachOMagic::Thin64Be),
        [0xCE, 0xFA, 0xED, 0xFE] => Some(MachOMagic::Thin32Le),
        [0xCF, 0xFA, 0xED, 0xFE] => Some(MachOMagic::Thin64Le),
        [0xCA, 0xFE, 0xBA, 0xBE] | [0xCA, 0xFE, 0xBA, 0xBF] => Some(MachOMagic::Fat),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_thin64_le() {
        let mut buf = vec![0u8; 256];
        buf[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
        let f = is_macho_in_memory(&buf, true).unwrap();
        assert_eq!(f.magic, MachOMagic::Thin64Le);
        assert_eq!(f.offset_in_region, 0);
    }

    #[test]
    fn detects_fat_binary() {
        let mut buf = vec![0u8; 256];
        buf[0..4].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        let f = is_macho_in_memory(&buf, true).unwrap();
        assert_eq!(f.magic, MachOMagic::Fat);
    }

    #[test]
    fn benign_region_yields_none() {
        let buf = vec![0u8; 4096];
        assert!(is_macho_in_memory(&buf, true).is_none());
    }

    #[test]
    fn anonymous_exec_required() {
        let mut buf = vec![0u8; 256];
        buf[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
        // region_is_anonymous_exec = false → suppressed.
        assert!(is_macho_in_memory(&buf, false).is_none());
    }

    #[test]
    fn detects_macho_with_leading_padding() {
        let mut buf = vec![0u8; 1024];
        buf[256..260].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
        let f = is_macho_in_memory(&buf, true).unwrap();
        assert_eq!(f.offset_in_region, 256);
    }

    #[test]
    fn detects_magic_at_exactly_four_byte_buffer() {
        // The previous off-by-one (`0..limit-4`) excluded
        // `off = 0` when limit = 4 and returned None.
        let buf = [0xCFu8, 0xFA, 0xED, 0xFE];
        let f = is_macho_in_memory(&buf, true).expect("detected");
        assert_eq!(f.offset_in_region, 0);
        assert_eq!(f.magic, MachOMagic::Thin64Le);
    }

    #[test]
    fn detects_magic_at_final_window_of_larger_buffer() {
        // Magic sits at offset (limit - 4); previously skipped.
        let mut buf = vec![0u8; 1024];
        let off = 1024 - 4;
        buf[off..off + 4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
        let f = is_macho_in_memory(&buf, true).expect("detected");
        assert_eq!(f.offset_in_region, off);
    }

    #[test]
    fn buffer_too_short_for_any_magic_returns_none() {
        for len in 0..4usize {
            let buf = vec![0u8; len];
            assert!(is_macho_in_memory(&buf, true).is_none(), "len={len}");
        }
    }

    #[test]
    fn detects_thin32_be_and_le() {
        let mut be = vec![0u8; 64];
        be[0..4].copy_from_slice(&[0xFE, 0xED, 0xFA, 0xCE]);
        assert_eq!(
            is_macho_in_memory(&be, true).unwrap().magic,
            MachOMagic::Thin32Be
        );
        let mut le = vec![0u8; 64];
        le[0..4].copy_from_slice(&[0xCE, 0xFA, 0xED, 0xFE]);
        assert_eq!(
            is_macho_in_memory(&le, true).unwrap().magic,
            MachOMagic::Thin32Le
        );
    }
}
