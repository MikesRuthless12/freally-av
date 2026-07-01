//! TASK-216 — In-tree PE / ELF / Mach-O header parser.
//!
//! Triage-only: reads the first few KiB of a file and reports
//! `HeaderSummary { fmt, arch, subsystem, linker_version, sections,
//! entry_rva, has_signature }`. Pure-Rust, no `goblin`/`pelite` deps
//! (the existing dep-tree budget is tight; adding two parsers when we
//! only need read-only summary extraction is overkill for the
//! free-tier license discipline).
//!
//! Used by the scanner's first-MiB pass for header-mismatch detection
//! (file claims `.exe` but the bytes are anything else) and as the
//! foundation for the format-aware detectors that follow:
//! TASK-209 (fat binary slices), TASK-217 (packer ID — already
//! shipped, currently signature-only), TASK-219 (.NET IL), TASK-222
//! (Mach-O code-signature), TASK-223 (Authenticode), TASK-224 (ELF
//! hardening).

use serde::{Deserialize, Serialize};

/// Top-level executable format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecFormat {
    Pe,
    Elf,
    MachO,
    MachOFat,
    /// Format-class not recognised at this triage depth. The scanner
    /// records this rather than failing — a file with an unknown
    /// magic is still a candidate for hashing.
    Unknown,
}

/// CPU architecture surfaced from the header. Only the values we
/// actually need to distinguish for downstream policy are enumerated;
/// novel / obscure machine types collapse to `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Arm64Ec,
    Arm64X,
    Mips,
    PowerPc,
    PowerPc64,
    RiscV,
    Other(u16),
    Unknown,
}

/// Compact summary returned by [`parse_header`]. Cheap to clone and
/// store on the finding row as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderSummary {
    pub fmt: ExecFormat,
    pub arch: Arch,
    /// PE subsystem id (1 = native, 2 = GUI, 3 = console, 9 = EFI app,
    /// …) or ELF e_type / Mach-O filetype. Format-specific.
    pub subsystem: Option<u32>,
    /// Linker version major.minor where available (PE only currently).
    pub linker_version: Option<(u8, u8)>,
    /// Number of sections / segments declared in the header.
    pub sections: u16,
    /// Entry-point relative virtual address.
    pub entry_rva: u64,
    /// Whether the binary advertises a signature directory (PE
    /// security entry, Mach-O `LC_CODE_SIGNATURE`, ELF `.note.gnu.…`
    /// signature notes). Validity is checked by later passes
    /// (TASK-222 / TASK-223); this is a boolean flag only.
    pub has_signature: bool,
}

impl HeaderSummary {
    pub fn unknown() -> Self {
        Self {
            fmt: ExecFormat::Unknown,
            arch: Arch::Unknown,
            subsystem: None,
            linker_version: None,
            sections: 0,
            entry_rva: 0,
            has_signature: false,
        }
    }
}

/// Parse the first few KiB of an in-memory buffer into a
/// [`HeaderSummary`]. Returns `None` only when `bytes` is too short
/// to recognise any magic; format-specific parse errors collapse to
/// `Unknown` so callers never panic on hostile input.
///
/// The function never reads past `bytes.len()`; it deliberately
/// doesn't take a `Path` — callers (the scanner, the fat-binary
/// dispatcher) already have a buffer in hand from the hasher
/// prefetch pass and shouldn't pay for another open().
pub fn parse_header(bytes: &[u8]) -> Option<HeaderSummary> {
    if bytes.len() < 4 {
        return None;
    }
    if let Some(s) = parse_pe(bytes) {
        return Some(s);
    }
    if let Some(s) = parse_elf(bytes) {
        return Some(s);
    }
    if let Some(s) = parse_macho(bytes) {
        return Some(s);
    }
    if let Some(s) = parse_macho_fat(bytes) {
        return Some(s);
    }
    Some(HeaderSummary::unknown())
}

// -----------------------------------------------------------------------------
// PE
// -----------------------------------------------------------------------------

const DOS_MAGIC: &[u8; 2] = b"MZ";
const PE_MAGIC: &[u8; 4] = b"PE\0\0";

fn parse_pe(bytes: &[u8]) -> Option<HeaderSummary> {
    if bytes.len() < 0x40 || &bytes[..2] != DOS_MAGIC {
        return None;
    }
    let e_lfanew = read_u32_le(bytes, 0x3c)? as usize;
    if bytes.len() < e_lfanew + 24 || &bytes[e_lfanew..e_lfanew + 4] != PE_MAGIC {
        return None;
    }
    let coff = e_lfanew + 4;
    let machine = read_u16_le(bytes, coff)?;
    let num_sections = read_u16_le(bytes, coff + 2)?;
    let size_of_optional = read_u16_le(bytes, coff + 16)? as usize;
    let opt_hdr = coff + 20;
    if size_of_optional == 0 || bytes.len() < opt_hdr + size_of_optional.min(96) {
        // Object file or extremely truncated PE — return what we have.
        return Some(HeaderSummary {
            fmt: ExecFormat::Pe,
            arch: pe_arch(machine),
            subsystem: None,
            linker_version: None,
            sections: num_sections,
            entry_rva: 0,
            has_signature: false,
        });
    }
    let magic = read_u16_le(bytes, opt_hdr)?;
    let pe32_plus = magic == 0x20B;
    let linker_major = bytes.get(opt_hdr + 2).copied().unwrap_or(0);
    let linker_minor = bytes.get(opt_hdr + 3).copied().unwrap_or(0);
    let entry_point = read_u32_le(bytes, opt_hdr + 16)? as u64;
    // Subsystem field is at the same +68 offset in both PE32 and PE32+
    // — the Image Base size change earlier in the optional header
    // self-cancels by the time we reach this field. Use a single
    // constant rather than a branch.
    let subsys_off = opt_hdr + 68;
    let _ = pe32_plus; // referenced again below in the data-dir math
    let subsystem = read_u16_le(bytes, subsys_off).map(|v| v as u32);
    // NumberOfRvaAndSizes is at +108 in PE32+, +92 in PE32. The
    // Security data directory (index 4) sits 8*4=32 bytes after that.
    let data_dir_off = opt_hdr + if pe32_plus { 112 } else { 96 };
    let mut has_signature = false;
    if let Some(num_dirs) = read_u32_le(bytes, data_dir_off - 4)
        && num_dirs >= 5
    {
        let sec_dir = data_dir_off + 4 * 8;
        if let (Some(va), Some(sz)) = (read_u32_le(bytes, sec_dir), read_u32_le(bytes, sec_dir + 4))
        {
            // Even when va==0, sz > 0 indicates "signature follows
            // file" (Authenticode appends the PKCS#7 after the last
            // section). We treat sz>0 as the advertise.
            has_signature = sz > 0 || va > 0;
        }
    }
    Some(HeaderSummary {
        fmt: ExecFormat::Pe,
        arch: pe_arch(machine),
        subsystem,
        linker_version: Some((linker_major, linker_minor)),
        sections: num_sections,
        entry_rva: entry_point,
        has_signature,
    })
}

fn pe_arch(machine: u16) -> Arch {
    match machine {
        0x014c => Arch::X86,
        0x8664 => Arch::X86_64,
        0x01c0 | 0x01c2 | 0x01c4 => Arch::Arm,
        0xAA64 => Arch::Aarch64,
        0xA641 => Arch::Arm64Ec, // ARM64EC
        0xA64E => Arch::Arm64X,  // ARM64X (hybrid)
        0x5032 => Arch::RiscV,   // RISCV32
        0x5064 => Arch::RiscV,   // RISCV64
        other => Arch::Other(other),
    }
}

// -----------------------------------------------------------------------------
// ELF
// -----------------------------------------------------------------------------

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";

fn parse_elf(bytes: &[u8]) -> Option<HeaderSummary> {
    if bytes.len() < 52 || &bytes[..4] != ELF_MAGIC {
        return None;
    }
    let class = bytes[4]; // 1 = 32-bit, 2 = 64-bit
    let data = bytes[5]; // 1 = LE, 2 = BE
    let read_u16 = |off: usize| read_int_endian_u16(bytes, off, data == 1);
    let read_u32 = |off: usize| read_int_endian_u32(bytes, off, data == 1);
    let read_u64 = |off: usize| read_int_endian_u64(bytes, off, data == 1);
    let e_type = read_u16(16)?;
    let e_machine = read_u16(18)?;
    let (entry, phnum_off, shnum_off) = if class == 2 {
        let entry = read_u64(24)?;
        (entry, 56usize, 60usize)
    } else {
        let entry = read_u32(24)? as u64;
        (entry, 44usize, 48usize)
    };
    let phnum = read_u16(phnum_off)?;
    let shnum = read_u16(shnum_off)?;
    Some(HeaderSummary {
        fmt: ExecFormat::Elf,
        arch: elf_arch(e_machine),
        subsystem: Some(e_type as u32),
        linker_version: None,
        sections: shnum.max(phnum),
        entry_rva: entry,
        // ELF "signature" is detected separately via .note sections;
        // the header itself doesn't advertise. Default false.
        has_signature: false,
    })
}

fn elf_arch(machine: u16) -> Arch {
    match machine {
        3 => Arch::X86,
        62 => Arch::X86_64,
        40 => Arch::Arm,
        183 => Arch::Aarch64,
        8 => Arch::Mips,
        20 => Arch::PowerPc,
        21 => Arch::PowerPc64,
        243 => Arch::RiscV,
        other => Arch::Other(other),
    }
}

// -----------------------------------------------------------------------------
// Mach-O (single-arch)
// -----------------------------------------------------------------------------

const MACHO_MAGIC_32: u32 = 0xFEEDFACE;
const MACHO_CIGAM_32: u32 = 0xCEFAEDFE;
const MACHO_MAGIC_64: u32 = 0xFEEDFACF;
const MACHO_CIGAM_64: u32 = 0xCFFAEDFE;

fn parse_macho(bytes: &[u8]) -> Option<HeaderSummary> {
    if bytes.len() < 28 {
        return None;
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let (le, sixty_four) = match magic {
        MACHO_MAGIC_32 => (true, false),
        MACHO_MAGIC_64 => (true, true),
        MACHO_CIGAM_32 => (false, false),
        MACHO_CIGAM_64 => (false, true),
        _ => return None,
    };
    let read_u32 = |off: usize| read_int_endian_u32(bytes, off, le);
    let cputype = read_u32(4)?;
    let ncmds = read_u32(16)?;
    let filetype = read_u32(12)?;
    // entry_point isn't directly in the mach_header; we need
    // LC_MAIN/LC_UNIXTHREAD walking. Triage leaves it 0.
    let arch = macho_arch(cputype);
    // Scan load commands within the first 4 KiB window for
    // LC_CODE_SIGNATURE (0x1d).
    let lc_start = if sixty_four { 32 } else { 28 };
    let mut has_signature = false;
    let mut off = lc_start;
    for _ in 0..ncmds.min(256) {
        if off + 8 > bytes.len() {
            break;
        }
        let cmd = read_int_endian_u32(bytes, off, le)?;
        let cmdsize = read_int_endian_u32(bytes, off + 4, le)? as usize;
        if cmdsize == 0 {
            break;
        }
        if cmd == 0x1d {
            has_signature = true;
            break;
        }
        off = off.saturating_add(cmdsize);
    }
    Some(HeaderSummary {
        fmt: ExecFormat::MachO,
        arch,
        subsystem: Some(filetype),
        linker_version: None,
        sections: ncmds as u16,
        entry_rva: 0,
        has_signature,
    })
}

fn macho_arch(cputype: u32) -> Arch {
    // CPU_ARCH_ABI64 = 0x0100_0000
    const ABI64: u32 = 0x0100_0000;
    const CPU_TYPE_X86: u32 = 7;
    const CPU_TYPE_X86_64: u32 = 7 | ABI64;
    const CPU_TYPE_ARM: u32 = 12;
    const CPU_TYPE_ARM64: u32 = 12 | ABI64;
    const CPU_TYPE_POWERPC: u32 = 18;
    const CPU_TYPE_POWERPC64: u32 = 18 | ABI64;
    match cputype {
        CPU_TYPE_X86 => Arch::X86,
        CPU_TYPE_X86_64 => Arch::X86_64,
        CPU_TYPE_ARM => Arch::Arm,
        CPU_TYPE_ARM64 => Arch::Aarch64,
        CPU_TYPE_POWERPC => Arch::PowerPc,
        CPU_TYPE_POWERPC64 => Arch::PowerPc64,
        other => Arch::Other((other & 0xFFFF) as u16),
    }
}

// -----------------------------------------------------------------------------
// Mach-O fat (universal binary)
// -----------------------------------------------------------------------------

/// Mach-O fat magic constants — exposed as `pub` so the slice
/// enumerator in [`crate::walker::dual_arch`] and any future
/// fat-binary consumer can import the canonical values rather than
/// redeclaring them.
pub const FAT_MAGIC: u32 = 0xCAFEBABE;
pub const FAT_CIGAM: u32 = 0xBEBAFECA;
pub const FAT_MAGIC_64: u32 = 0xCAFEBABF;
pub const FAT_CIGAM_64: u32 = 0xBFBAFECA;

fn parse_macho_fat(bytes: &[u8]) -> Option<HeaderSummary> {
    if bytes.len() < 8 {
        return None;
    }
    let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let is_fat = matches!(magic, FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64);
    if !is_fat {
        return None;
    }
    let big_endian = matches!(magic, FAT_MAGIC | FAT_MAGIC_64);
    let read = if big_endian {
        u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
    } else {
        u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
    };
    Some(HeaderSummary {
        fmt: ExecFormat::MachOFat,
        arch: Arch::Unknown, // Per-slice — caller iterates slices.
        subsystem: None,
        linker_version: None,
        sections: read.min(u16::MAX as u32) as u16,
        entry_rva: 0,
        has_signature: false,
    })
}

// -----------------------------------------------------------------------------
// Little/Big endian primitives
// -----------------------------------------------------------------------------

fn read_u16_le(bytes: &[u8], off: usize) -> Option<u16> {
    if off + 2 > bytes.len() {
        return None;
    }
    Some(u16::from_le_bytes([bytes[off], bytes[off + 1]]))
}

fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    if off + 4 > bytes.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
    ]))
}

fn read_int_endian_u16(bytes: &[u8], off: usize, le: bool) -> Option<u16> {
    if off + 2 > bytes.len() {
        return None;
    }
    let arr = [bytes[off], bytes[off + 1]];
    Some(if le {
        u16::from_le_bytes(arr)
    } else {
        u16::from_be_bytes(arr)
    })
}

fn read_int_endian_u32(bytes: &[u8], off: usize, le: bool) -> Option<u32> {
    if off + 4 > bytes.len() {
        return None;
    }
    let arr = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
    Some(if le {
        u32::from_le_bytes(arr)
    } else {
        u32::from_be_bytes(arr)
    })
}

fn read_int_endian_u64(bytes: &[u8], off: usize, le: bool) -> Option<u64> {
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
    Some(if le {
        u64::from_le_bytes(arr)
    } else {
        u64::from_be_bytes(arr)
    })
}

/// File-extension based hint used by the scanner to detect a
/// header-mismatch (a `.exe` whose bytes aren't a PE). Returns the
/// expected [`ExecFormat`] for a given extension, or `None` when the
/// extension is unrelated to executables.
pub fn expected_format_for_extension(ext: &str) -> Option<ExecFormat> {
    let lower = ext.to_ascii_lowercase();
    match lower.as_str() {
        "exe" | "dll" | "sys" | "ocx" | "scr" | "cpl" | "drv" | "efi" => Some(ExecFormat::Pe),
        "so" => Some(ExecFormat::Elf),
        "dylib" | "bundle" => Some(ExecFormat::MachO),
        _ => None,
    }
}

/// Convenience: returns `true` when the parsed format doesn't match
/// the file's claimed extension. Used by the scanner's first-MiB pass
/// (TASK-216 reference; full integration deferred until the engine's
/// scanner.rs is touched).
pub fn is_header_mismatch(summary: &HeaderSummary, ext: &str) -> bool {
    match expected_format_for_extension(ext) {
        Some(expected) => match (expected, summary.fmt) {
            (ExecFormat::MachO, ExecFormat::MachOFat) => false,
            (a, b) => a != b,
        },
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pe_header(machine: u16) -> Vec<u8> {
        // Minimal PE: MZ header, e_lfanew at 0x40, PE\0\0, COFF, opt hdr.
        let mut v = vec![0u8; 0x100];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3c] = 0x40;
        v[0x40] = b'P';
        v[0x41] = b'E';
        // COFF starts at 0x44
        v[0x44..0x46].copy_from_slice(&machine.to_le_bytes());
        v[0x46..0x48].copy_from_slice(&3u16.to_le_bytes()); // 3 sections
        v[0x54..0x56].copy_from_slice(&224u16.to_le_bytes()); // size_of_optional
        // Optional header magic at COFF + 20 = 0x58
        v[0x58..0x5a].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
        v[0x5a] = 14; // linker major
        v[0x5b] = 28; // linker minor
        v[0x68..0x6c].copy_from_slice(&0x1234u32.to_le_bytes()); // entry point
        v[0x9c..0x9e].copy_from_slice(&3u16.to_le_bytes()); // subsystem = console (PE32+ offset 0x58+68=0x9c)
        // NumberOfRvaAndSizes at +108 → 0x58+108 = 0xc4, but we need a longer buffer for that.
        v
    }

    #[test]
    fn parse_pe_minimal_amd64() {
        let v = make_pe_header(0x8664);
        let h = parse_header(&v).unwrap();
        assert_eq!(h.fmt, ExecFormat::Pe);
        assert_eq!(h.arch, Arch::X86_64);
        assert_eq!(h.sections, 3);
        assert_eq!(h.entry_rva, 0x1234);
        assert_eq!(h.linker_version, Some((14, 28)));
        assert_eq!(h.subsystem, Some(3));
    }

    #[test]
    fn parse_pe_minimal_arm64ec() {
        let v = make_pe_header(0xA641);
        let h = parse_header(&v).unwrap();
        assert_eq!(h.arch, Arch::Arm64Ec);
    }

    #[test]
    fn parse_pe_minimal_arm64x() {
        let v = make_pe_header(0xA64E);
        let h = parse_header(&v).unwrap();
        assert_eq!(h.arch, Arch::Arm64X);
    }

    #[test]
    fn parse_pe_minimal_i386() {
        let v = make_pe_header(0x014c);
        let h = parse_header(&v).unwrap();
        assert_eq!(h.arch, Arch::X86);
    }

    fn make_elf64(machine: u16, entry: u64) -> Vec<u8> {
        let mut v = vec![0u8; 64];
        v[..4].copy_from_slice(b"\x7fELF");
        v[4] = 2; // 64-bit
        v[5] = 1; // LE
        v[16..18].copy_from_slice(&2u16.to_le_bytes()); // EXEC
        v[18..20].copy_from_slice(&machine.to_le_bytes());
        v[24..32].copy_from_slice(&entry.to_le_bytes());
        v[56..58].copy_from_slice(&4u16.to_le_bytes()); // phnum
        v[60..62].copy_from_slice(&7u16.to_le_bytes()); // shnum
        v
    }

    #[test]
    fn parse_elf64_amd64() {
        let v = make_elf64(62, 0x40_1234);
        let h = parse_header(&v).unwrap();
        assert_eq!(h.fmt, ExecFormat::Elf);
        assert_eq!(h.arch, Arch::X86_64);
        assert_eq!(h.entry_rva, 0x40_1234);
        assert_eq!(h.sections, 7);
        assert_eq!(h.subsystem, Some(2));
    }

    #[test]
    fn parse_elf64_aarch64() {
        let v = make_elf64(183, 0);
        let h = parse_header(&v).unwrap();
        assert_eq!(h.arch, Arch::Aarch64);
    }

    fn make_macho64(cputype: u32) -> Vec<u8> {
        let mut v = vec![0u8; 64];
        v[..4].copy_from_slice(&MACHO_MAGIC_64.to_le_bytes());
        v[4..8].copy_from_slice(&cputype.to_le_bytes());
        v[12..16].copy_from_slice(&2u32.to_le_bytes()); // filetype = MH_EXECUTE
        v[16..20].copy_from_slice(&1u32.to_le_bytes()); // ncmds = 1
        // First load command at offset 32 (size 0x18, cmd LC_CODE_SIGNATURE = 0x1d)
        v[32..36].copy_from_slice(&0x1du32.to_le_bytes());
        v[36..40].copy_from_slice(&0x18u32.to_le_bytes());
        v
    }

    #[test]
    fn parse_macho_arm64_with_signature() {
        let v = make_macho64(12 | 0x0100_0000); // ARM64
        let h = parse_header(&v).unwrap();
        assert_eq!(h.fmt, ExecFormat::MachO);
        assert_eq!(h.arch, Arch::Aarch64);
        assert_eq!(h.subsystem, Some(2));
        assert!(h.has_signature);
    }

    #[test]
    fn parse_macho_fat_be_magic() {
        // FAT_MAGIC is BE; fat_arch count = 2.
        let mut v = vec![0u8; 32];
        v[..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        v[4..8].copy_from_slice(&2u32.to_be_bytes());
        let h = parse_header(&v).unwrap();
        assert_eq!(h.fmt, ExecFormat::MachOFat);
        assert_eq!(h.sections, 2);
    }

    #[test]
    fn unknown_bytes_yield_unknown_summary() {
        let v = vec![0u8; 64];
        let h = parse_header(&v).unwrap();
        assert_eq!(h.fmt, ExecFormat::Unknown);
        assert_eq!(h.arch, Arch::Unknown);
    }

    #[test]
    fn truncated_input_returns_none() {
        assert!(parse_header(&[]).is_none());
        assert!(parse_header(&[0u8; 3]).is_none());
    }

    #[test]
    fn extension_mismatch_detected() {
        let elf = make_elf64(62, 0);
        let h = parse_header(&elf).unwrap();
        assert!(is_header_mismatch(&h, "exe"));
        assert!(!is_header_mismatch(&h, "so"));
        // Unrelated extension: never a mismatch.
        assert!(!is_header_mismatch(&h, "txt"));
    }

    #[test]
    fn fat_extension_compatibility() {
        // A universal Mach-O is acceptable for `.dylib`/`.bundle` too.
        let mut v = vec![0u8; 16];
        v[..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        v[4..8].copy_from_slice(&2u32.to_be_bytes());
        let h = parse_header(&v).unwrap();
        assert!(!is_header_mismatch(&h, "dylib"));
    }

    #[test]
    fn expected_format_table_covers_common_extensions() {
        assert_eq!(expected_format_for_extension("exe"), Some(ExecFormat::Pe));
        assert_eq!(expected_format_for_extension("DLL"), Some(ExecFormat::Pe));
        assert_eq!(expected_format_for_extension("so"), Some(ExecFormat::Elf));
        assert_eq!(
            expected_format_for_extension("dylib"),
            Some(ExecFormat::MachO)
        );
        assert_eq!(expected_format_for_extension("txt"), None);
    }
}
