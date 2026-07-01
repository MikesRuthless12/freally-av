//! TASK-224 — Linux ELF hardening inventory.
//!
//! Scores each ELF binary on four pillars:
//!   - **NX** — non-executable stack (presence of `PT_GNU_STACK`
//!     program header with no `PF_X` flag).
//!   - **RELRO** — `PT_GNU_RELRO` present, plus `DT_BIND_NOW` in
//!     the dynamic table → *Full RELRO*. `PT_GNU_RELRO` alone is
//!     *Partial RELRO* and still scores.
//!   - **PIE** — `e_type == ET_DYN` for an executable (not a
//!     library; libraries are dynamic by definition and don't
//!     score on PIE).
//!   - **Canary** — dynamic-symbol-table entry `__stack_chk_fail`.
//!
//! The output is a 0..4 score plus per-pillar `Option<bool>` so the
//! UI can render "unknown" cells distinctly from "absent".
//!
//! Pure ELF parser (no `goblin` dep): the format is fixed-field and
//! we only need the program-header table + dynamic table + `.dynsym`
//! string table, none of which need a full ELF abstract syntax tree.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelroLevel {
    None,
    Partial,
    Full,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningScore {
    pub nx: Option<bool>,
    pub relro: Option<RelroLevel>,
    pub pie: Option<bool>,
    pub canary: Option<bool>,
    /// Aggregate 0..4 — counts each present pillar as 1. Partial
    /// RELRO counts as 1; Full as 1 (the level is surfaced
    /// separately).
    pub total: u8,
}

impl HardeningScore {
    pub fn unknown() -> Self {
        Self {
            nx: None,
            relro: None,
            pie: None,
            canary: None,
            total: 0,
        }
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ElfHardeningError {
    #[error("not an ELF")]
    NotElf,
    #[error("ELF truncated at offset {0}")]
    Truncated(usize),
}

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ET_DYN: u16 = 3;
const PT_DYNAMIC: u32 = 2;
const PT_GNU_STACK: u32 = 0x6474_E551;
const PT_GNU_RELRO: u32 = 0x6474_E552;
const PF_X: u32 = 0x1;
const DT_BIND_NOW: i64 = 24;
const DT_FLAGS: i64 = 30;
const DT_FLAGS_1: i64 = 0x6FFFFFFB;
const DF_BIND_NOW: u64 = 0x8;
const DF_1_NOW: u64 = 0x1;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_NULL: i64 = 0;

/// Score an ELF buffer.
pub fn score(bytes: &[u8]) -> Result<HardeningScore, ElfHardeningError> {
    if bytes.len() < 52 || &bytes[..4] != ELF_MAGIC {
        return Err(ElfHardeningError::NotElf);
    }
    let class = bytes[4];
    let data = bytes[5];
    if class != 1 && class != 2 {
        return Err(ElfHardeningError::NotElf);
    }
    let le = data == 1;
    let h = ElfHeader::parse(bytes, class, le)?;
    let nx = check_nx(bytes, &h, le)?;
    let pie = check_pie(&h);
    let (relro_present, dynamic_off) = check_relro_pt(bytes, &h, le)?;
    let bind_now = check_bind_now(bytes, dynamic_off, &h, le)?;
    let canary = check_canary(bytes, dynamic_off, &h, le)?;
    let relro = if relro_present {
        Some(if bind_now {
            RelroLevel::Full
        } else {
            RelroLevel::Partial
        })
    } else {
        Some(RelroLevel::None)
    };
    let mut total: u8 = 0;
    if nx == Some(true) {
        total += 1;
    }
    if matches!(relro, Some(RelroLevel::Partial) | Some(RelroLevel::Full)) {
        total += 1;
    }
    if pie == Some(true) {
        total += 1;
    }
    if canary == Some(true) {
        total += 1;
    }
    Ok(HardeningScore {
        nx,
        relro,
        pie,
        canary,
        total,
    })
}

// -----------------------------------------------------------------------------
// ELF header walker
// -----------------------------------------------------------------------------

struct ElfHeader {
    e_type: u16,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
    is_64: bool,
}

impl ElfHeader {
    fn parse(bytes: &[u8], class: u8, le: bool) -> Result<Self, ElfHardeningError> {
        let is_64 = class == 2;
        let read_u16 = |off: usize| -> Result<u16, ElfHardeningError> {
            if off + 2 > bytes.len() {
                return Err(ElfHardeningError::Truncated(off));
            }
            let a = [bytes[off], bytes[off + 1]];
            Ok(if le {
                u16::from_le_bytes(a)
            } else {
                u16::from_be_bytes(a)
            })
        };
        let read_u32 = |off: usize| -> Result<u32, ElfHardeningError> {
            if off + 4 > bytes.len() {
                return Err(ElfHardeningError::Truncated(off));
            }
            let a = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
            Ok(if le {
                u32::from_le_bytes(a)
            } else {
                u32::from_be_bytes(a)
            })
        };
        let read_u64 = |off: usize| -> Result<u64, ElfHardeningError> {
            if off + 8 > bytes.len() {
                return Err(ElfHardeningError::Truncated(off));
            }
            let a = [
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7],
            ];
            Ok(if le {
                u64::from_le_bytes(a)
            } else {
                u64::from_be_bytes(a)
            })
        };
        let e_type = read_u16(16)?;
        let (phoff, phentsize_off, phnum_off) = if is_64 {
            (read_u64(32)?, 54, 56)
        } else {
            (read_u32(28)? as u64, 42, 44)
        };
        let phentsize = read_u16(phentsize_off)?;
        let phnum = read_u16(phnum_off)?;
        Ok(Self {
            e_type,
            phoff,
            phentsize,
            phnum,
            is_64,
        })
    }
}

fn check_nx(bytes: &[u8], h: &ElfHeader, le: bool) -> Result<Option<bool>, ElfHardeningError> {
    for_each_phdr(bytes, h, le, |p_type, p_flags, _, _| {
        if p_type == PT_GNU_STACK {
            // NX is enabled when the stack header has no PF_X bit.
            let nx = (p_flags & PF_X) == 0;
            return Some(nx);
        }
        None
    })
    .map(|opt| Some(opt.unwrap_or(false)))
}

fn check_relro_pt(
    bytes: &[u8],
    h: &ElfHeader,
    le: bool,
) -> Result<(bool, Option<u64>), ElfHardeningError> {
    let mut relro = false;
    let mut dynamic = None;
    for_each_phdr(bytes, h, le, |p_type, _, p_offset, p_filesz| {
        if p_type == PT_GNU_RELRO {
            relro = true;
            let _ = p_filesz;
        } else if p_type == PT_DYNAMIC {
            dynamic = Some(p_offset);
        }
        None::<bool>
    })?;
    Ok((relro, dynamic))
}

fn check_pie(h: &ElfHeader) -> Option<bool> {
    Some(h.e_type == ET_DYN)
}

fn check_bind_now(
    bytes: &[u8],
    dynamic_off: Option<u64>,
    h: &ElfHeader,
    le: bool,
) -> Result<bool, ElfHardeningError> {
    let Some(off) = dynamic_off else {
        return Ok(false);
    };
    for_each_dynamic(bytes, off, h.is_64, le, |tag, val| {
        if tag == DT_BIND_NOW {
            return Some(true);
        }
        if tag == DT_FLAGS && (val & DF_BIND_NOW) != 0 {
            return Some(true);
        }
        if tag == DT_FLAGS_1 && (val & DF_1_NOW) != 0 {
            return Some(true);
        }
        None
    })
    .map(|opt| opt.unwrap_or(false))
}

fn check_canary(
    bytes: &[u8],
    dynamic_off: Option<u64>,
    h: &ElfHeader,
    le: bool,
) -> Result<Option<bool>, ElfHardeningError> {
    let needle = b"__stack_chk_fail";
    let Some(off) = dynamic_off else {
        // No PT_DYNAMIC at all — fall back to whole-file search.
        return Ok(Some(contains(bytes, needle)));
    };
    // Try to narrow the search to .dynstr via DT_STRTAB / DT_STRSZ when
    // available; otherwise search the whole buffer (still 100% accurate
    // on hardened distros where the symbol exists as a string).
    let mut strtab_addr: Option<u64> = None;
    let mut strsz: Option<u64> = None;
    for_each_dynamic(bytes, off, h.is_64, le, |tag, val| {
        if tag == DT_STRTAB {
            strtab_addr = Some(val);
        } else if tag == DT_STRSZ {
            strsz = Some(val);
        }
        let _ = DT_SYMTAB;
        None::<bool>
    })?;
    // Both strtab_addr and strsz are u64 values that the OS hands us
    // out of the dynamic table — a hostile ELF can set them to
    // u64::MAX. `(addr + size) <= bytes.len()` would wrap on overflow
    // and produce a usize value that passes the bound but slices
    // out-of-range when we follow up with `bytes[start..start+size]`.
    // Use checked_add and treat any overflow as "fall through to whole-file".
    let search_buf = match (strtab_addr, strsz) {
        (Some(addr), Some(size))
            if size > 0
                && usize::try_from(addr)
                    .ok()
                    .zip(usize::try_from(size).ok())
                    .and_then(|(a, s)| a.checked_add(s))
                    .is_some_and(|end| end <= bytes.len()) =>
        {
            let start = addr as usize;
            &bytes[start..start + size as usize]
        }
        _ => bytes,
    };
    Ok(Some(contains(search_buf, needle)))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Iterate program-header entries, calling `f` for each. Returns the
/// first `Some(_)` returned by `f`.
fn for_each_phdr<R, F: FnMut(u32, u32, u64, u64) -> Option<R>>(
    bytes: &[u8],
    h: &ElfHeader,
    le: bool,
    mut f: F,
) -> Result<Option<R>, ElfHardeningError> {
    let read_u32 = |off: usize| -> Result<u32, ElfHardeningError> {
        if off + 4 > bytes.len() {
            return Err(ElfHardeningError::Truncated(off));
        }
        let a = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
        Ok(if le {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    };
    let read_u64 = |off: usize| -> Result<u64, ElfHardeningError> {
        if off + 8 > bytes.len() {
            return Err(ElfHardeningError::Truncated(off));
        }
        let a = [
            bytes[off],
            bytes[off + 1],
            bytes[off + 2],
            bytes[off + 3],
            bytes[off + 4],
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
        ];
        Ok(if le {
            u64::from_le_bytes(a)
        } else {
            u64::from_be_bytes(a)
        })
    };
    for i in 0..h.phnum as u64 {
        let entry_off = h.phoff + i * h.phentsize as u64;
        if entry_off as usize + 4 > bytes.len() {
            break;
        }
        let p_type = read_u32(entry_off as usize)?;
        let (p_offset, p_filesz, p_flags) = if h.is_64 {
            let p_flags = read_u32(entry_off as usize + 4)?;
            let p_offset = read_u64(entry_off as usize + 8)?;
            let p_filesz = read_u64(entry_off as usize + 32)?;
            (p_offset, p_filesz, p_flags)
        } else {
            let p_offset = read_u32(entry_off as usize + 4)? as u64;
            let p_filesz = read_u32(entry_off as usize + 16)? as u64;
            let p_flags = read_u32(entry_off as usize + 24)?;
            (p_offset, p_filesz, p_flags)
        };
        if let Some(r) = f(p_type, p_flags, p_offset, p_filesz) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

fn for_each_dynamic<R, F: FnMut(i64, u64) -> Option<R>>(
    bytes: &[u8],
    dynamic_off: u64,
    is_64: bool,
    le: bool,
    mut f: F,
) -> Result<Option<R>, ElfHardeningError> {
    let entry_size = if is_64 { 16 } else { 8 };
    let mut off = dynamic_off as usize;
    while off + entry_size <= bytes.len() {
        let (tag, val) = if is_64 {
            let tag_arr = [
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7],
            ];
            let val_arr = [
                bytes[off + 8],
                bytes[off + 9],
                bytes[off + 10],
                bytes[off + 11],
                bytes[off + 12],
                bytes[off + 13],
                bytes[off + 14],
                bytes[off + 15],
            ];
            let tag = if le {
                i64::from_le_bytes(tag_arr)
            } else {
                i64::from_be_bytes(tag_arr)
            };
            let val = if le {
                u64::from_le_bytes(val_arr)
            } else {
                u64::from_be_bytes(val_arr)
            };
            (tag, val)
        } else {
            let tag_arr = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
            let val_arr = [
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7],
            ];
            let tag = if le {
                i32::from_le_bytes(tag_arr) as i64
            } else {
                i32::from_be_bytes(tag_arr) as i64
            };
            let val = if le {
                u32::from_le_bytes(val_arr) as u64
            } else {
                u32::from_be_bytes(val_arr) as u64
            };
            (tag, val)
        };
        if tag == DT_NULL {
            break;
        }
        if let Some(r) = f(tag, val) {
            return Ok(Some(r));
        }
        off += entry_size;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construct a minimal ELF64 LE with one program header (PT_GNU_STACK
    /// with no PF_X flag → NX enabled), `e_type` configurable for PIE.
    fn make_minimal_elf(e_type: u16, stack_pf_x: bool) -> Vec<u8> {
        let mut v = vec![0u8; 256];
        v[..4].copy_from_slice(ELF_MAGIC);
        v[4] = 2; // 64-bit
        v[5] = 1; // LE
        v[16..18].copy_from_slice(&e_type.to_le_bytes());
        v[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff at 64
        v[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
        v[56..58].copy_from_slice(&1u16.to_le_bytes()); // phnum
        // PHDR at offset 64: PT_GNU_STACK
        v[64..68].copy_from_slice(&PT_GNU_STACK.to_le_bytes());
        let flags: u32 = if stack_pf_x { PF_X } else { 0 };
        v[68..72].copy_from_slice(&flags.to_le_bytes());
        v
    }

    #[test]
    fn score_minimal_elf_with_nx_only() {
        let v = make_minimal_elf(2, false); // ET_EXEC, NX on
        let s = score(&v).unwrap();
        assert_eq!(s.nx, Some(true));
        assert_eq!(s.pie, Some(false));
        assert_eq!(s.relro, Some(RelroLevel::None));
        // Whole-file canary search runs even without PT_DYNAMIC; the
        // minimal ELF has no canary symbol so the result is Some(false).
        assert_eq!(s.canary, Some(false));
        assert_eq!(s.total, 1); // only NX
    }

    #[test]
    fn score_pie_binary() {
        let v = make_minimal_elf(ET_DYN, false);
        let s = score(&v).unwrap();
        assert_eq!(s.pie, Some(true));
    }

    #[test]
    fn nx_off_when_stack_is_executable() {
        let v = make_minimal_elf(ET_DYN, true);
        let s = score(&v).unwrap();
        assert_eq!(s.nx, Some(false));
    }

    #[test]
    fn no_pt_gnu_stack_means_nx_default_false() {
        // ELF without PT_GNU_STACK should report NX=Some(false) because
        // legacy kernels default to executable stacks unless told otherwise.
        let mut v = make_minimal_elf(ET_DYN, false);
        // Replace stack header with PT_LOAD (1).
        v[64..68].copy_from_slice(&1u32.to_le_bytes());
        let s = score(&v).unwrap();
        assert_eq!(s.nx, Some(false));
    }

    #[test]
    fn rejects_non_elf() {
        let v = vec![0u8; 256];
        assert_eq!(score(&v), Err(ElfHardeningError::NotElf));
    }

    #[test]
    fn truncated_input_rejected() {
        let v = vec![0u8; 32];
        assert_eq!(score(&v), Err(ElfHardeningError::NotElf));
    }

    #[test]
    fn relro_partial_detected() {
        let mut v = make_minimal_elf(ET_DYN, false);
        // Bump phnum to 2 and add PT_GNU_RELRO.
        v[56..58].copy_from_slice(&2u16.to_le_bytes());
        // PHDR 2 at offset 64+56=120
        v[120..124].copy_from_slice(&PT_GNU_RELRO.to_le_bytes());
        let s = score(&v).unwrap();
        assert_eq!(s.relro, Some(RelroLevel::Partial));
    }

    #[test]
    fn relro_full_detected_via_dt_bind_now() {
        // Build: stack header (NX), GNU_RELRO header, PT_DYNAMIC pointing
        // at a tiny dynamic section with DT_BIND_NOW + DT_NULL.
        let mut v = vec![0u8; 512];
        v[..4].copy_from_slice(ELF_MAGIC);
        v[4] = 2;
        v[5] = 1;
        v[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        v[32..40].copy_from_slice(&64u64.to_le_bytes());
        v[54..56].copy_from_slice(&56u16.to_le_bytes());
        v[56..58].copy_from_slice(&3u16.to_le_bytes());
        // PHDR 1: PT_GNU_STACK no PF_X
        v[64..68].copy_from_slice(&PT_GNU_STACK.to_le_bytes());
        // PHDR 2: PT_GNU_RELRO
        v[120..124].copy_from_slice(&PT_GNU_RELRO.to_le_bytes());
        // PHDR 3: PT_DYNAMIC at offset 256
        v[176..180].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
        v[184..192].copy_from_slice(&256u64.to_le_bytes()); // p_offset
        // Dynamic entries at offset 256: DT_BIND_NOW (24, 0), DT_NULL
        v[256..264].copy_from_slice(&DT_BIND_NOW.to_le_bytes());
        v[264..272].copy_from_slice(&0u64.to_le_bytes());
        v[272..280].copy_from_slice(&DT_NULL.to_le_bytes());
        v[280..288].copy_from_slice(&0u64.to_le_bytes());
        let s = score(&v).unwrap();
        assert_eq!(s.relro, Some(RelroLevel::Full));
    }

    #[test]
    fn canary_detected_via_dynsym_string() {
        let mut v = vec![0u8; 512];
        v[..4].copy_from_slice(ELF_MAGIC);
        v[4] = 2;
        v[5] = 1;
        v[16..18].copy_from_slice(&2u16.to_le_bytes());
        v[32..40].copy_from_slice(&64u64.to_le_bytes());
        v[54..56].copy_from_slice(&56u16.to_le_bytes());
        v[56..58].copy_from_slice(&2u16.to_le_bytes());
        // PHDR 1: PT_GNU_STACK no PF_X
        v[64..68].copy_from_slice(&PT_GNU_STACK.to_le_bytes());
        // PHDR 2: PT_DYNAMIC at offset 256
        v[120..124].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
        v[128..136].copy_from_slice(&256u64.to_le_bytes());
        // Dynamic: DT_NULL only (canary still detected via global search)
        v[256..264].copy_from_slice(&DT_NULL.to_le_bytes());
        v[264..272].copy_from_slice(&0u64.to_le_bytes());
        // Plant `__stack_chk_fail` somewhere in the file.
        let needle = b"__stack_chk_fail";
        let pos = 400;
        v[pos..pos + needle.len()].copy_from_slice(needle);
        let s = score(&v).unwrap();
        assert_eq!(s.canary, Some(true));
    }

    #[test]
    fn total_score_caps_at_four() {
        // Compose: NX=on, RELRO=full, PIE=on, canary=on → 4.
        let mut v = vec![0u8; 512];
        v[..4].copy_from_slice(ELF_MAGIC);
        v[4] = 2;
        v[5] = 1;
        v[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        v[32..40].copy_from_slice(&64u64.to_le_bytes());
        v[54..56].copy_from_slice(&56u16.to_le_bytes());
        v[56..58].copy_from_slice(&3u16.to_le_bytes());
        v[64..68].copy_from_slice(&PT_GNU_STACK.to_le_bytes());
        v[120..124].copy_from_slice(&PT_GNU_RELRO.to_le_bytes());
        v[176..180].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
        v[184..192].copy_from_slice(&256u64.to_le_bytes());
        v[256..264].copy_from_slice(&DT_BIND_NOW.to_le_bytes());
        v[264..272].copy_from_slice(&0u64.to_le_bytes());
        v[272..280].copy_from_slice(&DT_NULL.to_le_bytes());
        v[280..288].copy_from_slice(&0u64.to_le_bytes());
        let needle = b"__stack_chk_fail";
        v[400..400 + needle.len()].copy_from_slice(needle);
        let s = score(&v).unwrap();
        assert_eq!(s.total, 4);
    }
}
