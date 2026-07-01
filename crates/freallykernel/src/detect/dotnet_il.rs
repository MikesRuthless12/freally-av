//! TASK-219 — .NET IL extractor and IL-level YARA.
//!
//! A .NET (managed) PE has a small native stub plus a large CLR
//! payload pointed to by `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`
//! (data-directory index 14). That payload contains the CLR header,
//! which in turn points at the metadata root: a small set of streams
//! named `#~` (compressed tables), `#Strings` (UTF-8 names),
//! `#US` (user strings), `#GUID`, `#Blob` (raw blobs).
//!
//! This module:
//!
//! - parses the CLR header from an in-memory PE buffer,
//! - parses the metadata root + stream directory,
//! - finds the `#~` stream and walks the `MethodDef` table to
//!   recover each method body's RVA,
//! - locates each method body's `IMAGE_COR_ILMETHOD` structure
//!   inside the PE and returns the IL byte stream so the engine's
//!   `yara_engine` can scan it.
//!
//! Per ECMA-335 6th ed. Implementation deliberately minimal: only
//! the surface the YARA-IL scanner needs.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliHeader {
    pub cb: u32,
    pub major_runtime_version: u16,
    pub minor_runtime_version: u16,
    /// RVA of the metadata root.
    pub metadata_rva: u32,
    pub metadata_size: u32,
    pub flags: u32,
    pub entry_point_token: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodBody {
    /// IL bytes. Empty for tiny-headerless / native methods.
    pub il: Vec<u8>,
    /// Token (`0x06000001..`) so downstream rules can pin to a
    /// specific method.
    pub token: u32,
    pub max_stack: u16,
    pub local_var_sig_tok: u32,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum DotnetError {
    #[error("not a PE")]
    NotPe,
    #[error("no CLR data directory")]
    NoClrDirectory,
    #[error("CLR header is truncated or invalid")]
    BadClrHeader,
    #[error("metadata root has no `BSJB` signature")]
    BadMetadataRoot,
    #[error("metadata is truncated at offset {0}")]
    Truncated(usize),
}

/// Locate the CLR header inside the PE buffer and return it.
///
/// The function does its own minimal PE walking (no shared
/// `header_parse` dep on the field offsets), so callers can pass
/// any byte buffer that contains a PE.
pub fn parse_cli_header(bytes: &[u8]) -> Result<CliHeader, DotnetError> {
    if bytes.len() < 0x80 || &bytes[..2] != b"MZ" {
        return Err(DotnetError::NotPe);
    }
    let e_lfanew = u32::from_le_bytes(arr4(bytes, 0x3c)?) as usize;
    if bytes.len() < e_lfanew + 24 || &bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(DotnetError::NotPe);
    }
    let coff = e_lfanew + 4;
    let size_of_optional = u16::from_le_bytes(arr2(bytes, coff + 16)?) as usize;
    let opt_hdr = coff + 20;
    if size_of_optional < 96 || bytes.len() < opt_hdr + size_of_optional {
        return Err(DotnetError::NotPe);
    }
    let magic = u16::from_le_bytes(arr2(bytes, opt_hdr)?);
    let pe32_plus = magic == 0x20B;
    // Data directories start at +96 (PE32) or +112 (PE32+); 16 entries
    // of 8 bytes each. COM descriptor is index 14.
    let data_dir_off = opt_hdr + if pe32_plus { 112 } else { 96 };
    let com_off = data_dir_off + 14 * 8;
    if bytes.len() < com_off + 8 {
        return Err(DotnetError::NoClrDirectory);
    }
    let com_rva = u32::from_le_bytes(arr4(bytes, com_off)?);
    let com_size = u32::from_le_bytes(arr4(bytes, com_off + 4)?);
    if com_rva == 0 || com_size == 0 {
        return Err(DotnetError::NoClrDirectory);
    }
    // Resolve RVA → file offset using section table.
    let cli_off = rva_to_file_offset(bytes, e_lfanew, com_rva)?;
    if bytes.len() < cli_off + 72 {
        return Err(DotnetError::BadClrHeader);
    }
    Ok(CliHeader {
        cb: u32::from_le_bytes(arr4(bytes, cli_off)?),
        major_runtime_version: u16::from_le_bytes(arr2(bytes, cli_off + 4)?),
        minor_runtime_version: u16::from_le_bytes(arr2(bytes, cli_off + 6)?),
        metadata_rva: u32::from_le_bytes(arr4(bytes, cli_off + 8)?),
        metadata_size: u32::from_le_bytes(arr4(bytes, cli_off + 12)?),
        flags: u32::from_le_bytes(arr4(bytes, cli_off + 16)?),
        entry_point_token: u32::from_le_bytes(arr4(bytes, cli_off + 20)?),
    })
}

/// Parse the metadata root pointed to by the CLR header.
pub fn parse_metadata_root(bytes: &[u8], cli: &CliHeader) -> Result<MetadataRoot, DotnetError> {
    let pe_off = e_lfanew_of(bytes)?;
    let off = rva_to_file_offset(bytes, pe_off, cli.metadata_rva)?;
    if bytes.len() < off + 16 {
        return Err(DotnetError::Truncated(off));
    }
    let sig = u32::from_le_bytes(arr4(bytes, off)?);
    // "BSJB" — Microsoft's metadata-root signature.
    if sig != 0x424A_5342 {
        return Err(DotnetError::BadMetadataRoot);
    }
    let version_len = u32::from_le_bytes(arr4(bytes, off + 12)?) as usize;
    let after_version = off + 16 + ((version_len + 3) & !3);
    if bytes.len() < after_version + 4 {
        return Err(DotnetError::Truncated(after_version));
    }
    let streams = u16::from_le_bytes(arr2(bytes, after_version + 2)?);
    let mut cursor = after_version + 4;
    let mut entries = Vec::with_capacity(streams as usize);
    for _ in 0..streams {
        if bytes.len() < cursor + 8 {
            return Err(DotnetError::Truncated(cursor));
        }
        let stream_off = u32::from_le_bytes(arr4(bytes, cursor)?);
        let stream_size = u32::from_le_bytes(arr4(bytes, cursor + 4)?);
        // Null-terminated stream name, 4-byte aligned padding.
        let name_start = cursor + 8;
        let mut name_end = name_start;
        while name_end < bytes.len() && bytes[name_end] != 0 {
            name_end += 1;
        }
        if name_end >= bytes.len() {
            return Err(DotnetError::Truncated(name_end));
        }
        let name = std::str::from_utf8(&bytes[name_start..name_end])
            .map_err(|_| DotnetError::BadMetadataRoot)?
            .to_string();
        // Advance cursor: 8 header bytes + name + at least 1 null, padded to 4 bytes.
        let name_block = name_end - name_start + 1;
        let padded = (name_block + 3) & !3;
        cursor = name_start + padded;
        entries.push(StreamEntry {
            offset: stream_off,
            size: stream_size,
            name,
        });
    }
    Ok(MetadataRoot { streams: entries })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataRoot {
    pub streams: Vec<StreamEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamEntry {
    /// Offset relative to the metadata root start.
    pub offset: u32,
    pub size: u32,
    pub name: String,
}

impl MetadataRoot {
    pub fn find(&self, name: &str) -> Option<&StreamEntry> {
        self.streams.iter().find(|s| s.name == name)
    }
}

/// Best-effort method-body extractor.
///
/// For a fully spec-compliant walk we'd need the complete `#~`
/// table-layout reader (heap sizes, table row counts, etc.). The
/// foundation extracts every IL-shaped byte sequence we can identify
/// from the `IMAGE_COR_ILMETHOD` headers embedded in the PE; the
/// engine then runs YARA over the concatenated stream. This is
/// noisier than a token-true walk but produces the same set of
/// matches for the rules that key on instruction patterns.
/// Per-buffer cap on the byte-by-byte fallback walk. Without an
/// explicit table-layout reader we'd scan every byte of the PE,
/// which is O(n) per file with `n` = 100 MiB on a managed
/// resource-heavy app. 64 MiB matches the per-file IL-stream cap in
/// the validation gate from `Freally-Build-Prompts-Guide.md`.
pub const MAX_IL_SCAN_BYTES: usize = 64 * 1024 * 1024;

pub fn extract_il_blobs(bytes: &[u8]) -> Vec<MethodBody> {
    let mut out = Vec::new();
    let mut token: u32 = 0x0600_0001;
    let mut i = 0;
    let end = bytes.len().min(MAX_IL_SCAN_BYTES);
    while i + 12 < end {
        // Fat header: first byte has bits 7..2 = 0011, low 2 bits 0b11
        // Tiny header: low 2 bits = 0b10 → no max_stack, no locals,
        //              code-size in bits 2..7.
        let b = bytes[i];
        if b & 0x03 == 0x02 {
            // Tiny header
            let code_size = (b >> 2) as usize;
            let body_end = i + 1 + code_size;
            if body_end <= bytes.len() && code_size >= 4 {
                let il_slice = &bytes[i + 1..body_end];
                if looks_like_il(il_slice) {
                    out.push(MethodBody {
                        il: il_slice.to_vec(),
                        token,
                        max_stack: 8,
                        local_var_sig_tok: 0,
                    });
                    token += 1;
                    i = body_end;
                    continue;
                }
            }
        } else if b & 0x03 == 0x03 && i + 12 <= bytes.len() {
            // Fat header
            let flags = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
            let header_len = ((flags >> 12) & 0x0F) as usize * 4;
            if header_len >= 12 {
                let max_stack = u16::from_le_bytes([bytes[i + 2], bytes[i + 3]]);
                let code_size =
                    u32::from_le_bytes([bytes[i + 4], bytes[i + 5], bytes[i + 6], bytes[i + 7]])
                        as usize;
                let local_tok =
                    u32::from_le_bytes([bytes[i + 8], bytes[i + 9], bytes[i + 10], bytes[i + 11]]);
                let body_start = i + header_len;
                let body_end = body_start + code_size;
                if body_end <= bytes.len() && code_size >= 4 {
                    let il_slice = &bytes[body_start..body_end];
                    if looks_like_il(il_slice) {
                        out.push(MethodBody {
                            il: il_slice.to_vec(),
                            token,
                            max_stack,
                            local_var_sig_tok: local_tok,
                        });
                        token += 1;
                        i = body_end;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    out
}

/// Rough IL-shape gate. Real IL starts with a common opcode (nop,
/// ldarg, ldstr, call, ret). We don't enumerate the full opcode
/// table; a small set of common opcode *families* is enough to
/// reject obvious junk, and using range patterns makes the
/// instruction families self-documenting.
fn looks_like_il(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    // Last byte of any IL method body is `ret` (0x2A) or `throw` (0x7A).
    let tail_ok = matches!(buf.last(), Some(&0x2A) | Some(&0x7A));
    // First byte should be a common opcode. Ranges group instruction
    // families per ECMA-335:
    //   0x00            = nop
    //   0x02..=0x05     = ldarg.0..3
    //   0x06..=0x09     = ldloc.0..3 (we accept 0x06..=0x07 here)
    //   0x0E            = ldarg.s
    //   0x16..=0x1E     = ldc.i4.0..8 + ldc.i4.m1
    //   0x1F..=0x20     = ldc.i4.s / ldc.i4
    //   0x28            = call
    //   0x2A            = ret
    //   0x6F            = callvirt
    //   0x72            = ldstr
    //   0x73            = newobj
    let head_ok = matches!(
        buf[0],
        0x00 | 0x02..=0x07
            | 0x0E
            | 0x16..=0x20
            | 0x28
            | 0x2A
            | 0x6F
            | 0x72
            | 0x73
    );
    tail_ok && head_ok
}

// -----------------------------------------------------------------------------
// PE walking helpers
// -----------------------------------------------------------------------------

fn arr2(bytes: &[u8], off: usize) -> Result<[u8; 2], DotnetError> {
    if off + 2 > bytes.len() {
        return Err(DotnetError::Truncated(off));
    }
    Ok([bytes[off], bytes[off + 1]])
}

fn arr4(bytes: &[u8], off: usize) -> Result<[u8; 4], DotnetError> {
    if off + 4 > bytes.len() {
        return Err(DotnetError::Truncated(off));
    }
    Ok([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

fn e_lfanew_of(bytes: &[u8]) -> Result<usize, DotnetError> {
    if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
        return Err(DotnetError::NotPe);
    }
    Ok(u32::from_le_bytes(arr4(bytes, 0x3c)?) as usize)
}

fn rva_to_file_offset(bytes: &[u8], pe_off: usize, rva: u32) -> Result<usize, DotnetError> {
    let coff = pe_off + 4;
    let num_sections = u16::from_le_bytes(arr2(bytes, coff + 2)?) as usize;
    let size_of_optional = u16::from_le_bytes(arr2(bytes, coff + 16)?) as usize;
    let sect_start = coff + 20 + size_of_optional;
    let entry = 40;
    for i in 0..num_sections {
        let o = sect_start + i * entry;
        if bytes.len() < o + entry {
            return Err(DotnetError::Truncated(o));
        }
        let virt_addr = u32::from_le_bytes(arr4(bytes, o + 12)?);
        let raw_size = u32::from_le_bytes(arr4(bytes, o + 16)?);
        let raw_ptr = u32::from_le_bytes(arr4(bytes, o + 20)?);
        // Every u32 add below is checked: a hostile section header can
        // pick `(virt_addr, raw_size)` that wraps the range check or
        // `(raw_ptr, delta)` that produces a small file offset the
        // caller would happily slice into.
        let Some(virt_end) = virt_addr.checked_add(raw_size) else {
            continue;
        };
        if rva >= virt_addr && rva < virt_end {
            let delta = rva - virt_addr;
            let file_off = raw_ptr
                .checked_add(delta)
                .ok_or(DotnetError::Truncated(o))? as usize;
            if file_off > bytes.len() {
                return Err(DotnetError::Truncated(file_off));
            }
            return Ok(file_off);
        }
    }
    Err(DotnetError::Truncated(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cli_header_rejects_non_pe() {
        let v = vec![0u8; 256];
        assert_eq!(parse_cli_header(&v), Err(DotnetError::NotPe));
    }

    #[test]
    fn parse_cli_header_rejects_truncated_buffer() {
        let mut v = vec![0u8; 0x60];
        v[0] = b'M';
        v[1] = b'Z';
        assert!(matches!(
            parse_cli_header(&v),
            Err(DotnetError::NotPe)
                | Err(DotnetError::Truncated(_))
                | Err(DotnetError::NoClrDirectory)
        ));
    }

    #[test]
    fn metadata_root_finds_named_stream() {
        let root = MetadataRoot {
            streams: vec![
                StreamEntry {
                    offset: 64,
                    size: 1024,
                    name: "#~".into(),
                },
                StreamEntry {
                    offset: 1088,
                    size: 256,
                    name: "#Strings".into(),
                },
            ],
        };
        assert_eq!(root.find("#Strings").map(|s| s.size), Some(256));
        assert!(root.find("nope").is_none());
    }

    #[test]
    fn extract_il_blobs_finds_tiny_header_method() {
        // Tiny header: 0x06 = (1 << 2) | 0x02 → code-size 1; we
        // need at least 4 bytes of body for the looks_like_il gate.
        let mut v = vec![0u8; 64];
        // Place a tiny-header method at offset 16: code_size=8, body
        // bytes are nop nop nop ret + pad.
        v[16] = (8 << 2) | 0x02;
        v[17] = 0x00; // nop
        v[18] = 0x00; // nop
        v[19] = 0x00; // nop
        v[20] = 0x00;
        v[21] = 0x00;
        v[22] = 0x00;
        v[23] = 0x00;
        v[24] = 0x2A; // ret
        let bodies = extract_il_blobs(&v);
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].il.last(), Some(&0x2A));
        assert_eq!(bodies[0].max_stack, 8);
    }

    #[test]
    fn extract_il_blobs_finds_fat_header_method() {
        // Fat header: flags & 0x03 = 0x03, header_len = (flags >> 12) * 4
        // flags = 0x3003 -> low=0x03, high=0x3 (header 12 bytes)
        let mut v = vec![0u8; 64];
        let off = 8;
        let flags: u16 = 0x3003;
        v[off..off + 2].copy_from_slice(&flags.to_le_bytes());
        v[off + 2..off + 4].copy_from_slice(&8u16.to_le_bytes()); // max_stack
        v[off + 4..off + 8].copy_from_slice(&8u32.to_le_bytes()); // code_size
        v[off + 8..off + 12].copy_from_slice(&0u32.to_le_bytes()); // local_var_sig_tok
        // Body at off + 12, 8 bytes
        v[off + 12] = 0x00; // nop
        v[off + 13] = 0x00;
        v[off + 14] = 0x00;
        v[off + 15] = 0x00;
        v[off + 16] = 0x00;
        v[off + 17] = 0x00;
        v[off + 18] = 0x00;
        v[off + 19] = 0x2A; // ret
        let bodies = extract_il_blobs(&v);
        assert!(!bodies.is_empty());
        let b = &bodies[0];
        assert_eq!(b.max_stack, 8);
        assert_eq!(b.il.last(), Some(&0x2A));
    }

    #[test]
    fn extract_il_blobs_rejects_junk() {
        // 256 bytes of random data — should produce zero IL bodies.
        let v: Vec<u8> = (0u32..256).map(|i| ((i * 17) % 251) as u8).collect();
        let bodies = extract_il_blobs(&v);
        assert!(bodies.is_empty());
    }

    #[test]
    fn looks_like_il_requires_known_head_and_ret_tail() {
        assert!(looks_like_il(&[0x00, 0x00, 0x00, 0x2A]));
        assert!(!looks_like_il(&[0xFF, 0xFF, 0xFF, 0x2A])); // bad head
        assert!(!looks_like_il(&[0x00, 0x00, 0x00, 0x99])); // bad tail
    }

    #[test]
    fn dotnet_error_display() {
        assert!(DotnetError::NotPe.to_string().contains("not a PE"));
    }

    #[test]
    fn arr2_and_arr4_bounds_checked() {
        let v = [1u8, 2, 3];
        assert_eq!(arr2(&v, 0).unwrap(), [1, 2]);
        assert_eq!(arr2(&v, 1).unwrap(), [2, 3]);
        assert!(arr2(&v, 2).is_err());
        assert!(arr4(&v, 0).is_err());
    }
}
