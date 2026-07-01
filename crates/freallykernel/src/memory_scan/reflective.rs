//! Reflective-DLL detection (Windows) (TASK-294).
//!
//! Reflective-DLL Injection (the Stephen Fewer technique) loads a
//! PE image into a target process without going through
//! `LoadLibrary` — the image bytes sit in a private RW or RWX
//! page and the loader stub fixes imports / relocations
//! manually. Detection here looks at a region's bytes for:
//!
//!   * **PE header** (`MZ` magic + valid `e_lfanew` offset
//!     into `PE\0\0`)
//!   * **Region is private + executable** (caller supplies via
//!     `region_is_private_exec`)
//!   * **No matching mapped file** (caller supplies via
//!     `mapped_path` being None)
//!
//! The combination is the signal — none of these alone is
//! suspicious.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReflectiveFinding {
    pub base_offset_in_region: usize,
    /// Reported `PE\0\0` offset from the in-memory image
    /// header (after validation).
    pub pe_header_offset: usize,
    /// Whether the region was RWX (most aggressive) or
    /// merely RX private (still flagged).
    pub rwx: bool,
}

/// Scan a single region's bytes for a reflective-DLL load.
/// `region_is_private_exec` must be true for the finding to
/// fire — the caller is expected to have evaluated the
/// region's `MemoryProtection` first.
pub fn detect_reflective_dll(
    bytes: &[u8],
    region_is_private_exec: bool,
    mapped_path: Option<&str>,
    region_is_rwx: bool,
) -> Option<ReflectiveFinding> {
    if !region_is_private_exec {
        return None;
    }
    if mapped_path.is_some() {
        return None;
    }
    let pe = find_pe_signature(bytes)?;
    Some(ReflectiveFinding {
        base_offset_in_region: pe.mz_at,
        pe_header_offset: pe.pe_at,
        rwx: region_is_rwx,
    })
}

struct PeHeader {
    mz_at: usize,
    pe_at: usize,
}

fn find_pe_signature(bytes: &[u8]) -> Option<PeHeader> {
    if bytes.len() < 0x40 {
        return None;
    }
    // PE images carry the MZ magic at offset 0; we still allow
    // a configurable mz_at to support stubs that lead with a
    // few bytes of decryption preamble — but only when MZ
    // appears in the first 1 KiB.
    let search_limit = bytes.len().min(1024);
    let mz_at = bytes[..search_limit]
        .windows(2)
        .position(|w| w == [b'M', b'Z'])?;
    if mz_at + 0x40 >= bytes.len() {
        return None;
    }
    let e_lfanew = u32::from_le_bytes([
        bytes[mz_at + 0x3C],
        bytes[mz_at + 0x3D],
        bytes[mz_at + 0x3E],
        bytes[mz_at + 0x3F],
    ]) as usize;
    let pe_at = mz_at + e_lfanew;
    if pe_at + 4 > bytes.len() {
        return None;
    }
    if &bytes[pe_at..pe_at + 4] != b"PE\0\0" {
        return None;
    }
    Some(PeHeader { mz_at, pe_at })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_pe(prefix_len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; prefix_len + 0x100];
        let mz_at = prefix_len;
        buf[mz_at] = b'M';
        buf[mz_at + 1] = b'Z';
        // e_lfanew at +0x3C pointing at the PE signature 0x80
        // bytes into the buffer relative to MZ.
        let e_lfanew = 0x80u32;
        buf[mz_at + 0x3C..mz_at + 0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe_at = mz_at + e_lfanew as usize;
        buf[pe_at..pe_at + 4].copy_from_slice(b"PE\0\0");
        buf
    }

    #[test]
    fn detects_reflective_pe_in_private_exec_region() {
        let bytes = synth_pe(0);
        let f = detect_reflective_dll(&bytes, true, None, true).expect("flagged");
        assert_eq!(f.pe_header_offset, 0x80);
        assert!(f.rwx);
    }

    #[test]
    fn region_must_be_private_exec() {
        let bytes = synth_pe(0);
        assert!(detect_reflective_dll(&bytes, false, None, false).is_none());
    }

    #[test]
    fn mapped_file_clears_finding() {
        let bytes = synth_pe(0);
        assert!(detect_reflective_dll(&bytes, true, Some("C:\\ok.dll"), false).is_none());
    }

    #[test]
    fn pe_with_preamble_still_detected() {
        let bytes = synth_pe(64);
        let f = detect_reflective_dll(&bytes, true, None, false).expect("flagged");
        assert_eq!(f.base_offset_in_region, 64);
    }

    #[test]
    fn invalid_pe_signature_rejected() {
        let mut bytes = synth_pe(0);
        // Stomp the PE marker.
        bytes[0x80] = b'X';
        assert!(detect_reflective_dll(&bytes, true, None, false).is_none());
    }

    #[test]
    fn too_short_buffer_rejected() {
        let bytes = [b'M', b'Z'];
        assert!(detect_reflective_dll(&bytes, true, None, false).is_none());
    }

    #[test]
    fn rwx_flag_passthrough() {
        let bytes = synth_pe(0);
        let f_rwx = detect_reflective_dll(&bytes, true, None, true).unwrap();
        assert!(f_rwx.rwx);
        let f_rx = detect_reflective_dll(&bytes, true, None, false).unwrap();
        assert!(!f_rx.rwx);
    }
}
