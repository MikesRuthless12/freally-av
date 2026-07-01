//! TASK-222 — Mach-O `__cryptid` and code-signature parser.
//!
//! Walks Mach-O load commands for two interesting blocks:
//!
//! - `LC_ENCRYPTION_INFO[_64]` (cmd 0x21 / 0x2C) — records the
//!   range of bytes that's encrypted on disk (FairPlay-protected
//!   App Store apps have `cryptid != 0` over their `__TEXT.__text`
//!   range). The engine surfaces this so a hash mismatch on an
//!   App Store binary doesn't get mis-classified as tampering.
//!
//! - `LC_CODE_SIGNATURE` (cmd 0x1D) — points at the embedded
//!   super-blob: CodeDirectory hashes, entitlements XML,
//!   requirement set, and the CMS SignedData blob.
//!
//! Per `docs/prd.md` § 1.5: no `codesign --verify` shell-out. We
//! parse the structures ourselves.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionInfo {
    pub crypt_off: u32,
    pub crypt_size: u32,
    pub crypt_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeSignaturePointer {
    /// Offset of the super-blob in the file.
    pub data_off: u32,
    pub data_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MachoSigSummary {
    pub encryption: Option<EncryptionInfo>,
    pub signature: Option<CodeSignaturePointer>,
    /// Team ID, when recovered from the embedded CodeDirectory.
    pub team_id: Option<String>,
    /// Identifier (bundle id), when recovered.
    pub identifier: Option<String>,
    /// SHA-256 of the entitlements XML, when present.
    pub entitlements_sha256: Option<[u8; 32]>,
    /// Whether at least one of the architectures is encrypted on
    /// disk (`cryptid != 0`). True for App Store binaries.
    pub encrypted_slice: bool,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum MachoSigError {
    #[error("not a Mach-O")]
    NotMacho,
    #[error("Mach-O truncated at offset {0}")]
    Truncated(usize),
}

const LC_CODE_SIGNATURE: u32 = 0x1D;
const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_ENCRYPTION_INFO_64: u32 = 0x2C;

pub fn parse(bytes: &[u8]) -> Result<MachoSigSummary, MachoSigError> {
    if bytes.len() < 32 {
        return Err(MachoSigError::NotMacho);
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let (le, sixty_four) = match magic {
        0xFEED_FACE => (true, false),
        0xFEED_FACF => (true, true),
        0xCEFA_EDFE => (false, false),
        0xCFFA_EDFE => (false, true),
        _ => return Err(MachoSigError::NotMacho),
    };
    let read_u32 = |off: usize| -> Option<u32> {
        if off + 4 > bytes.len() {
            return None;
        }
        let a = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
        Some(if le {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    };
    let ncmds = read_u32(16).ok_or(MachoSigError::Truncated(16))?;
    let mut lc_off = if sixty_four { 32 } else { 28 };
    let mut summary = MachoSigSummary::default();
    for _ in 0..ncmds.min(2048) {
        if lc_off + 8 > bytes.len() {
            break;
        }
        let cmd = read_u32(lc_off).ok_or(MachoSigError::Truncated(lc_off))?;
        let cmdsize = read_u32(lc_off + 4).ok_or(MachoSigError::Truncated(lc_off))? as usize;
        if cmdsize == 0 {
            break;
        }
        match cmd {
            LC_CODE_SIGNATURE => {
                let data_off = read_u32(lc_off + 8).unwrap_or(0);
                let data_size = read_u32(lc_off + 12).unwrap_or(0);
                summary.signature = Some(CodeSignaturePointer {
                    data_off,
                    data_size,
                });
                if let Some(meta) = parse_super_blob(bytes, data_off as usize, data_size as usize) {
                    if summary.team_id.is_none() {
                        summary.team_id = meta.team_id;
                    }
                    if summary.identifier.is_none() {
                        summary.identifier = meta.identifier;
                    }
                    if summary.entitlements_sha256.is_none() {
                        summary.entitlements_sha256 = meta.entitlements_sha256;
                    }
                }
            }
            LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
                let crypt_off = read_u32(lc_off + 8).unwrap_or(0);
                let crypt_size = read_u32(lc_off + 12).unwrap_or(0);
                let crypt_id = read_u32(lc_off + 16).unwrap_or(0);
                summary.encryption = Some(EncryptionInfo {
                    crypt_off,
                    crypt_size,
                    crypt_id,
                });
                if crypt_id != 0 {
                    summary.encrypted_slice = true;
                }
            }
            _ => {}
        }
        lc_off = lc_off.saturating_add(cmdsize);
    }
    Ok(summary)
}

// -----------------------------------------------------------------------------
// Super-blob parsing
// -----------------------------------------------------------------------------

#[derive(Debug, Default)]
struct SuperBlobMeta {
    team_id: Option<String>,
    identifier: Option<String>,
    entitlements_sha256: Option<[u8; 32]>,
}

/// Walk the embedded CMS super-blob.
///
/// Super-blob layout (big-endian throughout):
///   magic   :u32 = 0xFADE0CC0
///   length  :u32
///   count   :u32
///   then `count` BlobIndex entries: (type:u32, offset:u32)
///   each indexed blob is itself { magic:u32, length:u32, ... }
fn parse_super_blob(bytes: &[u8], data_off: usize, data_size: usize) -> Option<SuperBlobMeta> {
    // Security: bound every offset against the *claimed* super-blob
    // region, not just the file. A hostile Mach-O can advertise a
    // tiny 12-byte signature and then point BlobIndex offsets at
    // attacker-planted strings in `__TEXT.__cstring` elsewhere in
    // the binary — without this gate, the parser would happily
    // surface those strings as `team_id` / `identifier`. The
    // super-blob's own outer length (read at offset +4) is the
    // authoritative size; we clamp `data_size` to it.
    if data_size < 12 {
        return None;
    }
    let region_end = data_off.checked_add(data_size)?;
    if region_end > bytes.len() {
        return None;
    }
    let mut meta = SuperBlobMeta::default();
    // Bounded reader: every offset must stay inside `[data_off, region_end)`.
    let read_u32_be_bounded = |o: usize| -> Option<u32> {
        if o < data_off || o.checked_add(4)? > region_end {
            return None;
        }
        Some(u32::from_be_bytes([
            bytes[o],
            bytes[o + 1],
            bytes[o + 2],
            bytes[o + 3],
        ]))
    };
    let super_magic = read_u32_be_bounded(data_off)?;
    if super_magic != 0xFADE_0CC0 {
        return None;
    }
    // Honor the super-blob's own outer length (offset +4) — it's the
    // canonical authority. Take the tighter of (data_size, outer_len).
    let outer_len = read_u32_be_bounded(data_off + 4)? as usize;
    let tight_end = region_end.min(data_off.checked_add(outer_len)?);
    let count = read_u32_be_bounded(data_off + 8)? as usize;
    let mut idx_off = data_off + 12;
    let mut blobs = Vec::with_capacity(count.min(256));
    for _ in 0..count.min(256) {
        let typ = read_u32_be_bounded(idx_off)?;
        let off = read_u32_be_bounded(idx_off + 4)? as usize;
        let abs = data_off.checked_add(off)?;
        // Reject blob offsets that fall outside the claimed super-blob.
        if abs >= tight_end {
            return Some(meta);
        }
        blobs.push((typ, abs));
        idx_off = idx_off.checked_add(8)?;
        if idx_off >= tight_end {
            break;
        }
    }
    for (typ, blob_off) in blobs {
        let blob_magic = read_u32_be_bounded(blob_off)?;
        match blob_magic {
            // CodeDirectory.
            0xFADE_0C02 => {
                if let Some((id, team)) = parse_code_directory(bytes, blob_off, tight_end) {
                    if meta.identifier.is_none() {
                        meta.identifier = id;
                    }
                    if meta.team_id.is_none() {
                        meta.team_id = team;
                    }
                }
            }
            // Embedded entitlements (XML).
            0xFADE_7171 => {
                let length = read_u32_be_bounded(blob_off + 4)? as usize;
                let xml_end = blob_off.checked_add(length)?;
                if length > 8 && xml_end <= tight_end {
                    let xml = &bytes[blob_off + 8..xml_end];
                    let h = blake3::hash(xml);
                    meta.entitlements_sha256 = Some(*h.as_bytes());
                }
            }
            _ => {
                let _ = typ;
            }
        }
    }
    Some(meta)
}

/// CodeDirectory blob layout (truncated to what we use):
///   magic:u32 = 0xFADE0C02
///   length:u32
///   version:u32
///   flags:u32
///   hash_off:u32
///   ident_off:u32  <-- offset (from start of CD) to NUL-terminated identifier
///   nSpecialSlots:u32
///   nCodeSlots:u32
///   ...
///   teamOff:u32 (version ≥ 0x20200) <-- offset to NUL-terminated team ID
fn parse_code_directory(
    bytes: &[u8],
    cd_off: usize,
    region_end: usize,
) -> Option<(Option<String>, Option<String>)> {
    // `region_end` is the authoritative upper bound for everything
    // the CodeDirectory is allowed to reference — it's the
    // super-blob's outer length from `parse_super_blob`. Without
    // it, a hostile Mach-O could plant attacker-chosen strings
    // anywhere in the file and have them surface as team_id.
    let read_u32_be = |o: usize| -> Option<u32> {
        if o.checked_add(4)? > region_end {
            return None;
        }
        Some(u32::from_be_bytes([
            bytes[o],
            bytes[o + 1],
            bytes[o + 2],
            bytes[o + 3],
        ]))
    };
    let version = read_u32_be(cd_off + 8)?;
    let ident_off = read_u32_be(cd_off + 20)? as usize;
    let mut identifier = None;
    let ident_abs = cd_off.checked_add(ident_off)?;
    if ident_abs < region_end {
        identifier = read_c_string(bytes, ident_abs, region_end);
    }
    let mut team_id = None;
    // teamOff is at fixed offset 0x30 (48) inside the CD for
    // version >= 0x20200.
    if version >= 0x0002_0200 && cd_off.checked_add(52)? <= region_end {
        let team_off = read_u32_be(cd_off + 48)? as usize;
        if team_off != 0 {
            let team_abs = cd_off.checked_add(team_off)?;
            if team_abs < region_end {
                team_id = read_c_string(bytes, team_abs, region_end);
            }
        }
    }
    Some((identifier, team_id))
}

fn read_c_string(bytes: &[u8], start: usize, region_end: usize) -> Option<String> {
    let cap = region_end.min(bytes.len());
    let mut end = start;
    while end < cap && bytes[end] != 0 {
        end += 1;
    }
    std::str::from_utf8(&bytes[start..end])
        .ok()
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_macho_with_codesig() -> Vec<u8> {
        // Mach-O 64-bit LE header with two load commands:
        //   LC_ENCRYPTION_INFO_64 (cryptid=0)
        //   LC_CODE_SIGNATURE pointing at offset 256 with size 64
        let mut v = vec![0u8; 512];
        v[..4].copy_from_slice(&0xFEED_FACFu32.to_le_bytes());
        v[16..20].copy_from_slice(&2u32.to_le_bytes()); // ncmds = 2
        // First LC at offset 32
        v[32..36].copy_from_slice(&LC_ENCRYPTION_INFO_64.to_le_bytes());
        v[36..40].copy_from_slice(&24u32.to_le_bytes());
        // (crypt_off, crypt_size, crypt_id) = (4096, 8192, 0)
        v[40..44].copy_from_slice(&4096u32.to_le_bytes());
        v[44..48].copy_from_slice(&8192u32.to_le_bytes());
        v[48..52].copy_from_slice(&0u32.to_le_bytes());
        // Second LC at offset 56
        v[56..60].copy_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
        v[60..64].copy_from_slice(&16u32.to_le_bytes());
        v[64..68].copy_from_slice(&256u32.to_le_bytes());
        v[68..72].copy_from_slice(&64u32.to_le_bytes());
        // Plant a CMS super-blob magic at offset 256 (not a real one).
        v[256..260].copy_from_slice(&0xFADE_0CC0u32.to_be_bytes());
        v[260..264].copy_from_slice(&64u32.to_be_bytes());
        v[264..268].copy_from_slice(&0u32.to_be_bytes()); // 0 blobs
        v
    }

    #[test]
    fn parse_recognises_encryption_info() {
        let v = make_macho_with_codesig();
        let s = parse(&v).unwrap();
        let e = s.encryption.unwrap();
        assert_eq!(e.crypt_off, 4096);
        assert_eq!(e.crypt_size, 8192);
        assert_eq!(e.crypt_id, 0);
        assert!(!s.encrypted_slice);
    }

    #[test]
    fn parse_finds_code_signature_pointer() {
        let v = make_macho_with_codesig();
        let s = parse(&v).unwrap();
        let sig = s.signature.unwrap();
        assert_eq!(sig.data_off, 256);
        assert_eq!(sig.data_size, 64);
    }

    #[test]
    fn encrypted_slice_when_cryptid_nonzero() {
        let mut v = make_macho_with_codesig();
        v[48..52].copy_from_slice(&1u32.to_le_bytes());
        let s = parse(&v).unwrap();
        assert!(s.encrypted_slice);
    }

    #[test]
    fn non_macho_rejected() {
        let v = vec![0u8; 64];
        assert_eq!(parse(&v), Err(MachoSigError::NotMacho));
    }

    #[test]
    fn truncated_input_rejected() {
        let v = vec![0u8; 8];
        assert_eq!(parse(&v), Err(MachoSigError::NotMacho));
    }

    #[test]
    fn code_directory_parser_pulls_identifier() {
        // Construct a minimal CD blob at offset 0:
        //   magic (FADE0C02), length, version=0x20100, flags=0,
        //   hash_off=0, ident_off=48, then "com.example.app\0"
        let mut v = vec![0u8; 96];
        v[0..4].copy_from_slice(&0xFADE_0C02u32.to_be_bytes());
        v[4..8].copy_from_slice(&64u32.to_be_bytes());
        v[8..12].copy_from_slice(&0x0002_0100u32.to_be_bytes()); // version < 0x20200 - no team
        v[20..24].copy_from_slice(&48u32.to_be_bytes()); // ident_off
        let ident = b"com.example.app";
        v[48..48 + ident.len()].copy_from_slice(ident);
        let len = v.len();
        let (id, team) = parse_code_directory(&v, 0, len).unwrap();
        assert_eq!(id.as_deref(), Some("com.example.app"));
        assert!(team.is_none());
    }

    #[test]
    fn code_directory_parser_pulls_team_id_when_version_supports() {
        let mut v = vec![0u8; 160];
        v[0..4].copy_from_slice(&0xFADE_0C02u32.to_be_bytes());
        v[4..8].copy_from_slice(&100u32.to_be_bytes());
        v[8..12].copy_from_slice(&0x0002_0200u32.to_be_bytes());
        v[20..24].copy_from_slice(&64u32.to_be_bytes()); // ident_off
        v[48..52].copy_from_slice(&96u32.to_be_bytes()); // team_off
        let ident = b"com.example.app";
        v[64..64 + ident.len()].copy_from_slice(ident);
        let team = b"TEAMID1234";
        v[96..96 + team.len()].copy_from_slice(team);
        let len = v.len();
        let (id, t) = parse_code_directory(&v, 0, len).unwrap();
        assert_eq!(id.as_deref(), Some("com.example.app"));
        assert_eq!(t.as_deref(), Some("TEAMID1234"));
    }

    #[test]
    fn read_c_string_basic() {
        let v = b"abc\0xyz";
        assert_eq!(read_c_string(v, 0, v.len()).as_deref(), Some("abc"));
        assert_eq!(read_c_string(v, 4, v.len()).as_deref(), Some("xyz"));
    }

    #[test]
    fn super_blob_rejects_blob_offsets_outside_claimed_region() {
        // Super-blob magic + outer length=12 (only header, no blobs).
        // Plant attacker-controlled "APPLEINC123\0" outside the
        // claimed region. A BlobIndex offset pointing to that data
        // should NOT be honored.
        let mut v = vec![0u8; 256];
        // Super-blob header at offset 0, claims size = 12.
        v[0..4].copy_from_slice(&0xFADE_0CC0u32.to_be_bytes());
        v[4..8].copy_from_slice(&12u32.to_be_bytes()); // outer length
        v[8..12].copy_from_slice(&1u32.to_be_bytes()); // count = 1
        // BlobIndex(typ, offset) — offset = 200 points OUTSIDE
        // the 12-byte claimed region.
        v[12..16].copy_from_slice(&0xFADE_0C02u32.to_be_bytes());
        v[16..20].copy_from_slice(&200u32.to_be_bytes());
        // Plant a CD-shape blob at offset 200 (magic + crafted strings).
        v[200..204].copy_from_slice(&0xFADE_0C02u32.to_be_bytes());
        v[208..212].copy_from_slice(&0x0002_0100u32.to_be_bytes());
        v[220..224].copy_from_slice(&30u32.to_be_bytes()); // ident_off = 30
        let ident = b"APPLEINC123";
        v[230..230 + ident.len()].copy_from_slice(ident);
        let meta = parse_super_blob(&v, 0, 256).unwrap();
        // The planted CN should NOT be surfaced — the BlobIndex
        // offset escapes the claimed super-blob region.
        assert!(meta.identifier.is_none());
        assert!(meta.team_id.is_none());
    }

    #[test]
    fn super_blob_parser_returns_none_on_bad_magic() {
        let v = vec![0u8; 32];
        assert!(parse_super_blob(&v, 0, 32).is_none());
    }

    #[test]
    fn entitlements_blob_records_sha256() {
        // Super blob with one entitlements blob.
        let mut v = vec![0u8; 256];
        v[0..4].copy_from_slice(&0xFADE_0CC0u32.to_be_bytes());
        v[4..8].copy_from_slice(&64u32.to_be_bytes());
        v[8..12].copy_from_slice(&1u32.to_be_bytes());
        // BlobIndex: type=0x05 (entitlements), offset=32
        v[12..16].copy_from_slice(&5u32.to_be_bytes());
        v[16..20].copy_from_slice(&32u32.to_be_bytes());
        // Embedded entitlements at offset 32: magic=FADE7171, length=24, payload "..."
        v[32..36].copy_from_slice(&0xFADE_7171u32.to_be_bytes());
        v[36..40].copy_from_slice(&24u32.to_be_bytes());
        // 16 bytes of payload: 8-byte blob header + 16-byte XML stub.
        v[40..56].copy_from_slice(b"<plist>true</p>\n");
        let meta = parse_super_blob(&v, 0, 256).unwrap();
        assert!(meta.entitlements_sha256.is_some());
    }
}
