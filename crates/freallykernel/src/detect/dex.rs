//! TASK-221 — Android APK / DEX bytecode scan.
//!
//! Parses the Dalvik EXecutable (`classes.dex`) header + key offset
//! tables so the engine can run YARA over the bytecode stream, plus
//! a minimal AXML (binary XML) reader for `AndroidManifest.xml`.
//!
//! The DEX file format is publicly documented by Google
//! (`source.android.com/devices/tech/dalvik/dex-format`). Per
//! `docs/prd.md` § 1.5, we implement the reader in-tree rather than
//! pulling a license-uncertain `dexparser` crate (the crate is MIT
//! but unmaintained; carrying our own bounded parser is simpler).

use serde::{Deserialize, Serialize};

/// DEX magic bytes — `dex\n035\0` through `dex\n041\0` over the years.
/// We accept any `dex\n` prefix and parse the version separately.
pub const DEX_MAGIC_PREFIX: [u8; 4] = [b'd', b'e', b'x', b'\n'];

/// Per-file DEX size cap from the spec.
pub const MAX_DEX_SIZE: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexHeader {
    pub version: [u8; 4],
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum DexError {
    #[error("not a DEX file (bad magic)")]
    BadMagic,
    #[error("DEX is truncated at offset {0}")]
    Truncated(usize),
    #[error("DEX is too large ({size} > {limit})")]
    TooLarge { size: usize, limit: usize },
    #[error("DEX header has unsupported endianness tag {0:#x}")]
    Endianness(u32),
}

/// Parse a DEX header.
pub fn parse_header(bytes: &[u8]) -> Result<DexHeader, DexError> {
    if bytes.len() > MAX_DEX_SIZE {
        return Err(DexError::TooLarge {
            size: bytes.len(),
            limit: MAX_DEX_SIZE,
        });
    }
    if bytes.len() < 0x70 {
        return Err(DexError::Truncated(bytes.len()));
    }
    if bytes[..4] != DEX_MAGIC_PREFIX {
        return Err(DexError::BadMagic);
    }
    let version = [bytes[4], bytes[5], bytes[6], bytes[7]];
    let endian_tag = u32::from_le_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]);
    if endian_tag != 0x1234_5678 && endian_tag != 0x7856_3412 {
        return Err(DexError::Endianness(endian_tag));
    }
    let r = |off: usize| {
        u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
    };
    let checksum = r(8);
    let mut signature = [0u8; 20];
    signature.copy_from_slice(&bytes[12..32]);
    Ok(DexHeader {
        version,
        checksum,
        signature,
        file_size: r(32),
        header_size: r(36),
        endian_tag,
        string_ids_size: r(56),
        string_ids_off: r(60),
        type_ids_size: r(64),
        type_ids_off: r(68),
        proto_ids_size: r(72),
        proto_ids_off: r(76),
        field_ids_size: r(80),
        field_ids_off: r(84),
        method_ids_size: r(88),
        method_ids_off: r(92),
        class_defs_size: r(96),
        class_defs_off: r(100),
        data_size: r(104),
        data_off: r(108),
    })
}

/// Read a single string from the string-data section given a
/// string_id offset. Returns the decoded string and the bytes
/// consumed.
///
/// DEX strings use Modified UTF-8 (MUTF-8), the same encoding as
/// Java `.class` files: embedded NULs become two bytes (`0xC0 0x80`)
/// and supplementary code points use surrogate-pair UTF-8. Strict
/// UTF-8 decode would silently drop any non-ASCII string containing
/// those sequences (Japanese / Cyrillic / Arabic / Chinese APKs), so
/// we decode MUTF-8 explicitly with a graceful UTF-8 fallback.
pub fn read_string_at(bytes: &[u8], string_data_off: u32) -> Option<String> {
    let mut idx = string_data_off as usize;
    let (_, used) = read_uleb128(bytes, idx)?;
    idx += used;
    let mut s = Vec::new();
    while idx < bytes.len() && bytes[idx] != 0 {
        s.push(bytes[idx]);
        idx += 1;
    }
    decode_mutf8(&s).or_else(|| String::from_utf8(s).ok())
}

/// Decode JVM/DEX modified-UTF-8: identical to UTF-8 except encoded
/// NUL is `0xC0 0x80` and supplementary code points come in as
/// surrogate-pair UTF-8 rather than a single 4-byte sequence.
fn decode_mutf8(bytes: &[u8]) -> Option<String> {
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b < 0x80 {
            // Plain ASCII (NUL is illegal in MUTF-8 strings — but if it
            // shows up in a non-terminator position we treat it as data
            // and stop here).
            if b == 0 {
                return None;
            }
            out.push(b as char);
            i += 1;
        } else if b & 0xE0 == 0xC0 {
            if i + 1 >= bytes.len() {
                return None;
            }
            let b2 = bytes[i + 1];
            if b2 & 0xC0 != 0x80 {
                return None;
            }
            let cp = (((b & 0x1F) as u32) << 6) | (b2 & 0x3F) as u32;
            out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
            i += 2;
        } else if b & 0xF0 == 0xE0 {
            if i + 2 >= bytes.len() {
                return None;
            }
            let b2 = bytes[i + 1];
            let b3 = bytes[i + 2];
            if b2 & 0xC0 != 0x80 || b3 & 0xC0 != 0x80 {
                return None;
            }
            let cp = (((b & 0x0F) as u32) << 12) | (((b2 & 0x3F) as u32) << 6) | (b3 & 0x3F) as u32;
            out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
            i += 3;
        } else {
            return None;
        }
    }
    Some(out)
}

/// Read a ULEB128-encoded unsigned integer from `bytes` starting at
/// `off`. Returns `(value, bytes_consumed)` or `None` on overrun.
pub fn read_uleb128(bytes: &[u8], off: usize) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    let mut i = 0;
    while off + i < bytes.len() {
        let b = bytes[off + i];
        result |= ((b & 0x7F) as u32).checked_shl(shift)?;
        i += 1;
        if b & 0x80 == 0 {
            return Some((result, i));
        }
        shift += 7;
        if shift > 28 {
            return None;
        }
    }
    None
}

/// Enumerate `string_ids` and resolve to UTF-8 strings (best-effort).
pub fn enumerate_strings(bytes: &[u8], hdr: &DexHeader) -> Vec<String> {
    let mut out = Vec::new();
    let max = hdr.string_ids_size as usize;
    let start = hdr.string_ids_off as usize;
    for i in 0..max {
        let id_off = start + i * 4;
        if id_off + 4 > bytes.len() {
            break;
        }
        let data_off = u32::from_le_bytes([
            bytes[id_off],
            bytes[id_off + 1],
            bytes[id_off + 2],
            bytes[id_off + 3],
        ]);
        if let Some(s) = read_string_at(bytes, data_off) {
            out.push(s);
        }
    }
    out
}

// -----------------------------------------------------------------------------
// AXML (compiled AndroidManifest.xml)
// -----------------------------------------------------------------------------

/// AXML chunk magic (first 4 bytes of a binary AndroidManifest.xml).
pub const AXML_MAGIC: u32 = 0x0008_0003;

/// Tag types recovered from a binary AXML file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AxmlEvent {
    Start {
        name: String,
        attrs: Vec<(String, String)>,
    },
    End {
        name: String,
    },
    Text {
        text: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManifestSummary {
    pub package: Option<String>,
    pub permissions: Vec<String>,
    pub min_sdk_version: Option<u32>,
    pub events: Vec<AxmlEvent>,
}

/// Best-effort AXML parser. We don't decode every chunk type — just
/// enough to surface the package name + permission list, which is
/// the surface YARA + analyst-readable display want.
pub fn parse_axml(bytes: &[u8]) -> Option<ManifestSummary> {
    if bytes.len() < 8 {
        return None;
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic != AXML_MAGIC {
        return None;
    }
    // String-pool chunk follows. Read its string table; we use it
    // to resolve attribute names + values referenced by index in
    // the START_ELEMENT chunks.
    let strings = read_axml_string_pool(bytes)?;
    let mut summary = ManifestSummary::default();
    // Walk chunks looking for START_ELEMENT (type 0x00100102) bodies.
    let mut pos = 8;
    while pos + 16 <= bytes.len() {
        let chunk_type = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
        let chunk_size = u32::from_le_bytes([
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]) as usize;
        if chunk_size == 0 || pos + chunk_size > bytes.len() {
            break;
        }
        if chunk_type == 0x0102 {
            // RES_XML_START_ELEMENT_TYPE
            if let Some(ev) = decode_start_element(&bytes[pos..pos + chunk_size], &strings) {
                if let AxmlEvent::Start { name, attrs } = &ev {
                    match name.as_str() {
                        "manifest" => {
                            for (k, v) in attrs {
                                if k == "package" {
                                    summary.package = Some(v.clone());
                                }
                            }
                        }
                        "uses-permission" => {
                            for (k, v) in attrs {
                                if k == "name" {
                                    summary.permissions.push(v.clone());
                                }
                            }
                        }
                        "uses-sdk" => {
                            for (k, v) in attrs {
                                if k == "minSdkVersion"
                                    && let Ok(n) = v.parse::<u32>()
                                {
                                    summary.min_sdk_version = Some(n);
                                }
                            }
                        }
                        _ => {}
                    }
                    summary.events.push(ev);
                }
            }
        }
        pos += chunk_size;
    }
    Some(summary)
}

fn read_axml_string_pool(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 28 {
        return None;
    }
    // String pool chunk starts at offset 8 (after the AXML header
    // 8-byte chunk header). Its header is itself 28 bytes:
    //   type:u16  hdr_size:u16  chunk_size:u32  string_count:u32
    //   style_count:u32  flags:u32  strings_off:u32  styles_off:u32
    let base = 8;
    if bytes[base] != 0x01 || bytes[base + 1] != 0x00 {
        return None;
    }
    let string_count = u32::from_le_bytes([
        bytes[base + 8],
        bytes[base + 9],
        bytes[base + 10],
        bytes[base + 11],
    ]) as usize;
    let strings_off = u32::from_le_bytes([
        bytes[base + 20],
        bytes[base + 21],
        bytes[base + 22],
        bytes[base + 23],
    ]) as usize;
    let flags = u32::from_le_bytes([
        bytes[base + 16],
        bytes[base + 17],
        bytes[base + 18],
        bytes[base + 19],
    ]);
    let utf8 = (flags & 0x100) != 0;
    let mut out = Vec::with_capacity(string_count);
    for i in 0..string_count {
        if base + 28 + i * 4 + 4 > bytes.len() {
            break;
        }
        let off = u32::from_le_bytes([
            bytes[base + 28 + i * 4],
            bytes[base + 29 + i * 4],
            bytes[base + 30 + i * 4],
            bytes[base + 31 + i * 4],
        ]) as usize;
        let abs = base + strings_off + off;
        if utf8 {
            if abs + 2 > bytes.len() {
                break;
            }
            let _u16_len = bytes[abs] as usize;
            let u8_len = bytes[abs + 1] as usize;
            let start = abs + 2;
            let end = start + u8_len;
            if end > bytes.len() {
                break;
            }
            out.push(String::from_utf8_lossy(&bytes[start..end]).to_string());
        } else {
            if abs + 2 > bytes.len() {
                break;
            }
            let len = u16::from_le_bytes([bytes[abs], bytes[abs + 1]]) as usize;
            let start = abs + 2;
            let end = start + len * 2;
            if end > bytes.len() {
                break;
            }
            let chars: Vec<u16> = bytes[start..end]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            out.push(String::from_utf16_lossy(&chars));
        }
    }
    Some(out)
}

fn decode_start_element(chunk: &[u8], strings: &[String]) -> Option<AxmlEvent> {
    // Layout (after the 8-byte chunk header):
    //   line_number:u32  comment:u32  ns:u32  name:u32  attr_start:u16
    //   attr_size:u16  attr_count:u16  ...
    if chunk.len() < 36 {
        return None;
    }
    let name_idx = u32::from_le_bytes([chunk[20], chunk[21], chunk[22], chunk[23]]);
    let attr_count = u16::from_le_bytes([chunk[28], chunk[29]]) as usize;
    let attr_start = u16::from_le_bytes([chunk[24], chunk[25]]) as usize;
    let attr_size = u16::from_le_bytes([chunk[26], chunk[27]]) as usize;
    let attrs_off = 16 + attr_start;
    let mut attrs = Vec::with_capacity(attr_count);
    for i in 0..attr_count {
        let off = attrs_off + i * attr_size;
        if off + 20 > chunk.len() {
            break;
        }
        let name_id = u32::from_le_bytes([
            chunk[off + 4],
            chunk[off + 5],
            chunk[off + 6],
            chunk[off + 7],
        ]);
        let raw_val_id = u32::from_le_bytes([
            chunk[off + 8],
            chunk[off + 9],
            chunk[off + 10],
            chunk[off + 11],
        ]);
        let typed_val = u32::from_le_bytes([
            chunk[off + 16],
            chunk[off + 17],
            chunk[off + 18],
            chunk[off + 19],
        ]);
        let attr_name = strings.get(name_id as usize).cloned().unwrap_or_default();
        let attr_value = if raw_val_id != 0xFFFFFFFF {
            strings
                .get(raw_val_id as usize)
                .cloned()
                .unwrap_or_default()
        } else {
            typed_val.to_string()
        };
        attrs.push((attr_name, attr_value));
    }
    let name = strings.get(name_idx as usize).cloned().unwrap_or_default();
    Some(AxmlEvent::Start { name, attrs })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dex_header() -> Vec<u8> {
        let mut v = vec![0u8; 0x70];
        v[..4].copy_from_slice(&DEX_MAGIC_PREFIX);
        v[4..8].copy_from_slice(b"035\0");
        v[32..36].copy_from_slice(&(0x70u32).to_le_bytes()); // file_size
        v[36..40].copy_from_slice(&(0x70u32).to_le_bytes()); // header_size
        v[40..44].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // endian tag
        v
    }

    #[test]
    fn parse_minimal_header() {
        let v = make_dex_header();
        let h = parse_header(&v).unwrap();
        assert_eq!(h.version, *b"035\0");
        assert_eq!(h.endian_tag, 0x1234_5678);
    }

    #[test]
    fn bad_magic_rejects() {
        let mut v = make_dex_header();
        v[0] = 0;
        assert_eq!(parse_header(&v), Err(DexError::BadMagic));
    }

    #[test]
    fn truncated_rejects() {
        let v = vec![b'd', b'e', b'x', b'\n', b'0', b'3', b'5', 0];
        match parse_header(&v) {
            Err(DexError::Truncated(_)) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn too_large_rejects() {
        let v = vec![0u8; MAX_DEX_SIZE + 1];
        match parse_header(&v) {
            Err(DexError::TooLarge { .. }) => {}
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn bad_endianness_rejects() {
        let mut v = make_dex_header();
        v[40..44].copy_from_slice(&0x0000_0000u32.to_le_bytes());
        assert!(matches!(parse_header(&v), Err(DexError::Endianness(_))));
    }

    #[test]
    fn read_uleb128_decodes_canonical_form() {
        assert_eq!(read_uleb128(&[0x00], 0), Some((0, 1)));
        assert_eq!(read_uleb128(&[0x7F], 0), Some((127, 1)));
        assert_eq!(read_uleb128(&[0x80, 0x01], 0), Some((128, 2)));
        assert_eq!(read_uleb128(&[0xE5, 0x8E, 0x26], 0), Some((624_485, 3)));
    }

    #[test]
    fn read_uleb128_rejects_overlong() {
        let v = vec![0x80u8; 8];
        assert!(read_uleb128(&v, 0).is_none());
    }

    #[test]
    fn read_string_at_decodes_uleb_prefix() {
        // Encode "hello": uleb128 length=5, then ASCII, then null.
        let mut v = vec![0u8; 8];
        v[2] = 0x05;
        v[3] = b'h';
        v[4] = b'e';
        v[5] = b'l';
        v[6] = b'l';
        v[7] = b'o';
        let s = read_string_at(&v, 2).unwrap();
        assert_eq!(s, "hello");
    }

    #[test]
    fn parse_axml_rejects_non_axml() {
        let v = vec![0u8; 16];
        assert!(parse_axml(&v).is_none());
    }

    #[test]
    fn manifest_summary_default_is_empty() {
        let m = ManifestSummary::default();
        assert!(m.package.is_none());
        assert!(m.permissions.is_empty());
        assert!(m.events.is_empty());
    }
}
