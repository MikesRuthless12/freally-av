//! TASK-218 — UPX in-place unpacker (copy-only).
//!
//! Decompresses a UPX-packed binary to a staging copy so downstream
//! detectors (YARA, header parsers, hashers) see the unpacked
//! payload. The live file is never touched.
//!
//! UPX-packed PEs / ELFs carry a `UPX!` magic block in their tail:
//!
//! ```text
//!   ... compressed payload ...
//!   [packheader: u_len u32 | c_len u32 | u_adler u32 | c_adler u32 |
//!                filter u8  | filter_cto u8 | format u8 | method u8]
//!   "UPX!" magic
//!   [u_file_size u32 | format u8 | method u8 | level u8 | unused u8]
//! ```
//!
//! Where `method` ∈ {NRV2B, NRV2D, NRV2E, LZMA, ...}. The official
//! UPX source includes the canonical decoders.
//!
//! This module ships a *structural* unpacker:
//! - parses the packheader,
//! - extracts the compressed-payload byte range,
//! - dispatches to a method-specific decoder (only the most common
//!   methods are implemented in-tree; novel methods return
//!   `UpxError::UnsupportedMethod` and the engine falls back to
//!   packed-only analysis).
//!
//! Per the spec (`docs/prd.md` § 1.5 — no GPL), the NRV decoders are
//! implemented from the public UPX file-format spec rather than
//! lifted from the UPX source tree (which is GPL2+ with an exception
//! that doesn't cover redistribution as a library). The LZMA path
//! defers to `lzma-rust` (Apache-2.0) if the dep is added in a
//! follow-up; for the foundation we leave LZMA as "unsupported" so
//! the engine logs and continues.

use serde::{Deserialize, Serialize};

/// UPX magic marker that appears between the compressed payload and
/// the trailer.
pub const UPX_MAGIC: &[u8; 4] = b"UPX!";

/// UPX compression methods. The numeric values match the constants in
/// the official UPX source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpxMethod {
    Nrv2b = 2,
    Nrv2d = 3,
    Nrv2e = 5,
    Lzma = 14,
    Zstd = 15,
    Deflate = 16,
    /// Future-proofing: novel method numbers collapse to this.
    Unknown,
}

impl UpxMethod {
    pub fn from_u8(v: u8) -> Self {
        match v {
            2 => UpxMethod::Nrv2b,
            3 => UpxMethod::Nrv2d,
            5 => UpxMethod::Nrv2e,
            14 => UpxMethod::Lzma,
            15 => UpxMethod::Zstd,
            16 => UpxMethod::Deflate,
            _ => UpxMethod::Unknown,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            UpxMethod::Nrv2b => "nrv2b",
            UpxMethod::Nrv2d => "nrv2d",
            UpxMethod::Nrv2e => "nrv2e",
            UpxMethod::Lzma => "lzma",
            UpxMethod::Zstd => "zstd",
            UpxMethod::Deflate => "deflate",
            UpxMethod::Unknown => "unknown",
        }
    }
}

/// Parsed UPX trailer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpxHeader {
    pub uncompressed_len: u32,
    pub compressed_len: u32,
    pub uncompressed_adler: u32,
    pub compressed_adler: u32,
    pub method: UpxMethod,
    pub format: u8,
    pub level: u8,
    /// Byte offset of the trailing `UPX!` magic in the file.
    pub magic_offset: usize,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum UpxError {
    #[error("upx magic not found")]
    MagicNotFound,
    #[error("upx trailer is truncated")]
    Truncated,
    #[error("upx method {0:?} not supported by in-tree decoder")]
    UnsupportedMethod(UpxMethod),
    #[error("upx decompressed size mismatch: expected {expected}, decoded {decoded}")]
    SizeMismatch { expected: usize, decoded: usize },
    #[error("upx decode failed at offset {offset}: {reason}")]
    DecodeFailed { offset: usize, reason: String },
}

/// Locate and parse the UPX trailer.
///
/// The trailer is at the very end of the file (last ~32-64 bytes). We
/// scan backwards from the end of the buffer looking for `UPX!` to
/// tolerate variant trailer layouts.
pub fn parse_header(bytes: &[u8]) -> Result<UpxHeader, UpxError> {
    if bytes.len() < 32 {
        return Err(UpxError::Truncated);
    }
    let magic_offset = locate_magic(bytes).ok_or(UpxError::MagicNotFound)?;
    // The pack-header struct sits immediately *before* the magic. Its
    // layout is documented in UPX `p_lx_elf.h` / `p_w32pe.h`. We need
    // 28 bytes (u_len + c_len + u_adler + c_adler + filter + filter_cto
    // + format + method + level + reserved).
    if magic_offset < 28 {
        return Err(UpxError::Truncated);
    }
    let off = magic_offset - 28;
    let u_len = read_u32_le(bytes, off);
    let c_len = read_u32_le(bytes, off + 4);
    let u_adler = read_u32_le(bytes, off + 8);
    let c_adler = read_u32_le(bytes, off + 12);
    // filter + filter_cto + format + method (4 bytes)
    let _filter = bytes[off + 16];
    let _filter_cto = bytes[off + 17];
    let format = bytes[off + 18];
    let method = UpxMethod::from_u8(bytes[off + 19]);
    let level = bytes[off + 20];
    Ok(UpxHeader {
        uncompressed_len: u_len,
        compressed_len: c_len,
        uncompressed_adler: u_adler,
        compressed_adler: c_adler,
        method,
        format,
        level,
        magic_offset,
    })
}

/// Maximum window (from end of file) we search for the trailing
/// `UPX!` magic. The UPX trailer always sits within the last ~64
/// bytes of the file; bounding the scan keeps us from byte-scanning
/// a 1 GiB PE that the packer-ID stage already mis-classified.
pub const MAGIC_SCAN_TAIL_BYTES: usize = 64 * 1024;

/// Locate the trailing `UPX!` magic. We scan backwards from the end
/// of the buffer for the last occurrence — the UPX runtime sometimes
/// embeds an earlier `UPX!` marker inside the payload itself, so the
/// trailing instance is what matters. Bounded by
/// [`MAGIC_SCAN_TAIL_BYTES`] so a non-UPX input doesn't drag the
/// whole file through a byte-by-byte scan.
fn locate_magic(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < UPX_MAGIC.len() {
        return None;
    }
    let end = bytes.len() - UPX_MAGIC.len();
    let floor = bytes.len().saturating_sub(MAGIC_SCAN_TAIL_BYTES);
    let mut i = end;
    loop {
        if &bytes[i..i + UPX_MAGIC.len()] == UPX_MAGIC {
            return Some(i);
        }
        if i <= floor {
            return None;
        }
        i -= 1;
    }
}

/// Decompress a UPX-packed buffer. Returns the unpacked payload.
///
/// Limitations:
/// - Only NRV2B is supported in the foundation. LZMA / NRV2D / NRV2E
///   yield `UpxError::UnsupportedMethod` and the engine logs +
///   continues. The wave-2 follow-up adds the rest.
/// - The compressed payload location is method- and format-specific;
///   we use the canonical "compressed payload precedes the trailer
///   by exactly `compressed_len` bytes" layout that UPX 3.x uses for
///   PE32+ / ELF binaries. Older binaries with a header overlay are
///   not yet supported.
pub fn decompress(bytes: &[u8]) -> Result<Vec<u8>, UpxError> {
    let h = parse_header(bytes)?;
    let trailer_block_start = h.magic_offset.saturating_sub(28);
    let payload_end = trailer_block_start;
    let payload_start = payload_end
        .checked_sub(h.compressed_len as usize)
        .ok_or(UpxError::Truncated)?;
    let payload = &bytes[payload_start..payload_end];
    match h.method {
        UpxMethod::Nrv2b => decompress_nrv2b(payload, h.uncompressed_len as usize),
        other => Err(UpxError::UnsupportedMethod(other)),
    }
}

/// NRV2B decompressor.
///
/// The NRV2B algorithm (used by UPX for most x86_64 / arm64 binaries)
/// is a simple bit-stream LZ77-ish coder:
///
///   - 1-bit "literal byte follows" tag → copy next byte.
///   - 0-bit followed by a Golomb-Rice encoded `offset` and
///     `match-length` triple → back-reference copy.
///
/// Reference: NRV2B specification published by Markus Oberhumer
/// (the algorithm's author) in the upx-ucl source tree under
/// `nrv2b_d.h`. We implement only the decoder; we never have to
/// emit NRV2B output.
fn decompress_nrv2b(input: &[u8], expected_size: usize) -> Result<Vec<u8>, UpxError> {
    let mut out: Vec<u8> = Vec::with_capacity(expected_size);
    let mut reader = BitReader::new(input);
    let mut last_offset: usize;
    loop {
        if reader.eof() {
            break;
        }
        let bit = reader.next_bit().ok_or(UpxError::DecodeFailed {
            offset: reader.byte_pos(),
            reason: "unexpected eof reading tag".into(),
        })?;
        if bit == 1 {
            // Literal byte follows.
            let byte = reader.next_byte().ok_or(UpxError::DecodeFailed {
                offset: reader.byte_pos(),
                reason: "unexpected eof reading literal".into(),
            })?;
            out.push(byte);
        } else {
            // Match.
            let mut offset = 1usize;
            loop {
                let m = reader.next_bit().ok_or(UpxError::DecodeFailed {
                    offset: reader.byte_pos(),
                    reason: "unexpected eof reading match prefix".into(),
                })?;
                if m == 1 {
                    break;
                }
                offset = offset.checked_mul(2).and_then(|v| v.checked_add(1)).ok_or(
                    UpxError::DecodeFailed {
                        offset: reader.byte_pos(),
                        reason: "offset overflow".into(),
                    },
                )?;
                let b = reader.next_bit().ok_or(UpxError::DecodeFailed {
                    offset: reader.byte_pos(),
                    reason: "unexpected eof reading offset bit".into(),
                })?;
                offset = offset
                    .checked_sub(1 - (b as usize))
                    .ok_or(UpxError::DecodeFailed {
                        offset: reader.byte_pos(),
                        reason: "offset underflow".into(),
                    })?;
            }
            // `offset` is built by the prefix loop above starting from 1; if
            // the loop terminates with `offset < 2` (a hostile bitstream
            // breaking on the very first `m==1`), the `* 256` step would
            // underflow `usize`. Surface that as a decode error rather
            // than letting the math wrap.
            let base = offset.checked_sub(2).ok_or(UpxError::DecodeFailed {
                offset: reader.byte_pos(),
                reason: "offset base underflow (prefix too short)".into(),
            })?;
            offset = base
                .checked_mul(256)
                .and_then(|v| v.checked_add(reader.next_byte()? as usize))
                .ok_or(UpxError::DecodeFailed {
                    offset: reader.byte_pos(),
                    reason: "offset assembly overflow".into(),
                })?;
            if offset == 0xFFFFFFFF || offset > out.len() {
                // Special "end-of-stream" sentinel or invalid back-ref.
                break;
            }
            last_offset = offset + 1;
            // Match length: 2-bit run-length prefix + Golomb-Rice tail.
            let mut m_len: usize = reader.next_bit().ok_or(UpxError::DecodeFailed {
                offset: reader.byte_pos(),
                reason: "unexpected eof reading mlen0".into(),
            })? as usize
                * 2
                + reader.next_bit().ok_or(UpxError::DecodeFailed {
                    offset: reader.byte_pos(),
                    reason: "unexpected eof reading mlen1".into(),
                })? as usize;
            if m_len == 0 {
                // Extended length.
                let mut ext = 1usize;
                loop {
                    let b = reader.next_bit().ok_or(UpxError::DecodeFailed {
                        offset: reader.byte_pos(),
                        reason: "unexpected eof reading mlen ext".into(),
                    })?;
                    if b == 1 {
                        break;
                    }
                    ext = ext.checked_mul(2).and_then(|v| v.checked_add(1)).ok_or(
                        UpxError::DecodeFailed {
                            offset: reader.byte_pos(),
                            reason: "match-len overflow".into(),
                        },
                    )?;
                    let lo = reader.next_bit().ok_or(UpxError::DecodeFailed {
                        offset: reader.byte_pos(),
                        reason: "unexpected eof in mlen lo".into(),
                    })?;
                    ext = ext
                        .checked_sub(1 - (lo as usize))
                        .ok_or(UpxError::DecodeFailed {
                            offset: reader.byte_pos(),
                            reason: "match-len underflow".into(),
                        })?;
                }
                m_len = ext + 2;
            }
            // Add minimum.
            m_len += 2;
            // Copy.
            for _ in 0..m_len {
                let src = match out.len().checked_sub(last_offset) {
                    Some(s) => s,
                    None => {
                        return Err(UpxError::DecodeFailed {
                            offset: reader.byte_pos(),
                            reason: "back-reference past output start".into(),
                        });
                    }
                };
                let b = out[src];
                out.push(b);
                if out.len() > expected_size * 4 {
                    return Err(UpxError::DecodeFailed {
                        offset: reader.byte_pos(),
                        reason: "decompression bomb suspected (output >> expected)".into(),
                    });
                }
            }
        }
        if out.len() >= expected_size {
            break;
        }
    }
    Ok(out)
}

/// Little-endian bit reader, MSB-first per byte. Matches the bit
/// order UPX uses (left-to-right within each byte).
struct BitReader<'a> {
    src: &'a [u8],
    byte_idx: usize,
    bit_idx: u8,
}

impl<'a> BitReader<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            byte_idx: 0,
            bit_idx: 0,
        }
    }

    fn eof(&self) -> bool {
        self.byte_idx >= self.src.len()
    }

    fn byte_pos(&self) -> usize {
        self.byte_idx
    }

    fn next_bit(&mut self) -> Option<u8> {
        if self.byte_idx >= self.src.len() {
            return None;
        }
        let bit = (self.src[self.byte_idx] >> (7 - self.bit_idx)) & 1;
        self.bit_idx += 1;
        if self.bit_idx == 8 {
            self.bit_idx = 0;
            self.byte_idx += 1;
        }
        Some(bit)
    }

    fn next_byte(&mut self) -> Option<u8> {
        // Byte-aligned read after a fresh byte boundary; otherwise
        // we have to pull 8 successive bits.
        if self.bit_idx == 0 {
            if self.byte_idx >= self.src.len() {
                return None;
            }
            let b = self.src[self.byte_idx];
            self.byte_idx += 1;
            return Some(b);
        }
        let mut acc = 0u8;
        for _ in 0..8 {
            let b = self.next_bit()?;
            acc = (acc << 1) | b;
        }
        Some(acc)
    }
}

fn read_u32_le(bytes: &[u8], off: usize) -> u32 {
    let arr = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
    u32::from_le_bytes(arr)
}

/// Compute a UPX-style Adler-32 checksum. Useful for downstream
/// validation; not currently invoked by the decompressor.
pub fn adler32(bytes: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &x in bytes {
        a = (a + x as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_packed(method: u8, u_len: u32, c_len: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 128];
        v.extend_from_slice(payload);
        // Pack header (28 bytes), starting right before UPX! magic.
        let mut hdr = [0u8; 28];
        hdr[0..4].copy_from_slice(&u_len.to_le_bytes());
        hdr[4..8].copy_from_slice(&c_len.to_le_bytes());
        hdr[8..12].copy_from_slice(&adler32(&[]).to_le_bytes());
        hdr[12..16].copy_from_slice(&adler32(payload).to_le_bytes());
        hdr[18] = 0; // format
        hdr[19] = method;
        hdr[20] = 9; // level
        v.extend_from_slice(&hdr);
        v.extend_from_slice(UPX_MAGIC);
        v
    }

    #[test]
    fn parse_header_round_trip() {
        let v = make_packed(2, 1024, 250, &[0u8; 250]);
        let h = parse_header(&v).unwrap();
        assert_eq!(h.method, UpxMethod::Nrv2b);
        assert_eq!(h.uncompressed_len, 1024);
        assert_eq!(h.compressed_len, 250);
    }

    #[test]
    fn parse_header_finds_trailing_magic() {
        let mut v = vec![0u8; 64];
        // Plant an earlier `UPX!` inside the payload — must NOT be
        // chosen.
        v[10..14].copy_from_slice(UPX_MAGIC);
        let mut packed = make_packed(2, 100, 20, &[0u8; 20]);
        v.append(&mut packed);
        let h = parse_header(&v).unwrap();
        assert_eq!(h.uncompressed_len, 100);
    }

    #[test]
    fn parse_header_truncated_input_errors() {
        let small = [0u8; 8];
        assert_eq!(parse_header(&small), Err(UpxError::Truncated));
    }

    #[test]
    fn parse_header_no_magic_errors() {
        let v = vec![0u8; 256];
        assert_eq!(parse_header(&v), Err(UpxError::MagicNotFound));
    }

    #[test]
    fn unsupported_method_surfaces_method_kind() {
        let v = make_packed(14, 32, 16, &[0u8; 16]);
        match decompress(&v) {
            Err(UpxError::UnsupportedMethod(m)) => assert_eq!(m, UpxMethod::Lzma),
            other => panic!("expected UnsupportedMethod, got {other:?}"),
        }
    }

    #[test]
    fn method_table_names_unique() {
        let names: Vec<&str> = [
            UpxMethod::Nrv2b,
            UpxMethod::Nrv2d,
            UpxMethod::Nrv2e,
            UpxMethod::Lzma,
            UpxMethod::Zstd,
            UpxMethod::Deflate,
            UpxMethod::Unknown,
        ]
        .iter()
        .map(|m| m.name())
        .collect();
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());
    }

    #[test]
    fn adler32_known_vectors() {
        assert_eq!(adler32(b""), 1);
        // RFC 1950 example: adler32 of "Wikipedia" = 0x11E60398
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn bit_reader_pulls_bits_then_byte() {
        let mut r = BitReader::new(&[0b1010_0011, 0xFF]);
        assert_eq!(r.next_bit(), Some(1));
        assert_eq!(r.next_bit(), Some(0));
        assert_eq!(r.next_bit(), Some(1));
        // Mid-byte byte read pulls remaining 5 bits + 3 from the next.
        assert_eq!(r.next_byte(), Some(0b00_011_111));
    }

    #[test]
    fn locate_magic_on_minimum_buffer() {
        let v = vec![b'U', b'P', b'X', b'!'];
        assert_eq!(locate_magic(&v), Some(0));
    }

    #[test]
    fn nrv2b_empty_input_returns_empty() {
        let v = decompress_nrv2b(&[], 0).unwrap();
        assert!(v.is_empty());
    }
}
