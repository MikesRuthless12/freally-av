//! TASK-209 — Fat-binary scan dispatcher.
//!
//! Bridges the slice enumeration ([`crate::walker::dual_arch`]) into
//! the existing hashing path. Each slice gets its own BLAKE3 hash and
//! finding-key. A `bad` slice in a universal binary surfaces as a
//! finding keyed on `(path, arch)` so an x86_64-only malware planted
//! in an arm64+x86_64 universal binary doesn't get hidden behind the
//! arm64 slice's clean result.
//!
//! This module is intentionally pure (no I/O) — it consumes a byte
//! buffer (the engine already mmap'd) and yields the per-slice hash
//! table. The engine integration (wiring into `engine.rs`) is part of
//! the Phase 7C closeout commit.

use crate::detect::header_parse::Arch;
use crate::walker::dual_arch::{ArchSlice, Container, SliceEnumeration, enumerate_slices};
use serde::{Deserialize, Serialize};

/// Per-slice hash result with its arch tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SliceHash {
    pub arch: Arch,
    pub offset: u64,
    pub size: u64,
    /// BLAKE3 of the slice's bytes, hex-encoded.
    pub blake3: String,
}

/// Aggregate result of scanning every slice in a multi-arch input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FatBinaryHashes {
    pub container: Container,
    pub slices: Vec<SliceHash>,
}

/// Hash every slice independently.
///
/// `bytes` should be the entire file (or at least cover every
/// slice's `(offset, offset+size)` range). Slices whose `offset+size`
/// exceeds the buffer length are recorded with an empty digest so the
/// caller can surface "slice truncated" without aborting the whole
/// scan.
pub fn hash_slices(bytes: &[u8]) -> FatBinaryHashes {
    let SliceEnumeration { container, slices } = enumerate_slices(bytes);
    let slice_hashes = slices.iter().map(|s| hash_one_slice(bytes, s)).collect();
    FatBinaryHashes {
        container,
        slices: slice_hashes,
    }
}

fn hash_one_slice(bytes: &[u8], slice: &ArchSlice) -> SliceHash {
    let start = slice.offset as usize;
    let end = start.saturating_add(slice.size as usize);
    let digest = if end <= bytes.len() {
        let hash = blake3::hash(&bytes[start..end]);
        hex::encode(hash.as_bytes())
    } else {
        // Slice range exceeds the buffer; surface an empty digest so
        // the caller can record "truncated slice" without crashing.
        String::new()
    };
    SliceHash {
        arch: slice.arch,
        offset: slice.offset,
        size: slice.size,
        blake3: digest,
    }
}

/// Verdict aggregation contract: if any slice in a universal binary
/// hits the blacklist, the file's verdict is `Detected` and the
/// finding's `evidence` carries the slice arch.
///
/// This helper is exposed so the engine's blacklist evaluator can
/// stay arch-agnostic — given the per-slice hash table, it asks
/// "which slices match these BLAKE3s?" and we return the matching
/// arch tags + slice byte ranges.
pub fn matching_slices<'a>(
    hashes: &'a FatBinaryHashes,
    blacklisted_blake3_hex: &[String],
) -> Vec<&'a SliceHash> {
    let needles: std::collections::HashSet<&str> =
        blacklisted_blake3_hex.iter().map(|s| s.as_str()).collect();
    hashes
        .slices
        .iter()
        .filter(|s| needles.contains(s.blake3.as_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_byte_buf(seed: u32, len: usize) -> Vec<u8> {
        // Deterministic LCG; the actual content doesn't matter for
        // these tests, only that two different (seed, len) pairs
        // produce distinct buffers so BLAKE3 differs.
        let mut s = seed as u64 | 1;
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            v.push((s >> 33) as u8);
        }
        v
    }

    fn make_macho_fat_2_slices(
        slice0_offset: u32,
        slice0_size: u32,
        slice1_offset: u32,
        slice1_size: u32,
    ) -> Vec<u8> {
        const FAT_MAGIC: u32 = 0xCAFEBABE;
        const ABI64: u32 = 0x0100_0000;
        let header_len = 8 + 2 * 20;
        let total =
            (slice1_offset + slice1_size).max(slice0_offset + slice0_size) as usize + header_len;
        let mut v = vec![0u8; total];
        v[..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        v[4..8].copy_from_slice(&2u32.to_be_bytes());
        // x86_64 slice
        v[8..12].copy_from_slice(&(7 | ABI64).to_be_bytes());
        v[16..20].copy_from_slice(&slice0_offset.to_be_bytes());
        v[20..24].copy_from_slice(&slice0_size.to_be_bytes());
        // arm64 slice
        v[28..32].copy_from_slice(&(12u32 | ABI64).to_be_bytes());
        v[36..40].copy_from_slice(&slice1_offset.to_be_bytes());
        v[40..44].copy_from_slice(&slice1_size.to_be_bytes());
        v
    }

    #[test]
    fn hash_slices_yields_unique_digests_per_slice() {
        let mut bytes = make_macho_fat_2_slices(100, 50, 200, 60);
        // Fill the slice ranges with distinct payloads.
        for (i, b) in random_byte_buf(1, 50).iter().enumerate() {
            bytes[100 + i] = *b;
        }
        for (i, b) in random_byte_buf(2, 60).iter().enumerate() {
            bytes[200 + i] = *b;
        }
        let h = hash_slices(&bytes);
        assert_eq!(h.container, Container::MachOFat);
        assert_eq!(h.slices.len(), 2);
        assert_eq!(h.slices[0].size, 50);
        assert_eq!(h.slices[1].size, 60);
        assert_ne!(
            h.slices[0].blake3, h.slices[1].blake3,
            "distinct slice payloads must produce different blake3"
        );
    }

    #[test]
    fn single_arch_fat_returns_one_full_file_slice() {
        let mut v = vec![0u8; 64];
        v[..4].copy_from_slice(b"\x7fELF");
        v[4] = 2;
        v[5] = 1;
        v[16..18].copy_from_slice(&2u16.to_le_bytes());
        v[18..20].copy_from_slice(&62u16.to_le_bytes());
        let h = hash_slices(&v);
        assert_eq!(h.container, Container::Single);
        assert_eq!(h.slices.len(), 1);
        assert_eq!(h.slices[0].size, v.len() as u64);
    }

    #[test]
    fn matching_slices_filters_by_blacklist() {
        let bytes = make_macho_fat_2_slices(100, 50, 200, 60);
        let h = hash_slices(&bytes);
        // The all-zero slice will hash to a determined BLAKE3.
        let zero_50 = hex::encode(blake3::hash(&[0u8; 50]).as_bytes());
        let needles = vec![zero_50];
        let m = matching_slices(&h, &needles);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].arch, Arch::X86_64);
    }

    #[test]
    fn truncated_slice_produces_empty_digest_no_panic() {
        // Fat header advertises a slice that runs past buffer end.
        let mut v = vec![0u8; 8 + 20];
        const FAT_MAGIC: u32 = 0xCAFEBABE;
        v[..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        v[4..8].copy_from_slice(&1u32.to_be_bytes());
        v[8..12].copy_from_slice(&7u32.to_be_bytes());
        v[16..20].copy_from_slice(&1000u32.to_be_bytes()); // offset past buffer end
        v[20..24].copy_from_slice(&500u32.to_be_bytes());
        let h = hash_slices(&v);
        assert_eq!(h.slices.len(), 1);
        assert!(h.slices[0].blake3.is_empty());
    }
}
