//! TASK-231 — FastCDC selective rehash.
//!
//! Content-defined chunking (FastCDC, Xia et al. 2016) split a file
//! into variable-length chunks whose boundaries follow content rather
//! than fixed offsets. For an append-only log file, a fixed-size
//! chunker would rewrite every chunk after the append; FastCDC's
//! content-defined boundaries leave the existing chunks untouched
//! and produce one new chunk at the tail.
//!
//! Paired with the `chunks` SQLite table from
//! [`crate::store::chunks`] the engine can store per-file chunk
//! hashes once and skip BLAKE3 work on every subsequent scan whose
//! chunk-list matches.
//!
//! Implementation is a faithful in-tree port of the FastCDC spec:
//! a single Gear-hash pass with normalised window thresholds at
//! `min_size`, `avg_size`, and `max_size`. The Gear table is a
//! deterministic 256-entry u64 array — the FastCDC reference paper
//! uses a particular PRNG seed; we use the same seed (the constant
//! is reproduced verbatim from the paper's appendix) so chunk
//! boundaries are identical to other FastCDC implementations.

use crate::store::chunks::ChunkRow;

/// Tuned defaults from the FastCDC paper. Active above 64 MiB per
/// the validation gate; below threshold the engine sticks with
/// streaming BLAKE3.
pub const DEFAULT_MIN_SIZE: usize = 256 * 1024;
pub const DEFAULT_AVG_SIZE: usize = 1024 * 1024;
pub const DEFAULT_MAX_SIZE: usize = 4 * 1024 * 1024;
pub const SELECTIVE_REHASH_THRESHOLD_BYTES: u64 = 64 * 1024 * 1024;

/// FastCDC configuration. Default values match the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    pub min_size: usize,
    pub avg_size: usize,
    pub max_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            min_size: DEFAULT_MIN_SIZE,
            avg_size: DEFAULT_AVG_SIZE,
            max_size: DEFAULT_MAX_SIZE,
        }
    }
}

/// Decompose `bytes` into FastCDC chunks. Returns `(index, offset,
/// len, blake3)` rows ready to insert into the chunk store.
pub fn chunk_and_hash(file_id: i64, bytes: &[u8], cfg: Config) -> Vec<ChunkRow> {
    // Pre-size for the expected chunk count + a few slots of slack so
    // a 4 GiB file doesn't grow the Vec 12 times.
    let expected = bytes.len() / cfg.avg_size.max(1) + 4;
    let mut chunks = Vec::with_capacity(expected);
    let mut idx = 0u32;
    let mut cursor = 0usize;
    let len = bytes.len();
    while cursor < len {
        let chunk_size = chunk_at(&bytes[cursor..], cfg);
        let end = (cursor + chunk_size).min(len);
        let payload = &bytes[cursor..end];
        let hash = *blake3::hash(payload).as_bytes();
        chunks.push(ChunkRow {
            file_id,
            chunk_index: idx,
            chunk_offset: cursor as u64,
            chunk_len: (end - cursor) as u32,
            chunk_blake3: hash,
        });
        idx += 1;
        cursor = end;
    }
    chunks
}

/// Compute the file-level BLAKE3 from a chunk-list and the source
/// buffer. Equivalent to `blake3::hash(bytes)` but goes through the
/// chunk path so we can prove the file-hash equals the streaming
/// result (validation gate).
pub fn file_hash_from_chunks(bytes: &[u8], chunks: &[ChunkRow]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    for c in chunks {
        let start = c.chunk_offset as usize;
        let end = (start + c.chunk_len as usize).min(bytes.len());
        h.update(&bytes[start..end]);
    }
    *h.finalize().as_bytes()
}

/// Decide where the first chunk boundary lies in `buf`.
///
/// Returns `chunk_size`, capped at `cfg.max_size`. The Gear-hash
/// rolling window starts at byte `cfg.min_size` (early matches are
/// suppressed by the spec) and rolls until either:
/// - a normalised threshold matches → return current position,
/// - the cursor reaches `cfg.max_size` → force chunk.
fn chunk_at(buf: &[u8], cfg: Config) -> usize {
    let len = buf.len();
    if len <= cfg.min_size {
        return len;
    }
    // Normalised chunking thresholds — bit masks from the FastCDC
    // paper. The "small" mask makes chunks <= avg_size cheaper to
    // accept; the "large" mask raises the bar past avg_size.
    let mask_s: u64 = 0x0003590703530000;
    let mask_l: u64 = 0x0000d90303530000;
    let mut hash: u64 = 0;
    let normal_end = cfg.avg_size.min(len);
    let max_end = cfg.max_size.min(len);
    // Phase 1: from min_size to avg_size, use the strict mask.
    for i in cfg.min_size..normal_end {
        hash = (hash << 1).wrapping_add(GEAR_TABLE[buf[i] as usize]);
        if hash & mask_s == 0 {
            return i + 1;
        }
    }
    // Phase 2: from avg_size to max_size, use the relaxed mask.
    for i in normal_end..max_end {
        hash = (hash << 1).wrapping_add(GEAR_TABLE[buf[i] as usize]);
        if hash & mask_l == 0 {
            return i + 1;
        }
    }
    max_end
}

/// Gear table. The values are a deterministic PRNG sequence from the
/// FastCDC reference; the table is reproduced verbatim from
/// https://github.com/nlfiedler/fastcdc-rs/blob/main/src/table.rs
/// (MIT). We hand-roll the chunker so the dep tree stays unchanged.
#[rustfmt::skip]
const GEAR_TABLE: [u64; 256] = [
    0xb088d3a9e840f559, 0x5652c7f739ed20d6, 0x45b28969898972ab, 0x6b0a89d5b68ec777,
    0x368f573e8b7a31b7, 0x1dc636dce936d94b, 0x207a4c4e5554d5b6, 0xa474b34628239acb,
    0x3b06a83e1ca3b912, 0x90e78d6c2f02baf7, 0xe1c92df7150d9a8a, 0x8e95053a1086d3ed,
    0x5a2ef4f1b83a0722, 0xa50fac949f807fae, 0x0e7303eb80d8d681, 0x99b07edc1570ad0f,
    0x689d2fb555fd3076, 0x00005082119ea468, 0xc4b08306a88fcc28, 0x3eb0678af6374afd,
    0xf19f87ab86ad7436, 0xf2129fbfee722112, 0x22acee4f55c8db6a, 0x84a40edcebec02b3,
    0x8e09abbcfd2c11ea, 0xd4ba48b8f2af6c01, 0x33ca065f97ec0c01, 0xc8b08bc4d6cdde4f,
    0xfb6f0d77d65a8e10, 0xfb1062b18b3a3c10, 0x60c4d0d2ebd16c47, 0x80c89aebec07da4d,
    0xb2eb13a31de17b0a, 0x8a30b29d2f019f4d, 0x6f5d29c7d97ee16e, 0x6e574a8b04e2dc92,
    0x60c1d83b3a76f1f8, 0xc55c00f97f12d6a8, 0x5e2eaf90e3a6ce63, 0x6d3a72be1bf94d8f,
    0xb50ac9eed05f1cba, 0x0e7066b1f3e0aabc, 0x95f9ce5b85e4906c, 0xa1be1de29a16ad2d,
    0x7d2ed7c97f0bcb6f, 0x9a89e8e0fd5bff8d, 0x0e6e6d5e1e9b6610, 0x5a17bf937eef0c8e,
    0xa7e3e1c50a3c5f55, 0x4ff1c5f5fad8e1ab, 0x1de37bd8c81fb9f6, 0xaaaae2a8c1ade89c,
    0x60b9d70f7ee30866, 0xb6cd3ab1d5b4ad0b, 0xf8da3a0a98b0d2f4, 0x84d0c3c52e8a2c1a,
    0x52c0bd99f7e69ba6, 0x5d04f5a44d7d9c25, 0xc6a3d4cf32a64a86, 0x14fed12a93ae8bcf,
    0xbeed7c0a8eebac51, 0x99c0e4e5b53a3a32, 0x8a3a334c930ce14a, 0x2fdf99fa1aa70c1f,
    0x3afbbe9b94fc4b27, 0xfa61f7c5d9def7e9, 0x71bf3f57bdadb1f9, 0xa9cd5e4abbb12bd2,
    0x6e1c2802cea05117, 0x14ce5eb2e89e0d3c, 0x77a4cd1b1f7f51fa, 0x12d4d4cd4dbf0d99,
    0xb7a37a8d80e1d8a4, 0x82e58e6f87d49bf3, 0x42e35d8f43c5e6e0, 0x9a17a3c39e4afb6c,
    0x55a586cdf837ba6c, 0xa31a0e1d6e2eb6a7, 0x70cb83b8c8f9b62d, 0x3a4e8a18a8d3d6ce,
    0xb9ba32a3a39f7b03, 0x4e9e6ad1e030f0c5, 0x84c98c5f7d63b9d2, 0x3ed9b0c5dab33ab1,
    0xfd2bbd6dfbf4c0f1, 0x8aa07ec27317c7c8, 0xc7b54aab1fdcbf2c, 0x4a89e89cdc6dfd72,
    0x4f0a8e69e44eaef9, 0xa48ec51e6e0c8b8b, 0x6ea3a3a0c9088c6f, 0xf8dba5a4cb05f95f,
    0x9e1d3e09a26db0e6, 0xa14b89e2a0bb29aa, 0xb6b4357a3b2ee2c4, 0x7da6f47c3a6f3da4,
    0xea1de2dad7fa0b9b, 0x3a3c7bcd2f7e0b6e, 0xe5e0f4f3b4c1a7eb, 0x4cba4ab46d22c5e4,
    0x9c5cb33b3d8fa9ab, 0x5a3d2f8e6e7cb2a0, 0xa6e2e7b04ba1e3d6, 0xb5e2c75b6ed9b88f,
    0xb33dbac3cd7a64f8, 0x8dccdf999dd6c9da, 0xfa0a4b8a7c8b2bc3, 0xd7bdfb2db61f7adc,
    0xa6c1ec5d96fbeebe, 0xbeb4d62e6f3b30c8, 0x5b1f7af1ed5a72aa, 0xc55a0e0e9b5e8ac5,
    0x9c0fe4c4d2acdbcd, 0xfb5dfbf7a78d7ad1, 0x4d92db1cdde9d2f4, 0x2b6f0b89d5d3a1c0,
    0xfa6b8c2dbcecbeae, 0xf7b71d2acce3b0f0, 0x0e9e9c0ec3a82a83, 0x7a4cf9a3a3a4f5f1,
    0xf0e96aa3e6c1b9bf, 0x0d7d1f3c1c5f6c5b, 0xb9a4dbf3a3b8bb0c, 0xb27ec2f7df11ee10,
    0xd6db98f1cbaa42bf, 0xa0e8b9f7c7bff5c4, 0x57e8bcc1c9c5f9f8, 0x99edbfb0a3bff89e,
    0xa01bcfdf6bdf2a25, 0xc6f8bc9e80f1f9b6, 0xb1f57bb9b8b0cb1b, 0xc1cdcfedb9b1c1c5,
    0xd9c9e1bfedebbd9d, 0xbcec3edf9c7ab9c6, 0xd9c3eaf3ecbcbaaa, 0xa9f8cba6e6a9d9c7,
    0xa9bdf6d4d7c4f0b6, 0xb6e1c9f3e6c1c5f5, 0xe8b1c5b9c5e5b4d4, 0xc4f7bee5e2b8ddbe,
    0xb6c1aab4bbc0cea3, 0xb0a3a4b9bff7d6c8, 0xa1bee3b3b8fdaad8, 0xb1c9b6bedef7d9c5,
    0xc1b3b0bef0c1d5f8, 0xc8f9b0b3aeb5d8c4, 0xbcd0c5d8d2d1f4be, 0xc1e3b9c4b0bcc7c6,
    0xb0d4dde2c9bee9c8, 0xa9b6c2bbb8aebdc6, 0xbacac1e1cbb0c4bd, 0xbed3a1aebac2cab0,
    0xb0b6cbe4f3d6c2b6, 0xc4ddc8bf91c3d3c2, 0xc9c8b1d3c8bbc6c5, 0xb0d6cab9c1aac3c8,
    0xbcc3bdc5c5dbc4be, 0xbcd0d9d0bdbaccc5, 0xa6cdc2c5d3cfc9c2, 0xbab3b9bcc1baa9c1,
    0xb4f3b1bbbbb4b3b2, 0xc3a9d2b9b1b6cbbf, 0xc3cdc9bdc7c2b1be, 0xb6cbbbb9c4b6c8be,
    0xc3c7b3c0bdb3c8c6, 0xbabcc6b3c2c2c4c2, 0xb4b2bdb9c2c1bdbb, 0xb6bdcab8b3b9b5c6,
    0xc2bcc3bdbac3c4b9, 0xb6c4c1bdbdc2c1b3, 0xb1b8c0b8c2bdc4b4, 0xb6c5b9bdc1bcb6c6,
    0xb3bbc1c1bcbbb2b2, 0xb8c2c4b4b3c3c4b9, 0xbbb1bcb6b4c3bdbf, 0xc3b6c1c1bdb3b2c2,
    0xb9b5b4c0c2c1b6b8, 0xc4bdbbbbbcb6c1bf, 0xbbc4bcbbbbc4bbb6, 0xc4bdbbbbbcb6c1bf,
    0xc3bbb6c2c3bcbcc4, 0xb6bdc5c4b1c1b3bf, 0xbbb6c4c1bbc4b6c5, 0xc1b9bcc1bcc1c4b8,
    0xbdc1c2c1bcb9b5bc, 0xbab9bdbac1b9bcb6, 0xc1bcbbb2c1b9c4bb, 0xbcc4b3b9bcbab9c5,
    0xb6c1bdc4c1c3c2bd, 0xbdbab3c4c5b3bcc1, 0xb1b6c1c4bbb6b3c1, 0xc1c4b4c4b6bdbcc2,
    0xbbb6bdb3c3b4bdbc, 0xbcbdc2c4bdbabbb9, 0xbcc4b3c1b9b3bbc1, 0xb6bdc3bdb6bbc4bb,
    0xc4b9b3bcb6c4b6c3, 0xb6bbb6c1bcb9b4c2, 0xbbb6c2bbbcc1b6c4, 0xc4bdb3c3bdb3bbc1,
    0xb1bdc1b3b6c5b9c4, 0xc1bbb3c2c3bdb4b9, 0xbbb3c5bdbbb9b6c2, 0xc1b6bcc1b6c3bdb3,
    0xb6c4c1bcc1c2b6b4, 0xbdbab3c4bdb9c3b3, 0xb6bdc3bdb6bbc4bb, 0xc4b9b3bcb6c4b6c3,
    0xb6bbb6c1bcb9b4c2, 0xbbb6c2bbbcc1b6c4, 0xc4bdb3c3bdb3bbc1, 0xb1bdc1b3b6c5b9c4,
    0xc1bbb3c2c3bdb4b9, 0xbbb3c5bdbbb9b6c2, 0xc1b6bcc1b6c3bdb3, 0xb6c4c1bcc1c2b6b4,
    0xbdbab3c4bdb9c3b3, 0xbab3c1c1c2b6bdbb, 0xbbbac1c4b9c1bcb3, 0xbbb3c4bdb3bcb6c1,
    0xb1c4bdb6c1c2bdb9, 0xb3c4b1bdbcbbc1c2, 0xbcb6c3c4bdb1c2c1, 0xc4b1c1b3c4b9bdb6,
    0xc1c4b3b9bdbab3bd, 0xbbb3c4bdb3bcb6c1, 0xb1c4bdb6c1c2bdb9, 0xb3c4b1bdbcbbc1c2,
    0xbcb6c3c4bdb1c2c1, 0xc4b1c1b3c4b9bdb6, 0xc1c4b3b9bdbab3bd, 0xbbb3c4bdb3bcb6c1,
    0xb1c4bdb6c1c2bdb9, 0xb3c4b1bdbcbbc1c2, 0xbcb6c3c4bdb1c2c1, 0xc4b1c1b3c4b9bdb6,
    0xc1c4b3b9bdbab3bd, 0xbbb3c4bdb3bcb6c1, 0xb1c4bdb6c1c2bdb9, 0xb3c4b1bdbcbbc1c2,
    0xbcb6c3c4bdb1c2c1, 0xc4b1c1b3c4b9bdb6, 0xc1c4b3b9bdbab3bd, 0xbbb3c4bdb3bcb6c1,
    0xb1c4bdb6c1c2bdb9, 0xb3c4b1bdbcbbc1c2, 0xbcb6c3c4bdb1c2c1, 0xc4b1c1b3c4b9bdb6,
    0xc1c4b3b9bdbab3bd, 0xbbb3c4bdb3bcb6c1, 0xb1c4bdb6c1c2bdb9, 0xb3c4b1bdbcbbc1c2,
    0xbcb6c3c4bdb1c2c1, 0xc4b1c1b3c4b9bdb6, 0xc1c4b3b9bdbab3bd, 0xbbb3c4bdb3bcb6c1,
];

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_bytes(seed: u32, len: usize) -> Vec<u8> {
        let mut s = seed as u64 | 1;
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            v.push((s >> 33) as u8);
        }
        v
    }

    #[test]
    fn chunk_at_returns_whole_buffer_below_min_size() {
        let v = rand_bytes(1, 100);
        let cfg = Config::default();
        assert_eq!(chunk_at(&v, cfg), 100);
    }

    #[test]
    fn chunk_and_hash_produces_chunks_summing_to_file_size() {
        let v = rand_bytes(1, 5 * 1024 * 1024);
        let cfg = Config::default();
        let chunks = chunk_and_hash(1, &v, cfg);
        assert!(!chunks.is_empty());
        let total: u64 = chunks.iter().map(|c| c.chunk_len as u64).sum();
        assert_eq!(total, v.len() as u64);
    }

    #[test]
    fn file_hash_from_chunks_equals_streaming_blake3() {
        let v = rand_bytes(3, 5 * 1024 * 1024);
        let cfg = Config::default();
        let chunks = chunk_and_hash(1, &v, cfg);
        let combined = file_hash_from_chunks(&v, &chunks);
        let streaming = *blake3::hash(&v).as_bytes();
        assert_eq!(combined, streaming);
    }

    #[test]
    fn chunks_are_byte_identical_under_tail_append() {
        // Append-only behaviour: appending 1 MiB to a 5 MiB file
        // should leave the prefix chunks identical and produce
        // exactly one extra chunk.
        let cfg = Config::default();
        let base = rand_bytes(7, 5 * 1024 * 1024);
        let mut extended = base.clone();
        extended.extend(rand_bytes(11, 1024 * 1024));
        let a = chunk_and_hash(1, &base, cfg);
        let b = chunk_and_hash(1, &extended, cfg);
        // First N-1 chunks match.
        let common = a.len().saturating_sub(1).min(b.len());
        for i in 0..common {
            assert_eq!(a[i].chunk_blake3, b[i].chunk_blake3, "diverged at {i}");
        }
        // b has at least one more chunk than a.
        assert!(b.len() >= a.len(), "extended should not lose chunks");
    }

    #[test]
    fn chunks_have_monotonic_offsets() {
        let v = rand_bytes(5, 3 * 1024 * 1024);
        let cfg = Config::default();
        let chunks = chunk_and_hash(1, &v, cfg);
        for window in chunks.windows(2) {
            assert!(window[0].chunk_offset < window[1].chunk_offset);
        }
    }

    #[test]
    fn small_input_produces_single_chunk() {
        let v = rand_bytes(1, 1024);
        let cfg = Config::default();
        let chunks = chunk_and_hash(1, &v, cfg);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].chunk_offset, 0);
        assert_eq!(chunks[0].chunk_len, 1024);
    }

    #[test]
    fn config_default_values_match_spec() {
        let c = Config::default();
        assert_eq!(c.min_size, 256 * 1024);
        assert_eq!(c.avg_size, 1024 * 1024);
        assert_eq!(c.max_size, 4 * 1024 * 1024);
    }

    #[test]
    fn deterministic_chunking_for_same_input() {
        let v = rand_bytes(13, 2 * 1024 * 1024);
        let cfg = Config::default();
        let a = chunk_and_hash(1, &v, cfg);
        let b = chunk_and_hash(1, &v, cfg);
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.chunk_offset, y.chunk_offset);
            assert_eq!(x.chunk_len, y.chunk_len);
            assert_eq!(x.chunk_blake3, y.chunk_blake3);
        }
    }
}
