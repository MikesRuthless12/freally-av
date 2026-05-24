//! TASK-178 — Bloom-filter front-end for the hash blocklist.
//!
//! Sub-microsecond pre-screen consulted *before* the sorted-`.bin`
//! binary search. On a typical scan the vast majority of files are
//! clean — every cache miss into the on-disk sorted set costs ~26
//! compare-load cycles (≈ 2-3 µs) against an mmap'd 120 MB region.
//! Replacing those misses with a single Bloom probe (≤ 1 µs, two
//! u64 loads + k bit checks against an mmap'd bit array) collapses
//! per-file blacklist-check wall-time roughly an order of magnitude
//! on the hot path.
//!
//! ## On-disk format
//!
//! ```text
//!  0..8     magic        ASCII "MYTHBLOM"
//!  8..12    version      u32 LE (= 1)
//! 12..16    reserved     u32 LE (= 0)
//! 16..24    epoch_id     u64 LE — must match the consuming export epoch
//! 24..32    n_items      u64 LE — number of items expected to be inserted
//! 32..36    fpr_ppm      u32 LE — target false-positive rate in parts-per-million
//! 36..40    k_hashes     u32 LE — number of hash positions per item
//! 40..48    m_bits       u64 LE — total bit positions in the filter
//! 48..56    built_at     i64 LE — unix timestamp of the build
//! 56..72    reserved2    16 bytes (padded for future fields)
//! 72..N     payload      ceil(m_bits / 8) bytes — the bit array
//! ```
//!
//! ## Hashing
//!
//! We **do not** add a separate SipHash dependency. The blacklist
//! keys are already SHA-256 / BLAKE3 digests (cryptographically
//! uniform); we extract two independent u64 slices from the digest
//! and compose k bit positions via Kirsch-Mitzenmacher double
//! hashing:
//!
//! ```text
//!   bit_i = (h1.wrapping_add(i × h2)) mod m_bits
//! ```
//!
//! Kirsch & Mitzenmacher (2006) prove this gives equivalent FPR to
//! k independent hash functions at the cost of one extra wrap-add
//! per position — strictly better than paying for a SipHash crate.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use memmap2::Mmap;

const MAGIC: &[u8; 8] = b"MYTHBLOM";
const VERSION: u32 = 1;
const HEADER_LEN: usize = 72;

#[derive(Debug, thiserror::Error)]
pub enum BloomError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("bloom file is too short to contain a header ({0} bytes)")]
    TooShort(usize),
    #[error("bloom file has wrong magic")]
    BadMagic,
    #[error("bloom file has unsupported version {0}")]
    BadVersion(u32),
    #[error(
        "bloom file declares m_bits={declared_bits} (≈ {declared_bytes} bytes) but payload holds {actual_payload_bytes} bytes"
    )]
    LengthMismatch {
        declared_bits: u64,
        declared_bytes: u64,
        actual_payload_bytes: usize,
    },
    #[error(
        "bloom epoch mismatch: file says {file_epoch}, caller asked for {wanted_epoch}"
    )]
    EpochMismatch { file_epoch: u64, wanted_epoch: u64 },
    #[error("bloom filter input digest must be at least 16 bytes, got {0}")]
    DigestTooShort(usize),
}

/// Read-only view of an on-disk Bloom filter. Cheap to clone — the
/// mmap is reference-counted via the underlying `Mmap`.
#[derive(Debug)]
pub struct BloomFile {
    _mmap: Mmap,
    payload_ptr: *const u8,
    payload_len_bytes: usize,
    epoch_id: u64,
    n_items: u64,
    fpr_ppm: u32,
    k_hashes: u32,
    m_bits: u64,
    built_at: i64,
}

// SAFETY: the `Mmap` is `Send + Sync` and we only read through the
// raw pointer below; the data is immutable for the lifetime of `self`.
unsafe impl Send for BloomFile {}
unsafe impl Sync for BloomFile {}

impl BloomFile {
    /// Open and validate a Bloom file. `expected_epoch` lets the
    /// caller enforce that the filter matches the same export epoch
    /// the rest of the artifacts came from — pass `None` to skip the
    /// epoch check (forensic / debugging only).
    pub fn open<P: AsRef<Path>>(
        path: P,
        expected_epoch: Option<u64>,
    ) -> Result<Self, BloomError> {
        let f = File::open(path)?;
        // SAFETY: we map a regular file we just opened read-only; the
        // OS returns an immutable mapping.
        let mmap = unsafe { Mmap::map(&f)? };
        Self::from_mmap(mmap, expected_epoch)
    }

    fn from_mmap(mmap: Mmap, expected_epoch: Option<u64>) -> Result<Self, BloomError> {
        let bytes = &mmap[..];
        if bytes.len() < HEADER_LEN {
            return Err(BloomError::TooShort(bytes.len()));
        }
        if &bytes[0..8] != MAGIC {
            return Err(BloomError::BadMagic);
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes"));
        if version != VERSION {
            return Err(BloomError::BadVersion(version));
        }
        let epoch_id = u64::from_le_bytes(bytes[16..24].try_into().expect("8 bytes"));
        let n_items = u64::from_le_bytes(bytes[24..32].try_into().expect("8 bytes"));
        let fpr_ppm = u32::from_le_bytes(bytes[32..36].try_into().expect("4 bytes"));
        let k_hashes = u32::from_le_bytes(bytes[36..40].try_into().expect("4 bytes"));
        let m_bits = u64::from_le_bytes(bytes[40..48].try_into().expect("8 bytes"));
        let built_at = i64::from_le_bytes(bytes[48..56].try_into().expect("8 bytes"));

        if let Some(want) = expected_epoch {
            if epoch_id != want {
                return Err(BloomError::EpochMismatch {
                    file_epoch: epoch_id,
                    wanted_epoch: want,
                });
            }
        }

        let expected_payload_bytes = m_bits.div_ceil(8) as usize;
        let payload_len_bytes = bytes.len() - HEADER_LEN;
        if payload_len_bytes != expected_payload_bytes {
            return Err(BloomError::LengthMismatch {
                declared_bits: m_bits,
                declared_bytes: expected_payload_bytes as u64,
                actual_payload_bytes: payload_len_bytes,
            });
        }

        let payload_ptr = unsafe { bytes.as_ptr().add(HEADER_LEN) };

        Ok(Self {
            _mmap: mmap,
            payload_ptr,
            payload_len_bytes,
            epoch_id,
            n_items,
            fpr_ppm,
            k_hashes,
            m_bits,
            built_at,
        })
    }

    pub fn epoch_id(&self) -> u64 {
        self.epoch_id
    }
    pub fn n_items(&self) -> u64 {
        self.n_items
    }
    pub fn fpr_ppm(&self) -> u32 {
        self.fpr_ppm
    }
    pub fn k_hashes(&self) -> u32 {
        self.k_hashes
    }
    pub fn m_bits(&self) -> u64 {
        self.m_bits
    }
    pub fn built_at_unix(&self) -> i64 {
        self.built_at
    }
    pub fn payload_bytes(&self) -> u64 {
        self.payload_len_bytes as u64
    }

    /// Probe the filter. Returns `true` on "possibly in set"
    /// (proceed to the sorted-bin lookup) and `false` on "definitely
    /// not in set" (skip the on-disk binary search entirely).
    ///
    /// `digest` is the raw bytes of the key — typically a 32-byte
    /// SHA-256 or BLAKE3. We require at least 16 bytes so we can
    /// extract two u64 slices for the double-hash decomposition.
    pub fn contains(&self, digest: &[u8]) -> Result<bool, BloomError> {
        if digest.len() < 16 {
            return Err(BloomError::DigestTooShort(digest.len()));
        }
        if self.m_bits == 0 {
            // Empty / degenerate filter — accept nothing.
            return Ok(false);
        }
        let (h1, h2) = split_digest(digest);
        let m = self.m_bits;
        for i in 0..self.k_hashes {
            let pos = h1.wrapping_add((i as u64).wrapping_mul(h2)) % m;
            if !self.bit_is_set(pos) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn bit_is_set(&self, pos: u64) -> bool {
        let byte_idx = (pos / 8) as usize;
        let bit_idx = (pos % 8) as u8;
        // SAFETY: `pos < self.m_bits` and `self.payload_len_bytes ==
        // ceil(m_bits / 8)`, so byte_idx is in-range.
        debug_assert!(byte_idx < self.payload_len_bytes);
        let byte = unsafe { *self.payload_ptr.add(byte_idx) };
        (byte & (1u8 << bit_idx)) != 0
    }
}

/// Builder for offline construction (called by the feed-builder
/// export pipeline). Allocate the bit array in RAM, INSERT every
/// digest, then [`Builder::write_to`] the file.
pub struct Builder {
    epoch_id: u64,
    n_items: u64,
    fpr_ppm: u32,
    k_hashes: u32,
    m_bits: u64,
    bits: Vec<u8>,
}

impl Builder {
    /// Create a new builder sized for `expected_items` at target
    /// `fpr_ppm` (parts-per-million; pass `10_000` for 1%).
    pub fn new(expected_items: u64, fpr_ppm: u32, epoch_id: u64) -> Self {
        let (m_bits, k_hashes) = optimal_params(expected_items, fpr_ppm);
        let m_bytes = m_bits.div_ceil(8) as usize;
        Self {
            epoch_id,
            n_items: expected_items,
            fpr_ppm,
            k_hashes,
            m_bits,
            bits: vec![0u8; m_bytes],
        }
    }

    pub fn insert(&mut self, digest: &[u8]) {
        assert!(digest.len() >= 16, "digest must be ≥ 16 bytes");
        if self.m_bits == 0 {
            return;
        }
        let (h1, h2) = split_digest(digest);
        let m = self.m_bits;
        for i in 0..self.k_hashes {
            let pos = h1.wrapping_add((i as u64).wrapping_mul(h2)) % m;
            let byte_idx = (pos / 8) as usize;
            let bit_idx = (pos % 8) as u8;
            self.bits[byte_idx] |= 1u8 << bit_idx;
        }
    }

    pub fn m_bits(&self) -> u64 {
        self.m_bits
    }
    pub fn k_hashes(&self) -> u32 {
        self.k_hashes
    }

    /// Write the filter to `path` atomically (`<path>.tmp` + rename).
    pub fn write_to<P: AsRef<Path>>(&self, path: P) -> Result<(), BloomError> {
        let final_path = path.as_ref();
        let tmp_path = final_path.with_extension({
            let ext = final_path.extension().and_then(|s| s.to_str()).unwrap_or("bloom");
            format!("{ext}.tmp")
        });
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let f = File::create(&tmp_path)?;
        let mut w = BufWriter::new(f);
        w.write_all(MAGIC)?;
        w.write_all(&VERSION.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?; // reserved
        w.write_all(&self.epoch_id.to_le_bytes())?;
        w.write_all(&self.n_items.to_le_bytes())?;
        w.write_all(&self.fpr_ppm.to_le_bytes())?;
        w.write_all(&self.k_hashes.to_le_bytes())?;
        w.write_all(&self.m_bits.to_le_bytes())?;
        w.write_all(&now.to_le_bytes())?;
        w.write_all(&[0u8; 16])?; // reserved2
        w.write_all(&self.bits)?;
        w.flush()?;
        w.into_inner()
            .map_err(|e| BloomError::Io(io::Error::other(format!("flush bloom: {}", e.error()))))?
            .sync_all()?;
        std::fs::rename(&tmp_path, final_path)?;
        Ok(())
    }
}

fn split_digest(digest: &[u8]) -> (u64, u64) {
    let h1 = u64::from_le_bytes(digest[0..8].try_into().expect("≥ 16 bytes"));
    let h2 = u64::from_le_bytes(digest[8..16].try_into().expect("≥ 16 bytes"));
    // Guard: if h2 happens to be zero, every position collapses to
    // h1 (one bit). Coerce to 1 — sacrifices one bit of entropy on
    // a 2^-64 event, never silently kills FPR.
    (h1, if h2 == 0 { 1 } else { h2 })
}

/// Solve for `(m, k)` given `n` expected items and target false-
/// positive rate. Standard Bloom-filter sizing:
///   `m = -n × ln(p) / (ln 2)^2`
///   `k = (m / n) × ln 2`
pub fn optimal_params(n_items: u64, fpr_ppm: u32) -> (u64, u32) {
    if n_items == 0 || fpr_ppm == 0 {
        return (0, 0);
    }
    let p = (fpr_ppm as f64) / 1_000_000.0;
    let ln2 = std::f64::consts::LN_2;
    let m = -(n_items as f64) * p.ln() / (ln2 * ln2);
    let k = (m / n_items as f64) * ln2;
    let m_bits = m.ceil().max(8.0) as u64;
    let k_hashes = k.round().max(1.0) as u32;
    (m_bits, k_hashes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn mk_digest(seed: u8) -> [u8; 32] {
        let mut d = [0u8; 32];
        for i in 0..32 {
            d[i] = seed.wrapping_add(i as u8).wrapping_mul(31);
        }
        d
    }

    #[test]
    fn optimal_params_sane() {
        // 1% FPR / 100M items → ~960M bits / k=7.
        let (m, k) = optimal_params(100_000_000, 10_000);
        let m_mb = m / 8 / 1_048_576;
        assert!(m_mb > 100 && m_mb < 150, "expected ~120 MB, got {m_mb} MB");
        assert!(k >= 6 && k <= 8, "expected k≈7, got {k}");

        // 1% FPR / 1k items → ~10k bits / k=7.
        let (m_small, k_small) = optimal_params(1_000, 10_000);
        assert!(m_small < 20_000);
        assert_eq!(k_small, 7);

        // Degenerate.
        assert_eq!(optimal_params(0, 10_000), (0, 0));
        assert_eq!(optimal_params(100, 0), (0, 0));
    }

    #[test]
    fn build_probe_roundtrip_small() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("small.bloom");

        let mut b = Builder::new(1000, 10_000, 0xdeadbeef);
        let inserted: Vec<[u8; 32]> = (0u8..200).map(mk_digest).collect();
        for d in &inserted {
            b.insert(d);
        }
        b.write_to(&path).unwrap();

        let f = BloomFile::open(&path, Some(0xdeadbeef)).unwrap();
        for d in &inserted {
            assert!(f.contains(d).unwrap(), "expected hit for inserted digest");
        }
    }

    /// Hash `seed` through SHA-256 so the resulting digest has the
    /// full-entropy 32-byte profile of a real production key. The
    /// Bloom's double-hashing decomposition relies on h2 being a
    /// uniformly random u64 — a synthetic digest like
    /// `[i, 0, 0, 0, 0, ...]` would give h2 = 0 and collapse the
    /// probe positions into dense linear runs, blowing the FPR.
    fn sha256_seed(seed: u32) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(seed.to_le_bytes());
        h.finalize().into()
    }

    #[test]
    fn probe_rejects_most_random_misses() {
        // 1% FPR target on 5k items. Build with 5k inserts, probe
        // 50k randoms, assert no more than ~2.5% false-positive rate
        // (looser than the 1% theoretical bound to absorb sample
        // variance; this also caught a real bug where degenerate
        // synthetic digests collapsed the double-hashing).
        let td = TempDir::new().unwrap();
        let path = td.path().join("fpr.bloom");
        let mut b = Builder::new(5_000, 10_000, 1);
        for i in 0u32..5_000 {
            b.insert(&sha256_seed(i));
        }
        b.write_to(&path).unwrap();
        let f = BloomFile::open(&path, None).unwrap();

        let probes = 50_000u32;
        let mut false_positives = 0;
        for i in 0..probes {
            // Different keyspace so probe digests can't collide
            // with inserted ones (the SHA-256 inputs are disjoint).
            if f.contains(&sha256_seed(i + 100_000_000)).unwrap() {
                false_positives += 1;
            }
        }
        let rate = (false_positives as f64) / (probes as f64);
        assert!(
            rate < 0.025,
            "FPR {rate:.4} above 2.5% guard rail ({false_positives}/{probes})"
        );
    }

    #[test]
    fn empty_filter_rejects_everything() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("empty.bloom");
        let b = Builder::new(1000, 10_000, 99);
        b.write_to(&path).unwrap();
        let f = BloomFile::open(&path, Some(99)).unwrap();
        for seed in 0u8..50 {
            assert!(!f.contains(&mk_digest(seed)).unwrap());
        }
    }

    #[test]
    fn epoch_mismatch_rejects_open() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("epoch.bloom");
        let mut b = Builder::new(100, 10_000, 42);
        b.insert(&mk_digest(7));
        b.write_to(&path).unwrap();

        let err = BloomFile::open(&path, Some(43)).unwrap_err();
        assert!(matches!(
            err,
            BloomError::EpochMismatch { file_epoch: 42, wanted_epoch: 43 }
        ));

        // Open with the right epoch works.
        let f = BloomFile::open(&path, Some(42)).unwrap();
        assert_eq!(f.epoch_id(), 42);
    }

    #[test]
    fn bad_magic_rejected() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("bad.bloom");
        // Write a header with the wrong magic.
        std::fs::write(&path, b"NOPENOPE\x01\x00\x00\x00\x00\x00\x00\x00").unwrap();
        // Pad to header length.
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[0u8; HEADER_LEN - 16]).unwrap();
        drop(f);
        let err = BloomFile::open(&path, None).unwrap_err();
        assert!(matches!(err, BloomError::BadMagic));
    }

    #[test]
    fn truncated_file_rejected() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("short.bloom");
        std::fs::write(&path, b"MYTHBLOM").unwrap(); // only magic, no rest
        let err = BloomFile::open(&path, None).unwrap_err();
        assert!(matches!(err, BloomError::TooShort(8)));
    }

    #[test]
    fn length_mismatch_rejected() {
        // Build a valid filter, then truncate the payload by 1 byte.
        let td = TempDir::new().unwrap();
        let path = td.path().join("trunc.bloom");
        let mut b = Builder::new(50, 10_000, 1);
        b.insert(&mk_digest(0));
        b.write_to(&path).unwrap();
        let len = std::fs::metadata(&path).unwrap().len();
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(len - 1).unwrap();
        let err = BloomFile::open(&path, None).unwrap_err();
        assert!(matches!(err, BloomError::LengthMismatch { .. }));
    }

    #[test]
    fn digest_too_short_rejected() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("ok.bloom");
        let mut b = Builder::new(50, 10_000, 1);
        b.insert(&mk_digest(0));
        b.write_to(&path).unwrap();
        let f = BloomFile::open(&path, None).unwrap();
        let short = [0u8; 8];
        let err = f.contains(&short).unwrap_err();
        assert!(matches!(err, BloomError::DigestTooShort(8)));
    }
}
