//! On-disk sorted-CRC32 hash-set format — the fast pre-screen artifact
//! that pairs with the existing 32-byte BLAKE3 set in
//! [`super::hash_set_file`].
//!
//! The feed-builder produces `crc32_blacklist.bin` alongside
//! `blake3_blacklist.bin`. Both cover the same set of malicious
//! samples; CRC32 is a cheap fingerprint (4 bytes, hardware-accelerated
//! on every x86 since Nehalem and on every ARMv8 with the CRC32
//! extension), used as a fast filter before the BLAKE3 confirmation
//! step. ~1 in 4,300 random clean files will collide with a malware
//! CRC32 (1M-sample set ÷ 2^32 keyspace) — those false positives get
//! caught by the subsequent BLAKE3 lookup.
//!
//! File layout (little-endian throughout):
//!
//! ```text
//!  0..8     magic            ASCII "MYTHCRC3"
//!  8..12    version          u32 (= 1)
//! 12..16    reserved         u32 (= 0)
//! 16..24    count            u64 (= N)
//! 24..      payload         N * 4 bytes of u32 CRC32 values, sorted ascending
//! ```
//!
//! Files are written atomically by the feed-builder export step: write
//! to `<path>.tmp`, fsync, rename over the live file.
//!
//! The format intentionally mirrors `MYTHHASH` so the loaders share
//! structure but the magic differs so a caller can never accidentally
//! mmap a CRC32 set as a BLAKE3 set or vice versa.

use std::fs::File;
use std::io;
use std::path::Path;

use memmap2::Mmap;

const MAGIC: &[u8; 8] = b"MYTHCRC3";
const VERSION: u32 = 1;
const HEADER_LEN: usize = 24;
const CRC32_LEN: usize = 4;

/// Errors returned by the CRC32-set reader.
#[derive(Debug, thiserror::Error)]
pub enum Crc32SetError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("crc32-set file is too short to contain a header ({0} bytes)")]
    TooShort(usize),
    #[error("crc32-set file has wrong magic")]
    BadMagic,
    #[error("crc32-set file has unsupported version {0}")]
    BadVersion(u32),
    #[error("crc32-set file declares {declared} entries but body holds {actual} bytes")]
    LengthMismatch { declared: u64, actual: usize },
    #[error("crc32 values are not sorted ascending (failed at index {0})")]
    NotSorted(usize),
}

/// Read-only view of an on-disk sorted-CRC32 set. Cheap to clone (the
/// mmap is reference-counted).
pub struct Crc32SetFile {
    _mmap: Mmap,
    payload_ptr: *const u8,
    payload_len: usize,
    count: u64,
}

// SAFETY: the `Mmap` is `Send + Sync`; we only ever read through the raw
// pointer below; the data is immutable for the lifetime of `self`.
unsafe impl Send for Crc32SetFile {}
unsafe impl Sync for Crc32SetFile {}

impl Crc32SetFile {
    /// Open a CRC32-set file in read-only mode. Validates magic,
    /// version, and declared length; does **not** verify sort order on
    /// open (O(N) — call [`Crc32SetFile::verify_sorted`] if needed on a
    /// freshly-built file).
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Crc32SetError> {
        let f = File::open(path)?;
        // SAFETY: regular file just opened read-only; the OS returns an
        // immutable mapping.
        let mmap = unsafe { Mmap::map(&f)? };
        Self::from_mmap(mmap)
    }

    fn from_mmap(mmap: Mmap) -> Result<Self, Crc32SetError> {
        let bytes = &mmap[..];
        if bytes.len() < HEADER_LEN {
            return Err(Crc32SetError::TooShort(bytes.len()));
        }
        if &bytes[0..8] != MAGIC {
            return Err(Crc32SetError::BadMagic);
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes"));
        if version != VERSION {
            return Err(Crc32SetError::BadVersion(version));
        }
        let count = u64::from_le_bytes(bytes[16..24].try_into().expect("8 bytes"));
        let expected_payload_len =
            (count as usize)
                .checked_mul(CRC32_LEN)
                .ok_or(Crc32SetError::LengthMismatch {
                    declared: count,
                    actual: 0,
                })?;
        let actual_payload_len = bytes.len() - HEADER_LEN;
        if actual_payload_len != expected_payload_len {
            return Err(Crc32SetError::LengthMismatch {
                declared: count,
                actual: actual_payload_len,
            });
        }
        let payload_ptr = unsafe { bytes.as_ptr().add(HEADER_LEN) };
        Ok(Self {
            _mmap: mmap,
            payload_ptr,
            payload_len: actual_payload_len,
            count,
        })
    }

    /// Number of CRC32 entries in the set.
    pub fn len(&self) -> u64 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Walk the payload once and assert ascending numeric order. O(N);
    /// call only on freshly-built files or when audit is warranted.
    pub fn verify_sorted(&self) -> Result<(), Crc32SetError> {
        if self.count < 2 {
            return Ok(());
        }
        let slice = self.payload();
        let mut prev = read_u32_le(&slice[0..CRC32_LEN]);
        for i in 1..self.count as usize {
            let curr = read_u32_le(&slice[i * CRC32_LEN..(i + 1) * CRC32_LEN]);
            if prev >= curr {
                return Err(Crc32SetError::NotSorted(i));
            }
            prev = curr;
        }
        Ok(())
    }

    /// O(log N) binary-search lookup. Returns true iff the CRC32 is
    /// present in the set.
    pub fn contains(&self, crc32: u32) -> bool {
        let slice = self.payload();
        if slice.is_empty() {
            return false;
        }
        let mut lo: usize = 0;
        let mut hi: usize = self.count as usize;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let start = mid * CRC32_LEN;
            let candidate = read_u32_le(&slice[start..start + CRC32_LEN]);
            match candidate.cmp(&crc32) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return true,
            }
        }
        false
    }

    fn payload(&self) -> &[u8] {
        // SAFETY: payload_ptr / payload_len describe a slice into the
        // live mmap, which lives at least as long as &self.
        unsafe { std::slice::from_raw_parts(self.payload_ptr, self.payload_len) }
    }
}

impl std::fmt::Debug for Crc32SetFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Crc32SetFile")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_header_and_values(path: &Path, count: u64, values: &[u32]) {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(MAGIC).unwrap();
        f.write_all(&VERSION.to_le_bytes()).unwrap();
        f.write_all(&0u32.to_le_bytes()).unwrap();
        f.write_all(&count.to_le_bytes()).unwrap();
        for v in values {
            f.write_all(&v.to_le_bytes()).unwrap();
        }
    }

    #[test]
    fn empty_set_roundtrips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        write_header_and_values(&path, 0, &[]);
        let set = Crc32SetFile::open(&path).unwrap();
        assert_eq!(set.len(), 0);
        assert!(set.is_empty());
        assert!(!set.contains(0xdeadbeef));
    }

    #[test]
    fn single_value_lookup_hits_and_misses() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("one.bin");
        write_header_and_values(&path, 1, &[0x1234abcd]);
        let set = Crc32SetFile::open(&path).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(0x1234abcd));
        assert!(!set.contains(0x1234abce));
        assert!(!set.contains(0));
    }

    #[test]
    fn many_values_lookup_and_sort_check() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("many.bin");
        let values: Vec<u32> = (0u32..1000).map(|i| i * 7919).collect();
        write_header_and_values(&path, values.len() as u64, &values);
        let set = Crc32SetFile::open(&path).unwrap();
        set.verify_sorted().expect("sorted");
        for v in &values {
            assert!(set.contains(*v));
        }
        assert!(!set.contains(1));
        assert!(!set.contains(7918));
    }

    #[test]
    fn bad_magic_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.bin");
        std::fs::write(&path, b"NOTACRC3HEADERPADDINGXXX").unwrap();
        let err = Crc32SetFile::open(&path).unwrap_err();
        match err {
            Crc32SetError::BadMagic => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn truncated_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("short.bin");
        std::fs::write(&path, MAGIC).unwrap();
        let err = Crc32SetFile::open(&path).unwrap_err();
        match err {
            Crc32SetError::TooShort(_) => {}
            other => panic!("expected TooShort, got {other:?}"),
        }
    }

    #[test]
    fn length_mismatch_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("lenmismatch.bin");
        // Declare count=3 but write only one value.
        write_header_and_values(&path, 3, &[0xaa]);
        let err = Crc32SetFile::open(&path).unwrap_err();
        match err {
            Crc32SetError::LengthMismatch { declared, actual } => {
                assert_eq!(declared, 3);
                assert_eq!(actual, 4);
            }
            other => panic!("expected LengthMismatch, got {other:?}"),
        }
    }

    #[test]
    fn unsorted_detected_by_verify() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("unsorted.bin");
        write_header_and_values(&path, 2, &[100, 50]);
        let set = Crc32SetFile::open(&path).expect("opens despite bad order");
        match set.verify_sorted().unwrap_err() {
            Crc32SetError::NotSorted(i) => assert_eq!(i, 1),
            other => panic!("expected NotSorted, got {other:?}"),
        }
    }

    #[test]
    fn binary_search_finds_boundary_entries() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("boundary.bin");
        let values: Vec<u32> = (1u32..=10u32).collect();
        write_header_and_values(&path, values.len() as u64, &values);
        let set = Crc32SetFile::open(&path).unwrap();
        assert!(set.contains(1));
        assert!(set.contains(10));
        assert!(!set.contains(0));
        assert!(!set.contains(11));
    }
}
