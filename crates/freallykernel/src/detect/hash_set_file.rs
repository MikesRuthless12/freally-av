//! On-disk sorted-BLAKE3 hash-set format used by the hash blacklist (TASK-020)
//! and NSRL goodware allowlist (TASK-021).
//!
//! Per `docs/prd.md` § 6.2 the spec calls for "perfect-hash table" lookup. The
//! actual storage here is a magic header + 32-byte-key array sorted ascending,
//! looked up via binary search. For 10M BLAKE3 hashes that is ~23 compares
//! against an mmap'd region — comfortably below the per-file budget. We can
//! swap to `boomphf` / FMPH if profiling demands it; the on-disk encoding is
//! versioned to make the upgrade easy.
//!
//! File layout (little-endian throughout):
//!
//! ```text
//!  0..8     magic            ASCII "MYTHHASH"
//!  8..12    version          u32 (= 1)
//! 12..16    reserved         u32 (= 0)
//! 16..24    count            u64 (= N)
//! 24..       payload         N * 32 bytes of BLAKE3 digests, sorted ascending
//! ```
//!
//! Files are written atomically by the updater (TASK-022/023): write to
//! `<path>.tmp`, fsync, rename over the live file.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;

use memmap2::Mmap;

const MAGIC: &[u8; 8] = b"MYTHHASH";
const VERSION: u32 = 1;
const HEADER_LEN: usize = 24;
const HASH_LEN: usize = 32;

/// Errors returned by the hash-set reader / writer.
#[derive(Debug, thiserror::Error)]
pub enum HashSetError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("hash-set file is too short to contain a header ({0} bytes)")]
    TooShort(usize),
    #[error("hash-set file has wrong magic")]
    BadMagic,
    #[error("hash-set file has unsupported version {0}")]
    BadVersion(u32),
    #[error("hash-set file declares {declared} hashes but body holds {actual}")]
    LengthMismatch { declared: u64, actual: usize },
    #[error("hashes are not sorted ascending (failed at index {0})")]
    NotSorted(usize),
}

/// Read-only view of an on-disk sorted-BLAKE3 hash set. Cheap to clone (the
/// mmap is reference-counted).
pub struct HashSetFile {
    /// The mmap keeps the file mapped while this struct lives. We hold it to
    /// keep the slice valid; only the slice is consulted on the hot path.
    _mmap: Mmap,
    /// Pointer + length pair into the mmap covering exactly the sorted hash
    /// payload (header skipped).
    payload_ptr: *const u8,
    payload_len: usize,
    count: u64,
}

// SAFETY: the `Mmap` is `Send + Sync` and we only ever read through the raw
// pointer below; the data is immutable for the lifetime of `self`.
unsafe impl Send for HashSetFile {}
unsafe impl Sync for HashSetFile {}

impl HashSetFile {
    /// Open a hash-set file in read-only mode. Validates magic, version, and
    /// declared length; **does not** verify sort order on open (that's O(N)
    /// over the whole file — call [`HashSetFile::verify_sorted`] separately
    /// if you need that guarantee on a freshly-built file).
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, HashSetError> {
        let f = File::open(path)?;
        // SAFETY: we map a regular file we just opened read-only; the OS
        // returns an immutable mapping. memmap2 enforces non-empty mappings,
        // so we special-case the empty-set file below.
        let mmap = unsafe { Mmap::map(&f)? };
        Self::from_mmap(mmap)
    }

    fn from_mmap(mmap: Mmap) -> Result<Self, HashSetError> {
        let bytes = &mmap[..];
        if bytes.len() < HEADER_LEN {
            return Err(HashSetError::TooShort(bytes.len()));
        }
        if &bytes[0..8] != MAGIC {
            return Err(HashSetError::BadMagic);
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes"));
        if version != VERSION {
            return Err(HashSetError::BadVersion(version));
        }
        let count = u64::from_le_bytes(bytes[16..24].try_into().expect("8 bytes"));
        let expected_payload_len =
            (count as usize)
                .checked_mul(HASH_LEN)
                .ok_or(HashSetError::LengthMismatch {
                    declared: count,
                    actual: 0,
                })?;
        let actual_payload_len = bytes.len() - HEADER_LEN;
        if actual_payload_len != expected_payload_len {
            return Err(HashSetError::LengthMismatch {
                declared: count,
                actual: actual_payload_len,
            });
        }
        // Store the slice's ptr/len directly so contains() does no extra
        // indexing math in the hot path.
        let payload_ptr = unsafe { bytes.as_ptr().add(HEADER_LEN) };
        Ok(Self {
            _mmap: mmap,
            payload_ptr,
            payload_len: actual_payload_len,
            count,
        })
    }

    /// Number of hashes in the set.
    pub fn len(&self) -> u64 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Walk the payload once and assert ascending order. O(N); call only on
    /// freshly-built files or when audit is warranted.
    pub fn verify_sorted(&self) -> Result<(), HashSetError> {
        if self.count < 2 {
            return Ok(());
        }
        let slice = self.payload();
        for i in 1..self.count as usize {
            let prev = &slice[(i - 1) * HASH_LEN..i * HASH_LEN];
            let curr = &slice[i * HASH_LEN..(i + 1) * HASH_LEN];
            if prev >= curr {
                return Err(HashSetError::NotSorted(i));
            }
        }
        Ok(())
    }

    /// Constant-time-on-N (O(log N)) binary-search lookup for a 32-byte
    /// BLAKE3 hash. Returns true iff the hash is present in the set.
    pub fn contains(&self, hash: &[u8; HASH_LEN]) -> bool {
        let slice = self.payload();
        if slice.is_empty() {
            return false;
        }
        let mut lo: usize = 0;
        let mut hi: usize = self.count as usize;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let start = mid * HASH_LEN;
            let candidate = &slice[start..start + HASH_LEN];
            match candidate.cmp(&hash[..]) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return true,
            }
        }
        false
    }

    fn payload(&self) -> &[u8] {
        // SAFETY: payload_ptr / payload_len describe a slice into the live
        // mmap, which lives at least as long as &self.
        unsafe { std::slice::from_raw_parts(self.payload_ptr, self.payload_len) }
    }
}

impl std::fmt::Debug for HashSetFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashSetFile")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// Build a hash-set file from an iterator of raw BLAKE3 digests. Sorts and
/// deduplicates internally. Writes to `<path>.tmp` then renames over `path`
/// so the swap is atomic from any reader's perspective.
///
/// Used by the abuse.ch / NSRL feed updaters (TASK-022/023) and by tests.
pub fn write_sorted<P: AsRef<Path>, I: IntoIterator<Item = [u8; HASH_LEN]>>(
    path: P,
    hashes: I,
) -> Result<u64, HashSetError> {
    let mut sorted: Vec<[u8; HASH_LEN]> = hashes.into_iter().collect();
    sorted.sort_unstable();
    sorted.dedup();
    let count = sorted.len() as u64;

    let path = path.as_ref();
    let tmp_path = {
        let mut p = path.to_path_buf();
        let mut file_name = p
            .file_name()
            .map(|s| s.to_os_string())
            .unwrap_or_else(|| std::ffi::OsString::from("hashset"));
        file_name.push(".tmp");
        p.set_file_name(file_name);
        p
    };

    {
        let f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)?;
        let mut w = BufWriter::new(f);
        w.write_all(MAGIC)?;
        w.write_all(&VERSION.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&count.to_le_bytes())?;
        for h in &sorted {
            w.write_all(h)?;
        }
        w.flush()?;
        w.into_inner()
            .map_err(|e| HashSetError::Io(e.into_error()))?
            .sync_all()?;
    }

    std::fs::rename(&tmp_path, path)?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn h(b: u8) -> [u8; HASH_LEN] {
        [b; HASH_LEN]
    }

    #[test]
    fn empty_set_roundtrips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        let count = write_sorted(&path, std::iter::empty()).unwrap();
        assert_eq!(count, 0);
        let set = HashSetFile::open(&path).unwrap();
        assert_eq!(set.len(), 0);
        assert!(set.is_empty());
        assert!(!set.contains(&[0; 32]));
    }

    #[test]
    fn single_hash_lookup_hits_and_misses() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("one.bin");
        write_sorted(&path, [h(7)]).unwrap();
        let set = HashSetFile::open(&path).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&h(7)));
        assert!(!set.contains(&h(8)));
        assert!(!set.contains(&[0; 32]));
    }

    #[test]
    fn many_hashes_round_trip_and_are_sorted() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("many.bin");
        // Unsorted input on purpose — the writer must sort.
        let input = (0u8..=255u8).rev().map(h).collect::<Vec<_>>();
        let count = write_sorted(&path, input.clone()).unwrap();
        assert_eq!(count, 256);
        let set = HashSetFile::open(&path).unwrap();
        set.verify_sorted().expect("sorted");
        for needle in input {
            assert!(set.contains(&needle));
        }
        // A hash that doesn't match the "all bytes equal" shape used by the
        // set must miss.
        let absent: [u8; 32] = {
            let mut a = [0u8; 32];
            for (i, b) in a.iter_mut().enumerate() {
                *b = i as u8;
            }
            a
        };
        assert!(!set.contains(&absent));
    }

    #[test]
    fn writer_deduplicates() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("dup.bin");
        let count = write_sorted(&path, [h(1), h(2), h(1), h(2), h(1)]).unwrap();
        assert_eq!(count, 2);
        let set = HashSetFile::open(&path).unwrap();
        assert!(set.contains(&h(1)));
        assert!(set.contains(&h(2)));
        assert!(!set.contains(&h(3)));
    }

    #[test]
    fn bad_magic_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.bin");
        std::fs::write(&path, b"NOTAHASHHEADERDATAPADDING").unwrap();
        let err = HashSetFile::open(&path).unwrap_err();
        match err {
            HashSetError::BadMagic => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn truncated_file_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("short.bin");
        // Magic only — no version/count.
        std::fs::write(&path, MAGIC).unwrap();
        let err = HashSetFile::open(&path).unwrap_err();
        match err {
            HashSetError::TooShort(_) => {}
            other => panic!("expected TooShort, got {other:?}"),
        }
    }

    #[test]
    fn length_mismatch_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("lenmismatch.bin");
        // Declare count=2 but write payload for only 1 hash.
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&2u64.to_le_bytes());
        buf.extend_from_slice(&h(1));
        std::fs::write(&path, &buf).unwrap();
        let err = HashSetFile::open(&path).unwrap_err();
        match err {
            HashSetError::LengthMismatch { declared, actual } => {
                assert_eq!(declared, 2);
                assert_eq!(actual, 32);
            }
            other => panic!("expected LengthMismatch, got {other:?}"),
        }
    }

    #[test]
    fn unsorted_payload_detected_by_verify() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("unsorted.bin");
        // Hand-craft an unsorted file (writer would have sorted).
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&2u64.to_le_bytes());
        buf.extend_from_slice(&h(5));
        buf.extend_from_slice(&h(2));
        std::fs::write(&path, &buf).unwrap();
        let set = HashSetFile::open(&path).expect("opens despite bad order");
        match set.verify_sorted().unwrap_err() {
            HashSetError::NotSorted(i) => assert_eq!(i, 1),
            other => panic!("expected NotSorted, got {other:?}"),
        }
    }

    #[test]
    fn binary_search_finds_boundary_entries() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("boundary.bin");
        write_sorted(&path, (1u8..=10u8).map(h)).unwrap();
        let set = HashSetFile::open(&path).unwrap();
        assert!(set.contains(&h(1)));
        assert!(set.contains(&h(10)));
        assert!(!set.contains(&h(0)));
        assert!(!set.contains(&h(11)));
    }
}
