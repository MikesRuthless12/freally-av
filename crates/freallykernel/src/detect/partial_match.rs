//! TASK-180 — Partial-match index for big files (≥ 256 MB).
//!
//! On cold scans across media disks (ISOs, VM images, archives), a
//! single multi-GB blob costs O(file size) to BLAKE3 + SHA-256 before
//! we know whether to bother. Most of those blobs are benign — the
//! full hash is wasted I/O.
//!
//! The partial-match path computes a cheap fingerprint over just the
//! first 8 MB of the file plus the file's size bucketed to the
//! nearest 64 MB. If that `(prefix_blake3, size_band)` tuple isn't
//! in the partial-match index, we know the full file *can't* be a
//! known-malicious match (because if it were, the maintainer's build
//! pipeline would have included its prefix in the index — the build
//! always derives the partial fingerprint from the same prefix and
//! the same size bucket). On a hit, we fall through to the full
//! hash to confirm the match (rare; ~1-in-many-thousands).
//!
//! ## On-disk format
//!
//! Sorted fixed-stride array, binary-searchable via mmap:
//!
//! ```text
//!  0..8     magic        ASCII "MYTHPMI1"
//!  8..12    version      u32 LE (= 1)
//! 12..16    reserved     u32 LE (= 0)
//! 16..24    epoch_id     u64 LE
//! 24..32    count        u64 LE — number of (prefix, size_band) entries
//! 32..40    built_at     i64 LE
//! 40..56    reserved2    16 bytes
//! 56..N     payload      count × (32-byte prefix_blake3 || 8-byte size_band LE)
//! ```
//!
//! Sort key is the full 40-byte row (prefix major, size_band minor)
//! ascending. Binary search compares the row prefix first; on prefix
//! tie, the size_band differentiates the bucket.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use memmap2::Mmap;

const MAGIC: &[u8; 8] = b"MYTHPMI1";
const VERSION: u32 = 1;
const HEADER_LEN: usize = 56;
const ROW_LEN: usize = 40; // 32 (prefix) + 8 (size_band)

/// Files smaller than this don't participate in the partial-match
/// fast path — for small files the full hash is faster than the
/// prefix + lookup overhead. Per TASK-180 spec.
pub const PARTIAL_MATCH_MIN_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Prefix-hash window. 8 MB matches the spec; a single sequential
/// read on NVMe completes in ~20-30 ms.
pub const PREFIX_WINDOW_BYTES: u64 = 8 * 1024 * 1024;

/// Size band granularity — 64 MB. Each file rounds to the nearest
/// multiple of 64 MB. A 1 GB file lands in the 1024 MB band; a
/// 1.03 GB file also lands in the 1024 MB band.
pub const SIZE_BAND_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PartialMatchError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("partial-match file is too short to contain a header ({0} bytes)")]
    TooShort(usize),
    #[error("partial-match file has wrong magic")]
    BadMagic,
    #[error("partial-match file has unsupported version {0}")]
    BadVersion(u32),
    #[error(
        "partial-match file declares {declared} rows ({declared_bytes} bytes) but payload holds {actual_bytes} bytes"
    )]
    LengthMismatch {
        declared: u64,
        declared_bytes: u64,
        actual_bytes: usize,
    },
    #[error("rows are not sorted ascending (failed at row {0})")]
    NotSorted(usize),
    #[error("partial-match epoch mismatch: file says {file_epoch}, caller wants {wanted_epoch}")]
    EpochMismatch { file_epoch: u64, wanted_epoch: u64 },
}

/// Round `file_size` down to the nearest multiple of [`SIZE_BAND_BYTES`].
/// Returns 0 for files smaller than one band, which is fine — the
/// caller already short-circuits files below [`PARTIAL_MATCH_MIN_FILE_BYTES`]
/// so size-0 rows never appear in practice.
pub fn size_band(file_size: u64) -> u64 {
    (file_size / SIZE_BAND_BYTES) * SIZE_BAND_BYTES
}

/// Compute the partial-match fingerprint for a candidate file at
/// `path`. Streams the first [`PREFIX_WINDOW_BYTES`] through a
/// BLAKE3 hasher; returns `None` when the file is smaller than the
/// minimum (caller should skip the partial path entirely).
///
/// The returned tuple is what the [`PartialMatchIndex::contains`]
/// path consumes; the build pipeline emits the same tuple for every
/// gold-tier sample whose `size_bytes ≥ PARTIAL_MATCH_MIN_FILE_BYTES`.
pub fn compute_fingerprint(path: &Path) -> Result<Option<PartialFingerprint>, io::Error> {
    let mut f = File::open(path)?;
    let file_size = f.metadata()?.len();
    if file_size < PARTIAL_MATCH_MIN_FILE_BYTES {
        return Ok(None);
    }
    let mut hasher = blake3::Hasher::new();
    let mut remaining = PREFIX_WINDOW_BYTES;
    let mut buf = [0u8; 64 * 1024];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = f.read(&mut buf[..want])?;
        if n == 0 {
            // Short read — file shrank between metadata() and now;
            // fold what we have and stop.
            break;
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    let prefix: [u8; 32] = hasher.finalize().into();
    Ok(Some(PartialFingerprint {
        prefix_blake3: prefix,
        size_band: size_band(file_size),
    }))
}

/// Pair of (prefix_blake3, size_band) — the partial-match probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartialFingerprint {
    pub prefix_blake3: [u8; 32],
    pub size_band: u64,
}

impl PartialFingerprint {
    fn to_row(self) -> [u8; ROW_LEN] {
        let mut row = [0u8; ROW_LEN];
        row[0..32].copy_from_slice(&self.prefix_blake3);
        row[32..40].copy_from_slice(&self.size_band.to_le_bytes());
        row
    }
}

/// Read-only view of an on-disk partial-match index.
#[derive(Debug)]
pub struct PartialMatchIndex {
    _mmap: Mmap,
    payload_ptr: *const u8,
    count: u64,
    epoch_id: u64,
    built_at: i64,
}

// SAFETY: `Mmap` is `Send + Sync`; we only read through the raw
// pointer below; data is immutable for the lifetime of `self`.
unsafe impl Send for PartialMatchIndex {}
unsafe impl Sync for PartialMatchIndex {}

impl PartialMatchIndex {
    pub fn open<P: AsRef<Path>>(
        path: P,
        expected_epoch: Option<u64>,
    ) -> Result<Self, PartialMatchError> {
        let f = File::open(path)?;
        let mmap = unsafe { Mmap::map(&f)? };
        Self::from_mmap(mmap, expected_epoch)
    }

    fn from_mmap(mmap: Mmap, expected_epoch: Option<u64>) -> Result<Self, PartialMatchError> {
        let bytes = &mmap[..];
        if bytes.len() < HEADER_LEN {
            return Err(PartialMatchError::TooShort(bytes.len()));
        }
        if &bytes[0..8] != MAGIC {
            return Err(PartialMatchError::BadMagic);
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes"));
        if version != VERSION {
            return Err(PartialMatchError::BadVersion(version));
        }
        let epoch_id = u64::from_le_bytes(bytes[16..24].try_into().expect("8 bytes"));
        let count = u64::from_le_bytes(bytes[24..32].try_into().expect("8 bytes"));
        let built_at = i64::from_le_bytes(bytes[32..40].try_into().expect("8 bytes"));

        if let Some(want) = expected_epoch
            && epoch_id != want
        {
            return Err(PartialMatchError::EpochMismatch {
                file_epoch: epoch_id,
                wanted_epoch: want,
            });
        }

        let declared_bytes = count.saturating_mul(ROW_LEN as u64);
        let actual_bytes = bytes.len() - HEADER_LEN;
        if actual_bytes as u64 != declared_bytes {
            return Err(PartialMatchError::LengthMismatch {
                declared: count,
                declared_bytes,
                actual_bytes,
            });
        }

        let payload_ptr = unsafe { bytes.as_ptr().add(HEADER_LEN) };
        Ok(Self {
            _mmap: mmap,
            payload_ptr,
            count,
            epoch_id,
            built_at,
        })
    }

    pub fn epoch_id(&self) -> u64 {
        self.epoch_id
    }
    pub fn built_at_unix(&self) -> i64 {
        self.built_at
    }
    pub fn len(&self) -> u64 {
        self.count
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Verify the on-disk rows are sorted ascending. O(N) — not called
    /// on the hot path; the build pipeline writes sorted-already and
    /// the load-time `LengthMismatch` is the typical integrity check.
    /// Operators can call this once after a fresh deploy.
    pub fn verify_sorted(&self) -> Result<(), PartialMatchError> {
        for i in 1..self.count {
            let prev = self.row(i - 1);
            let cur = self.row(i);
            if cur < prev {
                return Err(PartialMatchError::NotSorted(i as usize));
            }
        }
        Ok(())
    }

    /// Lookup. Returns `true` when the (prefix, size_band) tuple is
    /// in the index (proceed to full-hash confirmation). Returns
    /// `false` otherwise (no possible partial match — caller can
    /// skip the rest of the detection pipeline for this file).
    pub fn contains(&self, fp: &PartialFingerprint) -> bool {
        if self.count == 0 {
            return false;
        }
        let target = fp.to_row();
        let mut lo = 0u64;
        let mut hi = self.count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let row = self.row(mid);
            match row.cmp(&target) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return true,
            }
        }
        false
    }

    fn row(&self, idx: u64) -> [u8; ROW_LEN] {
        debug_assert!(idx < self.count);
        let offset = (idx as usize) * ROW_LEN;
        // SAFETY: idx < self.count and payload_len_bytes ==
        // count * ROW_LEN, so offset + ROW_LEN <= payload bounds.
        let mut out = [0u8; ROW_LEN];
        unsafe {
            std::ptr::copy_nonoverlapping(self.payload_ptr.add(offset), out.as_mut_ptr(), ROW_LEN);
        }
        out
    }
}

/// Build the sorted partial-match `.bin` file from an iterator of
/// (prefix, size_band) tuples. Atomic write via `.tmp` + rename.
pub fn write_sorted<P: AsRef<Path>>(
    path: P,
    epoch_id: u64,
    fingerprints: impl IntoIterator<Item = PartialFingerprint>,
) -> Result<u64, PartialMatchError> {
    let mut rows: Vec<[u8; ROW_LEN]> = fingerprints
        .into_iter()
        .map(PartialFingerprint::to_row)
        .collect();
    rows.sort_unstable();
    rows.dedup();
    let count = rows.len() as u64;
    let final_path = path.as_ref();
    let tmp_path = final_path.with_extension({
        let ext = final_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("bin");
        format!("{ext}.tmp")
    });
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)?;
    let mut w = BufWriter::new(f);
    w.write_all(MAGIC)?;
    w.write_all(&VERSION.to_le_bytes())?;
    w.write_all(&0u32.to_le_bytes())?; // reserved
    w.write_all(&epoch_id.to_le_bytes())?;
    w.write_all(&count.to_le_bytes())?;
    w.write_all(&now.to_le_bytes())?;
    w.write_all(&[0u8; 16])?; // reserved2
    for row in &rows {
        w.write_all(row)?;
    }
    w.flush()?;
    let mut file = w.into_inner().map_err(|e| {
        PartialMatchError::Io(io::Error::other(format!(
            "flush partial-match: {}",
            e.error()
        )))
    })?;
    file.seek(SeekFrom::Start(0))?;
    file.sync_all()?;
    std::fs::rename(&tmp_path, final_path)?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn size_band_rounds_down_to_64mb() {
        assert_eq!(size_band(0), 0);
        assert_eq!(size_band(SIZE_BAND_BYTES - 1), 0);
        assert_eq!(size_band(SIZE_BAND_BYTES), SIZE_BAND_BYTES);
        assert_eq!(size_band(SIZE_BAND_BYTES + 1), SIZE_BAND_BYTES);
        assert_eq!(size_band(SIZE_BAND_BYTES * 16), SIZE_BAND_BYTES * 16);
        // 1.03 GB rounds to 1024 MB band.
        let one_gb_plus = 1024 * 1024 * 1024 + 30 * 1024 * 1024;
        assert_eq!(size_band(one_gb_plus), 1024 * 1024 * 1024);
    }

    fn mk_fp(seed: u8, sz: u64) -> PartialFingerprint {
        let mut prefix = [0u8; 32];
        for (i, byte) in prefix.iter_mut().enumerate() {
            *byte = seed.wrapping_add(i as u8).wrapping_mul(31);
        }
        PartialFingerprint {
            prefix_blake3: prefix,
            size_band: sz,
        }
    }

    #[test]
    fn write_roundtrip_small() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("pmi.bin");
        let fps: Vec<PartialFingerprint> = (0u8..20)
            .map(|s| mk_fp(s, SIZE_BAND_BYTES * (s as u64 + 4)))
            .collect();
        let n = write_sorted(&path, 0xfeed_dead, fps.iter().copied()).unwrap();
        assert_eq!(n, 20);
        let idx = PartialMatchIndex::open(&path, Some(0xfeed_dead)).unwrap();
        assert_eq!(idx.len(), 20);
        assert_eq!(idx.epoch_id(), 0xfeed_dead);
        for fp in &fps {
            assert!(idx.contains(fp), "expected hit for {fp:?}");
        }
        idx.verify_sorted().unwrap();
    }

    #[test]
    fn lookup_miss_returns_false() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("pmi.bin");
        let fps: Vec<_> = (0u8..10).map(|s| mk_fp(s, SIZE_BAND_BYTES * 4)).collect();
        write_sorted(&path, 1, fps.iter().copied()).unwrap();
        let idx = PartialMatchIndex::open(&path, None).unwrap();
        // Wrong prefix.
        assert!(!idx.contains(&mk_fp(99, SIZE_BAND_BYTES * 4)));
        // Right prefix, wrong size band.
        let mut wrong_band = fps[0];
        wrong_band.size_band = SIZE_BAND_BYTES * 99;
        assert!(!idx.contains(&wrong_band));
    }

    #[test]
    fn dedup_collapses_duplicate_rows() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("dedup.bin");
        let fp = mk_fp(7, SIZE_BAND_BYTES * 2);
        let fps = vec![fp, fp, fp, fp]; // four identical
        let n = write_sorted(&path, 1, fps).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn empty_index_misses_everything() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("empty.bin");
        write_sorted(&path, 1, std::iter::empty()).unwrap();
        let idx = PartialMatchIndex::open(&path, None).unwrap();
        assert_eq!(idx.len(), 0);
        assert!(idx.is_empty());
        assert!(!idx.contains(&mk_fp(0, 0)));
    }

    #[test]
    fn epoch_mismatch_rejects_open() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("epoch.bin");
        write_sorted(&path, 42, [mk_fp(0, SIZE_BAND_BYTES * 4)]).unwrap();
        let err = PartialMatchIndex::open(&path, Some(43)).unwrap_err();
        assert!(matches!(err, PartialMatchError::EpochMismatch { .. }));
    }

    #[test]
    fn compute_fingerprint_skips_small_files() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("small.bin");
        std::fs::write(&path, vec![0u8; 1024]).unwrap();
        assert!(compute_fingerprint(&path).unwrap().is_none());
    }

    #[test]
    fn compute_fingerprint_handles_big_files() {
        // 257 MB file — just clears the minimum threshold.
        // Build with deterministic content so we can re-derive
        // the expected prefix BLAKE3 by hand.
        let td = TempDir::new().unwrap();
        let path = td.path().join("big.bin");
        let file_size = PARTIAL_MATCH_MIN_FILE_BYTES + 1024 * 1024; // +1 MB
        {
            let mut f = File::create(&path).unwrap();
            let chunk = vec![0xCDu8; 4 * 1024 * 1024];
            let mut written = 0u64;
            while written < file_size {
                let want = (file_size - written).min(chunk.len() as u64) as usize;
                f.write_all(&chunk[..want]).unwrap();
                written += want as u64;
            }
            f.sync_all().unwrap();
        }
        let fp = compute_fingerprint(&path)
            .unwrap()
            .expect("file is big enough");
        // Expected prefix: BLAKE3 of 8 MB of 0xCD.
        let expected: [u8; 32] = {
            let mut h = blake3::Hasher::new();
            h.update(&vec![0xCDu8; PREFIX_WINDOW_BYTES as usize]);
            h.finalize().into()
        };
        assert_eq!(fp.prefix_blake3, expected);
        // Size band rounds 257 MB → 256 MB (4 × 64 MB).
        assert_eq!(fp.size_band, 256 * 1024 * 1024);
    }
}
