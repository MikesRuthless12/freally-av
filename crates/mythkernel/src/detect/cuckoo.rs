//! TASK-179 — Cuckoo-filter alternative to Bloom.
//!
//! Same purpose as [`super::bloom`] (cheap pre-screen before the
//! sorted-`.bin` binary search) with one extra capability: **delete
//! support**. The TASK-181 aging job evicts silver-tier rows from
//! the live blacklist; under Bloom those evicted hashes can't be
//! cleanly removed from the filter without a full rebuild. Cuckoo
//! supports per-item deletion via fingerprint match.
//!
//! On-disk format:
//!
//! ```text
//!  0..8     magic        ASCII "MYTHCKOO"
//!  8..12    version      u32 LE (= 1)
//! 12..16    reserved     u32 LE (= 0)
//! 16..24    epoch_id     u64 LE
//! 24..32    bucket_count u64 LE — number of buckets
//! 32..36    entries_per_bucket u32 LE (default 4)
//! 36..40    fingerprint_bits u32 LE (default 12)
//! 40..48    n_items      u64 LE — observed inserts
//! 48..56    built_at     i64 LE
//! 56..72    reserved2    16 bytes
//! 72..N     payload      bucket_count * entries_per_bucket * 2 bytes (u16 fingerprint, 0 = empty)
//! ```
//!
//! Fingerprints are u16-stored with the low `fingerprint_bits`
//! significant; a value of 0 always denotes an empty slot (matches
//! standard Cuckoo conventions). When `fingerprint_bits = 12`, the
//! upper 4 bits of each u16 stay zero — small space overhead but
//! lets us bump fingerprint width to 16 later by changing only the
//! header.
//!
//! ## Insert / lookup / delete
//!
//! Per Fan et al. (2014) "Cuckoo Filter: Practically Better Than Bloom":
//!   * `i1 = hash(x) mod bucket_count`
//!   * `i2 = i1 XOR hash(fingerprint(x)) mod bucket_count`
//! Insert tries i1, then i2; on bucket-full, kicks a random
//! occupant and re-homes it (bounded retries). Lookup checks both
//! buckets. Delete checks both buckets, zeros first match.
//!
//! Like Bloom, we use the input digest's u64 slices directly rather
//! than adding a SipHash dependency — SHA-256/BLAKE3 are uniformly
//! distributed in every byte slice.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use memmap2::Mmap;

const MAGIC: &[u8; 8] = b"MYTHCKOO";
const VERSION: u32 = 1;
const HEADER_LEN: usize = 72;

pub const DEFAULT_ENTRIES_PER_BUCKET: u32 = 4;
pub const DEFAULT_FINGERPRINT_BITS: u32 = 12;
const MAX_KICKS: u32 = 500;

#[derive(Debug, thiserror::Error)]
pub enum CuckooError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("cuckoo file is too short to contain a header ({0} bytes)")]
    TooShort(usize),
    #[error("cuckoo file has wrong magic")]
    BadMagic,
    #[error("cuckoo file has unsupported version {0}")]
    BadVersion(u32),
    #[error(
        "cuckoo file declares {declared_buckets} buckets * {entries_per_bucket} entries * 2 bytes = {declared_payload_bytes} but payload holds {actual_payload_bytes} bytes"
    )]
    LengthMismatch {
        declared_buckets: u64,
        entries_per_bucket: u32,
        declared_payload_bytes: u64,
        actual_payload_bytes: usize,
    },
    #[error(
        "cuckoo epoch mismatch: file says {file_epoch}, caller asked for {wanted_epoch}"
    )]
    EpochMismatch { file_epoch: u64, wanted_epoch: u64 },
    #[error("digest must be at least 16 bytes, got {0}")]
    DigestTooShort(usize),
    #[error("cuckoo insert failed after {0} kicks (filter likely too full)")]
    InsertExhausted(u32),
}

#[derive(Debug)]
pub struct CuckooFilter {
    bucket_count: u64,
    entries_per_bucket: u32,
    fingerprint_bits: u32,
    fingerprint_mask: u16,
    n_items: u64,
    epoch_id: u64,
    built_at: i64,
    /// `bucket_count × entries_per_bucket` u16 slots, row-major
    /// (bucket-major). Stored as a flat `Vec<u16>` during build;
    /// the [`CuckooFile`] reader uses an mmap instead.
    buckets: Vec<u16>,
}

impl CuckooFilter {
    /// Build a fresh in-memory filter sized for `expected_items` at
    /// approximate 1% FPR with default 4-entry buckets + 12-bit
    /// fingerprints. Load factor ≈ 0.95 under those defaults.
    pub fn new(expected_items: u64, epoch_id: u64) -> Self {
        let entries_per_bucket = DEFAULT_ENTRIES_PER_BUCKET;
        let fingerprint_bits = DEFAULT_FINGERPRINT_BITS;
        // Cuckoo at 95% load factor needs ~items / (entries × 0.95) buckets.
        // Round up to the next power of two for fast modulo.
        let raw = (expected_items as f64) / (entries_per_bucket as f64) / 0.95;
        let mut bucket_count = (raw.ceil() as u64).max(1);
        bucket_count = bucket_count.next_power_of_two();
        Self::with_params(bucket_count, entries_per_bucket, fingerprint_bits, epoch_id)
    }

    fn with_params(
        bucket_count: u64,
        entries_per_bucket: u32,
        fingerprint_bits: u32,
        epoch_id: u64,
    ) -> Self {
        // CR-C1 fix — `(1u32 << 16) as u16 - 1` underflows in debug
        // and gets lucky in release; spell out the 16-bit case.
        let fingerprint_mask: u16 = if fingerprint_bits >= 16 {
            u16::MAX
        } else if fingerprint_bits == 0 {
            // Empty mask = degenerate filter; surface a usable
            // single-bit minimum.
            1
        } else {
            ((1u32 << fingerprint_bits) - 1) as u16
        };
        // CR-LOW-1 fix — checked_mul against absurd values.
        let size = (bucket_count as usize)
            .checked_mul(entries_per_bucket as usize)
            .unwrap_or(0);
        Self {
            bucket_count,
            entries_per_bucket,
            fingerprint_bits,
            fingerprint_mask,
            n_items: 0,
            epoch_id,
            built_at: 0,
            buckets: vec![0u16; size],
        }
    }

    pub fn epoch_id(&self) -> u64 {
        self.epoch_id
    }
    pub fn n_items(&self) -> u64 {
        self.n_items
    }
    pub fn bucket_count(&self) -> u64 {
        self.bucket_count
    }

    fn slot(&self, bucket: u64, entry: u32) -> usize {
        (bucket as usize) * (self.entries_per_bucket as usize) + (entry as usize)
    }

    fn fingerprint_from_digest(&self, digest: &[u8]) -> u16 {
        // Take the second u64 of the digest as the source of the
        // fingerprint. Truncate to fingerprint_bits; ensure non-zero
        // (zero is the empty marker).
        let raw = u64::from_le_bytes(digest[8..16].try_into().expect("≥ 16 bytes")) as u16;
        let masked = raw & self.fingerprint_mask;
        if masked == 0 {
            // Coerce zero to a low-bit pattern so the slot isn't
            // mistaken for empty.
            1
        } else {
            masked
        }
    }

    fn bucket1_from_digest(&self, digest: &[u8]) -> u64 {
        let h1 = u64::from_le_bytes(digest[0..8].try_into().expect("≥ 16 bytes"));
        h1 & (self.bucket_count - 1)
    }

    fn bucket2(&self, bucket1: u64, fingerprint: u16) -> u64 {
        // Cuckoo "partial-key" trick: i2 = i1 XOR hash(fp).
        // We hash the fingerprint by multiplying with a large odd
        // constant (good mixing) and reducing mod bucket_count.
        let fp_hash = (fingerprint as u64).wrapping_mul(0x5bd1e995);
        (bucket1 ^ fp_hash) & (self.bucket_count - 1)
    }

    pub fn insert(&mut self, digest: &[u8]) -> Result<(), CuckooError> {
        if digest.len() < 16 {
            return Err(CuckooError::DigestTooShort(digest.len()));
        }
        if self.bucket_count == 0 {
            return Err(CuckooError::InsertExhausted(0));
        }
        let fp = self.fingerprint_from_digest(digest);
        let i1 = self.bucket1_from_digest(digest);
        let i2 = self.bucket2(i1, fp);

        if self.try_insert(i1, fp) || self.try_insert(i2, fp) {
            self.n_items += 1;
            return Ok(());
        }

        // CR-H1 fix — bias the kick-chain start with real-ish
        // randomness so colliding (i1,i2) pairs don't deadlock on
        // the same victim. Seed from a process-wide RNG; for
        // deterministic builds (e.g. CI), the runtime seed is fine
        // because the filter content is content-addressed via the
        // input digest stream anyway.
        let mut current_bucket = {
            use rand::Rng;
            if rand::thread_rng().r#gen::<bool>() {
                i1
            } else {
                i2
            }
        };
        let mut current_fp = fp;
        let mut kick_seed = current_fp as u32 ^ (rand::random::<u32>());
        for _ in 0..MAX_KICKS {
            let entry = (kick_seed) % self.entries_per_bucket;
            kick_seed = kick_seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let slot = self.slot(current_bucket, entry);
            let evicted = self.buckets[slot];
            self.buckets[slot] = current_fp;
            current_fp = evicted;
            let alt = self.bucket2(current_bucket, current_fp);
            if self.try_insert(alt, current_fp) {
                self.n_items += 1;
                return Ok(());
            }
            current_bucket = alt;
        }
        Err(CuckooError::InsertExhausted(MAX_KICKS))
    }

    fn try_insert(&mut self, bucket: u64, fingerprint: u16) -> bool {
        for entry in 0..self.entries_per_bucket {
            let slot = self.slot(bucket, entry);
            if self.buckets[slot] == 0 {
                self.buckets[slot] = fingerprint;
                return true;
            }
        }
        false
    }

    pub fn contains(&self, digest: &[u8]) -> Result<bool, CuckooError> {
        if digest.len() < 16 {
            return Err(CuckooError::DigestTooShort(digest.len()));
        }
        let fp = self.fingerprint_from_digest(digest);
        let i1 = self.bucket1_from_digest(digest);
        let i2 = self.bucket2(i1, fp);
        Ok(self.bucket_has(i1, fp) || self.bucket_has(i2, fp))
    }

    fn bucket_has(&self, bucket: u64, fingerprint: u16) -> bool {
        for entry in 0..self.entries_per_bucket {
            let slot = self.slot(bucket, entry);
            if self.buckets[slot] == fingerprint {
                return true;
            }
        }
        false
    }

    /// Remove one occurrence of `digest` from the filter. Returns
    /// `true` if a matching slot was found and zeroed. Cuckoo
    /// fingerprint matching is approximate (12-bit fingerprint =
    /// 1-in-4096 false positive on delete), so the caller should
    /// only invoke this from the aging job — never from the hot
    /// scanner path.
    pub fn delete(&mut self, digest: &[u8]) -> Result<bool, CuckooError> {
        if digest.len() < 16 {
            return Err(CuckooError::DigestTooShort(digest.len()));
        }
        let fp = self.fingerprint_from_digest(digest);
        let i1 = self.bucket1_from_digest(digest);
        let i2 = self.bucket2(i1, fp);
        if self.try_delete(i1, fp) || self.try_delete(i2, fp) {
            self.n_items = self.n_items.saturating_sub(1);
            return Ok(true);
        }
        Ok(false)
    }

    fn try_delete(&mut self, bucket: u64, fingerprint: u16) -> bool {
        for entry in 0..self.entries_per_bucket {
            let slot = self.slot(bucket, entry);
            if self.buckets[slot] == fingerprint {
                self.buckets[slot] = 0;
                return true;
            }
        }
        false
    }

    pub fn write_to<P: AsRef<Path>>(&self, path: P) -> Result<(), CuckooError> {
        let final_path = path.as_ref();
        let tmp_path = final_path.with_extension({
            let ext = final_path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("cuckoo");
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
        w.write_all(&self.bucket_count.to_le_bytes())?;
        w.write_all(&self.entries_per_bucket.to_le_bytes())?;
        w.write_all(&self.fingerprint_bits.to_le_bytes())?;
        w.write_all(&self.n_items.to_le_bytes())?;
        w.write_all(&now.to_le_bytes())?;
        w.write_all(&[0u8; 16])?;
        for fp in &self.buckets {
            w.write_all(&fp.to_le_bytes())?;
        }
        w.flush()?;
        w.into_inner()
            .map_err(|e| CuckooError::Io(io::Error::other(format!("flush cuckoo: {}", e.error()))))?
            .sync_all()?;
        std::fs::rename(&tmp_path, final_path)?;
        Ok(())
    }

    /// SR-H2 fix — open read-only. The deletion path
    /// (TASK-181 aging job) re-builds the filter in RAM and writes
    /// a fresh artifact via [`Self::write_to`] rather than mutating
    /// in place. Read-only mapping avoids needing write permission
    /// on the artifact + closes off any concurrent-mutation footgun.
    pub fn open<P: AsRef<Path>>(
        path: P,
        expected_epoch: Option<u64>,
    ) -> Result<Self, CuckooError> {
        let f = File::open(path)?;
        // SAFETY: we map a regular file we just opened read-only;
        // the OS returns an immutable mapping.
        let mmap = unsafe { Mmap::map(&f)? };
        Self::from_mmap_mut(mmap, expected_epoch)
    }

    fn from_mmap_mut(
        mmap: Mmap,
        expected_epoch: Option<u64>,
    ) -> Result<Self, CuckooError> {
        let bytes = &mmap[..];
        if bytes.len() < HEADER_LEN {
            return Err(CuckooError::TooShort(bytes.len()));
        }
        if &bytes[0..8] != MAGIC {
            return Err(CuckooError::BadMagic);
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes"));
        if version != VERSION {
            return Err(CuckooError::BadVersion(version));
        }
        let epoch_id = u64::from_le_bytes(bytes[16..24].try_into().expect("8 bytes"));
        let bucket_count = u64::from_le_bytes(bytes[24..32].try_into().expect("8 bytes"));
        let entries_per_bucket = u32::from_le_bytes(bytes[32..36].try_into().expect("4 bytes"));
        let fingerprint_bits = u32::from_le_bytes(bytes[36..40].try_into().expect("4 bytes"));
        let n_items = u64::from_le_bytes(bytes[40..48].try_into().expect("8 bytes"));
        let built_at = i64::from_le_bytes(bytes[48..56].try_into().expect("8 bytes"));
        if let Some(want) = expected_epoch
            && epoch_id != want
        {
            return Err(CuckooError::EpochMismatch {
                file_epoch: epoch_id,
                wanted_epoch: want,
            });
        }
        // CR-C2 fix — reject malformed headers up front. The mask
        // arithmetic in `bucket2` assumes `bucket_count` is a
        // power of two ≥ 1; a corrupted file declaring 0 would
        // wrap to u64::MAX and panic on the subsequent index.
        // `fingerprint_bits` must also be in (0, 16] for the mask
        // path to work after the CR-C1 fix.
        if bucket_count == 0 || !bucket_count.is_power_of_two() {
            return Err(CuckooError::LengthMismatch {
                declared_buckets: bucket_count,
                entries_per_bucket,
                declared_payload_bytes: 0,
                actual_payload_bytes: bytes.len() - HEADER_LEN,
            });
        }
        if !(1..=16).contains(&fingerprint_bits) || entries_per_bucket == 0 {
            return Err(CuckooError::LengthMismatch {
                declared_buckets: bucket_count,
                entries_per_bucket,
                declared_payload_bytes: 0,
                actual_payload_bytes: bytes.len() - HEADER_LEN,
            });
        }
        let declared_payload_bytes =
            bucket_count.saturating_mul(entries_per_bucket as u64).saturating_mul(2);
        let actual_payload_bytes = bytes.len() - HEADER_LEN;
        if actual_payload_bytes as u64 != declared_payload_bytes {
            return Err(CuckooError::LengthMismatch {
                declared_buckets: bucket_count,
                entries_per_bucket,
                declared_payload_bytes,
                actual_payload_bytes,
            });
        }
        // Read all fingerprints into an owned Vec so the filter is
        // self-contained even after the mmap drops. Trade memory for
        // simplicity — the production scanner uses Bloom (TASK-178)
        // as the hot-path filter; Cuckoo is build-pipeline only.
        let mut buckets = Vec::with_capacity((bucket_count as usize) * (entries_per_bucket as usize));
        let mut off = HEADER_LEN;
        for _ in 0..(bucket_count as usize) * (entries_per_bucket as usize) {
            buckets.push(u16::from_le_bytes(bytes[off..off + 2].try_into().expect("2 bytes")));
            off += 2;
        }
        // Same CR-C1 derivation as `with_params`.
        let fingerprint_mask: u16 = if fingerprint_bits >= 16 {
            u16::MAX
        } else {
            ((1u32 << fingerprint_bits) - 1) as u16
        };
        Ok(Self {
            bucket_count,
            entries_per_bucket,
            fingerprint_bits,
            fingerprint_mask,
            n_items,
            epoch_id,
            built_at,
            buckets,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sha(seed: u32) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(seed.to_le_bytes());
        h.finalize().into()
    }

    #[test]
    fn insert_then_contains() {
        let mut c = CuckooFilter::new(1_000, 1);
        for i in 0u32..500 {
            c.insert(&sha(i)).unwrap();
        }
        for i in 0u32..500 {
            assert!(c.contains(&sha(i)).unwrap(), "expected hit for seed {i}");
        }
    }

    #[test]
    fn delete_returns_absent_on_subsequent_lookup() {
        let mut c = CuckooFilter::new(1_000, 1);
        for i in 0u32..200 {
            c.insert(&sha(i)).unwrap();
        }
        assert!(c.contains(&sha(7)).unwrap());
        assert!(c.delete(&sha(7)).unwrap());
        assert!(!c.contains(&sha(7)).unwrap());
        // Re-deleting a missing item is a no-op.
        assert!(!c.delete(&sha(7)).unwrap());
    }

    #[test]
    fn write_roundtrip() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("c.cuckoo");
        {
            let mut c = CuckooFilter::new(500, 0xfee1d);
            for i in 0u32..200 {
                c.insert(&sha(i)).unwrap();
            }
            c.write_to(&path).unwrap();
        }
        let c = CuckooFilter::open(&path, Some(0xfee1d)).unwrap();
        assert_eq!(c.epoch_id(), 0xfee1d);
        assert_eq!(c.n_items(), 200);
        for i in 0u32..200 {
            assert!(c.contains(&sha(i)).unwrap());
        }
    }

    #[test]
    fn epoch_mismatch_rejected() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("e.cuckoo");
        {
            let c = CuckooFilter::new(50, 42);
            c.write_to(&path).unwrap();
        }
        let err = CuckooFilter::open(&path, Some(99)).unwrap_err();
        assert!(matches!(
            err,
            CuckooError::EpochMismatch { file_epoch: 42, wanted_epoch: 99 }
        ));
    }

    #[test]
    fn empty_filter_misses_everything() {
        let c = CuckooFilter::new(100, 1);
        for i in 0u32..50 {
            assert!(!c.contains(&sha(i)).unwrap());
        }
    }

    #[test]
    fn malformed_header_bucket_count_zero_rejected() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("bad.cuckoo");
        // Hand-write a header with bucket_count = 0.
        let mut buf = Vec::new();
        buf.extend_from_slice(b"MYTHCKOO");
        buf.extend_from_slice(&1u32.to_le_bytes()); // version
        buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
        buf.extend_from_slice(&1u64.to_le_bytes()); // epoch
        buf.extend_from_slice(&0u64.to_le_bytes()); // bucket_count = 0 ← bad
        buf.extend_from_slice(&4u32.to_le_bytes()); // entries_per_bucket
        buf.extend_from_slice(&12u32.to_le_bytes()); // fingerprint_bits
        buf.extend_from_slice(&0u64.to_le_bytes()); // n_items
        buf.extend_from_slice(&0i64.to_le_bytes()); // built_at
        buf.extend_from_slice(&[0u8; 16]); // reserved2
        std::fs::write(&path, &buf).unwrap();
        let err = CuckooFilter::open(&path, None).unwrap_err();
        assert!(matches!(err, CuckooError::LengthMismatch { .. }));
    }

    #[test]
    fn malformed_header_bad_fingerprint_bits_rejected() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("bad2.cuckoo");
        let mut buf = Vec::new();
        buf.extend_from_slice(b"MYTHCKOO");
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&1u64.to_le_bytes());
        buf.extend_from_slice(&8u64.to_le_bytes()); // bucket_count (pow2)
        buf.extend_from_slice(&4u32.to_le_bytes());
        buf.extend_from_slice(&99u32.to_le_bytes()); // fingerprint_bits = 99 ← bad
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&0i64.to_le_bytes());
        buf.extend_from_slice(&[0u8; 16]);
        buf.extend(std::iter::repeat(0u8).take(8 * 4 * 2));
        std::fs::write(&path, &buf).unwrap();
        let err = CuckooFilter::open(&path, None).unwrap_err();
        assert!(matches!(err, CuckooError::LengthMismatch { .. }));
    }

    #[test]
    fn fingerprint_mask_works_at_16_bits() {
        // CR-C1: ensure the 16-bit boundary doesn't overflow.
        let c = CuckooFilter::with_params(16, 4, 16, 0);
        let d = [0xAAu8; 32];
        // Insert + contains must not panic with mask == u16::MAX.
        let mut c2 = c;
        c2.insert(&d).unwrap();
        assert!(c2.contains(&d).unwrap());
    }

    #[test]
    fn fpr_below_3pct() {
        // 1k inserts into a 10k-capacity filter, probe 50k disjoint.
        // Cuckoo's theoretical FPR at 12-bit fingerprints is roughly
        // 2 * entries / 2^12 ≈ 8 * 4 / 4096 ≈ 0.78% at full load;
        // our test guards against ≥ 3% which is a wide margin.
        let mut c = CuckooFilter::new(10_000, 1);
        for i in 0u32..1_000 {
            c.insert(&sha(i)).unwrap();
        }
        let mut fp = 0;
        for i in 0u32..50_000 {
            if c.contains(&sha(i + 100_000_000)).unwrap() {
                fp += 1;
            }
        }
        let rate = (fp as f64) / 50_000.0;
        assert!(rate < 0.03, "Cuckoo FPR {rate:.4} > 3% ({fp}/50000)");
    }
}
