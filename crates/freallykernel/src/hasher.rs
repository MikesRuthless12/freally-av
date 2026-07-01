//! BLAKE3 + lazy SHA-256 hasher.
//!
//! Phase 1 (TASK-010) ships a streaming hasher that reads files in 1 MB chunks
//! and computes BLAKE3 always; SHA-256 is opt-in (`with_sha256(true)`) because
//! it's only needed for IOC lookups and dual-feed correlation (FR-009).
//!
//! [`StreamingHasher`] exposes `partial()` so the scan engine can publish the
//! mid-flight BLAKE3 hex prefix per FR-136 (TASK-134).
//!
//! [`HashCache`] is the engine's "skip-if-unchanged" book — keyed by `(path,
//! mtime, size)`, the hasher returns the cached digest without touching the
//! file when nothing relevant has changed.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

use crate::detect::crc32_set_file::Crc32SetFile;

/// Default chunk size for streaming reads. 1 MiB matches the spec from
/// `docs/prd.md` § 6.1 (FR-008) and keeps BLAKE3 fully fed without paging in
/// huge buffers.
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// Final hash output for one file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashResult {
    /// BLAKE3 hash, hex-encoded.
    pub blake3: String,
    /// SHA-256 hash, hex-encoded. `None` unless `with_sha256(true)` was set.
    pub sha256: Option<String>,
    /// File size in bytes (as observed during hashing).
    pub size: u64,
}

/// Hasher configuration. Cheap to clone.
#[derive(Debug, Clone, Default)]
pub struct Hasher {
    chunk_size: usize,
    compute_sha256: bool,
    /// Cooperative cancellation flag — checked between chunks. When
    /// set, [`Self::hash_file`] returns `io::ErrorKind::Interrupted`
    /// without finishing the file. The engine's scan worker shares
    /// the same flag with its pause/cancel paths so a click on Pause
    /// or Cancel takes effect within one chunk (~1 ms on NVMe) even
    /// in the middle of hashing a multi-GiB blob.
    abort_flag: Option<Arc<AtomicBool>>,
    /// Optional CRC32 fast-screen gate. When set, the hasher's
    /// gated entry-point [`Self::hash_file_with_crc32_gate`] does a
    /// cheap CRC32 pre-pass over the file. If the CRC32 isn't in
    /// the gate set, the hasher short-circuits — no BLAKE3, no
    /// SHA-256, no mmap. On a CPU-bound NVMe scan this skips the
    /// BLAKE3 computation for ~99.977% of files, where 1M-sample
    /// gates collide with random clean files at 1-in-4300.
    crc32_gate: Option<Arc<Crc32SetFile>>,
}

/// Outcome of [`Hasher::hash_file_with_crc32_gate`].
#[derive(Debug, Clone)]
pub enum MaybeHashResult {
    /// File's CRC32 was not in the gate set. BLAKE3 + SHA-256 were
    /// **not** computed. The engine should treat the file as
    /// hash-clean (no entry in any hash-keyed detector's blacklist
    /// could possibly hit). `crc32` and `size` are still reported so
    /// progress accounting can stay accurate.
    GatedMiss { crc32: u32, size: u64 },
    /// File's CRC32 hit the gate; full hashing ran. The BLAKE3 (and
    /// optionally SHA-256) digest is in the inner result. May still
    /// be a CRC32-collision false-positive at the gate stage; the
    /// BLAKE3 lookup in the detection pipeline confirms or rejects.
    Hashed { crc32: u32, result: HashResult },
}

impl Hasher {
    pub fn new() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            compute_sha256: false,
            abort_flag: None,
            crc32_gate: None,
        }
    }

    pub fn with_sha256(mut self, on: bool) -> Self {
        self.compute_sha256 = on;
        self
    }

    pub fn with_chunk_size(mut self, n: usize) -> Self {
        self.chunk_size = n.max(1);
        self
    }

    /// Register a cooperative-cancellation flag. The hasher polls it
    /// between chunks; when the flag is `true`, `hash_file` returns
    /// `Err(ErrorKind::Interrupted)` immediately. Engine workers
    /// share the same flag with their pause/cancel paths so user
    /// clicks take effect mid-hash.
    pub fn with_abort_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.abort_flag = Some(flag);
        self
    }

    /// Attach a CRC32 fast-screen gate. The gated entry-point
    /// [`Self::hash_file_with_crc32_gate`] consults this before
    /// computing BLAKE3; misses skip the BLAKE3 (and SHA-256) work
    /// entirely. Existing callers of [`Self::hash_file`] are
    /// unaffected.
    pub fn with_crc32_gate(mut self, gate: Arc<Crc32SetFile>) -> Self {
        self.crc32_gate = Some(gate);
        self
    }

    /// Compute the CRC32 of a file via a streaming read. Used as the
    /// fast-pre-screen pass; ~5-10 GB/s on x86 with hardware CRC32
    /// vs BLAKE3's ~1.5-3 GB/s — meaningful when scans are CPU-bound
    /// on NVMe.
    pub fn crc32_only_pass(&self, path: &Path) -> io::Result<(u32, u64)> {
        if let Some(flag) = self.abort_flag.as_ref()
            && flag.load(Ordering::Relaxed)
        {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "scan aborted before crc32 pass",
            ));
        }
        let mut f = File::open(path)?;
        let len = f.metadata()?.len();
        let mut hasher = crc32fast::Hasher::new();
        let mut buf = vec![0u8; self.chunk_size.max(64 * 1024)];
        loop {
            if let Some(flag) = self.abort_flag.as_ref()
                && flag.load(Ordering::Relaxed)
            {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "scan aborted mid-crc32",
                ));
            }
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok((hasher.finalize(), len))
    }

    /// Hash a file with a CRC32 fast-screen gate. If a gate is
    /// configured (via [`Self::with_crc32_gate`]), compute CRC32
    /// first; if the CRC32 isn't in the gate set, return
    /// [`MaybeHashResult::GatedMiss`] without computing BLAKE3.
    /// Otherwise fall through to the normal hashing path and return
    /// [`MaybeHashResult::Hashed`].
    ///
    /// If no gate is configured, this is equivalent to
    /// [`Self::hash_file`] wrapped in `Hashed`; CRC32 still computes
    /// so the caller gets the value for telemetry / per-file
    /// reporting.
    pub fn hash_file_with_crc32_gate(&self, path: &Path) -> io::Result<MaybeHashResult> {
        let (crc32, size) = self.crc32_only_pass(path)?;
        if let Some(gate) = self.crc32_gate.as_ref() {
            if !gate.contains(crc32) {
                return Ok(MaybeHashResult::GatedMiss { crc32, size });
            }
        }
        let result = self.hash_file(path)?;
        Ok(MaybeHashResult::Hashed { crc32, result })
    }

    /// File-size threshold above which `hash_file` switches from the
    /// streaming chunked read into the mmap + rayon-parallel BLAKE3
    /// path. 16 MiB is well above the per-rayon-task overhead and
    /// covers ~90% of "big" files (game assets, video, installers).
    /// Below this threshold streaming wins because the mmap setup
    /// cost dominates.
    pub const PARALLEL_THRESHOLD_BYTES: u64 = 16 * 1024 * 1024;

    /// Hash a file from disk.
    ///
    /// Three internal paths, chosen by file size:
    /// - **Below `PARALLEL_THRESHOLD_BYTES` (16 MiB)**: chunked
    ///   streaming read with the abort flag polled between chunks.
    ///   This is the only path that respects mid-hash cancellation
    ///   for small files — but small files hash in tens of ms so
    ///   responsiveness is not at issue.
    /// - **`PARALLEL_THRESHOLD_BYTES` and above**: memory-mapped
    ///   (`memmap2`) + `blake3::Hasher::update_rayon` — the BLAKE3
    ///   Merkle tree parallelizes across every available core. On
    ///   an 8-core machine a 1.5 GiB file hashes in 150-300 ms
    ///   instead of 1+ s single-threaded. SHA-256 streams over the
    ///   same mmap'd bytes (sha2 is single-threaded; SHA-NI helps
    ///   when the host CPU has it). Mid-hash cancellation degrades
    ///   to per-file granularity in this mode — the user clicks
    ///   Pause/Cancel, the in-flight file finishes (~hundreds of
    ///   ms), and the next iteration's flag check fires the exit.
    pub fn hash_file(&self, path: &Path) -> io::Result<HashResult> {
        // Cheap abort check before touching the FS at all.
        if let Some(flag) = self.abort_flag.as_ref()
            && flag.load(Ordering::Relaxed)
        {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "scan aborted before hash start",
            ));
        }

        let f = File::open(path)?;
        let len = f.metadata()?.len();
        if len >= Self::PARALLEL_THRESHOLD_BYTES {
            return hash_big_file_parallel(&f, len, self.compute_sha256, self.abort_flag.as_ref());
        }
        self.hash_file_streaming(f)
    }

    fn hash_file_streaming(&self, mut f: File) -> io::Result<HashResult> {
        let mut streaming = StreamingHasher::new(self.compute_sha256);
        let mut buf = vec![0u8; self.chunk_size];
        loop {
            if let Some(flag) = self.abort_flag.as_ref()
                && flag.load(Ordering::Relaxed)
            {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "scan aborted mid-hash",
                ));
            }
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            streaming.update(&buf[..n]);
        }
        Ok(streaming.finalize())
    }
}

/// Big-file fast path: mmap + chunked `blake3::Hasher::update_rayon`.
///
/// Chunk granularity matters two ways:
/// - Each call to `update_rayon` parallelizes within the chunk, so
///   we want chunks big enough to amortize rayon's task-graph
///   overhead. BLAKE3's docs recommend `update_rayon` from ~128 KiB
///   upward, so 4 MiB chunks are comfortably amortized.
/// - The abort flag is polled between chunks; smaller chunks =
///   tighter pause/cancel responsiveness. 4 MiB is the current
///   sweet spot: at BLAKE3 rayon's ~20-30 GB/s in release builds
///   each chunk hashes in ~0.2 ms; in dev (`opt-level=0`) builds
///   it's ~40 ms, which keeps Pause/Cancel feeling instant even
///   on a giant blob.
///
/// SHA-256 streams over the same mmap'd bytes when requested so we
/// only page each byte in once.
const PARALLEL_HASH_CHUNK: usize = 4 * 1024 * 1024;

fn hash_big_file_parallel(
    f: &File,
    len: u64,
    compute_sha256: bool,
    abort_flag: Option<&Arc<AtomicBool>>,
) -> io::Result<HashResult> {
    // SAFETY: `memmap2::Mmap::map` is unsafe only because of the well-
    // known caveat that the file must not be truncated underneath the
    // mmap. We don't write the file ourselves, and a concurrent
    // truncate would produce SIGBUS on Unix / EXCEPTION_IN_PAGE_ERROR
    // on Windows. The scan engine has no truncate path during a scan
    // (no findings layer writes mid-scan; quarantine moves the file
    // only AFTER hashing completes), so this is sound in our usage.
    let mmap = unsafe { memmap2::Mmap::map(f)? };
    let bytes: &[u8] = &mmap[..];
    let mut blake = blake3::Hasher::new();
    let mut sha: Option<sha2::Sha256> = if compute_sha256 {
        use sha2::Digest;
        Some(sha2::Sha256::new())
    } else {
        None
    };
    for chunk in bytes.chunks(PARALLEL_HASH_CHUNK) {
        if let Some(flag) = abort_flag
            && flag.load(Ordering::Relaxed)
        {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "scan aborted mid-hash (big-file parallel path)",
            ));
        }
        // `update_rayon` has measurable task-graph overhead; only
        // pay it on chunks large enough to amortize. Below ~1 MiB
        // the scalar path wins anyway.
        if chunk.len() >= 1024 * 1024 {
            blake.update_rayon(chunk);
        } else {
            blake.update(chunk);
        }
        if let Some(s) = sha.as_mut() {
            use sha2::Digest;
            s.update(chunk);
        }
    }
    let blake3_hex = blake.finalize().to_hex().to_string();
    let sha256_hex = sha.map(|s| {
        use sha2::Digest;
        hex::encode(s.finalize())
    });
    Ok(HashResult {
        blake3: blake3_hex,
        sha256: sha256_hex,
        size: len,
    })
}

/// Incremental hasher that supports mid-stream `partial()` snapshots.
///
/// The scan engine drives this directly so it can both finalize at end-of-file
/// and publish a hex prefix at ≤ 10 Hz for the live current-file display
/// (FR-136 / TASK-134).
pub struct StreamingHasher {
    blake3: blake3::Hasher,
    sha256: Option<sha2::Sha256>,
    bytes: u64,
}

impl StreamingHasher {
    pub fn new(compute_sha256: bool) -> Self {
        use sha2::Digest;
        Self {
            blake3: blake3::Hasher::new(),
            sha256: if compute_sha256 {
                Some(sha2::Sha256::new())
            } else {
                None
            },
            bytes: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        use sha2::Digest;
        self.blake3.update(data);
        if let Some(s) = self.sha256.as_mut() {
            s.update(data);
        }
        self.bytes += data.len() as u64;
    }

    /// Mid-stream BLAKE3 snapshot (full hex). Cloning the hasher is cheap; this
    /// does not consume self or commit to a final value.
    pub fn partial(&self) -> String {
        let snap = self.blake3.clone().finalize();
        hex::encode(snap.as_bytes())
    }

    /// Bytes processed so far.
    pub fn bytes_seen(&self) -> u64 {
        self.bytes
    }

    pub fn finalize(self) -> HashResult {
        use sha2::Digest;
        let blake3 = hex::encode(self.blake3.finalize().as_bytes());
        let sha256 = self.sha256.map(|h| hex::encode(h.finalize()));
        HashResult {
            blake3,
            sha256,
            size: self.bytes,
        }
    }
}

/// Cache key for skip-if-unchanged lookups.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CacheKey {
    pub path: PathBuf,
    pub mtime: i64,
    pub size: u64,
}

/// In-memory hash cache. Phase 1 keeps it RAM-only; TASK-011 (history layer)
/// persists hot entries to SQLite.
#[derive(Debug, Default)]
pub struct HashCache {
    map: HashMap<CacheKey, HashResult>,
}

impl HashCache {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn get(&self, key: &CacheKey) -> Option<&HashResult> {
        self.map.get(key)
    }

    pub fn insert(&mut self, key: CacheKey, result: HashResult) {
        self.map.insert(key, result);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn empty_file_blake3_matches_known_vector() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("empty.bin");
        fs::write(&p, []).unwrap();
        let r = Hasher::new().hash_file(&p).unwrap();
        // BLAKE3 of empty input.
        assert_eq!(
            r.blake3,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert!(r.sha256.is_none());
        assert_eq!(r.size, 0);
    }

    #[test]
    fn known_input_blake3_and_sha256() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("hello.txt");
        fs::write(&p, b"hello world").unwrap();
        let r = Hasher::new().with_sha256(true).hash_file(&p).unwrap();
        assert_eq!(
            r.blake3,
            "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
        );
        assert_eq!(
            r.sha256.as_deref(),
            Some("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        );
        assert_eq!(r.size, 11);
    }

    #[test]
    fn streaming_partial_matches_finalize_when_no_more_input() {
        let mut s = StreamingHasher::new(false);
        s.update(b"hello world");
        let partial = s.partial();
        let final_ = s.finalize();
        assert_eq!(partial, final_.blake3);
    }

    #[test]
    fn cache_returns_hit_for_same_key() {
        let mut cache = HashCache::new();
        let key = CacheKey {
            path: "/tmp/x".into(),
            mtime: 1234,
            size: 99,
        };
        let r = HashResult {
            blake3: "deadbeef".into(),
            sha256: None,
            size: 99,
        };
        cache.insert(key.clone(), r.clone());
        assert_eq!(cache.get(&key).unwrap().blake3, "deadbeef");
        let stale = CacheKey { mtime: 9999, ..key };
        assert!(cache.get(&stale).is_none());
    }

    #[test]
    fn chunked_reads_match_single_read() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("big.bin");
        let payload: Vec<u8> = (0..(3 * DEFAULT_CHUNK_SIZE))
            .map(|i| (i % 251) as u8)
            .collect();
        fs::write(&p, &payload).unwrap();

        let big = Hasher::new().hash_file(&p).unwrap();
        let small = Hasher::new()
            .with_chunk_size(64 * 1024)
            .hash_file(&p)
            .unwrap();
        assert_eq!(big.blake3, small.blake3);
        assert_eq!(big.size, payload.len() as u64);
    }

    // ---- CRC32 fast-screen gate tests ----------------------------------

    /// Helper: build a Crc32SetFile containing `values`.
    fn build_crc32_set(dir: &std::path::Path, name: &str, values: &[u32]) -> std::path::PathBuf {
        use std::io::Write;
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let path = dir.join(name);
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(b"MYTHCRC3").unwrap();
        f.write_all(&1u32.to_le_bytes()).unwrap(); // version
        f.write_all(&0u32.to_le_bytes()).unwrap(); // reserved
        f.write_all(&(sorted.len() as u64).to_le_bytes()).unwrap();
        for v in &sorted {
            f.write_all(&v.to_le_bytes()).unwrap();
        }
        path
    }

    fn crc32_of(bytes: &[u8]) -> u32 {
        let mut h = crc32fast::Hasher::new();
        h.update(bytes);
        h.finalize()
    }

    #[test]
    fn crc32_only_pass_empty_file() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("empty.bin");
        fs::write(&p, []).unwrap();
        let (crc, size) = Hasher::new().crc32_only_pass(&p).unwrap();
        assert_eq!(crc, 0);
        assert_eq!(size, 0);
    }

    #[test]
    fn crc32_only_pass_matches_independent_compute() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("data.bin");
        let payload = b"hello world, malware-shaped content for the test".to_vec();
        fs::write(&p, &payload).unwrap();
        let (crc, size) = Hasher::new().crc32_only_pass(&p).unwrap();
        assert_eq!(size, payload.len() as u64);
        assert_eq!(crc, crc32_of(&payload));
    }

    #[test]
    fn crc32_only_pass_handles_multi_chunk_file() {
        // Make a file bigger than the default chunk so the streaming
        // read loop fires multiple iterations.
        let dir = tempdir().unwrap();
        let p = dir.path().join("multi.bin");
        let payload: Vec<u8> = (0..(3 * DEFAULT_CHUNK_SIZE))
            .map(|i| (i % 251) as u8)
            .collect();
        fs::write(&p, &payload).unwrap();
        let (crc, size) = Hasher::new().crc32_only_pass(&p).unwrap();
        assert_eq!(size, payload.len() as u64);
        assert_eq!(crc, crc32_of(&payload));
    }

    #[test]
    fn crc32_only_pass_respects_abort_flag_before_open() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("never_opened.bin");
        fs::write(&p, b"won't be read").unwrap();
        let flag = Arc::new(AtomicBool::new(true));
        let err = Hasher::new()
            .with_abort_flag(flag)
            .crc32_only_pass(&p)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn hash_file_with_crc32_gate_no_gate_acts_as_hash_file() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("nogate.bin");
        fs::write(&p, b"plain content").unwrap();
        let outcome = Hasher::new().hash_file_with_crc32_gate(&p).expect("hash");
        match outcome {
            MaybeHashResult::Hashed { crc32, result } => {
                assert_eq!(crc32, crc32_of(b"plain content"));
                // BLAKE3 of "plain content" — must be non-empty.
                assert!(!result.blake3.is_empty());
                assert_eq!(result.size, b"plain content".len() as u64);
            }
            MaybeHashResult::GatedMiss { .. } => {
                panic!("no gate configured but got GatedMiss");
            }
        }
    }

    #[test]
    fn hash_file_with_crc32_gate_hit_returns_hashed() {
        let dir = tempdir().unwrap();
        let payload = b"this is malware-shaped";
        let p = dir.path().join("hit.bin");
        fs::write(&p, payload).unwrap();
        let crc = crc32_of(payload);
        let set_path = build_crc32_set(dir.path(), "gate.bin", &[crc]);
        let gate = Arc::new(Crc32SetFile::open(&set_path).unwrap());

        let outcome = Hasher::new()
            .with_crc32_gate(gate)
            .hash_file_with_crc32_gate(&p)
            .expect("hash");
        match outcome {
            MaybeHashResult::Hashed { crc32, result } => {
                assert_eq!(crc32, crc);
                assert_eq!(result.size, payload.len() as u64);
                assert!(!result.blake3.is_empty());
            }
            MaybeHashResult::GatedMiss { .. } => {
                panic!("CRC32 was in the gate set but got GatedMiss");
            }
        }
    }

    #[test]
    fn hash_file_with_crc32_gate_miss_skips_blake3() {
        let dir = tempdir().unwrap();
        let payload = b"definitely benign user data";
        let p = dir.path().join("miss.bin");
        fs::write(&p, payload).unwrap();
        // Build a gate with a DIFFERENT crc.
        let other_crc = crc32_of(b"unrelated content").wrapping_add(1);
        let our_crc = crc32_of(payload);
        assert_ne!(other_crc, our_crc, "test setup: crcs must differ");
        let set_path = build_crc32_set(dir.path(), "gate.bin", &[other_crc]);
        let gate = Arc::new(Crc32SetFile::open(&set_path).unwrap());

        let outcome = Hasher::new()
            .with_crc32_gate(gate)
            .hash_file_with_crc32_gate(&p)
            .expect("hash");
        match outcome {
            MaybeHashResult::GatedMiss { crc32, size } => {
                assert_eq!(crc32, our_crc);
                assert_eq!(size, payload.len() as u64);
            }
            MaybeHashResult::Hashed { .. } => {
                panic!("CRC32 was NOT in gate set but got Hashed");
            }
        }
    }

    #[test]
    fn hash_file_with_crc32_gate_empty_gate_misses_every_file() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("any.bin");
        fs::write(&p, b"contents").unwrap();
        let set_path = build_crc32_set(dir.path(), "empty_gate.bin", &[]);
        let gate = Arc::new(Crc32SetFile::open(&set_path).unwrap());

        let outcome = Hasher::new()
            .with_crc32_gate(gate)
            .hash_file_with_crc32_gate(&p)
            .expect("hash");
        assert!(matches!(outcome, MaybeHashResult::GatedMiss { .. }));
    }

    #[test]
    fn hash_file_with_crc32_gate_empty_file_uses_zero_crc() {
        // CRC32 of empty input is 0; a gate containing 0 should hit.
        let dir = tempdir().unwrap();
        let p = dir.path().join("empty.bin");
        fs::write(&p, []).unwrap();
        let set_path = build_crc32_set(dir.path(), "zero_gate.bin", &[0]);
        let gate = Arc::new(Crc32SetFile::open(&set_path).unwrap());

        let outcome = Hasher::new()
            .with_crc32_gate(gate)
            .hash_file_with_crc32_gate(&p)
            .expect("hash");
        match outcome {
            MaybeHashResult::Hashed { crc32, result } => {
                assert_eq!(crc32, 0);
                assert_eq!(result.size, 0);
            }
            _ => panic!("expected Hashed for crc=0 file with crc=0 in gate"),
        }
    }

    #[test]
    fn hash_file_with_crc32_gate_respects_abort_flag() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("abort.bin");
        fs::write(&p, b"contents").unwrap();
        let set_path = build_crc32_set(dir.path(), "gate.bin", &[crc32_of(b"contents")]);
        let gate = Arc::new(Crc32SetFile::open(&set_path).unwrap());
        let flag = Arc::new(AtomicBool::new(true));
        let err = Hasher::new()
            .with_crc32_gate(gate)
            .with_abort_flag(flag)
            .hash_file_with_crc32_gate(&p)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
    }
}
