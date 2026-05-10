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

use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone)]
pub struct Hasher {
    chunk_size: usize,
    compute_sha256: bool,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    pub fn new() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            compute_sha256: false,
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

    /// Hash a file from disk. Streams the file through BLAKE3 (and SHA-256 if
    /// configured) without loading the whole thing into memory.
    pub fn hash_file(&self, path: &Path) -> io::Result<HashResult> {
        let mut f = File::open(path)?;
        let mut streaming = StreamingHasher::new(self.compute_sha256);
        let mut buf = vec![0u8; self.chunk_size];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            streaming.update(&buf[..n]);
        }
        Ok(streaming.finalize())
    }
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
        let stale = CacheKey {
            mtime: 9999,
            ..key
        };
        assert!(cache.get(&stale).is_none());
    }

    #[test]
    fn chunked_reads_match_single_read() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("big.bin");
        let payload: Vec<u8> = (0..(3 * DEFAULT_CHUNK_SIZE)).map(|i| (i % 251) as u8).collect();
        fs::write(&p, &payload).unwrap();

        let big = Hasher::new().hash_file(&p).unwrap();
        let small = Hasher::new()
            .with_chunk_size(64 * 1024)
            .hash_file(&p)
            .unwrap();
        assert_eq!(big.blake3, small.blake3);
        assert_eq!(big.size, payload.len() as u64);
    }
}
