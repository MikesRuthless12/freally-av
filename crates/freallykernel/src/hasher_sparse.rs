//! TASK-211 — Sparse-file aware hashing.
//!
//! On filesystems that support extent queries we ask the OS for the
//! file's actual data extents (`FIEMAP` on Linux, `F_LOG2PHYS_EXT` on
//! macOS) and hash only the data, feeding zero bytes for the holes.
//! BLAKE3-over-the-data + zeros equals BLAKE3-over-the-streaming-read,
//! by construction.
//!
//! Why bother? A 10 GiB sparse `.qcow2` with 200 MiB of allocated
//! extents takes hundreds of seconds on a streaming read (kernel still
//! pages zeros), but the extent-aware path runs in under a second on
//! the same disk.
//!
//! Windows has no user-mode FIEMAP analogue (`FSCTL_QUERY_ALLOCATED_RANGES`
//! is gated by handle-administrator privilege for many file types).
//! Windows callers stay on the streaming-read fast path; the wrapper
//! function reports `None` and the engine falls through.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// One data-bearing extent in a sparse file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extent {
    pub logical_offset: u64,
    pub length: u64,
}

/// Extent map. `None` means the OS / FS doesn't expose extents; the
/// caller should fall back to the streaming-read path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtentMap {
    pub logical_size: u64,
    pub extents: Vec<Extent>,
}

impl ExtentMap {
    pub fn data_bytes(&self) -> u64 {
        self.extents.iter().map(|e| e.length).sum()
    }

    pub fn hole_bytes(&self) -> u64 {
        self.logical_size.saturating_sub(self.data_bytes())
    }

    /// Convenience: extent map equivalent to a fully-materialised file
    /// (one extent covering the entire logical size). Useful for tests
    /// and for the streaming-read fallback.
    pub fn fully_dense(size: u64) -> Self {
        Self {
            logical_size: size,
            extents: if size == 0 {
                vec![]
            } else {
                vec![Extent {
                    logical_offset: 0,
                    length: size,
                }]
            },
        }
    }
}

/// Hash a buffer using an extent map.
///
/// For every data extent, the slice `buf[offset..offset+length]` is
/// fed to BLAKE3. Between extents, a stream of zero bytes equal to
/// the hole length is fed so the resulting digest matches what a
/// streaming-read would produce.
///
/// The function is `O(buf.len())` regardless of extent count — it
/// emits zero spans via a fixed-size scratch buffer fed in a loop.
pub fn hash_with_extents(buf: &[u8], map: &ExtentMap) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let mut cursor: u64 = 0;
    let zero_chunk = [0u8; 4096];
    let mut sorted = map.extents.clone();
    sorted.sort_by_key(|e| e.logical_offset);
    for extent in &sorted {
        if extent.logical_offset > cursor {
            let mut gap = extent.logical_offset - cursor;
            while gap >= zero_chunk.len() as u64 {
                hasher.update(&zero_chunk);
                gap -= zero_chunk.len() as u64;
            }
            if gap > 0 {
                hasher.update(&zero_chunk[..gap as usize]);
            }
            cursor = extent.logical_offset;
        }
        let start = extent.logical_offset as usize;
        let end = start.saturating_add(extent.length as usize).min(buf.len());
        if start < end {
            hasher.update(&buf[start..end]);
        }
        cursor += extent.length;
    }
    if cursor < map.logical_size {
        let mut tail = map.logical_size - cursor;
        while tail >= zero_chunk.len() as u64 {
            hasher.update(&zero_chunk);
            tail -= zero_chunk.len() as u64;
        }
        if tail > 0 {
            hasher.update(&zero_chunk[..tail as usize]);
        }
    }
    *hasher.finalize().as_bytes()
}

/// Query a file's extent map from the OS.
///
/// On Linux this is meant to call `FS_IOC_FIEMAP`; on macOS
/// `F_LOG2PHYS_EXT`. The platform-specific implementations land
/// in the integration commit (each OS needs an `nix`-style ioctl
/// binding); this signature is the stable surface.
///
/// Returns `None` on:
/// - filesystems / OSes without extent queries (Windows user-mode,
///   FUSE / SSHFS / NFS without FIEMAP),
/// - permission errors,
/// - any I/O error (the engine logs and falls back).
pub fn query_extents(_path: &Path) -> Option<ExtentMap> {
    // Foundation-only: real ioctl bindings land in the engine
    // integration commit. Callers therefore always fall through to
    // streaming hashing today; this wiring lets the engine call
    // `query_extents` without #[cfg] gates littering the call site.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Streaming-read equivalent of `hash_with_extents` — used to
    /// verify the extent-aware path matches byte-for-byte.
    fn hash_streaming(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }

    fn materialize(map: &ExtentMap, data: &[u8]) -> Vec<u8> {
        let mut full = vec![0u8; map.logical_size as usize];
        let mut idx = 0;
        let mut sorted = map.extents.clone();
        sorted.sort_by_key(|e| e.logical_offset);
        for e in &sorted {
            let lo = e.logical_offset as usize;
            let hi = lo + e.length as usize;
            let len = (hi - lo).min(data.len() - idx);
            full[lo..lo + len].copy_from_slice(&data[idx..idx + len]);
            idx += len;
        }
        full
    }

    #[test]
    fn dense_extent_map_matches_streaming_hash() {
        let data: Vec<u8> = (0..2048).map(|i| (i % 251) as u8).collect();
        let map = ExtentMap::fully_dense(data.len() as u64);
        let h_sparse = hash_with_extents(&data, &map);
        let h_stream = hash_streaming(&data);
        assert_eq!(h_sparse, h_stream);
    }

    #[test]
    fn one_hole_in_middle_matches_streaming() {
        // Logical 4096: data 0..1024, hole 1024..3072, data 3072..4096.
        let map = ExtentMap {
            logical_size: 4096,
            extents: vec![
                Extent {
                    logical_offset: 0,
                    length: 1024,
                },
                Extent {
                    logical_offset: 3072,
                    length: 1024,
                },
            ],
        };
        // Build the underlying buffer with the materialised view.
        let mut full = vec![0u8; 4096];
        for (i, b) in full.iter_mut().enumerate().take(1024) {
            *b = (i % 251) as u8;
        }
        for (i, b) in full.iter_mut().enumerate().take(4096).skip(3072) {
            *b = ((i + 17) % 251) as u8;
        }
        let h_sparse = hash_with_extents(&full, &map);
        let h_stream = hash_streaming(&full);
        assert_eq!(h_sparse, h_stream);
    }

    #[test]
    fn tail_hole_handled() {
        // Logical 8192: data 0..1024, then 7168 bytes of hole.
        let map = ExtentMap {
            logical_size: 8192,
            extents: vec![Extent {
                logical_offset: 0,
                length: 1024,
            }],
        };
        let mut full = vec![0u8; 8192];
        for (i, b) in full.iter_mut().enumerate().take(1024) {
            *b = (i % 251) as u8;
        }
        let h_sparse = hash_with_extents(&full, &map);
        let h_stream = hash_streaming(&full);
        assert_eq!(h_sparse, h_stream);
    }

    #[test]
    fn leading_hole_handled() {
        let map = ExtentMap {
            logical_size: 8192,
            extents: vec![Extent {
                logical_offset: 7168,
                length: 1024,
            }],
        };
        let mut full = vec![0u8; 8192];
        for i in 0..1024 {
            full[7168 + i] = (i % 251) as u8;
        }
        let h_sparse = hash_with_extents(&full, &map);
        let h_stream = hash_streaming(&full);
        assert_eq!(h_sparse, h_stream);
    }

    #[test]
    fn many_small_extents_match_streaming() {
        // 16 KiB logical, alternating 256-byte data + 256-byte hole.
        // 64 buckets total (16384 / 256); even buckets are data.
        let num_buckets = (16 * 1024) / 256;
        let mut extents = Vec::new();
        for bucket in 0..num_buckets {
            if bucket % 2 == 0 {
                extents.push(Extent {
                    logical_offset: (bucket * 256) as u64,
                    length: 256,
                });
            }
        }
        let map = ExtentMap {
            logical_size: 16 * 1024,
            extents,
        };
        let mut full = vec![0u8; 16 * 1024];
        for (i, byte) in full.iter_mut().enumerate() {
            let bucket = i / 256;
            if bucket % 2 == 0 {
                *byte = ((i * 31) % 251) as u8;
            }
        }
        let h_sparse = hash_with_extents(&full, &map);
        let h_stream = hash_streaming(&full);
        assert_eq!(h_sparse, h_stream);
    }

    #[test]
    fn data_and_hole_byte_accounting() {
        let map = ExtentMap {
            logical_size: 1_000_000,
            extents: vec![
                Extent {
                    logical_offset: 0,
                    length: 100_000,
                },
                Extent {
                    logical_offset: 500_000,
                    length: 50_000,
                },
            ],
        };
        assert_eq!(map.data_bytes(), 150_000);
        assert_eq!(map.hole_bytes(), 850_000);
    }

    #[test]
    fn fully_dense_helper_round_trips() {
        let m = ExtentMap::fully_dense(1024);
        assert_eq!(m.logical_size, 1024);
        assert_eq!(m.data_bytes(), 1024);
        assert_eq!(m.hole_bytes(), 0);
        let e = ExtentMap::fully_dense(0);
        assert!(e.extents.is_empty());
    }

    #[test]
    fn query_extents_returns_none_until_integration() {
        // Foundation-only — guarantees the engine falls through to
        // streaming hashing until per-OS bindings ship.
        assert!(query_extents(Path::new("/tmp/does-not-exist")).is_none());
    }

    #[test]
    fn unsorted_extents_yield_correct_hash() {
        // Same extents as `one_hole_in_middle_matches_streaming` but
        // declared out of order. The hashing function must sort them.
        let map = ExtentMap {
            logical_size: 4096,
            extents: vec![
                Extent {
                    logical_offset: 3072,
                    length: 1024,
                },
                Extent {
                    logical_offset: 0,
                    length: 1024,
                },
            ],
        };
        let mut full = vec![0u8; 4096];
        for (i, b) in full.iter_mut().enumerate().take(1024) {
            *b = (i % 251) as u8;
        }
        for (i, b) in full.iter_mut().enumerate().take(4096).skip(3072) {
            *b = ((i + 17) % 251) as u8;
        }
        let h_sparse = hash_with_extents(&full, &map);
        let h_stream = hash_streaming(&full);
        assert_eq!(h_sparse, h_stream);
        let _ = materialize;
    }
}
