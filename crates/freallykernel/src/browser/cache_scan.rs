//! Browser-cache YARA pass enumeration (TASK-260, FEAT-205, Phase 10 Wave 2).
//!
//! Opt-in cache walker for Chromium-family `Cache/Cache_Data/` and
//! Firefox `cache2/entries/`. Returns one [`CacheEntry`] per cached
//! resource on disk. The actual yara-x scan reuses the engine's
//! existing detector pipeline (`crate::detect::yara_engine`) — this
//! module supplies the iterator + the per-entry size cap honoring
//! (the same `BombGuard` shape TASK-085 used for archive members).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEntry {
    pub family: super::BrowserFamily,
    pub profile_path: PathBuf,
    pub entry_path: PathBuf,
    pub byte_size: u64,
}

/// Per-scan cap: skip entries larger than this. Default matches the
/// per-archive-member cap from TASK-085 (16 MiB).
pub const DEFAULT_MAX_ENTRY_BYTES: u64 = 16 * 1024 * 1024;

/// Enumerate every cache entry under the supplied browser roots.
/// Returns the union across each.
///
/// Opt-in only: callers in the engine must check
/// `Config::Scanning::scan_browser_cache` (default `false`) before
/// invoking. The walker itself does not consult config — it is a
/// pure iterator.
pub fn enumerate(roots: &super::BrowserRoots, max_entry_bytes: u64) -> Vec<CacheEntry> {
    let mut out = Vec::new();
    for (family, root) in roots.iter() {
        if family.is_chromium() {
            enumerate_chromium(family, root, max_entry_bytes, &mut out);
        } else if family == super::BrowserFamily::Firefox {
            enumerate_firefox(root, max_entry_bytes, &mut out);
        }
    }
    out
}

fn enumerate_chromium(
    family: super::BrowserFamily,
    user_data_root: &Path,
    cap: u64,
    out: &mut Vec<CacheEntry>,
) {
    for profile in super::chromium_profile_dirs(user_data_root) {
        let cache = profile.join("Cache").join("Cache_Data");
        push_files_under(family, &profile, &cache, cap, out);
        // Code cache is a sibling under modern Chromium; it carries
        // raw V8 byte-code blobs that yara-x can still inspect.
        let code_cache = profile.join("Code Cache").join("js");
        push_files_under(family, &profile, &code_cache, cap, out);
    }
}

fn enumerate_firefox(profiles_root: &Path, cap: u64, out: &mut Vec<CacheEntry>) {
    for profile in super::firefox_profile_dirs(profiles_root) {
        let cache = profile.join("cache2").join("entries");
        push_files_under(super::BrowserFamily::Firefox, &profile, &cache, cap, out);
    }
}

fn push_files_under(
    family: super::BrowserFamily,
    profile: &Path,
    dir: &Path,
    cap: u64,
    out: &mut Vec<CacheEntry>,
) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let size = meta.len();
        if size > cap {
            continue;
        }
        out.push(CacheEntry {
            family,
            profile_path: profile.to_path_buf(),
            entry_path: p,
            byte_size: size,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn chromium_cache_walker_yields_only_files_under_cap() {
        let dir = tempdir().unwrap();
        let user_data = dir.path();
        let profile = user_data.join("Default");
        let cache = profile.join("Cache/Cache_Data");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join("small.bin"), [0u8; 1024]).unwrap();
        std::fs::write(cache.join("large.bin"), vec![0u8; 32 * 1024]).unwrap();
        let roots = super::super::BrowserRoots {
            chrome: vec![user_data.to_path_buf()],
            ..Default::default()
        };
        // 2 KiB cap; only the 1 KiB file qualifies.
        let entries = enumerate(&roots, 2 * 1024);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].family, super::super::BrowserFamily::Chrome);
        assert_eq!(entries[0].byte_size, 1024);
    }

    #[test]
    fn firefox_cache_walker_reads_entries_dir() {
        let dir = tempdir().unwrap();
        let profiles_root = dir.path();
        let profile = profiles_root.join("abc.default-release");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::write(profile.join("prefs.js"), b"").unwrap();
        let entries_dir = profile.join("cache2/entries");
        std::fs::create_dir_all(&entries_dir).unwrap();
        std::fs::write(entries_dir.join("abc"), [0u8; 200]).unwrap();
        let roots = super::super::BrowserRoots {
            firefox: vec![profiles_root.to_path_buf()],
            ..Default::default()
        };
        let entries = enumerate(&roots, DEFAULT_MAX_ENTRY_BYTES);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].family, super::super::BrowserFamily::Firefox);
    }

    #[test]
    fn missing_cache_dir_is_silent() {
        let dir = tempdir().unwrap();
        let user_data = dir.path();
        std::fs::create_dir_all(user_data.join("Default")).unwrap();
        let roots = super::super::BrowserRoots {
            chrome: vec![user_data.to_path_buf()],
            ..Default::default()
        };
        assert!(enumerate(&roots, DEFAULT_MAX_ENTRY_BYTES).is_empty());
    }

    #[test]
    fn code_cache_js_dir_included() {
        let dir = tempdir().unwrap();
        let user_data = dir.path();
        let profile = user_data.join("Default");
        let cc = profile.join("Code Cache/js");
        std::fs::create_dir_all(&cc).unwrap();
        std::fs::write(cc.join("blob"), [0u8; 100]).unwrap();
        let roots = super::super::BrowserRoots {
            chrome: vec![user_data.to_path_buf()],
            ..Default::default()
        };
        let entries = enumerate(&roots, DEFAULT_MAX_ENTRY_BYTES);
        assert_eq!(entries.len(), 1);
    }
}
