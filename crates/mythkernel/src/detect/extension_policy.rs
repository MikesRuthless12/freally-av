//! TASK-228 — Per-extension scan policy.
//!
//! Lets users (and Settings → Performance) configure per-extension
//! scan-depth rules: which file types get the full hash + detect
//! pipeline, which skip straight to "clean", which trigger an
//! archive-expand pass (TASK-233), etc. Layered on top of the
//! existing exclusions matcher — extension policy is a coarser,
//! cheaper pre-filter that runs BEFORE the path/glob exclusions
//! consult the DB.
//!
//! Defaults are conservative: every extension goes through the full
//! pipeline. Skipping is opt-in.

use std::collections::HashMap;

/// Per-extension scan policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionPolicy {
    /// Full hash + detect pipeline (default).
    Full,
    /// Hash but skip YARA (fast for known-uninteresting bulk data).
    HashOnly,
    /// Skip entirely (emit `source=ext-skip` clean shortcut).
    Skip,
    /// Archive — recurse via the archive expander (TASK-233).
    Archive,
}

/// Lookup table mapping extension (lowercase, no leading dot) to a
/// policy. Missing entries default to [`ExtensionPolicy::Full`].
#[derive(Debug, Clone, Default)]
pub struct ExtensionPolicyMap {
    inner: HashMap<String, ExtensionPolicy>,
}

impl ExtensionPolicyMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct with the bundled defaults. Bundles cover the safe
    /// archive set (zip / tar / gz / 7z / rar / xz / bz2) marked as
    /// Archive, and a handful of obviously-skippable bulk extensions
    /// (log / tmp / bak / swp / part) marked as Skip.
    pub fn with_defaults() -> Self {
        let mut m = Self::new();
        for ext in &[
            "zip", "tar", "gz", "tgz", "7z", "rar", "xz", "bz2", "tbz2", "lz", "lzma", "zst",
            "zstd", "jar", "war", "ear", "apk", "ipa", "deb", "rpm",
        ] {
            m.inner.insert((*ext).into(), ExtensionPolicy::Archive);
        }
        for ext in &[
            "log",
            "tmp",
            "bak",
            "swp",
            "part",
            "crdownload",
            "download",
            "lock",
        ] {
            m.inner.insert((*ext).into(), ExtensionPolicy::Skip);
        }
        m
    }

    pub fn set(&mut self, ext: &str, policy: ExtensionPolicy) {
        self.inner.insert(ext.to_ascii_lowercase(), policy);
    }

    /// Look up the policy for a file extension (no leading dot, any
    /// case). Returns `Full` when the extension isn't configured.
    pub fn lookup(&self, ext: &str) -> ExtensionPolicy {
        self.inner
            .get(&ext.to_ascii_lowercase())
            .copied()
            .unwrap_or(ExtensionPolicy::Full)
    }

    /// Look up by full path. Convenience wrapper over [`Self::lookup`]
    /// that extracts the extension. Returns `Full` when the path has
    /// no extension.
    pub fn lookup_path(&self, path: &std::path::Path) -> ExtensionPolicy {
        match path.extension().and_then(|e| e.to_str()) {
            Some(e) => self.lookup(e),
            None => ExtensionPolicy::Full,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn unconfigured_ext_defaults_to_full() {
        let m = ExtensionPolicyMap::new();
        assert_eq!(m.lookup("exe"), ExtensionPolicy::Full);
        assert_eq!(
            m.lookup_path(&PathBuf::from("foo.exe")),
            ExtensionPolicy::Full
        );
    }

    #[test]
    fn defaults_classify_archives_and_skippables() {
        let m = ExtensionPolicyMap::with_defaults();
        assert_eq!(m.lookup("zip"), ExtensionPolicy::Archive);
        assert_eq!(
            m.lookup("ZIP"),
            ExtensionPolicy::Archive,
            "case-insensitive"
        );
        assert_eq!(m.lookup("log"), ExtensionPolicy::Skip);
        assert_eq!(m.lookup("tmp"), ExtensionPolicy::Skip);
        assert_eq!(m.lookup("exe"), ExtensionPolicy::Full);
    }

    #[test]
    fn set_overrides_default() {
        let mut m = ExtensionPolicyMap::with_defaults();
        // User decides to scan their `.log` files after all.
        m.set("log", ExtensionPolicy::Full);
        assert_eq!(m.lookup("log"), ExtensionPolicy::Full);
    }

    #[test]
    fn lookup_path_handles_no_extension() {
        let m = ExtensionPolicyMap::with_defaults();
        assert_eq!(
            m.lookup_path(&PathBuf::from("/usr/bin/ls")),
            ExtensionPolicy::Full
        );
    }

    #[test]
    fn lookup_path_normalises_case() {
        let m = ExtensionPolicyMap::with_defaults();
        assert_eq!(
            m.lookup_path(&PathBuf::from("/tmp/archive.ZIP")),
            ExtensionPolicy::Archive
        );
    }
}
