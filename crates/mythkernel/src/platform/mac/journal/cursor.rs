//! Per-watch FSEvents stream cursor — vendored from Sourcerer.
//!
//! Cursors live under `~/Library/Application Support/Mythodikal/journal/<root_hash>.json`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamCursor {
    pub root: PathBuf,
    pub device: u64,
    pub last_event_id: u64,
    pub fs_name: String,
    pub bootstrap_complete: bool,
}

impl StreamCursor {
    pub fn default_root() -> PathBuf {
        if let Some(home) = std::env::var_os("HOME") {
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("Mythodikal")
                .join("journal")
        } else {
            std::env::temp_dir().join("Mythodikal").join("journal")
        }
    }

    pub fn path_in(cursor_root: &Path, watch_root: &Path) -> PathBuf {
        cursor_root.join(format!("{}.json", stable_key(watch_root)))
    }

    pub fn load(cursor_root: &Path, watch_root: &Path) -> Result<Option<Self>, CursorError> {
        let path = Self::path_in(cursor_root, watch_root);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(CursorError::Io(e)),
        };
        let cursor: Self = serde_json::from_slice(&bytes)?;
        if cursor.root != watch_root {
            tracing::info!(
                file = %path.display(),
                stored = %cursor.root.display(),
                requested = %watch_root.display(),
                "cursor file's stored root does not match requested watch root \
                 (FNV-1a collision); discarding cursor",
            );
            return Ok(None);
        }
        Ok(Some(cursor))
    }

    pub fn save(&self, cursor_root: &Path) -> Result<(), CursorError> {
        std::fs::create_dir_all(cursor_root)?;
        let path = Self::path_in(cursor_root, &self.root);
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self)?;
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }
}

fn stable_key(path: &Path) -> String {
    let s = path.to_string_lossy();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

#[derive(Debug, thiserror::Error)]
pub enum CursorError {
    #[error("cursor I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("cursor JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StreamCursor {
        StreamCursor {
            root: PathBuf::from("/Users/alice/Documents"),
            device: 0x0123_4567_89AB_CDEF,
            last_event_id: 0xDEAD_BEEF_CAFE_F00D,
            fs_name: "apfs".to_string(),
            bootstrap_complete: true,
        }
    }

    #[test]
    fn round_trip_through_json() {
        let c = sample();
        let bytes = serde_json::to_vec(&c).unwrap();
        let back: StreamCursor = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn save_then_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let c = sample();
        c.save(dir.path()).unwrap();
        let loaded = StreamCursor::load(dir.path(), &c.root).unwrap().unwrap();
        assert_eq!(c, loaded);
    }

    #[test]
    fn load_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = StreamCursor::load(dir.path(), Path::new("/some/missing")).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn load_discards_cursor_when_root_mismatches() {
        let dir = tempfile::tempdir().unwrap();
        let requested = PathBuf::from("/Users/alice/Documents");
        let stored = StreamCursor {
            root: PathBuf::from("/Users/bob/SomethingElse"),
            ..sample()
        };
        let file_path = StreamCursor::path_in(dir.path(), &requested);
        std::fs::write(&file_path, serde_json::to_vec(&stored).unwrap()).unwrap();

        let loaded = StreamCursor::load(dir.path(), &requested).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn cursor_path_uses_stable_key() {
        let p1 = StreamCursor::path_in(Path::new("/cursors"), Path::new("/Users/alice/Documents"));
        let p2 = StreamCursor::path_in(Path::new("/cursors"), Path::new("/Users/alice/Documents"));
        let p3 = StreamCursor::path_in(Path::new("/cursors"), Path::new("/Users/alice/Pictures"));
        assert_eq!(p1, p2);
        assert_ne!(p1, p3);
        assert!(p1.to_string_lossy().ends_with(".json"));
    }

    #[test]
    fn stable_key_is_16_hex_chars_and_deterministic_within_a_run() {
        let k = stable_key(Path::new("/Users/alice/Documents"));
        assert_eq!(k.len(), 16);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(k, stable_key(Path::new("/Users/alice/Documents")));
    }
}
