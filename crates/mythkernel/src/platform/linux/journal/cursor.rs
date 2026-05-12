//! Per-watch Linux cursor — vendored from Sourcerer.
//!
//! Cursors live under `$XDG_DATA_HOME/mythodikal/journal/<root_hash>.json`
//! (defaults to `~/.local/share/mythodikal/journal/`).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WatchBackend {
    Inotify,
    Fanotify,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchCursor {
    pub root: PathBuf,
    pub device: u64,
    pub fs_name: String,
    pub backend: WatchBackend,
    pub bootstrap_complete: bool,
    pub last_event_time_ns: i128,
}

impl WatchCursor {
    pub fn default_root() -> PathBuf {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            return PathBuf::from(xdg).join("mythodikal").join("journal");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("mythodikal")
                .join("journal");
        }
        std::env::temp_dir().join("mythodikal").join("journal")
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

    fn sample() -> WatchCursor {
        WatchCursor {
            root: PathBuf::from("/home/alice/Documents"),
            device: 0x0123_4567_89AB_CDEF,
            fs_name: "ext4".to_string(),
            backend: WatchBackend::Inotify,
            bootstrap_complete: true,
            last_event_time_ns: 1_700_000_000_000_000_000,
        }
    }

    #[test]
    fn round_trip_through_json() {
        let c = sample();
        let bytes = serde_json::to_vec(&c).unwrap();
        let back: WatchCursor = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn save_then_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let c = sample();
        c.save(dir.path()).unwrap();
        let loaded = WatchCursor::load(dir.path(), &c.root).unwrap().unwrap();
        assert_eq!(c, loaded);
    }

    #[test]
    fn load_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = WatchCursor::load(dir.path(), Path::new("/missing/root")).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn load_discards_cursor_when_root_mismatches() {
        let dir = tempfile::tempdir().unwrap();
        let requested = PathBuf::from("/home/alice/Documents");
        let stored = WatchCursor {
            root: PathBuf::from("/home/bob/SomethingElse"),
            ..sample()
        };
        let file_path = WatchCursor::path_in(dir.path(), &requested);
        std::fs::write(&file_path, serde_json::to_vec(&stored).unwrap()).unwrap();

        let loaded = WatchCursor::load(dir.path(), &requested).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn cursor_path_uses_stable_key() {
        let p1 = WatchCursor::path_in(Path::new("/cursors"), Path::new("/home/alice/Documents"));
        let p2 = WatchCursor::path_in(Path::new("/cursors"), Path::new("/home/alice/Documents"));
        let p3 = WatchCursor::path_in(Path::new("/cursors"), Path::new("/home/alice/Pictures"));
        assert_eq!(p1, p2);
        assert_ne!(p1, p3);
        assert!(p1.to_string_lossy().ends_with(".json"));
    }

    #[test]
    fn stable_key_is_16_hex_chars_and_deterministic_within_a_run() {
        let k = stable_key(Path::new("/home/alice/Documents"));
        assert_eq!(k.len(), 16);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(k, stable_key(Path::new("/home/alice/Documents")));
    }

    #[test]
    fn backend_serde_uses_lowercase_strings() {
        let json = serde_json::to_string(&WatchBackend::Inotify).unwrap();
        assert_eq!(json, "\"inotify\"");
        let json = serde_json::to_string(&WatchBackend::Fanotify).unwrap();
        assert_eq!(json, "\"fanotify\"");
    }
}
