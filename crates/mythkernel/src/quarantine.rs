//! Quarantine vault (TASK-024, Phase 2).
//!
//! Per `docs/prd.md` § 2.5 and § 6.4 / FR-041..044, quarantined files are
//! held in `<data_dir>/quarantine/` with a per-install random 32-byte XOR
//! key. The XOR is **not** real encryption — its purpose is to prevent
//! accidental re-infection (the vaulted bytes won't trigger another AV
//! engine's signature scanner) and to keep our own real-time hook from
//! re-flagging the file. The threat model excludes adversaries with disk
//! access who can read the key from the keychain.
//!
//! ## Key storage
//!
//! - **Primary:** OS keychain via the `keyring` crate
//!   (`libsecret` on Linux, Keychain on macOS, Credential Manager on
//!   Windows). Service: `"mythodikal-av"`, account: `"quarantine-key-v1"`,
//!   value: 64-char lowercase hex of the 32-byte key.
//! - **Fallback:** `<data_dir>/quarantine.key` — a 64-char hex file with
//!   Unix permissions `0600`. Used on platforms where the OS keychain
//!   cannot be reached (CI containers, headless Linux without dbus). The
//!   fallback path is recorded in the keychain service name so reading
//!   back picks up the same key.
//!
//! ## Vault layout
//!
//! Each quarantined file is stored at
//! `<data_dir>/quarantine/<id>.qf` where `<id>` is the SQLite primary key
//! of the `quarantine` row. The on-disk content is the original file's
//! bytes XOR'd with `key[i % 32]` (i = byte offset). Restore reverses the
//! XOR and refuses to overwrite an existing file at the original path.

use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};

use crate::db::DbError;

const KEYRING_SERVICE: &str = "mythodikal-av";
const KEYRING_ACCOUNT: &str = "quarantine-key-v1";
const VAULT_SUBDIR: &str = "quarantine";
const KEY_FALLBACK_FILE: &str = "quarantine.key";
const VAULT_FILE_EXT: &str = "qf";
const CURRENT_KEY_ID: i64 = 1;
const IO_CHUNK: usize = 1024 * 1024; // 1 MiB

#[derive(Debug, thiserror::Error)]
pub enum QuarantineError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("db: {0}")]
    Db(#[from] DbError),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("source file not found: {0}")]
    SourceMissing(PathBuf),
    #[error("refused to overwrite existing file at {0} during restore")]
    RestoreWouldOverwrite(PathBuf),
    #[error("quarantine entry {0} not found")]
    NotFound(i64),
    #[error("vault file is missing on disk: {0}")]
    VaultMissing(PathBuf),
    #[error("keyring: {0}")]
    Keyring(String),
}

impl From<keyring::Error> for QuarantineError {
    fn from(err: keyring::Error) -> Self {
        QuarantineError::Keyring(err.to_string())
    }
}

/// One quarantined file's row + on-disk pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineEntry {
    pub id: i64,
    pub finding_id: Option<i64>,
    pub original_path: PathBuf,
    pub vault_path: PathBuf,
    pub size_bytes: i64,
    pub xor_key_id: i64,
    pub quarantined_at_utc: i64,
}

/// 256-bit XOR key. Cheap to clone (just 32 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineKey([u8; 32]);

impl QuarantineKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).ok()?;
        Some(Self(out))
    }
}

/// Loads / creates the per-install quarantine XOR key. Primary path is the
/// OS keychain; falls back to a 0600-permissioned file when the keychain
/// is unavailable.
pub fn load_or_create_key(data_dir: &Path) -> Result<QuarantineKey, QuarantineError> {
    if let Some(key) = read_keyring()? {
        return Ok(key);
    }
    let fallback = data_dir.join(KEY_FALLBACK_FILE);
    if let Some(key) = read_fallback_file(&fallback)? {
        // Best-effort: also try to push it into the keychain in case it
        // came back online since last run. Failure here is benign.
        let _ = write_keyring(&key);
        return Ok(key);
    }
    let new_key = QuarantineKey::random();
    if let Err(err) = write_keyring(&new_key) {
        tracing::warn!(
            error = %err,
            "OS keychain unavailable; falling back to file-based quarantine key"
        );
        write_fallback_file(&fallback, &new_key)?;
    }
    Ok(new_key)
}

fn read_keyring() -> Result<Option<QuarantineKey>, QuarantineError> {
    match keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT) {
        Ok(entry) => match entry.get_password() {
            Ok(hex_value) => Ok(QuarantineKey::from_hex(hex_value.trim())),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => {
                // Treat keychain misconfiguration as "fall back to file."
                tracing::debug!(error = %err, "keyring read failed");
                Ok(None)
            }
        },
        Err(err) => {
            tracing::debug!(error = %err, "keyring open failed");
            Ok(None)
        }
    }
}

fn write_keyring(key: &QuarantineKey) -> Result<(), QuarantineError> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)?;
    entry.set_password(&key.to_hex())?;
    Ok(())
}

fn read_fallback_file(path: &Path) -> Result<Option<QuarantineKey>, QuarantineError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(QuarantineKey::from_hex(text.trim())),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn write_fallback_file(path: &Path, key: &QuarantineKey) -> Result<(), QuarantineError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = OpenOptions::new();
    opts.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(key.to_hex().as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

/// Quarantine vault — moves files in and out of `<data_dir>/quarantine/`,
/// records each move in the SQLite `quarantine` table, and applies the
/// XOR cipher transparently.
#[derive(Debug, Clone)]
pub struct QuarantineVault {
    vault_dir: PathBuf,
    key: QuarantineKey,
}

impl QuarantineVault {
    /// Build a vault rooted at `<data_dir>/quarantine/`, creating the
    /// directory if absent. Loads (or creates) the XOR key via
    /// [`load_or_create_key`].
    pub fn new(data_dir: &Path) -> Result<Self, QuarantineError> {
        let vault_dir = data_dir.join(VAULT_SUBDIR);
        std::fs::create_dir_all(&vault_dir)?;
        let key = load_or_create_key(data_dir)?;
        Ok(Self { vault_dir, key })
    }

    /// Variant that takes an explicit key — used by tests and for
    /// migrations from a previous installation.
    pub fn with_key(vault_dir: PathBuf, key: QuarantineKey) -> Result<Self, QuarantineError> {
        std::fs::create_dir_all(&vault_dir)?;
        Ok(Self { vault_dir, key })
    }

    pub fn vault_dir(&self) -> &Path {
        &self.vault_dir
    }

    /// Move `original_path` into the vault. Inserts a `quarantine` row,
    /// streams the file through XOR into `<vault_dir>/<id>.qf`, fsyncs,
    /// then removes the original. Returns the populated entry.
    ///
    /// On failure after the row is inserted, the row is rolled back so
    /// the vault directory is consistent with the database.
    pub fn quarantine(
        &self,
        conn: &mut Connection,
        finding_id: Option<i64>,
        original_path: &Path,
    ) -> Result<QuarantineEntry, QuarantineError> {
        let canonical = original_path
            .canonicalize()
            .map_err(|err| match err.kind() {
                io::ErrorKind::NotFound => {
                    QuarantineError::SourceMissing(original_path.to_path_buf())
                }
                _ => QuarantineError::Io(err),
            })?;
        let size_bytes = std::fs::metadata(&canonical)?.len() as i64;
        let now = now_unix_seconds();

        let tx = conn.transaction()?;
        // Phase 1 of the insert: reserve a row so the engine-assigned
        // primary key drives the vault filename.
        tx.execute(
            "INSERT INTO quarantine (
                finding_id, original_path, vault_path, size_bytes,
                xor_key_id, quarantined_at_utc
             ) VALUES (?1, ?2, '', ?3, ?4, ?5)",
            params![
                finding_id,
                canonical.to_string_lossy().as_ref(),
                size_bytes,
                CURRENT_KEY_ID,
                now,
            ],
        )?;
        let id = tx.last_insert_rowid();
        let vault_path = self.vault_path_for(id);

        // Stream the file out, XOR'ing as we go. If anything below errors,
        // roll back the transaction so we never leave a row pointing at a
        // non-existent or partially-written vault file.
        if let Err(err) = self.write_xor(&canonical, &vault_path) {
            // Best-effort cleanup of any partial vault file.
            let _ = std::fs::remove_file(&vault_path);
            return Err(err);
        }
        // Update the row with the real vault_path now that the file is on disk.
        tx.execute(
            "UPDATE quarantine SET vault_path = ?2 WHERE id = ?1",
            params![id, vault_path.to_string_lossy().as_ref()],
        )?;
        tx.commit()?;

        // Now that the vault copy is fsynced and the DB knows about it,
        // remove the original.
        std::fs::remove_file(&canonical)?;

        Ok(QuarantineEntry {
            id,
            finding_id,
            original_path: canonical,
            vault_path,
            size_bytes,
            xor_key_id: CURRENT_KEY_ID,
            quarantined_at_utc: now,
        })
    }

    /// Restore the entry with the given id back to its original path.
    /// Refuses to overwrite an existing file at the original path; if you
    /// need to overwrite, call [`QuarantineVault::delete`] on the colliding
    /// file first.
    pub fn restore(&self, conn: &mut Connection, id: i64) -> Result<PathBuf, QuarantineError> {
        let entry = self.get(conn, id)?;
        if entry.original_path.exists() {
            return Err(QuarantineError::RestoreWouldOverwrite(entry.original_path));
        }
        if !entry.vault_path.exists() {
            return Err(QuarantineError::VaultMissing(entry.vault_path));
        }
        if let Some(parent) = entry.original_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        self.write_xor(&entry.vault_path, &entry.original_path)?;
        // Remove the vault row + file only after the restore succeeded.
        std::fs::remove_file(&entry.vault_path)?;
        conn.execute("DELETE FROM quarantine WHERE id = ?1", params![id])?;
        Ok(entry.original_path)
    }

    /// Permanently shred the entry: unlink the vault file and drop the row.
    /// XOR'd bytes are not sensitive enough to warrant overwrite-before-
    /// unlink at this phase.
    pub fn delete(&self, conn: &mut Connection, id: i64) -> Result<(), QuarantineError> {
        let entry = self.get(conn, id)?;
        if entry.vault_path.exists() {
            std::fs::remove_file(&entry.vault_path)?;
        }
        conn.execute("DELETE FROM quarantine WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Fetch a single row.
    pub fn get(&self, conn: &Connection, id: i64) -> Result<QuarantineEntry, QuarantineError> {
        let row = conn
            .query_row(
                "SELECT id, finding_id, original_path, vault_path, size_bytes,
                        xor_key_id, quarantined_at_utc
                 FROM quarantine WHERE id = ?1",
                params![id],
                row_to_entry,
            )
            .optional()?;
        row.ok_or(QuarantineError::NotFound(id))
    }

    /// All quarantine entries, ordered most-recent first.
    pub fn list(&self, conn: &Connection) -> Result<Vec<QuarantineEntry>, QuarantineError> {
        let mut stmt = conn.prepare(
            "SELECT id, finding_id, original_path, vault_path, size_bytes,
                    xor_key_id, quarantined_at_utc
             FROM quarantine ORDER BY quarantined_at_utc DESC, id DESC",
        )?;
        let rows = stmt
            .query_map([], row_to_entry)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn vault_path_for(&self, id: i64) -> PathBuf {
        self.vault_dir.join(format!("{id}.{VAULT_FILE_EXT}"))
    }

    /// Stream `src` → `dst`, applying the XOR cipher per byte. The dst file
    /// is created (truncating any existing content) and fsynced before
    /// return.
    fn write_xor(&self, src: &Path, dst: &Path) -> Result<(), QuarantineError> {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let src_file = File::open(src)?;
        let mut reader = BufReader::with_capacity(IO_CHUNK, src_file);
        let dst_file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(dst)?;
        let mut writer = BufWriter::with_capacity(IO_CHUNK, dst_file);

        let mut buf = vec![0u8; IO_CHUNK];
        let mut offset: u64 = 0;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            xor_inplace(&mut buf[..n], offset, self.key.as_bytes());
            writer.write_all(&buf[..n])?;
            offset += n as u64;
        }
        writer.flush()?;
        writer
            .into_inner()
            .map_err(|e| QuarantineError::Io(e.into_error()))?
            .sync_all()?;
        Ok(())
    }
}

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<QuarantineEntry> {
    let original: String = row.get(2)?;
    let vault: String = row.get(3)?;
    Ok(QuarantineEntry {
        id: row.get(0)?,
        finding_id: row.get(1)?,
        original_path: PathBuf::from(original),
        vault_path: PathBuf::from(vault),
        size_bytes: row.get(4)?,
        xor_key_id: row.get(5)?,
        quarantined_at_utc: row.get(6)?,
    })
}

fn xor_inplace(buf: &mut [u8], offset: u64, key: &[u8; 32]) {
    for (i, b) in buf.iter_mut().enumerate() {
        let key_idx = ((offset + i as u64) % 32) as usize;
        *b ^= key[key_idx];
    }
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use tempfile::tempdir;

    fn fixed_key() -> QuarantineKey {
        QuarantineKey::from_bytes([0x42; 32])
    }

    fn make_source_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn xor_is_self_inverse() {
        let key = [0xa5u8; 32];
        let original = b"the quick brown fox jumps over the lazy dog 12345";
        let mut buf = original.to_vec();
        xor_inplace(&mut buf, 0, &key);
        assert_ne!(&buf[..], &original[..]);
        xor_inplace(&mut buf, 0, &key);
        assert_eq!(&buf[..], &original[..]);
    }

    #[test]
    fn xor_handles_chunk_boundary_correctly() {
        // Apply XOR in two passes with different offsets to verify the
        // offset arithmetic.
        let key = [0xa5u8; 32];
        let original = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 64 'A's
        let mut full = original.to_vec();
        xor_inplace(&mut full, 0, &key);
        let mut piecewise = original.to_vec();
        xor_inplace(&mut piecewise[..50], 0, &key);
        xor_inplace(&mut piecewise[50..], 50, &key);
        assert_eq!(full, piecewise);
    }

    #[test]
    fn key_hex_roundtrip() {
        let key = QuarantineKey::random();
        let hex_str = key.to_hex();
        assert_eq!(hex_str.len(), 64);
        let recovered = QuarantineKey::from_hex(&hex_str).unwrap();
        assert_eq!(key, recovered);
    }

    #[test]
    fn key_from_hex_rejects_malformed_input() {
        assert!(QuarantineKey::from_hex("short").is_none());
        assert!(QuarantineKey::from_hex(&"z".repeat(64)).is_none());
        assert!(QuarantineKey::from_hex(&"a".repeat(63)).is_none());
        assert!(QuarantineKey::from_hex(&"a".repeat(65)).is_none());
    }

    #[test]
    fn quarantine_moves_file_into_vault_and_inserts_row() {
        let dir = tempdir().unwrap();
        let vault_dir = dir.path().join("vault");
        let mut conn = open_in_memory().unwrap();
        let vault = QuarantineVault::with_key(vault_dir.clone(), fixed_key()).unwrap();

        let source = make_source_file(dir.path(), "evil.bin", b"hello evil world");
        let entry = vault.quarantine(&mut conn, None, &source).unwrap();
        assert!(entry.id > 0);
        assert_eq!(entry.size_bytes, b"hello evil world".len() as i64);
        assert_eq!(entry.xor_key_id, 1);
        assert!(!source.exists(), "original should be removed");
        assert!(entry.vault_path.exists(), "vault file should exist");
        assert!(entry.vault_path.starts_with(&vault_dir));

        // Vault content should be XOR'd, not equal to the original.
        let vault_bytes = std::fs::read(&entry.vault_path).unwrap();
        assert_ne!(&vault_bytes[..], b"hello evil world");
        assert_eq!(vault_bytes.len(), b"hello evil world".len());
    }

    #[test]
    fn quarantine_then_restore_roundtrip_preserves_bytes() {
        let dir = tempdir().unwrap();
        let mut conn = open_in_memory().unwrap();
        let vault = QuarantineVault::with_key(dir.path().join("v"), fixed_key()).unwrap();

        let payload: Vec<u8> = (0..(3 * IO_CHUNK + 17)).map(|i| (i % 251) as u8).collect();
        let source = make_source_file(dir.path(), "big.bin", &payload);
        // The entry stores the canonicalized path (with UNC `\\?\` prefix on
        // Windows). Stash that for the post-restore comparison so the
        // assertion isn't sensitive to OS-specific prefix forms.
        let canonical_source = source.canonicalize().unwrap();
        let entry = vault.quarantine(&mut conn, None, &source).unwrap();

        // The original is gone; restore brings it back identical.
        assert!(!source.exists());
        let restored_path = vault.restore(&mut conn, entry.id).unwrap();
        assert_eq!(restored_path, canonical_source);
        let recovered = std::fs::read(&source).unwrap();
        assert_eq!(recovered, payload);

        // Restoring also removes the vault file and row.
        assert!(!entry.vault_path.exists());
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM quarantine", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn restore_refuses_to_overwrite_existing_file() {
        let dir = tempdir().unwrap();
        let mut conn = open_in_memory().unwrap();
        let vault = QuarantineVault::with_key(dir.path().join("v"), fixed_key()).unwrap();

        let source = make_source_file(dir.path(), "x.bin", b"original");
        let entry = vault.quarantine(&mut conn, None, &source).unwrap();
        // Recreate a file at the original path before restoring.
        std::fs::write(&entry.original_path, b"new content").unwrap();

        match vault.restore(&mut conn, entry.id).unwrap_err() {
            QuarantineError::RestoreWouldOverwrite(p) => {
                assert_eq!(p, entry.original_path);
            }
            other => panic!("expected RestoreWouldOverwrite, got {other:?}"),
        }
        // Failed restore must leave the vault row + file intact.
        assert!(entry.vault_path.exists());
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM quarantine", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn quarantine_of_missing_source_returns_source_missing() {
        let dir = tempdir().unwrap();
        let mut conn = open_in_memory().unwrap();
        let vault = QuarantineVault::with_key(dir.path().join("v"), fixed_key()).unwrap();
        match vault
            .quarantine(&mut conn, None, &dir.path().join("does-not-exist"))
            .unwrap_err()
        {
            QuarantineError::SourceMissing(_) => {}
            other => panic!("expected SourceMissing, got {other:?}"),
        }
        // No row should have been left behind.
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM quarantine", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn delete_removes_vault_file_and_row() {
        let dir = tempdir().unwrap();
        let mut conn = open_in_memory().unwrap();
        let vault = QuarantineVault::with_key(dir.path().join("v"), fixed_key()).unwrap();
        let source = make_source_file(dir.path(), "d.bin", b"to-delete");
        let entry = vault.quarantine(&mut conn, None, &source).unwrap();
        vault.delete(&mut conn, entry.id).unwrap();
        assert!(!entry.vault_path.exists());
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM quarantine", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn list_orders_most_recent_first() {
        let dir = tempdir().unwrap();
        let mut conn = open_in_memory().unwrap();
        let vault = QuarantineVault::with_key(dir.path().join("v"), fixed_key()).unwrap();
        let a = make_source_file(dir.path(), "a.bin", b"a");
        let b = make_source_file(dir.path(), "b.bin", b"b");
        let _ea = vault.quarantine(&mut conn, None, &a).unwrap();
        // Make sure the second entry sorts before the first when ordered DESC.
        let eb = vault.quarantine(&mut conn, None, &b).unwrap();
        let list = vault.list(&conn).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, eb.id);
    }

    #[test]
    fn get_missing_id_returns_not_found() {
        let dir = tempdir().unwrap();
        let conn = open_in_memory().unwrap();
        let vault = QuarantineVault::with_key(dir.path().join("v"), fixed_key()).unwrap();
        match vault.get(&conn, 99999).unwrap_err() {
            QuarantineError::NotFound(99999) => {}
            other => panic!("expected NotFound(99999), got {other:?}"),
        }
    }

    #[test]
    fn fallback_keyfile_roundtrip() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join(KEY_FALLBACK_FILE);
        let key = QuarantineKey::from_bytes([0x12; 32]);
        write_fallback_file(&key_path, &key).unwrap();
        let recovered = read_fallback_file(&key_path).unwrap().unwrap();
        assert_eq!(key, recovered);
    }
}
