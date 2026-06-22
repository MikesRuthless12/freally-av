//! Curated blacklist updater — repo-curated-DB distribution (2026-06-21).
//!
//! Part B of the repo-curated-DB decision: the app no longer pulls raw
//! hashes from `bazaar.abuse.ch` / ThreatFox at runtime. Instead it
//! downloads the maintainer-curated, YARA-refined, clean-room-labelled
//! SHA-256 blacklist that ships as a GitHub release asset and atomically
//! swaps it into `<feeds_dir>/abusech_sha256.bin` — the exact mmap'd
//! `MYTHHASH` file [`crate::detect::hash_blacklist::HashBlacklistDetector`]
//! reads. Disabling the upstream pull guarantees every user runs the same
//! curated, deduped, tested database (the product differentiator) rather
//! than the raw upstream feed.
//!
//! ## Integrity
//!
//! The asset is a prebuilt sorted-hash `.bin` (the same format
//! [`crate::detect::hash_set_file`] writes). On each run we:
//!
//!   1. fetch the published `…/abusech_sha256.bin.sha256` checksum manifest;
//!   2. short-circuit (no download) when the manifest digest matches the
//!      digest recorded for the currently-installed file (`<bin>.sha256`
//!      sidecar) — the FR-156 "unchanged" path, with no rate limit;
//!   3. stream the `.bin` to a temp file, hashing as we go, so we never
//!      buffer the whole ~1.7 GB set in RAM;
//!   4. reject on SHA-256 mismatch — a corrupted / MITM'd download never
//!      reaches the engine;
//!   5. validate that the temp file parses as a well-formed hash set
//!      ([`HashSetFile::open`]);
//!   6. atomically rename it over the live file (readers see the old or the
//!      new file, never a torn one) and persist the new sidecar digest.
//!
//! All transport is HTTPS-only (rustls) per `docs/prd.md` § 1.5.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use futures::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::detect::hash_set_file::{HashSetError, HashSetFile};

/// Curated blacklist `.bin` asset on the GitHub release. Pinned to the
/// data-release tag; bump on each curated-DB refresh (or override via
/// [`CuratedBlacklistUpdater::with_urls`]).
pub const DEFAULT_CURATED_BIN_URL: &str =
    "https://github.com/MikesRuthless12/mythodikal-av/releases/download/v0.7.14/abusech_sha256.bin";
/// SHA-256 checksum manifest for the asset above (sha256sum text format).
pub const DEFAULT_CURATED_SHA256_URL: &str = "https://github.com/MikesRuthless12/mythodikal-av/releases/download/v0.7.14/abusech_sha256.bin.sha256";

/// Filename the curated set installs as. Kept as `abusech_sha256.bin` so the
/// existing detector + pipeline wiring (which reads that exact path) is
/// unchanged — the *source* of the file changes, not its location.
pub const CURATED_BIN_FILENAME: &str = "abusech_sha256.bin";

const DEFAULT_USER_AGENT: &str =
    "Mythodikal-AV/0.7 (+https://github.com/MikesRuthless12/mythodikal-av)";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Emit a download-progress tick at most every 16 MiB.
const PROGRESS_STEP_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CuratedError {
    #[error("network: {0}")]
    Network(String),
    #[error("release returned HTTP {status} from {url}")]
    HttpStatus { status: u16, url: String },
    #[error("checksum manifest did not contain a sha256 for {0}")]
    BadManifest(String),
    #[error("sha256 mismatch: manifest {expected}, downloaded {actual}")]
    ChecksumMismatch { expected: String, actual: String },
    #[error("downloaded file is not a valid hash set: {0}")]
    BadBinFormat(#[from] HashSetError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<reqwest::Error> for CuratedError {
    fn from(err: reqwest::Error) -> Self {
        CuratedError::Network(err.to_string())
    }
}

/// Summary of one curated-update run.
#[derive(Debug, Clone)]
pub struct CuratedUpdateReport {
    /// Hashes in the installed set. `0` on the no-change path (see `changed`).
    pub entry_count: u64,
    /// Bytes downloaded this run. `0` on the no-change path.
    pub bytes_downloaded: u64,
    pub elapsed: Duration,
    /// True iff a new `.bin` was installed; false on the no-change path.
    pub changed: bool,
    /// SHA-256 (lowercase hex) of the installed / current `.bin`.
    pub sha256: String,
}

/// Downloads, verifies, and installs the curated blacklist `.bin`. Cheap to
/// clone; holds no live socket.
#[derive(Debug, Clone)]
pub struct CuratedBlacklistUpdater {
    bin_url: String,
    sha256_url: String,
    output_path: PathBuf,
    user_agent: String,
}

impl CuratedBlacklistUpdater {
    /// Build an updater that installs to `<feeds_dir>/abusech_sha256.bin`.
    pub fn new<P: AsRef<Path>>(feeds_dir: P) -> Self {
        Self {
            bin_url: DEFAULT_CURATED_BIN_URL.to_string(),
            sha256_url: DEFAULT_CURATED_SHA256_URL.to_string(),
            output_path: feeds_dir.as_ref().join(CURATED_BIN_FILENAME),
            user_agent: DEFAULT_USER_AGENT.to_string(),
        }
    }

    /// Override both URLs — used by tests to point at a local fixture server.
    pub fn with_urls(mut self, bin_url: impl Into<String>, sha256_url: impl Into<String>) -> Self {
        self.bin_url = bin_url.into();
        self.sha256_url = sha256_url.into();
        self
    }

    pub fn output_path(&self) -> &Path {
        &self.output_path
    }

    fn sidecar_path(&self) -> PathBuf {
        append_ext(&self.output_path, ".sha256")
    }

    fn download_tmp_path(&self) -> PathBuf {
        append_ext(&self.output_path, ".download")
    }

    fn read_sidecar(&self) -> Option<String> {
        std::fs::read_to_string(self.sidecar_path())
            .ok()
            .map(|s| s.trim().to_ascii_lowercase())
    }

    /// Fetch, verify, and atomically install the curated `.bin`. `on_progress`
    /// receives `(bytes_done, bytes_total)` during the download phase
    /// (`bytes_total` is `0` when the server omits `Content-Length`).
    pub async fn update(
        &self,
        on_progress: &(dyn Fn(u64, u64) + Send + Sync),
    ) -> Result<CuratedUpdateReport, CuratedError> {
        let started = Instant::now();
        let client = reqwest::Client::builder()
            .user_agent(self.user_agent.as_str())
            // rustls-only; refuse plaintext per docs/prd.md § 1.5.
            .https_only(true)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()?;

        // 1. checksum manifest (small).
        let manifest = self.fetch_text(&client, &self.sha256_url).await?;
        let expected = parse_sha256_manifest(&manifest, CURATED_BIN_FILENAME)
            .ok_or_else(|| CuratedError::BadManifest(CURATED_BIN_FILENAME.to_string()))?;

        // 2. short-circuit when the installed file already matches.
        if self.output_path.exists() && self.read_sidecar().as_deref() == Some(expected.as_str()) {
            return Ok(CuratedUpdateReport {
                entry_count: 0,
                bytes_downloaded: 0,
                elapsed: started.elapsed(),
                changed: false,
                sha256: expected,
            });
        }

        // 3. stream-download to a temp file, hashing as we go.
        if let Some(parent) = self.output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp_path = self.download_tmp_path();
        let (actual, bytes_downloaded) =
            match self.stream_to_file(&client, &tmp_path, on_progress).await {
                Ok(v) => v,
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err(e);
                }
            };

        // 4-6. verify + validate + atomic swap, then persist the sidecar.
        let entry_count = finalize_install(&tmp_path, &actual, &expected, &self.output_path)?;
        let _ = std::fs::write(self.sidecar_path(), &expected);

        Ok(CuratedUpdateReport {
            entry_count,
            bytes_downloaded,
            elapsed: started.elapsed(),
            changed: true,
            sha256: expected,
        })
    }

    async fn fetch_text(
        &self,
        client: &reqwest::Client,
        url: &str,
    ) -> Result<String, CuratedError> {
        let resp = client.get(url).send().await?;
        if !resp.status().is_success() {
            return Err(CuratedError::HttpStatus {
                status: resp.status().as_u16(),
                url: url.to_string(),
            });
        }
        Ok(resp.text().await?)
    }

    async fn stream_to_file(
        &self,
        client: &reqwest::Client,
        tmp_path: &Path,
        on_progress: &(dyn Fn(u64, u64) + Send + Sync),
    ) -> Result<(String, u64), CuratedError> {
        let resp = client.get(&self.bin_url).send().await?;
        if !resp.status().is_success() {
            return Err(CuratedError::HttpStatus {
                status: resp.status().as_u16(),
                url: self.bin_url.clone(),
            });
        }
        let total = resp.content_length().unwrap_or(0);
        let mut stream = resp.bytes_stream();
        let mut hasher = Sha256::new();
        let mut file = tokio::fs::File::create(tmp_path).await?;
        let mut downloaded: u64 = 0;
        let mut last_emit: u64 = 0;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            hasher.update(&chunk);
            file.write_all(&chunk).await?;
            downloaded += chunk.len() as u64;
            if downloaded - last_emit >= PROGRESS_STEP_BYTES {
                last_emit = downloaded;
                on_progress(downloaded, total);
            }
        }
        file.flush().await?;
        // Durably land the bytes before the rename so a crash can't leave a
        // truncated file masquerading as the live blacklist.
        file.sync_all().await?;
        on_progress(downloaded, total);
        Ok((hex::encode(hasher.finalize()), downloaded))
    }
}

/// Verify the SHA-256, validate structure, then atomically swap into place.
/// On any failure the temp file is removed and the live file is untouched.
fn finalize_install(
    tmp_path: &Path,
    actual_sha: &str,
    expected_sha: &str,
    output: &Path,
) -> Result<u64, CuratedError> {
    if !actual_sha.eq_ignore_ascii_case(expected_sha) {
        let _ = std::fs::remove_file(tmp_path);
        return Err(CuratedError::ChecksumMismatch {
            expected: expected_sha.to_ascii_lowercase(),
            actual: actual_sha.to_ascii_lowercase(),
        });
    }
    // Validate the file parses as a well-formed MYTHHASH set before we swap
    // it in. Scope the mmap so it is dropped before the rename — Windows
    // refuses to replace a still-mapped file.
    let entry_count = match HashSetFile::open(tmp_path) {
        Ok(set) => set.len(),
        Err(e) => {
            let _ = std::fs::remove_file(tmp_path);
            return Err(CuratedError::BadBinFormat(e));
        }
    };
    std::fs::rename(tmp_path, output)?;
    Ok(entry_count)
}

/// Append `suffix` to a path's file name (`foo.bin` + `.sha256` →
/// `foo.bin.sha256`), preserving the directory.
fn append_ext(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from(CURATED_BIN_FILENAME));
    name.push(suffix);
    path.with_file_name(name)
}

/// Extract the SHA-256 hex digest for `filename` from a sha256sum-format
/// manifest. Accepts `<hex>  <name>` lines (with an optional `*` binary-mode
/// marker) and a bare single-hash file. Returns the digest lowercased.
pub fn parse_sha256_manifest(text: &str, filename: &str) -> Option<String> {
    let is_hex64 = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
    let mut bare: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(hash) = parts.next() else { continue };
        if !is_hex64(hash) {
            continue;
        }
        match parts.next() {
            Some(name) => {
                let name = name.trim_start_matches('*');
                if name == filename || name.ends_with(filename) {
                    return Some(hash.to_ascii_lowercase());
                }
            }
            // A line that is just a bare digest — remember it as a fallback
            // for a single-hash manifest with no filename column.
            None => bare = bare.or_else(|| Some(hash.to_ascii_lowercase())),
        }
    }
    bare
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::hash_set_file::write_sorted;
    use tempfile::tempdir;

    fn sha256_file(path: &Path) -> String {
        let bytes = std::fs::read(path).unwrap();
        let mut h = Sha256::new();
        h.update(&bytes);
        hex::encode(h.finalize())
    }

    #[test]
    fn finalize_install_swaps_valid_bin() {
        let dir = tempdir().unwrap();
        let tmp = dir.path().join("abusech_sha256.bin.download");
        let out = dir.path().join("abusech_sha256.bin");
        // Three hashes, one duplicate → 2 distinct after write_sorted.
        write_sorted(&tmp, [[1u8; 32], [2u8; 32], [1u8; 32]]).unwrap();
        let sha = sha256_file(&tmp);
        let count = finalize_install(&tmp, &sha, &sha, &out).unwrap();
        assert_eq!(count, 2);
        assert!(out.exists());
        assert!(!tmp.exists(), "temp file should be renamed away");
        let set = HashSetFile::open(&out).unwrap();
        assert!(set.contains(&[1u8; 32]));
        assert!(set.contains(&[2u8; 32]));
    }

    #[test]
    fn finalize_install_rejects_checksum_mismatch_and_keeps_live_file() {
        let dir = tempdir().unwrap();
        let tmp = dir.path().join("x.download");
        let out = dir.path().join("x.bin");
        write_sorted(&tmp, [[9u8; 32]]).unwrap();
        let real = sha256_file(&tmp);
        let wrong = "0".repeat(64);
        let err = finalize_install(&tmp, &real, &wrong, &out).unwrap_err();
        assert!(matches!(err, CuratedError::ChecksumMismatch { .. }));
        assert!(!out.exists(), "live file must not be created on mismatch");
        assert!(!tmp.exists(), "temp file must be cleaned up on mismatch");
    }

    #[test]
    fn finalize_install_rejects_bad_format() {
        let dir = tempdir().unwrap();
        let tmp = dir.path().join("y.download");
        let out = dir.path().join("y.bin");
        std::fs::write(&tmp, b"not a mythhash file at all").unwrap();
        let sha = sha256_file(&tmp);
        let err = finalize_install(&tmp, &sha, &sha, &out).unwrap_err();
        assert!(matches!(err, CuratedError::BadBinFormat(_)));
        assert!(!out.exists());
        assert!(!tmp.exists());
    }

    #[test]
    fn parse_manifest_handles_named_starred_and_bare() {
        let h = "a".repeat(64);
        let named = format!("{h}  abusech_sha256.bin");
        assert_eq!(
            parse_sha256_manifest(&named, "abusech_sha256.bin"),
            Some(h.clone())
        );
        let starred = format!("{h} *abusech_sha256.bin");
        assert_eq!(
            parse_sha256_manifest(&starred, "abusech_sha256.bin"),
            Some(h.clone())
        );
        // Bare single-hash manifest with no filename column.
        assert_eq!(
            parse_sha256_manifest(&h, "abusech_sha256.bin"),
            Some(h.clone())
        );
        // A named line for a different file, and no bare fallback → None.
        let other = format!("{h}  something_else.bin");
        assert_eq!(parse_sha256_manifest(&other, "abusech_sha256.bin"), None);
    }

    #[test]
    fn parse_manifest_normalizes_case_and_skips_comments() {
        let up = "A".repeat(64);
        let text = format!("# comment line\n\n{up}  abusech_sha256.bin\n");
        assert_eq!(
            parse_sha256_manifest(&text, "abusech_sha256.bin"),
            Some("a".repeat(64))
        );
    }

    #[test]
    fn append_ext_builds_sidecar_and_download_names() {
        let u = CuratedBlacklistUpdater::new("/feeds");
        assert!(
            u.sidecar_path()
                .to_string_lossy()
                .ends_with("abusech_sha256.bin.sha256")
        );
        assert!(
            u.download_tmp_path()
                .to_string_lossy()
                .ends_with("abusech_sha256.bin.download")
        );
    }
}
