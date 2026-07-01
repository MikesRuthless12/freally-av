//! NSRL (NIST Reference Data Set) goodware allowlist updater (TASK-023, Phase 2).
//!
//! Reads NIST's Reference Data Set — a US-public-domain corpus of SHA-256
//! hashes for known-good OS, application, and developer-tooling files — and
//! builds `<data_dir>/feeds/nsrl_sha256.bin` in the on-disk sorted-set
//! format used by [`crate::detect::goodware_allowlist`].
//!
//! **Source flexibility.** NIST distributes NSRL as a large `.zip`/`.iso`
//! containing TSV files. Freally does not ship a ZIP or ISO parser — per
//! `docs/prd.md` § 1.5 we keep the dependency footprint minimal. Instead the
//! updater accepts two modes:
//!
//! 1. **[`NsrlSource::Local`]** — point at a user-extracted text or TSV
//!    file on disk. The user (or a scheduled GitHub Action per § 1.5.2 /
//!    FR-151) is responsible for extracting NSRL's RDS into a SHA-256
//!    list ahead of time. This is the recommended posture.
//! 2. **[`NsrlSource::Url`]** — fetch a hash-per-line text file from any
//!    URL (HTTPS-only, rustls-only). Use this to pull a community-mirrored
//!    SHA-256-only NSRL slice — e.g. a static GitHub Release artifact —
//!    without re-implementing ISO extraction in Rust.
//!
//! **Parsing.** The parser is intentionally generous: each non-blank,
//! non-`#` line is scanned for the first 64-character ASCII-hex run
//! (case-insensitive) that decodes cleanly. That handles plain-hash-per-
//! line dumps, tab-separated NSRL exports (where SHA-256 is one column
//! among many), and quoted CSV. Malformed lines are skipped silently.
//!
//! Per `docs/prd.md` § 1.5.1 NSRL data is US public-domain and may be
//! commercially redistributed; the project may host its own slice in a
//! GitHub Release if desired, unlike abuse.ch which must always be fetched
//! live.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::detect::hash_set_file::{self, HashSetError};

/// Default per-request HTTP timeout (NSRL files can be tens of MB).
pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(600);
/// User-Agent string sent on every HTTP request.
pub const DEFAULT_USER_AGENT: &str =
    "Freally-AV/0.2 (+https://github.com/MikesRuthless12/freally-av)";

#[derive(Debug, thiserror::Error)]
pub enum NsrlError {
    #[error("network: {0}")]
    Network(String),
    #[error("NSRL upstream returned HTTP {status} from {url}")]
    HttpStatus { status: u16, url: String },
    #[error("hash-set write failed: {0}")]
    HashSet(#[from] HashSetError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<reqwest::Error> for NsrlError {
    fn from(err: reqwest::Error) -> Self {
        NsrlError::Network(err.to_string())
    }
}

/// Where the NSRL updater reads its input from.
#[derive(Debug, Clone)]
pub enum NsrlSource {
    /// Open a local file (the file must already be extracted from NSRL's
    /// `.zip`/`.iso` distribution).
    Local(PathBuf),
    /// Fetch the file via HTTPS. The endpoint must return plain text /
    /// TSV / CSV — no ZIP, no ISO.
    Url(String),
}

/// Summary of one update run.
#[derive(Debug, Clone)]
pub struct UpdateReport {
    /// Total SHA-256 hashes parsed from the input (pre-dedup).
    pub parsed_count: u64,
    /// Distinct hashes written to disk after dedup + sort.
    pub merged_count: u64,
    pub elapsed: Duration,
    pub source: NsrlSource,
}

/// NSRL feed updater.
#[derive(Debug, Clone)]
pub struct NsrlUpdater {
    source: NsrlSource,
    output_path: PathBuf,
    user_agent: String,
    http_timeout: Duration,
}

impl NsrlUpdater {
    /// Build an updater that writes to `<feeds_dir>/nsrl_sha256.bin`.
    pub fn new<P: AsRef<Path>>(source: NsrlSource, feeds_dir: P) -> Self {
        let output_path = feeds_dir.as_ref().join("nsrl_sha256.bin");
        Self {
            source,
            output_path,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            http_timeout: DEFAULT_HTTP_TIMEOUT,
        }
    }

    /// Override the output `.bin` path.
    pub fn with_output_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.output_path = path.as_ref().to_path_buf();
        self
    }

    pub fn output_path(&self) -> &Path {
        &self.output_path
    }

    /// Run one update: read the source, parse SHA-256s, build the `.bin`
    /// file atomically.
    pub async fn update(&self) -> Result<UpdateReport, NsrlError> {
        let started = Instant::now();
        let text = match &self.source {
            NsrlSource::Local(path) => std::fs::read_to_string(path)?,
            NsrlSource::Url(url) => self.fetch(url).await?,
        };
        let hashes = parse_nsrl_text(&text);
        let parsed_count = hashes.len() as u64;
        if let Some(parent) = self.output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let merged_count = hash_set_file::write_sorted(&self.output_path, hashes)?;
        Ok(UpdateReport {
            parsed_count,
            merged_count,
            elapsed: started.elapsed(),
            source: self.source.clone(),
        })
    }

    async fn fetch(&self, url: &str) -> Result<String, NsrlError> {
        let client = reqwest::Client::builder()
            .user_agent(&self.user_agent)
            .timeout(self.http_timeout)
            .https_only(true)
            .build()?;
        let resp = client.get(url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(NsrlError::HttpStatus {
                status: status.as_u16(),
                url: url.to_string(),
            });
        }
        Ok(resp.text().await?)
    }
}

/// Parse a generous NSRL-style text input. Each non-empty, non-`#`-prefixed
/// line is scanned for the **first** 64-character ASCII-hex run (case-
/// insensitive) that decodes to bytes; that run is taken as a SHA-256
/// hash. This handles:
///
/// - plain `<sha256>\n` lines
/// - quoted `"<sha256>"` lines
/// - tab/comma-separated NSRL TSV exports where SHA-256 is one column
///   among many (filename, MD5, SHA-1, SHA-256, size, …)
///
/// Malformed lines are skipped silently.
pub fn parse_nsrl_text(text: &str) -> Vec<[u8; 32]> {
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            extract_first_hex32(trimmed)
        })
        .collect()
}

/// Walk a single line looking for a 64-char ASCII-hex run that decodes
/// cleanly, returning the first such 32-byte digest. Case-insensitive
/// (some NSRL distributions publish uppercase).
fn extract_first_hex32(line: &str) -> Option<[u8; 32]> {
    let bytes = line.as_bytes();
    if bytes.len() < 64 {
        return None;
    }
    let mut start = 0usize;
    while start + 64 <= bytes.len() {
        let window = &bytes[start..start + 64];
        if window.iter().all(|b| is_ascii_hex(*b)) {
            let mut out = [0u8; 32];
            if hex::decode_to_slice(window, &mut out).is_ok() {
                // Reject runs that bleed into more hex on either side
                // — a 96-char hex string isn't a SHA-256.
                let left_ok = start == 0 || !is_ascii_hex(bytes[start - 1]);
                let right_ok = start + 64 == bytes.len() || !is_ascii_hex(bytes[start + 64]);
                if left_ok && right_ok {
                    return Some(out);
                }
            }
        }
        start += 1;
    }
    None
}

fn is_ascii_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || (b'A'..=b'F').contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::hash_set_file::HashSetFile;
    use tempfile::tempdir;

    const HASH1: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const HASH2: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const HASH3: &str = "0000000000000000000000000000000000000000000000000000000000000003";

    #[test]
    fn parse_plain_hash_per_line() {
        let txt = format!("# header\n\n{HASH1}\n{HASH2}\n");
        let h = parse_nsrl_text(&txt);
        assert_eq!(h.len(), 2);
        assert_eq!(h[0][31], 1);
        assert_eq!(h[1][31], 2);
    }

    #[test]
    fn parse_tsv_picks_sha256_column() {
        // NSRL-style TSV with filename, md5, sha1, sha256, size columns.
        // sha256 is the 4th column.
        let txt = format!(
            "kernel32.dll\t00112233445566778899aabbccddeeff\t0011223344556677889900112233445566778899\t{HASH1}\t1024\n\
             user32.dll\tffeeddccbbaa99887766554433221100\t1122334455667788990011223344556677889900\t{HASH2}\t2048\n",
        );
        let h = parse_nsrl_text(&txt);
        assert_eq!(h.len(), 2);
        assert_eq!(h[0][31], 1);
        assert_eq!(h[1][31], 2);
    }

    #[test]
    fn parse_quoted_csv() {
        let txt = format!("\"{HASH3}\"\n");
        let h = parse_nsrl_text(&txt);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0][31], 3);
    }

    #[test]
    fn parse_skips_lines_without_hex32() {
        let txt = "filename only\nshort 1234\nblah blah blah\n";
        assert!(parse_nsrl_text(txt).is_empty());
    }

    #[test]
    fn parse_skips_oversize_hex_run() {
        // 96 chars of hex shouldn't be misread as a SHA-256.
        let big = "a".repeat(96);
        let txt = format!("{big}\n");
        assert!(parse_nsrl_text(&txt).is_empty());
    }

    #[test]
    fn parse_accepts_uppercase_hex() {
        // NSRL distributions in the wild publish both cases. Accept either.
        let mixed_case = "DeAdBeEfCaFeBaBe1234567890aBcDeF1234567890aBcDeF1234567890aBcDeF";
        let txt = format!("{mixed_case}\n");
        let h = parse_nsrl_text(&txt);
        assert_eq!(h.len(), 1);
        // First byte = 0xde.
        assert_eq!(h[0][0], 0xde);
        assert_eq!(h[0][1], 0xad);
    }

    #[tokio::test]
    async fn update_from_local_writes_bin_atomically() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("nsrl_in.txt");
        std::fs::write(&input, format!("{HASH1}\n{HASH2}\n{HASH1}\n# dup above\n")).unwrap();

        let feeds = dir.path().join("feeds");
        let updater = NsrlUpdater::new(NsrlSource::Local(input.clone()), &feeds);
        let report = updater.update().await.unwrap();
        assert_eq!(report.parsed_count, 3);
        assert_eq!(report.merged_count, 2);

        let set = HashSetFile::open(updater.output_path()).unwrap();
        assert_eq!(set.len(), 2);
        let mut want = [0u8; 32];
        want[31] = 1;
        assert!(set.contains(&want));
        want[31] = 2;
        assert!(set.contains(&want));
    }

    #[tokio::test]
    async fn update_from_local_with_missing_file_returns_io_error() {
        let dir = tempdir().unwrap();
        let updater = NsrlUpdater::new(
            NsrlSource::Local(dir.path().join("missing.txt")),
            dir.path(),
        );
        match updater.update().await.unwrap_err() {
            NsrlError::Io(_) => {}
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn output_path_uses_canonical_filename() {
        let dir = tempdir().unwrap();
        let u = NsrlUpdater::new(NsrlSource::Local(dir.path().join("x")), dir.path());
        assert!(u.output_path().ends_with("nsrl_sha256.bin"));
    }
}
