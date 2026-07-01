//! abuse.ch feed updater (TASK-022, Phase 2).
//!
//! Pulls two upstream sources from abuse.ch and merges them into a single
//! sorted SHA-256 set at `<data_dir>/feeds/abusech_sha256.bin`, where it is
//! mmap-read by [`crate::detect::hash_blacklist::HashBlacklistDetector`]:
//!
//! 1. **MalwareBazaar** bulk SHA-256 dump
//!    (`https://bazaar.abuse.ch/export/txt/sha256/full/`) — plain text,
//!    one hex SHA-256 per line, `#` comments. ~MB-scale.
//! 2. **ThreatFox** IOC query JSON
//!    (`https://threatfox-api.abuse.ch/api/v1/`) — JSON POST API returning
//!    a list of IOCs of various kinds; we filter for `ioc_type ==
//!    "sha256_hash"`.
//!
//! Both endpoints require a free **Auth-Key** as of 2024 — registration is
//! free at <https://auth.abuse.ch/>. The key is loaded from
//! `config.updater.abusech_auth_key`; absent key → clear error rather than
//! a silent zero-hash feed.
//!
//! Per `docs/prd.md` § 1.5.1 we may use abuse.ch data inside this product
//! but **must not redistribute the raw feed**. The updater always fetches
//! live; we ship no bundled snapshot. Network calls go through `reqwest`
//! with rustls-only TLS — no openssl / native-tls per § 1.5.
//!
//! The merge writes via [`crate::detect::hash_set_file::write_sorted`],
//! which sorts + deduplicates + writes atomically (tmp + rename). Readers
//! either see the old file or the new one; never a half-written one.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::detect::hash_set_file::{self, HashSetError};

/// Default MalwareBazaar bulk SHA-256 dump URL.
pub const DEFAULT_MALWAREBAZAAR_URL: &str = "https://bazaar.abuse.ch/export/txt/sha256/full/";
/// Default ThreatFox IOC API URL.
pub const DEFAULT_THREATFOX_URL: &str = "https://threatfox-api.abuse.ch/api/v1/";
/// User-Agent string sent with every request (abuse.ch's TOS asks for an
/// identifiable UA).
pub const DEFAULT_USER_AGENT: &str =
    "Freally-AV/0.2 (+https://github.com/MikesRuthless12/freally-av)";
/// How many days of ThreatFox IOCs to pull on each update. 90 is the API's
/// upper bound for the `get_iocs` action.
pub const DEFAULT_THREATFOX_DAYS: u32 = 90;
/// Per-request HTTP timeout.
pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, thiserror::Error)]
pub enum FeedError {
    #[error("network: {0}")]
    Network(String),
    #[error("abuse.ch returned HTTP {status} from {url}")]
    HttpStatus { status: u16, url: String },
    #[error("abuse.ch auth-key is missing or rejected (HTTP 401)")]
    AuthKeyRequired,
    #[error("malformed ThreatFox JSON response: {0}")]
    BadJson(String),
    #[error("abuse.ch returned non-ok query_status: {0}")]
    UpstreamStatus(String),
    #[error("hash-set write failed: {0}")]
    HashSet(#[from] HashSetError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<reqwest::Error> for FeedError {
    fn from(err: reqwest::Error) -> Self {
        FeedError::Network(err.to_string())
    }
}

impl From<serde_json::Error> for FeedError {
    fn from(err: serde_json::Error) -> Self {
        FeedError::BadJson(err.to_string())
    }
}

/// Summary of one update run. Surfaced in the engine log and in the
/// Settings → Updates UI (FR-153 progress events will subscribe to this in
/// Phase 3).
#[derive(Debug, Clone)]
pub struct UpdateReport {
    pub malwarebazaar_count: u64,
    pub threatfox_count: u64,
    /// Distinct hashes written to disk after merge + dedup.
    pub merged_count: u64,
    pub elapsed: Duration,
}

/// abuse.ch feed updater. Cheap to clone; holds no live socket.
#[derive(Debug, Clone)]
pub struct AbuseChUpdater {
    auth_key: String,
    malwarebazaar_url: String,
    threatfox_url: String,
    threatfox_days: u32,
    output_path: PathBuf,
    user_agent: String,
    http_timeout: Duration,
}

impl AbuseChUpdater {
    /// Build an updater that writes to `<feeds_dir>/abusech_sha256.bin`.
    pub fn new<P: AsRef<Path>>(auth_key: String, feeds_dir: P) -> Self {
        let output_path = feeds_dir.as_ref().join("abusech_sha256.bin");
        Self {
            auth_key,
            malwarebazaar_url: DEFAULT_MALWAREBAZAAR_URL.to_string(),
            threatfox_url: DEFAULT_THREATFOX_URL.to_string(),
            threatfox_days: DEFAULT_THREATFOX_DAYS,
            output_path,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            http_timeout: DEFAULT_HTTP_TIMEOUT,
        }
    }

    /// Override the upstream URLs — used by tests to point at a local
    /// fixture server.
    pub fn with_urls(mut self, malwarebazaar: String, threatfox: String) -> Self {
        self.malwarebazaar_url = malwarebazaar;
        self.threatfox_url = threatfox;
        self
    }

    /// Override the ThreatFox look-back window.
    pub fn with_threatfox_days(mut self, days: u32) -> Self {
        self.threatfox_days = days.clamp(1, 90);
        self
    }

    /// Override the output `.bin` path.
    pub fn with_output_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.output_path = path.as_ref().to_path_buf();
        self
    }

    pub fn output_path(&self) -> &Path {
        &self.output_path
    }

    /// Fetch both feeds, merge, dedup, and atomically replace the on-disk
    /// `.bin` file. Returns a summary of what was written.
    pub async fn update(&self) -> Result<UpdateReport, FeedError> {
        let started = Instant::now();
        let client = build_client(&self.user_agent, self.http_timeout)?;
        let (mb_text, tf_json) = tokio::try_join!(
            self.fetch_malwarebazaar(&client),
            self.fetch_threatfox(&client),
        )?;
        let mb_hashes = parse_malwarebazaar_text(&mb_text);
        let tf_hashes = parse_threatfox_json(&tf_json)?;
        self.write_merged(
            mb_hashes.len() as u64,
            tf_hashes.len() as u64,
            mb_hashes,
            tf_hashes,
            started,
        )
    }

    fn write_merged(
        &self,
        mb_count: u64,
        tf_count: u64,
        mb_hashes: Vec<[u8; 32]>,
        tf_hashes: Vec<[u8; 32]>,
        started: Instant,
    ) -> Result<UpdateReport, FeedError> {
        if let Some(parent) = self.output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let merged_iter = mb_hashes.into_iter().chain(tf_hashes);
        let merged_count = hash_set_file::write_sorted(&self.output_path, merged_iter)?;
        Ok(UpdateReport {
            malwarebazaar_count: mb_count,
            threatfox_count: tf_count,
            merged_count,
            elapsed: started.elapsed(),
        })
    }

    async fn fetch_malwarebazaar(&self, client: &reqwest::Client) -> Result<String, FeedError> {
        let resp = client
            .get(&self.malwarebazaar_url)
            .header("Auth-Key", &self.auth_key)
            .send()
            .await?;
        translate_status(&resp, &self.malwarebazaar_url)?;
        let text = resp.text().await?;
        Ok(text)
    }

    async fn fetch_threatfox(&self, client: &reqwest::Client) -> Result<String, FeedError> {
        let body = serde_json::json!({
            "query": "get_iocs",
            "days": self.threatfox_days,
        });
        let resp = client
            .post(&self.threatfox_url)
            .header("Auth-Key", &self.auth_key)
            .json(&body)
            .send()
            .await?;
        translate_status(&resp, &self.threatfox_url)?;
        let text = resp.text().await?;
        Ok(text)
    }
}

fn build_client(user_agent: &str, timeout: Duration) -> Result<reqwest::Client, FeedError> {
    let client = reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(timeout)
        // rustls-only — the workspace dep is built without native-tls
        // per docs/prd.md § 1.5.
        .https_only(true)
        .build()?;
    Ok(client)
}

fn translate_status(resp: &reqwest::Response, url: &str) -> Result<(), FeedError> {
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    if status.as_u16() == 401 {
        return Err(FeedError::AuthKeyRequired);
    }
    Err(FeedError::HttpStatus {
        status: status.as_u16(),
        url: url.to_string(),
    })
}

/// Parse a MalwareBazaar bulk SHA-256 dump. Each line is either a 64-char
/// lowercase hex SHA-256, blank, or `#`-prefixed comment. Malformed lines
/// are skipped silently — better to ship a slightly-shorter feed than to
/// fail the whole update on one bad line.
pub fn parse_malwarebazaar_text(text: &str) -> Vec<[u8; 32]> {
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            // MalwareBazaar dumps surround hashes with double-quotes
            // since 2023; strip them defensively.
            let cleaned = trimmed.trim_matches('"');
            decode_hex32(cleaned)
        })
        .collect()
}

/// One IOC entry in the ThreatFox `get_iocs` response.
#[derive(Debug, Deserialize)]
struct ThreatFoxIoc {
    #[serde(default)]
    ioc_type: String,
    #[serde(default)]
    ioc: String,
}

/// Outer shape of the ThreatFox response.
#[derive(Debug, Deserialize)]
struct ThreatFoxResponse {
    query_status: String,
    #[serde(default)]
    data: Vec<ThreatFoxIoc>,
}

/// Parse the ThreatFox JSON response and emit only SHA-256 IOCs.
pub fn parse_threatfox_json(json: &str) -> Result<Vec<[u8; 32]>, FeedError> {
    let parsed: ThreatFoxResponse = serde_json::from_str(json)?;
    if parsed.query_status != "ok" {
        return Err(FeedError::UpstreamStatus(parsed.query_status));
    }
    let out = parsed
        .data
        .into_iter()
        .filter(|i| i.ioc_type == "sha256_hash")
        .filter_map(|i| decode_hex32(i.ioc.trim()))
        .collect();
    Ok(out)
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::hash_set_file::HashSetFile;

    #[test]
    fn parse_malwarebazaar_skips_blanks_and_comments() {
        let txt = "\
# MalwareBazaar SHA-256 dump\n\
# Generated 2026-05-11\n\
\n\
0000000000000000000000000000000000000000000000000000000000000001\n\
\"0000000000000000000000000000000000000000000000000000000000000002\"\n\
not-a-hex-string\n\
0000000000000000000000000000000000000000000000000000000000000003\n\
";
        let hashes = parse_malwarebazaar_text(txt);
        assert_eq!(hashes.len(), 3);
        assert_eq!(hashes[0][31], 1);
        assert_eq!(hashes[1][31], 2);
        assert_eq!(hashes[2][31], 3);
    }

    #[test]
    fn parse_malwarebazaar_returns_empty_on_pure_comments() {
        let txt = "# nothing to see\n# more comments\n";
        let hashes = parse_malwarebazaar_text(txt);
        assert!(hashes.is_empty());
    }

    #[test]
    fn parse_threatfox_filters_to_sha256_only() {
        let json = r#"
        {
            "query_status": "ok",
            "data": [
                { "ioc_type": "sha256_hash", "ioc": "0000000000000000000000000000000000000000000000000000000000000010" },
                { "ioc_type": "md5_hash",    "ioc": "00112233445566778899aabbccddeeff" },
                { "ioc_type": "sha256_hash", "ioc": "0000000000000000000000000000000000000000000000000000000000000020" },
                { "ioc_type": "sha1_hash",   "ioc": "0011223344556677889900112233445566778899" },
                { "ioc_type": "url",         "ioc": "http://evil.example/x" }
            ]
        }
        "#;
        let hashes = parse_threatfox_json(json).unwrap();
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0][31], 0x10);
        assert_eq!(hashes[1][31], 0x20);
    }

    #[test]
    fn parse_threatfox_rejects_non_ok_status() {
        let json = r#"{ "query_status": "no_data", "data": [] }"#;
        match parse_threatfox_json(json).unwrap_err() {
            FeedError::UpstreamStatus(s) => assert_eq!(s, "no_data"),
            other => panic!("expected UpstreamStatus, got {other:?}"),
        }
    }

    #[test]
    fn parse_threatfox_rejects_malformed_json() {
        let json = "not json";
        match parse_threatfox_json(json).unwrap_err() {
            FeedError::BadJson(_) => {}
            other => panic!("expected BadJson, got {other:?}"),
        }
    }

    #[test]
    fn write_merged_writes_atomic_bin_file_and_dedups() {
        let dir = tempfile::tempdir().unwrap();
        let feeds_dir = dir.path().join("feeds");
        let updater = AbuseChUpdater::new("test-key".into(), &feeds_dir);
        // Overlap: hash 0x11 appears in both feeds — should appear once.
        let mb = vec![[0x11; 32], [0x22; 32]];
        let tf = vec![[0x11; 32], [0x33; 32]];
        let report = updater
            .write_merged(
                mb.len() as u64,
                tf.len() as u64,
                mb,
                tf,
                std::time::Instant::now(),
            )
            .unwrap();
        assert_eq!(report.malwarebazaar_count, 2);
        assert_eq!(report.threatfox_count, 2);
        assert_eq!(report.merged_count, 3);

        let set = HashSetFile::open(updater.output_path()).unwrap();
        assert_eq!(set.len(), 3);
        assert!(set.contains(&[0x11; 32]));
        assert!(set.contains(&[0x22; 32]));
        assert!(set.contains(&[0x33; 32]));
        assert!(!set.contains(&[0x44; 32]));
    }

    #[test]
    fn decode_hex32_rejects_wrong_length() {
        assert!(decode_hex32("abc").is_none());
        assert!(decode_hex32(&"a".repeat(63)).is_none());
        assert!(decode_hex32(&"a".repeat(65)).is_none());
        assert!(decode_hex32(&"a".repeat(64)).is_some());
    }

    #[test]
    fn decode_hex32_rejects_non_hex() {
        // 64 chars but with non-hex.
        let bad: String = std::iter::repeat_n('z', 64).collect();
        assert!(decode_hex32(&bad).is_none());
    }

    #[test]
    fn updater_with_urls_overrides_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let updater = AbuseChUpdater::new("k".into(), dir.path())
            .with_urls("http://x".into(), "http://y".into());
        assert_eq!(updater.malwarebazaar_url, "http://x");
        assert_eq!(updater.threatfox_url, "http://y");
    }

    #[test]
    fn threatfox_days_clamped_to_api_range() {
        let dir = tempfile::tempdir().unwrap();
        let u = AbuseChUpdater::new("k".into(), dir.path()).with_threatfox_days(500);
        assert_eq!(u.threatfox_days, 90);
        let u = AbuseChUpdater::new("k".into(), dir.path()).with_threatfox_days(0);
        assert_eq!(u.threatfox_days, 1);
    }
}
