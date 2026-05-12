//! BYOVD blocklist via loldrivers.io (TASK-139, FR-141 static portion).
//!
//! Pulls the public `drivers.json` artifact published by the loldrivers.io
//! project (community-maintained inventory of vulnerable Windows drivers
//! historically abused for BYOVD — "bring your own vulnerable driver" —
//! attacks). Extracts every SHA-256 from the `KnownVulnerableSamples`
//! array on each driver record, deduplicates, and writes a sorted-set
//! binary at `<feeds_dir>/byovd_sha256.bin` consumed by
//! [`crate::detect::byovd`].
//!
//! License posture: loldrivers.io data is **Apache-2.0**-licensed per
//! the upstream repository at
//! <https://github.com/magicsword-io/LOLDrivers/blob/main/LICENSE> —
//! commercial-clean per `docs/prd.md` § 1.5.1 sourcing constraints
//! (Apache-2.0 is on the project's allow-list). We redistribute SHA-256
//! digests only; no rule text or commentary is included in the feed
//! binary, so NOTICE attribution lives in `THIRD-PARTY-DATA.md` rather
//! than per-bundle. The static portion (this updater + the
//! hash-blacklist detector) is what FR-141 commits to in Phase 5;
//! driver-load-time enforcement via WDAC is TASK-154 (Phase 12) and
//! operates on the same hash list.
//!
//! HTTPS-only, rustls-only. No JSON-schema lock — `parse_drivers_json`
//! tolerates unknown fields and missing-section variations across
//! upstream releases. The HTTPS fetch enforces
//! [`MAX_LOLDRIVERS_BYTES`] as a hard ceiling on response-body size
//! (sec-review H1 / wave 3) so a malicious mirror or compromised CDN
//! cannot OOM the engine with a multi-GB JSON.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::detect::hash_set_file::{self, HashSetError};

/// Default per-request HTTP timeout. loldrivers.json is ~2 MB; 60 s
/// covers slow links comfortably.
pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(60);
/// Default upstream URL. Override via [`LolDriversUpdater::with_url`] in
/// tests or when pointing at a mirror.
pub const DEFAULT_URL: &str = "https://www.loldrivers.io/api/drivers.json";
/// User-Agent string sent on every HTTP request.
pub const DEFAULT_USER_AGENT: &str =
    "Mythodikal-AV/0.5 (+https://github.com/MikesRuthless12/mythodikal-av)";
/// Hard ceiling on the response body. Sec-review H1 mitigation —
/// without this a malicious mirror could serve a multi-GB JSON and
/// OOM the engine. 32 MiB is ~16× headroom over the current 2 MiB
/// upstream artifact.
pub const MAX_LOLDRIVERS_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum LolDriversError {
    #[error("network: {0}")]
    Network(String),
    #[error("loldrivers upstream returned HTTP {status} from {url}")]
    HttpStatus { status: u16, url: String },
    #[error("malformed loldrivers JSON: {0}")]
    Parse(String),
    #[error("loldrivers response body exceeded {limit} bytes (sec-review H1 cap); refused")]
    BodyTooLarge { limit: usize },
    #[error("hash-set write failed: {0}")]
    HashSet(#[from] HashSetError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<reqwest::Error> for LolDriversError {
    fn from(err: reqwest::Error) -> Self {
        LolDriversError::Network(err.to_string())
    }
}

/// Where the updater reads its input from.
#[derive(Debug, Clone)]
pub enum LolDriversSource {
    /// Open a local JSON file (cached snapshot, test fixture).
    Local(PathBuf),
    /// Fetch via HTTPS. Defaults to [`DEFAULT_URL`].
    Url(String),
}

/// Summary of one update run. Mirrors [`crate::updater::nsrl::UpdateReport`]
/// so the [`crate::updater::scheduler::ScheduledFeed`] adapter shape stays
/// uniform across feeds.
#[derive(Debug, Clone)]
pub struct UpdateReport {
    /// Total SHA-256 hashes parsed (pre-dedup).
    pub parsed_count: u64,
    /// Distinct hashes after dedup + sort.
    pub merged_count: u64,
    pub elapsed: Duration,
    pub source: LolDriversSource,
}

#[derive(Debug, Clone)]
pub struct LolDriversUpdater {
    source: LolDriversSource,
    output_path: PathBuf,
    user_agent: String,
    http_timeout: Duration,
}

impl LolDriversUpdater {
    /// Build an updater writing to `<feeds_dir>/byovd_sha256.bin`.
    pub fn new<P: AsRef<Path>>(feeds_dir: P) -> Self {
        let output_path = feeds_dir.as_ref().join("byovd_sha256.bin");
        Self {
            source: LolDriversSource::Url(DEFAULT_URL.to_string()),
            output_path,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            http_timeout: DEFAULT_HTTP_TIMEOUT,
        }
    }

    /// Override the upstream URL — used by tests and any future
    /// community-mirror configuration.
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.source = LolDriversSource::Url(url.into());
        self
    }

    /// Override the source to a local JSON file (test fixture or
    /// air-gapped install).
    pub fn with_local<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.source = LolDriversSource::Local(path.as_ref().to_path_buf());
        self
    }

    pub fn with_output_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.output_path = path.as_ref().to_path_buf();
        self
    }

    pub fn output_path(&self) -> &Path {
        &self.output_path
    }

    /// Run one update cycle.
    pub async fn update(&self) -> Result<UpdateReport, LolDriversError> {
        let started = Instant::now();
        let text = match &self.source {
            LolDriversSource::Local(p) => std::fs::read_to_string(p)?,
            LolDriversSource::Url(url) => self.fetch(url).await?,
        };
        let hashes = parse_drivers_json(&text)?;
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

    async fn fetch(&self, url: &str) -> Result<String, LolDriversError> {
        let client = reqwest::Client::builder()
            .user_agent(&self.user_agent)
            .timeout(self.http_timeout)
            .https_only(true)
            .build()?;
        let resp = client.get(url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(LolDriversError::HttpStatus {
                status: status.as_u16(),
                url: url.to_string(),
            });
        }

        // Sec-review H1: enforce a hard size cap on the response body
        // before we ever materialize it as a `String`. We check the
        // `Content-Length` advertisement first (fast-fail on advertised
        // overrun) then drain `chunk()` into a bounded `Vec` so a
        // chunked-transfer attacker can't lie about size and OOM us.
        // `resp.chunk()` is part of reqwest's base API; we don't need
        // the `stream` feature (which would pull `futures-util`).
        if let Some(advertised) = resp.content_length()
            && advertised as usize > MAX_LOLDRIVERS_BYTES
        {
            return Err(LolDriversError::BodyTooLarge {
                limit: MAX_LOLDRIVERS_BYTES,
            });
        }
        let mut resp = resp;
        let mut buf: Vec<u8> = Vec::with_capacity(2 * 1024 * 1024);
        while let Some(chunk) = resp.chunk().await? {
            if buf.len() + chunk.len() > MAX_LOLDRIVERS_BYTES {
                return Err(LolDriversError::BodyTooLarge {
                    limit: MAX_LOLDRIVERS_BYTES,
                });
            }
            buf.extend_from_slice(&chunk);
        }
        String::from_utf8(buf).map_err(|e| LolDriversError::Parse(e.to_string()))
    }
}

/// Minimal subset of the loldrivers schema we care about. `serde`
/// silently ignores unknown fields — important because the upstream
/// shape evolves over time. Per the upstream contract every driver
/// record carries a `KnownVulnerableSamples` array; each sample has
/// at least an `MD5`/`SHA1`/`SHA256` field (any subset). We harvest
/// SHA-256 only.
#[derive(Debug, Clone, Deserialize)]
struct Driver {
    #[serde(rename = "KnownVulnerableSamples", default)]
    known_vulnerable_samples: Vec<Sample>,
}

#[derive(Debug, Clone, Deserialize)]
struct Sample {
    #[serde(rename = "SHA256", default)]
    sha256: Option<String>,
}

/// Parse the loldrivers `drivers.json` body. The upstream artifact is a
/// JSON array of driver records; older snapshots used a top-level
/// object with a `drivers` array. We accept either shape.
///
/// Returns the deduped-by-the-caller list of 32-byte SHA-256 digests.
/// Empty / malformed entries are skipped silently; a fully malformed
/// JSON body returns [`LolDriversError::Parse`].
pub fn parse_drivers_json(text: &str) -> Result<Vec<[u8; 32]>, LolDriversError> {
    // Try the array shape first — that's the canonical upstream as of
    // the 2026 snapshot the build references.
    let drivers: Vec<Driver> = if text.trim_start().starts_with('[') {
        serde_json::from_str(text)
            .map_err(|e| LolDriversError::Parse(format!("array shape: {e}")))?
    } else {
        // Older snapshots used `{ "drivers": [...] }`.
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(default)]
            drivers: Vec<Driver>,
        }
        let w: Wrapper = serde_json::from_str(text)
            .map_err(|e| LolDriversError::Parse(format!("object shape: {e}")))?;
        w.drivers
    };

    let mut out: Vec<[u8; 32]> = Vec::new();
    for d in drivers {
        for sample in d.known_vulnerable_samples {
            if let Some(hex_str) = sample.sha256.as_deref()
                && let Some(digest) = decode_sha256_hex(hex_str)
            {
                out.push(digest);
            }
        }
    }
    Ok(out)
}

/// Decode a 64-char ASCII-hex string (case-insensitive) into a 32-byte
/// digest. `None` on any malformed input.
fn decode_sha256_hex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
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
    use tempfile::tempdir;

    const SAMPLE_JSON_ARRAY: &str = r#"[
        {
            "Tags": ["FilterDriver"],
            "Author": "Example",
            "KnownVulnerableSamples": [
                {"Filename": "bad1.sys", "SHA256": "0000000000000000000000000000000000000000000000000000000000000001"},
                {"Filename": "bad2.sys", "SHA256": "0000000000000000000000000000000000000000000000000000000000000002"}
            ]
        },
        {
            "Tags": ["Vulnerable"],
            "KnownVulnerableSamples": [
                {"Filename": "bad3.sys", "MD5": "00112233445566778899aabbccddeeff",
                 "SHA256": "0000000000000000000000000000000000000000000000000000000000000003"},
                {"Filename": "missing-sha.sys", "MD5": "ffeeddccbbaa99887766554433221100"}
            ]
        }
    ]"#;

    const SAMPLE_JSON_WRAPPER: &str = r#"{
        "drivers": [
            {
                "KnownVulnerableSamples": [
                    {"SHA256": "00000000000000000000000000000000000000000000000000000000000000aa"}
                ]
            }
        ]
    }"#;

    #[test]
    fn parses_array_shape_and_skips_missing_sha256() {
        let hashes = parse_drivers_json(SAMPLE_JSON_ARRAY).unwrap();
        assert_eq!(hashes.len(), 3);
        // Last byte uniquely identifies each fixture entry.
        assert_eq!(hashes[0][31], 1);
        assert_eq!(hashes[1][31], 2);
        assert_eq!(hashes[2][31], 3);
    }

    #[test]
    fn parses_object_wrapper_shape() {
        let hashes = parse_drivers_json(SAMPLE_JSON_WRAPPER).unwrap();
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0][31], 0xaa);
    }

    #[test]
    fn rejects_outright_garbage_json() {
        let err = parse_drivers_json("totally not json").unwrap_err();
        assert!(matches!(err, LolDriversError::Parse(_)));
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let txt = r#"[{"FutureField": 42, "KnownVulnerableSamples": [
            {"SHA256": "0000000000000000000000000000000000000000000000000000000000000007",
             "FutureSubField": "ignored"}
        ]}]"#;
        let hashes = parse_drivers_json(txt).unwrap();
        assert_eq!(hashes.len(), 1);
    }

    #[test]
    fn decode_sha256_hex_rejects_short_and_non_hex() {
        assert!(decode_sha256_hex("abc").is_none());
        assert!(decode_sha256_hex(&"z".repeat(64)).is_none());
    }

    #[test]
    fn max_loldrivers_bytes_is_at_least_16x_upstream() {
        // Sec-review H1 — the cap must comfortably exceed the current
        // ~2 MiB upstream artifact. Anything < 4 MiB would be a regression.
        const { assert!(MAX_LOLDRIVERS_BYTES >= 4 * 1024 * 1024) };
    }

    #[tokio::test]
    async fn update_from_local_writes_bin() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("drivers.json");
        std::fs::write(&input, SAMPLE_JSON_ARRAY).unwrap();

        let feeds = dir.path().join("feeds");
        let updater = LolDriversUpdater::new(&feeds).with_local(&input);
        let report = updater.update().await.unwrap();
        assert_eq!(report.parsed_count, 3);
        assert_eq!(report.merged_count, 3);

        let set = HashSetFile::open(updater.output_path()).unwrap();
        assert_eq!(set.len(), 3);
        let mut want = [0u8; 32];
        want[31] = 2;
        assert!(set.contains(&want));
    }
}
