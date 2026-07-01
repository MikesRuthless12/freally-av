//! Engine self-update channel (TASK-130, Phase 4 wave 3).
//!
//! Implements FR-152 + FR-153 (engine portion). The engine channel pulls
//! `latest.json` from `https://github.com/MikesRuthless12/freally-av/releases/latest/download/`
//! (resolved by the Tauri Updater plugin), compares the published version with
//! the running engine_version, and surfaces `EngineUpdateAvailable` when a
//! newer version is available.
//!
//! The actual download + signature-verify + install is performed by the Tauri
//! Updater plugin in the Tauri shell (see `apps/freally/src-tauri/src/lib.rs`);
//! the engine side is responsible for:
//!
//!   * state persistence (last check, last install, errors)
//!   * version comparison (semver-ish, pre-stable 0.x.y aware)
//!   * progress-event serialization for the IPC layer
//!
//! Per FR-153 progress is emitted at ≤ 10 Hz with the four phases
//! `download | verify | install | restart_pending`. The frontend's Updates
//! pane subscribes to `engine_update:progress` and renders a per-phase bar.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::updater::channels::{self, ChannelKind, ChannelState, LastCheckOutcome, updater_dir};

/// Default GitHub Releases endpoint Tauri Updater consults. Set via
/// `tauri.conf.json :: plugins.updater.endpoints` in the shell; the engine
/// side uses the same URL to perform a lightweight "is there a newer
/// release" probe when the user clicks "Check now" from Settings →
/// Updates.
pub const DEFAULT_LATEST_JSON_URL: &str =
    "https://github.com/MikesRuthless12/freally-av/releases/latest/download/latest.json";

/// Phases of an engine self-update (FR-153). The frontend renders a
/// per-phase progress bar; phase names are stable for as long as the
/// IPC contract is in v0.x — never rename without a TS-side update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineUpdatePhase {
    /// Bundle bytes downloading.
    Download,
    /// ed25519 signature being verified against the public key compiled
    /// into the app (`tauri.conf.json :: plugins.updater.pubkey`).
    Verify,
    /// Installer writing bytes into the install location.
    Install,
    /// Install complete; app waiting for user-initiated relaunch.
    RestartPending,
}

impl EngineUpdatePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            EngineUpdatePhase::Download => "download",
            EngineUpdatePhase::Verify => "verify",
            EngineUpdatePhase::Install => "install",
            EngineUpdatePhase::RestartPending => "restart_pending",
        }
    }
}

/// One progress event emitted to the `engine_update:progress` Tauri topic.
/// Frontend coalesces these into the per-phase bar in Settings → Updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineUpdateProgress {
    pub phase: EngineUpdatePhase,
    /// Bytes received (download) or written (install). Verify/RestartPending
    /// always report 0/0 — the phase identity is the signal.
    pub bytes_done: u64,
    pub bytes_total: u64,
    /// Free-text status the UI shows under the bar. Empty string means
    /// "no extra context — render the phase name".
    pub message: String,
}

/// What the engine channel discovered on a `check_for_updates()` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineUpdateAvailable {
    pub current_version: String,
    pub latest_version: String,
    pub release_url: String,
    pub release_notes: String,
    /// Unix seconds the release was published. UI renders this under
    /// "Available since".
    pub published_at_utc: i64,
}

/// Engine self-update channel. Cheap to clone; holds only config +
/// paths, no live state.
#[derive(Debug, Clone)]
pub struct EngineChannel {
    /// Where the per-channel state JSON lives
    /// (`<data_dir>/updater/engine_state.json`).
    state_dir: PathBuf,
    /// Where `latest.json` lives. Overridable for tests.
    latest_url: String,
    /// Engine version baked into the binary (typically `env!("CARGO_PKG_VERSION")`).
    current_version: String,
    /// HTTP timeout for the check probe.
    http_timeout: Duration,
}

impl EngineChannel {
    pub fn new(data_dir: &Path, current_version: impl Into<String>) -> Self {
        Self {
            state_dir: updater_dir(data_dir),
            latest_url: DEFAULT_LATEST_JSON_URL.to_string(),
            current_version: current_version.into(),
            http_timeout: Duration::from_secs(15),
        }
    }

    /// Override the upstream `latest.json` URL. Used by tests against a
    /// local fixture server.
    pub fn with_latest_url(mut self, url: impl Into<String>) -> Self {
        self.latest_url = url.into();
        self
    }

    /// Load persisted state from disk; missing → defaults.
    pub fn load_state(&self) -> ChannelState {
        channels::load_state(&self.state_dir, ChannelKind::Engine)
    }

    pub fn save_state(&self, state: &ChannelState) -> std::io::Result<PathBuf> {
        channels::save_state(&self.state_dir, ChannelKind::Engine, state)
    }

    /// Fetch the upstream `latest.json` and compare its `version` against
    /// `self.current_version`. Returns `Ok(Some(_))` when a newer version
    /// is available, `Ok(None)` when up-to-date, `Err(_)` on network /
    /// parse failure.
    ///
    /// **Side effect (code-review CR-I7):** the channel's persisted
    /// state (`<data_dir>/updater/engine_state.json`) is updated with
    /// the outcome of this check before this fn returns. Callers don't
    /// need to do their own `record_check` / `save_state` dance — that
    /// duplication used to live in the Tauri command layer.
    pub async fn check_for_updates(
        &self,
    ) -> Result<Option<EngineUpdateAvailable>, EngineUpdateError> {
        let outcome = self.check_for_updates_impl().await;
        let mut state = self.load_state();
        match &outcome {
            Ok(Some(_)) => state.record_check(LastCheckOutcome::UpdateAvailable, None),
            Ok(None) => state.record_check(LastCheckOutcome::UpToDate, None),
            Err(err) => state.record_check(LastCheckOutcome::Failed, Some(&err.to_string())),
        }
        if let Err(err) = self.save_state(&state) {
            tracing::warn!(error = %err, "engine channel: state persist failed");
        }
        outcome
    }

    async fn check_for_updates_impl(
        &self,
    ) -> Result<Option<EngineUpdateAvailable>, EngineUpdateError> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .timeout(self.http_timeout)
            .user_agent(format!(
                "Freally-AV/{} (+https://github.com/MikesRuthless12/freally-av)",
                self.current_version
            ))
            .build()
            .map_err(|e| EngineUpdateError::Network(e.to_string()))?;
        let resp = client
            .get(&self.latest_url)
            .send()
            .await
            .map_err(|e| EngineUpdateError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(EngineUpdateError::HttpStatus(resp.status().as_u16()));
        }
        let body = resp
            .text()
            .await
            .map_err(|e| EngineUpdateError::Network(e.to_string()))?;
        let parsed: LatestJson =
            serde_json::from_str(&body).map_err(|e| EngineUpdateError::BadJson(e.to_string()))?;
        if compare_versions(&parsed.version, &self.current_version) <= 0 {
            return Ok(None);
        }
        let tag_version = parsed.notes_version_from_url().to_string();
        Ok(Some(EngineUpdateAvailable {
            current_version: self.current_version.clone(),
            latest_version: parsed.version,
            release_url: format!(
                "https://github.com/MikesRuthless12/freally-av/releases/tag/v{tag_version}"
            ),
            release_notes: parsed.notes,
            published_at_utc: parse_iso8601_to_unix(&parsed.pub_date).unwrap_or(0),
        }))
    }

    pub fn current_version(&self) -> &str {
        &self.current_version
    }
}

/// Shape of the `latest.json` Tauri Updater consumes. Only the fields the
/// engine channel actually reads are modeled here; the per-platform payloads
/// are consumed by the Tauri plugin directly.
#[derive(Debug, Clone, Deserialize)]
struct LatestJson {
    version: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    pub_date: String,
}

impl LatestJson {
    /// Strip a leading `v` and return the canonical version string for
    /// constructing a tag URL.
    fn notes_version_from_url(&self) -> &str {
        self.version.strip_prefix('v').unwrap_or(&self.version)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EngineUpdateError {
    #[error("network: {0}")]
    Network(String),
    #[error("upstream HTTP {0}")]
    HttpStatus(u16),
    #[error("malformed latest.json: {0}")]
    BadJson(String),
    #[error("signature verification failed: {0}")]
    Signature(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Compare two pre-stable / semver strings. Returns -1 if `a < b`, 0 if
/// equal, 1 if `a > b`. Accepts strings with or without a `v` prefix and
/// handles 0.x.y pre-stable numbering (FR-152) correctly, including
/// `-rc1`/`-beta` suffixes per semver §11 (pre-release < final).
///
/// A version string whose numeric tuple parses to empty is treated as
/// `0` and ordered below every real version — that prevents a typo'd
/// `"latest": "alpha"` field in `latest.json` from being read as "newer"
/// (sec-review M6).
pub fn compare_versions(a: &str, b: &str) -> i32 {
    let (av_nums, av_pre_rank) = parse_version(a);
    let (bv_nums, bv_pre_rank) = parse_version(b);
    let max_len = av_nums.len().max(bv_nums.len());
    for i in 0..max_len {
        let ai = av_nums.get(i).copied().unwrap_or(0);
        let bi = bv_nums.get(i).copied().unwrap_or(0);
        if ai < bi {
            return -1;
        }
        if ai > bi {
            return 1;
        }
    }
    // Numeric tuples equal — apply pre-release ordering. Lower rank wins
    // (alpha < beta < rc < final). `1` is the "final release" rank.
    av_pre_rank.cmp(&bv_pre_rank) as i32
}

/// Parse a version string into `(numeric_tuple, pre_release_rank)`. The
/// pre-release rank is `0` for `alpha*`, `1` for `beta*`, `2` for
/// `rc*`/`pre*`, and `3` for a final release (no pre-release suffix).
fn parse_version(s: &str) -> (Vec<u32>, u8) {
    let trimmed = s.trim_start_matches('v');
    // Split numeric prefix from optional `-foo` suffix.
    let (numeric, suffix) = match trimmed.split_once('-') {
        Some((n, s)) => (n, s),
        None => (trimmed, ""),
    };
    let nums: Vec<u32> = numeric
        .split('.')
        .filter(|seg| !seg.is_empty())
        .filter_map(|seg| seg.parse::<u32>().ok())
        .collect();
    let pre_rank: u8 = if suffix.is_empty() {
        3
    } else if suffix.starts_with("alpha") {
        0
    } else if suffix.starts_with("beta") {
        1
    } else if suffix.starts_with("rc") || suffix.starts_with("pre") {
        2
    } else {
        // Unknown suffix: order between alpha and beta to be conservative
        // (treated as "less than a final release").
        0
    };
    (nums, pre_rank)
}

/// Best-effort ISO 8601 → unix-seconds. Returns `None` on parse failure
/// rather than zero so callers can render "unknown" vs "epoch".
fn parse_iso8601_to_unix(s: &str) -> Option<i64> {
    if s.is_empty() {
        return None;
    }
    // chrono::DateTime::parse_from_rfc3339 handles "2026-05-12T18:42:00Z"
    // and "2026-05-12T18:42:00+00:00" alike.
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.timestamp())
}

/// Verify a Tauri Updater bundle signature against the public key compiled
/// into the app. Delegates to the `minisign-verify` crate so we benefit from
/// its correct handling of:
///
///   * **key-id binding** — the 8-byte key-id in the sig must equal the
///     pubkey's key-id, otherwise verification fails (sec-review C1).
///   * **algorithm magic bytes** — `Ed` (legacy raw) vs `ED` (pre-hashed
///     blake2b) variants are dispatched correctly (sec-review C2). Tauri
///     Action emits the pre-hashed form for large bundles; this fn now
///     accepts both transparently.
///
/// On Phase 4 the Tauri Updater plugin still performs the primary
/// verification inside the shell; this fn is exposed so the CLI / tests
/// can verify a downloaded bundle without running the Tauri shell.
pub fn verify_signature(
    pubkey_str: &str,
    bundle_bytes: &[u8],
    minisign_signature: &str,
) -> Result<(), EngineUpdateError> {
    use minisign_verify::{PublicKey, Signature};

    // Accept either the raw base64 body (e.g. `RWQ...`) or the full
    // minisign text (with `untrusted comment:` headers). `from_base64`
    // takes the body; we strip headers first.
    let pubkey_body = pubkey_str
        .lines()
        .filter(|l| !l.starts_with("untrusted comment:"))
        .find(|l| !l.is_empty())
        .ok_or_else(|| EngineUpdateError::Signature("pubkey body missing".into()))?;
    let pk = PublicKey::from_base64(pubkey_body)
        .map_err(|e| EngineUpdateError::Signature(format!("pubkey decode: {e}")))?;
    let sig = Signature::decode(minisign_signature)
        .map_err(|e| EngineUpdateError::Signature(format!("sig decode: {e}")))?;
    // `pk.verify` enforces key-id match + algorithm dispatch + (for
    // pre-hashed sigs) re-hashes the bundle with blake2b-512 before
    // ed25519 verify. We never need to know which variant was used.
    pk.verify(bundle_bytes, &sig, false)
        .map_err(|e| EngineUpdateError::Signature(format!("verify: {e}")))?;
    Ok(())
}

/// Record the outcome of one engine-update cycle. Saves to disk
/// atomically.
pub fn record_check(
    data_dir: &Path,
    outcome: LastCheckOutcome,
    error: Option<&str>,
) -> std::io::Result<()> {
    let dir = updater_dir(data_dir);
    let mut state = channels::load_state(&dir, ChannelKind::Engine);
    state.record_check(outcome, error);
    channels::save_state(&dir, ChannelKind::Engine, &state)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn compare_versions_handles_pre_stable_zero_x_y() {
        assert_eq!(compare_versions("0.4.0", "0.4.0"), 0);
        assert_eq!(compare_versions("0.4.0", "0.4.1"), -1);
        assert_eq!(compare_versions("0.4.1", "0.4.0"), 1);
        assert_eq!(compare_versions("0.4.0", "0.5.0"), -1);
        assert_eq!(compare_versions("0.19.84", "0.4.0"), 1);
        assert_eq!(compare_versions("v0.4.1", "v0.4.0"), 1);
        // Tail-padding with zeroes: 0.4 == 0.4.0.
        assert_eq!(compare_versions("0.4", "0.4.0"), 0);
    }

    #[test]
    fn compare_versions_strips_v_prefix_consistently() {
        assert_eq!(compare_versions("v0.4.0", "0.4.0"), 0);
        assert_eq!(compare_versions("0.4.0", "v0.4.0"), 0);
    }

    #[test]
    fn parse_iso8601_returns_unix_seconds() {
        // 2026-05-12T18:42:00Z == 1778517720 unix
        let ts = parse_iso8601_to_unix("2026-05-12T18:42:00Z").unwrap();
        assert!(ts > 1_700_000_000);
        assert!(parse_iso8601_to_unix("").is_none());
        assert!(parse_iso8601_to_unix("not-a-date").is_none());
    }

    #[test]
    fn engine_phase_strings_are_stable() {
        assert_eq!(EngineUpdatePhase::Download.as_str(), "download");
        assert_eq!(EngineUpdatePhase::Verify.as_str(), "verify");
        assert_eq!(EngineUpdatePhase::Install.as_str(), "install");
        assert_eq!(
            EngineUpdatePhase::RestartPending.as_str(),
            "restart_pending"
        );
    }

    #[test]
    fn channel_state_persists_across_load() {
        let dir = tempdir().unwrap();
        let ch = EngineChannel::new(dir.path(), "0.4.0");
        let mut state = ch.load_state();
        state.record_check(LastCheckOutcome::UpToDate, None);
        ch.save_state(&state).unwrap();
        let again = ch.load_state();
        assert!(matches!(again.last_outcome, LastCheckOutcome::UpToDate));
        assert!(again.last_check_at_utc > 0);
    }

    #[test]
    fn record_check_writes_state_file() {
        let dir = tempdir().unwrap();
        record_check(dir.path(), LastCheckOutcome::UpdateAvailable, None).unwrap();
        let state = channels::load_state(&channels::updater_dir(dir.path()), ChannelKind::Engine);
        assert!(matches!(
            state.last_outcome,
            LastCheckOutcome::UpdateAvailable
        ));
    }

    #[test]
    fn verify_signature_rejects_garbage_pubkey() {
        let res = verify_signature("YWJj", b"payload", "sig");
        assert!(matches!(res, Err(EngineUpdateError::Signature(_))));
    }

    #[test]
    fn verify_signature_rejects_garbage_signature() {
        // Real Freally pubkey from `scripts/gen-signing-key/` — but
        // a fabricated signature body. The minisign-verify crate
        // rejects the base64 decode + key-id mismatch.
        let pk = "RWQbjEwBG41EGiaSTWW37d3G02hJDR5rK+Ik6bpQqHW/WEZlT58Ogk78";
        let res = verify_signature(pk, b"payload", "not a signature");
        assert!(matches!(res, Err(EngineUpdateError::Signature(_))));
    }

    #[test]
    fn compare_versions_rejects_garbage_as_zero() {
        // Sec-review M6: a typo'd "latest.json" with `version: "alpha"`
        // must NOT compare as newer than the current version.
        assert!(compare_versions("alpha", "0.4.0") < 0);
        assert!(compare_versions("", "0.4.0") < 0);
        assert_eq!(compare_versions("", ""), 0);
    }

    #[test]
    fn compare_versions_orders_pre_release_below_final() {
        // Semver: 0.4.0-rc1 < 0.4.0 < 0.4.0+meta.
        assert!(compare_versions("0.4.0-rc1", "0.4.0") < 0);
        assert!(compare_versions("0.4.0-beta", "0.4.0-rc1") < 0);
        assert!(compare_versions("0.4.0-alpha", "0.4.0-beta") < 0);
        // Two rc's compare equal at the rank level (this is a coarse
        // ordering; rc1 vs rc2 isn't distinguished, by design).
        assert_eq!(compare_versions("0.4.0-rc1", "0.4.0-rc2"), 0);
    }
}
