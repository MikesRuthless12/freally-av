//! TASK-193 — Feed mirror failover.
//!
//! Per feed, the updater consults a user-maintained list of fallback
//! URLs. The primary is the GitHub Releases asset (per `docs/prd.md`
//! § 1.5.2). On transport error / 404 / 5xx, the next mirror is
//! tried; per-mirror health stats persist in `mirror_health` so the
//! UI can show "fallback used N times in the last week."
//!
//! ## Scope for Wave 2 Phase A
//!
//! Pure data + selection logic (no network calls). The HTTP wiring
//! that consumes these mirrors lives in the per-feed updater
//! (`abusech.rs`, `nsrl.rs`, etc.); for v0.7.x they keep their
//! existing single-URL path and the [`MirrorPool`] type below is
//! wired in a follow-up. The data + tests give the UI a structured
//! Settings page to populate while the wire-up is staged.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A feed's pool of candidate URLs. The first URL is the
/// canonical primary (typically the GitHub Releases asset); the
/// rest are fallbacks tried in order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorPool {
    pub feed_name: String,
    pub urls: Vec<String>,
    /// Number of recent transport errors per URL. The selection
    /// logic rotates past URLs whose error counter is above the
    /// threshold within the lookback window.
    #[serde(default)]
    pub health: HashMap<String, MirrorHealth>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MirrorHealth {
    pub recent_errors: u32,
    pub last_error_unix: Option<i64>,
    pub fallback_count_30d: u32,
}

/// SR-M2 fix — strict allowlist of permitted URL schemes for a
/// mirror URL. Currently `https` only (no `http`, no `file://`,
/// no `ftp://`, no anything else). The maintainer can grow this
/// in the future via a feature flag, but the safe default is to
/// refuse anything else at the data-construction boundary.
#[derive(Debug, thiserror::Error)]
pub enum MirrorError {
    #[error("mirror URL must start with https:// (got {0:?})")]
    UnsafeScheme(String),
    #[error("mirror URL is empty or whitespace")]
    Empty,
}

fn validate_mirror_url(url: &str) -> Result<(), MirrorError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(MirrorError::Empty);
    }
    if !trimmed.starts_with("https://") {
        return Err(MirrorError::UnsafeScheme(trimmed.to_string()));
    }
    Ok(())
}

impl MirrorPool {
    /// Construct a pool, validating every URL against the SR-M2
    /// scheme allowlist. Returns `Err(MirrorError)` on the first
    /// invalid URL so a typo doesn't silently accept an `http://`
    /// mirror.
    pub fn new(
        feed_name: impl Into<String>,
        urls: Vec<String>,
    ) -> Result<Self, MirrorError> {
        for u in &urls {
            validate_mirror_url(u)?;
        }
        Ok(Self {
            feed_name: feed_name.into(),
            urls,
            health: HashMap::new(),
        })
    }

    /// Append a new mirror URL with validation. Used by the
    /// Settings → Mirrors UI when the user adds an entry.
    pub fn add_url(&mut self, url: impl Into<String>) -> Result<(), MirrorError> {
        let s = url.into();
        validate_mirror_url(&s)?;
        self.urls.push(s);
        Ok(())
    }

    /// Pick the first URL whose recent_errors is below `threshold`.
    /// Falls back to the last URL even when all are unhealthy —
    /// better to retry one than to silently skip the update.
    pub fn pick_next(&self, threshold: u32) -> Option<&str> {
        for u in &self.urls {
            let healthy = self
                .health
                .get(u)
                .map(|h| h.recent_errors < threshold)
                .unwrap_or(true);
            if healthy {
                return Some(u.as_str());
            }
        }
        self.urls.last().map(String::as_str)
    }

    /// Record a transport error on `url` — increments the recent
    /// errors counter + the 30-day fallback count, stamps the
    /// last-error timestamp.
    pub fn record_error(&mut self, url: &str, now_unix: i64) {
        let h = self.health.entry(url.to_string()).or_default();
        h.recent_errors = h.recent_errors.saturating_add(1);
        h.fallback_count_30d = h.fallback_count_30d.saturating_add(1);
        h.last_error_unix = Some(now_unix);
    }

    /// Record a successful fetch on `url` — resets the recent
    /// errors counter; leaves the 30-day fallback history intact.
    pub fn record_success(&mut self, url: &str) {
        if let Some(h) = self.health.get_mut(url) {
            h.recent_errors = 0;
        }
    }

    /// Decay the recent-errors counter for all URLs. Called per
    /// scan-start (so a transient outage doesn't lock the mirror
    /// out forever).
    pub fn decay(&mut self) {
        for h in self.health.values_mut() {
            // Halve, rounding down. After ~5 decay ticks, a URL that
            // hit `threshold=3` errors is back to healthy.
            h.recent_errors /= 2;
        }
    }
}

/// Drive a fetch attempt across the pool. Calls `attempt(url)` until
/// one returns `Ok(T)`; records errors + successes on the way.
/// Bounded by `attempts.max(self.urls.len())`. Returns the last
/// error if all attempts fail.
pub fn fetch_with_failover<T, E, F>(
    pool: &mut MirrorPool,
    threshold: u32,
    now_unix: i64,
    attempts: usize,
    mut attempt: F,
) -> Result<(T, String), E>
where
    F: FnMut(&str) -> Result<T, E>,
    E: From<&'static str>,
{
    let cap = attempts.max(pool.urls.len()).max(1);
    let started = Instant::now();
    let urls_snapshot: Vec<String> = pool.urls.clone();
    for _ in 0..cap {
        // Stop runaway loops after 30 seconds wall-clock — the
        // updater is expected to ride out a slow feed, not block
        // the whole scan.
        if started.elapsed() > Duration::from_secs(30) {
            break;
        }
        let Some(url_str) = pool.pick_next(threshold) else {
            break;
        };
        let url = url_str.to_string();
        match attempt(&url) {
            Ok(val) => {
                pool.record_success(&url);
                return Ok((val, url));
            }
            Err(_) => {
                pool.record_error(&url, now_unix);
            }
        }
    }
    // One last attempt at the *last* URL so the caller's `Err`
    // carries useful context.
    let last = urls_snapshot
        .last()
        .cloned()
        .unwrap_or_else(|| "<no-url>".to_string());
    attempt(&last).map(|v| (v, last))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_next_prefers_first_healthy() {
        let mut pool = MirrorPool::new(
            "abusech",
            vec![
                "https://github.com/x".to_string(),
                "https://mirror.example.com".to_string(),
            ],
        )
        .unwrap();
        pool.record_error("https://github.com/x", 100);
        pool.record_error("https://github.com/x", 101);
        pool.record_error("https://github.com/x", 102);
        assert_eq!(pool.pick_next(3), Some("https://mirror.example.com"));
    }

    #[test]
    fn pick_next_falls_back_to_last_when_all_unhealthy() {
        let mut pool = MirrorPool::new(
            "abusech",
            vec!["https://a".to_string(), "https://b".to_string()],
        )
        .unwrap();
        for _ in 0..5 {
            pool.record_error("https://a", 1);
            pool.record_error("https://b", 1);
        }
        assert_eq!(pool.pick_next(3), Some("https://b"));
    }

    #[test]
    fn record_success_resets_counter() {
        let url = "https://u.example.com";
        let mut pool = MirrorPool::new("x", vec![url.to_string()]).unwrap();
        pool.record_error(url, 1);
        pool.record_error(url, 2);
        pool.record_success(url);
        assert_eq!(pool.health.get(url).unwrap().recent_errors, 0);
        // But the 30-day fallback count is preserved.
        assert_eq!(pool.health.get(url).unwrap().fallback_count_30d, 2);
    }

    #[test]
    fn decay_halves_recent_errors() {
        let url = "https://u.example.com";
        let mut pool = MirrorPool::new("x", vec![url.to_string()]).unwrap();
        for _ in 0..8 {
            pool.record_error(url, 1);
        }
        pool.decay();
        assert_eq!(pool.health.get(url).unwrap().recent_errors, 4);
        pool.decay();
        assert_eq!(pool.health.get(url).unwrap().recent_errors, 2);
    }

    #[test]
    fn fetch_with_failover_walks_pool() {
        let mut pool = MirrorPool::new(
            "x",
            vec!["https://bad.example.com".to_string(), "https://good.example.com".to_string()],
        )
        .unwrap();
        let result: Result<(u32, String), &'static str> =
            fetch_with_failover(&mut pool, 3, 1, 5, |u| {
                if u.contains("good") {
                    Ok(42)
                } else {
                    Err("oh no")
                }
            });
        let (value, served_by) = result.unwrap();
        assert_eq!(value, 42);
        assert!(served_by.contains("good"));
    }

    #[test]
    fn new_rejects_non_https_scheme() {
        // SR-M2 regression.
        let err = MirrorPool::new("x", vec!["http://example.com".to_string()]).unwrap_err();
        assert!(matches!(err, MirrorError::UnsafeScheme(_)));
        let err = MirrorPool::new("x", vec!["file:///etc/passwd".to_string()]).unwrap_err();
        assert!(matches!(err, MirrorError::UnsafeScheme(_)));
        let err = MirrorPool::new("x", vec!["".to_string()]).unwrap_err();
        assert!(matches!(err, MirrorError::Empty));
        let err = MirrorPool::new("x", vec!["  ".to_string()]).unwrap_err();
        assert!(matches!(err, MirrorError::Empty));
    }

    #[test]
    fn add_url_enforces_scheme_too() {
        let mut pool = MirrorPool::new("x", vec!["https://ok.example.com".to_string()]).unwrap();
        assert!(pool.add_url("https://also-ok.example.com").is_ok());
        assert!(matches!(
            pool.add_url("http://insecure.example.com").unwrap_err(),
            MirrorError::UnsafeScheme(_)
        ));
    }
}
