//! Extension permission report (TASK-257, FEAT-202, Phase 10 Wave 2).
//!
//! Reads each enumerated extension's `manifest.json` (TASK-256) and
//! surfaces a plain-English risk summary based on the requested
//! WebExtensions permissions. The risk score is intentionally coarse
//! (low / medium / high) — the UI surfaces the underlying permission
//! list verbatim so users see the substantive reasons.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Coarse-grained risk bands matching the UI sort order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskBand {
    Low,
    Medium,
    High,
}

impl RiskBand {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskBand::Low => "low",
            RiskBand::Medium => "medium",
            RiskBand::High => "high",
        }
    }
}

/// One extension's permission report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionPermissionReport {
    /// API permissions from `manifest.permissions`.
    pub permissions: Vec<String>,
    /// Host permissions from `manifest.host_permissions` (MV3) or
    /// `manifest.permissions` host-match entries (MV2 legacy).
    pub host_permissions: Vec<String>,
    /// Permissions deferred behind a user-action gesture
    /// (`manifest.optional_permissions`).
    pub optional_permissions: Vec<String>,
    /// Whether the manifest grants effective access to every site
    /// (`<all_urls>`, `http://*/*`, `https://*/*`, `*://*/*`).
    pub all_sites: bool,
    pub risk_band: RiskBand,
    /// Human-readable summary lines suitable for the
    /// `BrowserExtensions.tsx` table.
    pub summary_lines: Vec<String>,
}

/// Manifest field names that drive scoring even when present in
/// `permissions` (not `host_permissions`). Lower-case match.
const HIGH_RISK_API_PERMISSIONS: &[&str] = &[
    "webRequest",
    "webRequestBlocking",
    "debugger",
    "proxy",
    "privacy",
    "management",
    "nativeMessaging",
    "downloads.open",
];

const MEDIUM_RISK_API_PERMISSIONS: &[&str] = &[
    "tabs",
    "cookies",
    "history",
    "bookmarks",
    "topSites",
    "browsingData",
    "clipboardRead",
    "geolocation",
    "downloads",
    "storage",
    "scripting",
];

/// Match-pattern strings that imply effective access to the entire web.
const ALL_SITES_HOST_PATTERNS: &[&str] = &[
    "<all_urls>",
    "*://*/*",
    "http://*/*",
    "https://*/*",
    "file:///*",
];

/// Parse a manifest body + return its permission report.
pub fn report_from_manifest_body(body: &str) -> Option<ExtensionPermissionReport> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    let api_perms = string_array(&json, "permissions");
    let host_perms_mv3 = string_array(&json, "host_permissions");
    let optional = string_array(&json, "optional_permissions");

    // MV2 stuffed host match patterns into the same array as API
    // permissions. Split them apart so the UI can render the two
    // lists separately.
    let (api_perms, host_perms_legacy): (Vec<_>, Vec<_>) =
        api_perms.into_iter().partition(|p| !looks_like_host(p));
    let mut host_perms = host_perms_mv3;
    host_perms.extend(host_perms_legacy);

    let all_sites = host_perms
        .iter()
        .any(|h| ALL_SITES_HOST_PATTERNS.contains(&h.as_str()));

    let high_api_count = api_perms
        .iter()
        .filter(|p| HIGH_RISK_API_PERMISSIONS.contains(&p.as_str()))
        .count();
    let med_api_count = api_perms
        .iter()
        .filter(|p| MEDIUM_RISK_API_PERMISSIONS.contains(&p.as_str()))
        .count();

    let mut summary_lines: Vec<String> = Vec::new();
    if all_sites {
        summary_lines.push("Reads every site you visit".into());
    }
    if api_perms.iter().any(|p| p == "tabs") {
        summary_lines.push("Sees your open tabs and their URLs".into());
    }
    if api_perms.iter().any(|p| p == "cookies") {
        summary_lines.push("Reads cookies, including session tokens".into());
    }
    if api_perms.iter().any(|p| p == "webRequest") {
        summary_lines.push("Inspects every network request".into());
    }
    if api_perms.iter().any(|p| p == "nativeMessaging") {
        summary_lines.push("Can communicate with native applications on this device".into());
    }
    if api_perms.iter().any(|p| p == "downloads") {
        summary_lines.push("Can read your download history".into());
    }
    if api_perms.iter().any(|p| p == "history") {
        summary_lines.push("Reads your browsing history".into());
    }

    let risk_band = if high_api_count > 0 || (all_sites && med_api_count > 0) {
        RiskBand::High
    } else if all_sites || med_api_count > 0 {
        RiskBand::Medium
    } else {
        RiskBand::Low
    };

    Some(ExtensionPermissionReport {
        permissions: api_perms,
        host_permissions: host_perms,
        optional_permissions: optional,
        all_sites,
        risk_band,
        summary_lines,
    })
}

/// Read + parse the manifest at `path`. Returns `None` on missing
/// file / malformed JSON.
pub fn report_from_path(path: &Path) -> Option<ExtensionPermissionReport> {
    let body = std::fs::read_to_string(path).ok()?;
    report_from_manifest_body(&body)
}

fn string_array(json: &serde_json::Value, key: &str) -> Vec<String> {
    json.get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn looks_like_host(s: &str) -> bool {
    s.contains("://") || s.starts_with('*') || s == "<all_urls>"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_risk_manifest_yields_low_band() {
        let body = r#"{
            "name":"Tiny",
            "version":"0.1",
            "permissions":["activeTab"],
            "host_permissions":[]
        }"#;
        let r = report_from_manifest_body(body).unwrap();
        assert_eq!(r.risk_band, RiskBand::Low);
        assert!(!r.all_sites);
        assert!(r.summary_lines.is_empty());
    }

    #[test]
    fn all_urls_with_no_api_perms_is_medium() {
        let body = r#"{
            "name":"Reader",
            "version":"1",
            "host_permissions":["<all_urls>"]
        }"#;
        let r = report_from_manifest_body(body).unwrap();
        assert!(r.all_sites);
        assert_eq!(r.risk_band, RiskBand::Medium);
        assert!(
            r.summary_lines
                .iter()
                .any(|s| s == "Reads every site you visit")
        );
    }

    #[test]
    fn all_urls_plus_webrequest_is_high() {
        let body = r#"{
            "name":"Networker",
            "version":"1",
            "permissions":["webRequest","tabs"],
            "host_permissions":["<all_urls>"]
        }"#;
        let r = report_from_manifest_body(body).unwrap();
        assert_eq!(r.risk_band, RiskBand::High);
        assert!(
            r.summary_lines
                .iter()
                .any(|s| s == "Inspects every network request")
        );
        assert!(
            r.summary_lines
                .iter()
                .any(|s| s == "Sees your open tabs and their URLs")
        );
    }

    #[test]
    fn native_messaging_is_always_high() {
        let body = r#"{
            "permissions":["nativeMessaging"]
        }"#;
        let r = report_from_manifest_body(body).unwrap();
        assert_eq!(r.risk_band, RiskBand::High);
        assert!(
            r.summary_lines
                .iter()
                .any(|s| s == "Can communicate with native applications on this device")
        );
    }

    #[test]
    fn mv2_permissions_array_split_into_api_and_host() {
        // MV2 mixes match patterns into the `permissions` array.
        let body = r#"{
            "permissions":["tabs","https://*.example.com/*","cookies"]
        }"#;
        let r = report_from_manifest_body(body).unwrap();
        assert!(r.permissions.contains(&"tabs".to_string()));
        assert!(r.permissions.contains(&"cookies".to_string()));
        assert!(
            r.host_permissions
                .contains(&"https://*.example.com/*".to_string())
        );
        // Specific (not <all_urls>) match pattern doesn't trigger
        // `all_sites`.
        assert!(!r.all_sites);
        // Two medium-risk API perms + no all-sites = medium.
        assert_eq!(r.risk_band, RiskBand::Medium);
    }

    #[test]
    fn http_star_host_counts_as_all_sites() {
        let body = r#"{
            "host_permissions":["http://*/*"]
        }"#;
        let r = report_from_manifest_body(body).unwrap();
        assert!(r.all_sites);
    }

    #[test]
    fn missing_keys_yield_empty_vecs_and_low_band() {
        let body = r#"{"name":"x"}"#;
        let r = report_from_manifest_body(body).unwrap();
        assert!(r.permissions.is_empty());
        assert!(r.host_permissions.is_empty());
        assert!(r.optional_permissions.is_empty());
        assert_eq!(r.risk_band, RiskBand::Low);
    }

    #[test]
    fn risk_band_orders_low_lt_medium_lt_high() {
        assert!(RiskBand::Low < RiskBand::Medium);
        assert!(RiskBand::Medium < RiskBand::High);
    }

    #[test]
    fn malformed_json_returns_none() {
        assert!(report_from_manifest_body("{").is_none());
        assert!(report_from_manifest_body("not json").is_none());
    }
}
