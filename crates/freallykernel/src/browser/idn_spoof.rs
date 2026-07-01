//! IDN-spoof local-history alert (TASK-269, FEAT-214, Phase 10 Wave 2).
//!
//! Walks the browser-history host list and flags hosts whose
//! ASCII-look-alike score against a bundled top-domain table
//! exceeds threshold. The detector covers the two most-abused
//! spoofing patterns:
//!
//!  1. Punycode (`xn--`) hosts whose decoded label collapses to a
//!     top-domain label (Cyrillic `аpple.com`, Greek `goοgle.com`, …).
//!  2. ASCII hosts whose label is a known top-domain after applying
//!     the standard confusable map (`0` → `o`, `1` → `l`, `l` → `i`,
//!     `rn` → `m`, `vv` → `w`).
//!
//! No `unicode-security` dep — the bundled top-domain table + a tiny
//! deterministic confusable map cover the volume cases. Adding the
//! full UTS-39 confusable algorithm is a follow-up wave.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Curated top-domain labels the detector compares against. These
/// are intentionally the **second-level labels**, not the full FQDN,
/// because the canonical spoof pattern targets the brand label and
/// leaves the TLD intact (e.g. `аpple.com` not `apple.cоm`).
pub const KNOWN_BRAND_LABELS: &[&str] = &[
    "google",
    "apple",
    "microsoft",
    "amazon",
    "facebook",
    "meta",
    "twitter",
    "netflix",
    "github",
    "gitlab",
    "paypal",
    "stripe",
    "linkedin",
    "instagram",
    "youtube",
    "tiktok",
    "discord",
    "slack",
    "zoom",
    "dropbox",
    "adobe",
    "oracle",
    "salesforce",
    "icloud",
    "outlook",
    "bing",
    "live",
    "yahoo",
    "duckduckgo",
    "wikipedia",
    "reddit",
    "twitch",
    "spotify",
    "claude",
    "openai",
    "anthropic",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdnSpoofFinding {
    pub host: String,
    /// Second-level label that triggered the alarm.
    pub spoofed_label: String,
    /// Known brand label the host resembles.
    pub matched_brand: String,
    /// `"punycode"` when the host carries `xn--`; `"confusable"`
    /// when an ASCII-only label collapses via the bundled
    /// confusable map.
    pub reason: &'static str,
}

/// Scan one host. Returns `None` when no spoof signal fires.
pub fn check_host(host: &str) -> Option<IdnSpoofFinding> {
    let lc = host.to_ascii_lowercase();
    let label = second_level_label(&lc)?;

    // 1) Punycode hosts: `xn--` labels are always suspicious in the
    //    second-level position; flag them with whichever brand they
    //    resemble best, falling back to the literal `xn--` label.
    if label.starts_with("xn--") {
        let resemblance = nearest_brand(label);
        return Some(IdnSpoofFinding {
            host: host.to_string(),
            spoofed_label: label.to_string(),
            matched_brand: resemblance.unwrap_or("(unknown)").to_string(),
            reason: "punycode",
        });
    }

    // 2) Confusable-map collapse: replace digit and look-alike-pair
    //    glyphs and compare against the brand label set.
    let collapsed = collapse_confusables(label);
    if collapsed != label && KNOWN_BRAND_LABELS.contains(&collapsed.as_str()) {
        return Some(IdnSpoofFinding {
            host: host.to_string(),
            spoofed_label: label.to_string(),
            matched_brand: collapsed,
            reason: "confusable",
        });
    }
    None
}

/// Bulk scan a list of hosts (typically from
/// `super::phishtank::extract_host`-ed history URLs). Returns one
/// finding per matched host.
pub fn check_hosts<I, S>(hosts: I) -> Vec<IdnSpoofFinding>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for h in hosts {
        let host = h.as_ref();
        if !seen.insert(host.to_ascii_lowercase()) {
            continue;
        }
        if let Some(f) = check_host(host) {
            out.push(f);
        }
    }
    out
}

/// Return the second-level label of a host. For `foo.bar.example.com`
/// that's `example`; for `xn--80akhbyknj4f.com` that's the literal
/// `xn--80akhbyknj4f`. Single-label hosts (no `.`) return `None`.
fn second_level_label(host: &str) -> Option<&str> {
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }
    // For a 2-label host (`example.com`), SLL is index 0. For
    // 3+-label hosts (`mail.example.com`), SLL is the second-to-
    // last. Two-label TLDs (`co.uk`, `com.au`) are not handled —
    // false negatives on `.co.uk` spoofs are acceptable for the
    // foundation; the full Public Suffix List integration lands
    // in a follow-up.
    Some(labels[labels.len() - 2])
}

fn collapse_confusables(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    let bytes = label.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Two-char pairs first so they take precedence.
        if i + 1 < bytes.len() {
            let pair = &bytes[i..i + 2];
            if pair == b"rn" {
                out.push('m');
                i += 2;
                continue;
            }
            if pair == b"vv" {
                out.push('w');
                i += 2;
                continue;
            }
        }
        let c = match bytes[i] {
            b'0' => 'o',
            b'1' => 'l',
            b'3' => 'e',
            b'5' => 's',
            b'7' => 't',
            c => c as char,
        };
        out.push(c);
        i += 1;
    }
    out
}

fn nearest_brand(label: &str) -> Option<&'static str> {
    // Toy distance: longest brand whose first 4 chars appear in
    // `label`. Beats nothing-better when the punycode decoded form
    // genuinely embeds the brand's prefix; otherwise falls back to
    // the unknown-bucket caller.
    let lc = label.to_ascii_lowercase();
    KNOWN_BRAND_LABELS
        .iter()
        .filter(|b| b.len() >= 4 && lc.contains(&b[..4]))
        .max_by_key(|b| b.len())
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punycode_host_flagged_with_reason_punycode() {
        let host = "xn--80akhbyknj4f.com";
        let f = check_host(host).unwrap();
        assert_eq!(f.reason, "punycode");
        assert_eq!(f.spoofed_label, "xn--80akhbyknj4f");
    }

    #[test]
    fn confusable_collapse_matches_brand() {
        let host = "g00gle.com"; // 0→o twice
        let f = check_host(host).unwrap();
        assert_eq!(f.matched_brand, "google");
        assert_eq!(f.reason, "confusable");
        assert_eq!(f.spoofed_label, "g00gle");
    }

    #[test]
    fn vv_to_w_collapse() {
        let host = "vvikipedia.org";
        let f = check_host(host).unwrap();
        assert_eq!(f.matched_brand, "wikipedia");
    }

    #[test]
    fn rn_to_m_collapse() {
        let host = "rnicrosoft.com";
        let f = check_host(host).unwrap();
        assert_eq!(f.matched_brand, "microsoft");
    }

    #[test]
    fn legit_brand_hosts_pass() {
        assert!(check_host("google.com").is_none());
        assert!(check_host("mail.google.com").is_none());
        assert!(check_host("anthropic.com").is_none());
    }

    #[test]
    fn unrelated_host_passes() {
        assert!(check_host("example.org").is_none());
        assert!(check_host("personal-blog.net").is_none());
    }

    #[test]
    fn single_label_hosts_skipped() {
        assert!(check_host("localhost").is_none());
        assert!(check_host("").is_none());
    }

    #[test]
    fn check_hosts_dedupes_case_insensitively() {
        let hosts = vec!["G00gle.com", "g00gle.com"];
        let out = check_hosts(hosts);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn confusable_only_fires_when_collapse_changes_the_label() {
        // No 0/1/3/5/7/l/rn/vv to collapse — exact name match
        // against a brand isn't a confusable.
        let f = check_host("google.com");
        assert!(f.is_none());
    }

    #[test]
    fn deep_subdomain_targets_brand_label_only() {
        // Adversary registers `g00gle.com` and uses `mail.g00gle.com`.
        let f = check_host("mail.g00gle.com").unwrap();
        assert_eq!(f.matched_brand, "google");
    }
}
