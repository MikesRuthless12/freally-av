//! TASK-189 — SBOM-aware allowlist (CycloneDX).
//!
//! User imports a known-good CycloneDX SBOM (vendor-supplied, or
//! self-generated from a future Phase-10 SBOM generator). At scan
//! time, any binary whose `(name, version, sha256)` tuple matches
//! an SBOM component is allowlisted with `source = sbom:<name>`.
//!
//! Multiple SBOMs can be active; conflict (same hash, different
//! SBOMs) is fine — the listing just records both.
//!
//! ## CycloneDX subset supported
//!
//! Only the components-array shape (CycloneDX 1.4+ JSON):
//!
//! ```json
//! {
//!   "bomFormat": "CycloneDX",
//!   "specVersion": "1.4",
//!   "components": [
//!     {
//!       "type": "library",
//!       "name": "openssl",
//!       "version": "3.0.12",
//!       "hashes": [
//!         {"alg": "SHA-256", "content": "<hex>"}
//!       ]
//!     }
//!   ]
//! }
//! ```
//!
//! Per-component hashes other than SHA-256 are ignored (the engine
//! computes SHA-256 only for blacklist + allowlist consultation).

use std::collections::HashMap;

use serde::Deserialize;

use super::{Detector, DetectorVerdict, FileCtx, HashKind};

pub const DETECTOR_ID: &str = "sbom_allowlist";
pub const PRIORITY: u32 = 14;

#[derive(Debug, Deserialize)]
struct CdxRoot {
    #[serde(default, rename = "bomFormat")]
    bom_format: Option<String>,
    #[serde(default)]
    components: Vec<CdxComponent>,
}

#[derive(Debug, Deserialize)]
struct CdxComponent {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    hashes: Vec<CdxHash>,
}

#[derive(Debug, Deserialize)]
struct CdxHash {
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    content: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SbomError {
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("not a CycloneDX bom (bomFormat field missing or wrong)")]
    NotCycloneDx,
}

#[derive(Debug, Default, Clone)]
pub struct SbomAllowlist {
    /// sha256 hex (lowercase) → (component name, version, sbom_label).
    by_sha256: HashMap<String, (String, String, String)>,
}

impl SbomAllowlist {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse one CycloneDX JSON document into the in-memory
    /// allowlist. `label` is what the detector surfaces in evidence
    /// (e.g. "openssl-vendor-sbom-2026-Q1").
    pub fn load_cyclonedx(&mut self, label: &str, json: &str) -> Result<usize, SbomError> {
        let root: CdxRoot = serde_json::from_str(json)?;
        if !root
            .bom_format
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("cyclonedx"))
            .unwrap_or(false)
        {
            return Err(SbomError::NotCycloneDx);
        }
        let mut added = 0usize;
        for comp in root.components {
            let (Some(name), Some(version)) = (comp.name, comp.version) else {
                continue;
            };
            for h in comp.hashes {
                let Some(alg) = h.alg else {
                    continue;
                };
                if !alg.eq_ignore_ascii_case("SHA-256") && !alg.eq_ignore_ascii_case("SHA256") {
                    continue;
                }
                let Some(hex) = h.content else {
                    continue;
                };
                let lc = hex.to_ascii_lowercase();
                if lc.len() == 64 && lc.chars().all(|c| c.is_ascii_hexdigit()) {
                    self.by_sha256.insert(
                        lc,
                        (name.clone(), version.clone(), label.to_string()),
                    );
                    added += 1;
                }
            }
        }
        Ok(added)
    }

    pub fn lookup(&self, sha256_hex: &str) -> Option<&(String, String, String)> {
        self.by_sha256.get(&sha256_hex.to_ascii_lowercase())
    }

    pub fn len(&self) -> usize {
        self.by_sha256.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_sha256.is_empty()
    }
}

#[derive(Debug)]
pub struct SbomAllowlistDetector {
    sbom: SbomAllowlist,
}

impl SbomAllowlistDetector {
    pub fn new(sbom: SbomAllowlist) -> Self {
        Self { sbom }
    }
}

impl Detector for SbomAllowlistDetector {
    fn id(&self) -> &str {
        DETECTOR_ID
    }
    fn priority(&self) -> u32 {
        PRIORITY
    }
    fn requires_sha256(&self) -> bool {
        true
    }
    fn check(&self, ctx: &FileCtx<'_>) -> DetectorVerdict {
        let Some(sha256) = HashKind::Sha256.select(ctx) else {
            return DetectorVerdict::Clean;
        };
        let hex = hex::encode(sha256);
        if self.sbom.lookup(&hex).is_some() {
            DetectorVerdict::SkipFile
        } else {
            DetectorVerdict::Clean
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_cyclonedx_components_with_sha256() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {
                    "type": "library",
                    "name": "openssl",
                    "version": "3.0.12",
                    "hashes": [{"alg": "SHA-256", "content": "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"}]
                },
                {
                    "type": "library",
                    "name": "zlib",
                    "version": "1.3",
                    "hashes": [{"alg": "MD5", "content": "deadbeefdeadbeefdeadbeefdeadbeef"}]
                }
            ]
        }"#;
        let mut sbom = SbomAllowlist::new();
        let added = sbom.load_cyclonedx("vendor-sbom-q1", json).unwrap();
        assert_eq!(added, 1); // zlib skipped — non-sha256 hash
        assert_eq!(
            sbom.lookup("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
                .map(|(n, _, _)| n.as_str()),
            Some("openssl")
        );
    }

    #[test]
    fn rejects_non_cyclonedx_json() {
        let json = r#"{"some": "other format"}"#;
        let mut sbom = SbomAllowlist::new();
        let err = sbom.load_cyclonedx("x", json).unwrap_err();
        assert!(matches!(err, SbomError::NotCycloneDx));
    }

    #[test]
    fn multiple_sboms_coexist() {
        let json1 = r#"{"bomFormat":"CycloneDX","components":[
            {"name":"a","version":"1","hashes":[{"alg":"SHA-256","content":"aa00000000000000000000000000000000000000000000000000000000000000"}]}]}"#;
        let json2 = r#"{"bomFormat":"CycloneDX","components":[
            {"name":"b","version":"2","hashes":[{"alg":"SHA-256","content":"bb00000000000000000000000000000000000000000000000000000000000000"}]}]}"#;
        let mut sbom = SbomAllowlist::new();
        sbom.load_cyclonedx("sbom1", json1).unwrap();
        sbom.load_cyclonedx("sbom2", json2).unwrap();
        assert_eq!(sbom.len(), 2);
    }
}
