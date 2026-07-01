//! SBOM generator — CycloneDX 1.5 + SPDX 2.3 JSON (TASK-321).
//!
//! Takes the union of every supply-chain walker plus the OS
//! package-manager ownership view (TASK-184) and the browser-
//! extension inventory (TASK-256) and emits two parallel JSON
//! documents. Pure-local serialization — no network.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::{Ecosystem, InstalledPackage};

/// One row in the SBOM. We carry the SBOM-flavored shape
/// (CycloneDX `purl` / SPDX `SPDXID`) once at emit time —
/// callers only need to pass [`InstalledPackage`] inventories
/// and we synthesize the rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomComponent {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub install_path: PathBuf,
    pub purl: String,
    pub spdx_id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomSnapshot {
    pub created_unix_s: i64,
    pub components: Vec<SbomComponent>,
}

impl SbomSnapshot {
    /// Build a normalized snapshot from raw walker output.
    /// Components are de-duplicated by `(ecosystem, name, version)`
    /// and sorted for deterministic SBOM hashes.
    pub fn from_inventory(created_unix_s: i64, inventory: &[InstalledPackage]) -> Self {
        let mut by_key: BTreeMap<(String, String, String), SbomComponent> = BTreeMap::new();
        for (idx, p) in inventory.iter().enumerate() {
            let purl = build_purl(p.ecosystem, &p.name, &p.version);
            let spdx_id = format!(
                "SPDXRef-{}-{}",
                p.ecosystem.as_osv_str().replace(['/', ' '], "_"),
                idx,
            );
            by_key
                .entry((
                    p.ecosystem.as_osv_str().to_string(),
                    p.name.clone(),
                    p.version.clone(),
                ))
                .or_insert(SbomComponent {
                    ecosystem: p.ecosystem,
                    name: p.name.clone(),
                    version: p.version.clone(),
                    install_path: p.install_path.clone(),
                    purl,
                    spdx_id,
                });
        }
        SbomSnapshot {
            created_unix_s,
            components: by_key.into_values().collect(),
        }
    }

    /// CycloneDX 1.5 JSON document.
    pub fn to_cyclonedx_json(&self) -> serde_json::Value {
        let components: Vec<serde_json::Value> = self
            .components
            .iter()
            .map(|c| {
                serde_json::json!({
                    "type": "library",
                    "name": c.name,
                    "version": c.version,
                    "purl": c.purl,
                })
            })
            .collect();
        serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": { "timestamp_unix_s": self.created_unix_s },
            "components": components,
        })
    }

    /// SPDX 2.3 JSON document.
    pub fn to_spdx_json(&self) -> serde_json::Value {
        let packages: Vec<serde_json::Value> = self
            .components
            .iter()
            .map(|c| {
                serde_json::json!({
                    "SPDXID": c.spdx_id,
                    "name": c.name,
                    "versionInfo": c.version,
                    "downloadLocation": "NOASSERTION",
                    "externalRefs": [{
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": c.purl,
                    }],
                })
            })
            .collect();
        serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "Freally-SBOM",
            "creationInfo": { "created_unix_s": self.created_unix_s },
            "packages": packages,
        })
    }
}

fn build_purl(ecosystem: Ecosystem, name: &str, version: &str) -> String {
    let kind = match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::Cargo => "cargo",
        Ecosystem::Gem => "gem",
        Ecosystem::Composer => "composer",
        Ecosystem::Maven => "maven",
        Ecosystem::PyPI => "pypi",
        Ecosystem::VsCodeExtension => "vscode",
        Ecosystem::JetBrainsPlugin => "jetbrains",
    };
    format!("pkg:{kind}/{name}@{version}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_inventory() -> Vec<InstalledPackage> {
        vec![
            InstalledPackage {
                ecosystem: Ecosystem::Npm,
                name: "lodash".to_string(),
                version: "4.17.21".to_string(),
                install_path: PathBuf::from("/p/node_modules/lodash"),
            },
            InstalledPackage {
                ecosystem: Ecosystem::Cargo,
                name: "serde".to_string(),
                version: "1.0.197".to_string(),
                install_path: PathBuf::from("/p/Cargo.lock"),
            },
            // duplicate of lodash
            InstalledPackage {
                ecosystem: Ecosystem::Npm,
                name: "lodash".to_string(),
                version: "4.17.21".to_string(),
                install_path: PathBuf::from("/q/node_modules/lodash"),
            },
        ]
    }

    #[test]
    fn dedupes_components_by_key() {
        let snap = SbomSnapshot::from_inventory(1_700_000_000, &sample_inventory());
        assert_eq!(snap.components.len(), 2);
    }

    #[test]
    fn cyclonedx_json_has_expected_shape() {
        let snap = SbomSnapshot::from_inventory(1, &sample_inventory());
        let json = snap.to_cyclonedx_json();
        assert_eq!(json["bomFormat"], "CycloneDX");
        assert_eq!(json["specVersion"], "1.5");
        let comps = json["components"].as_array().unwrap();
        assert_eq!(comps.len(), 2);
        assert!(
            comps
                .iter()
                .any(|c| c["purl"].as_str().unwrap().starts_with("pkg:npm/lodash@"))
        );
    }

    #[test]
    fn spdx_json_has_expected_shape() {
        let snap = SbomSnapshot::from_inventory(1, &sample_inventory());
        let json = snap.to_spdx_json();
        assert_eq!(json["spdxVersion"], "SPDX-2.3");
        assert_eq!(json["SPDXID"], "SPDXRef-DOCUMENT");
        let pkgs = json["packages"].as_array().unwrap();
        assert_eq!(pkgs.len(), 2);
    }
}
