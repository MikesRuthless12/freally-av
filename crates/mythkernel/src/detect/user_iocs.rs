//! TASK-195 — User-supplied IOC bundles.
//!
//! Read/write API for the `user_iocs` table (migration 0007). The
//! UI (`apps/mythodikal/frontend/src/pages/IOCs.tsx`) calls Tauri
//! commands that wrap these helpers; the scanner consumes the
//! enabled rows as an extra in-memory hash set evaluated at the
//! same priority as the abuse.ch blacklist.
//!
//! Supported input formats handled by [`parse_bundle_text`]:
//!   * Plain hash list (one hex value per line; type inferred by
//!     length — 32 hex → md5, 40 hex → sha1, 64 hex → sha256).
//!   * CSV with a `type` column + a `value` column (per-row typed).
//!   * Minimal STIX 2.1 indicator JSON (only `pattern` field
//!     parsed; `[file:hashes.MD5 = '…']` style).
//!   * MISP-export JSON top-level `Event.Attribute[]` array.
//!
//! Parsers tolerate the lowest-common-denominator shapes; if the
//! input doesn't look like one of the four, returns
//! [`IocError::UnrecognisedFormat`] so the UI can surface a clear
//! error rather than silently dropping the data.

use rusqlite::{Connection, params};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum IocError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("input doesn't look like a supported IOC bundle (plain hash list, CSV, STIX 2.1, or MISP export)")]
    UnrecognisedFormat,
    #[error("invalid IOC type: {0} (expected md5, sha1, sha256, or blake3)")]
    BadType(String),
    #[error("invalid hash for type {kind:?}: {value:?} (length or chars don't match)")]
    BadHash { kind: IocType, value: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocType {
    Md5,
    Sha1,
    Sha256,
    Blake3,
}

impl IocType {
    pub fn as_str(self) -> &'static str {
        match self {
            IocType::Md5 => "md5",
            IocType::Sha1 => "sha1",
            IocType::Sha256 => "sha256",
            IocType::Blake3 => "blake3",
        }
    }
    pub fn expected_hex_len(self) -> usize {
        match self {
            IocType::Md5 => 32,
            IocType::Sha1 => 40,
            IocType::Sha256 => 64,
            IocType::Blake3 => 64,
        }
    }
    pub fn infer_from_hex_len(len: usize) -> Option<IocType> {
        match len {
            32 => Some(IocType::Md5),
            40 => Some(IocType::Sha1),
            // 64 hex could be sha256 OR blake3 — default to sha256
            // (more common in published IOC feeds; user can override
            // via CSV `type` column if they want blake3).
            64 => Some(IocType::Sha256),
            _ => None,
        }
    }
    pub fn from_label(label: &str) -> Result<IocType, IocError> {
        match label.to_ascii_lowercase().as_str() {
            "md5" => Ok(IocType::Md5),
            "sha1" => Ok(IocType::Sha1),
            "sha256" => Ok(IocType::Sha256),
            "blake3" => Ok(IocType::Blake3),
            other => Err(IocError::BadType(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ioc {
    pub kind: IocType,
    pub value: String,
}

/// Parse a user-pasted bundle string into a vector of typed IOCs.
/// Tries each format in turn and returns the first non-empty parse.
pub fn parse_bundle_text(text: &str) -> Result<Vec<Ioc>, IocError> {
    // 1. Try STIX 2.1 / MISP JSON.
    let trimmed = text.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(iocs) = parse_stix_json(trimmed) {
            if !iocs.is_empty() {
                return Ok(iocs);
            }
        }
        if let Ok(iocs) = parse_misp_json(trimmed) {
            if !iocs.is_empty() {
                return Ok(iocs);
            }
        }
    }
    // 2. CSV with a `type` column?
    if let Ok(iocs) = parse_csv(text) {
        if !iocs.is_empty() {
            return Ok(iocs);
        }
    }
    // 3. Plain hash list — type inferred per line.
    let mut iocs = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lc = line.to_ascii_lowercase();
        let Some(kind) = IocType::infer_from_hex_len(lc.len()) else {
            continue;
        };
        if !lc.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        iocs.push(Ioc { kind, value: lc });
    }
    if iocs.is_empty() {
        return Err(IocError::UnrecognisedFormat);
    }
    Ok(iocs)
}

fn parse_csv(text: &str) -> Result<Vec<Ioc>, IocError> {
    let mut iocs = Vec::new();
    let mut header: Option<Vec<String>> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(',').map(str::trim).collect();
        if header.is_none() {
            // Try to detect a header row by presence of "type" + "value"
            // (case-insensitive).
            let lc: Vec<String> = parts.iter().map(|p| p.to_ascii_lowercase()).collect();
            if lc.iter().any(|p| p == "type") && lc.iter().any(|p| p == "value") {
                header = Some(lc);
                continue;
            }
            // Not a CSV with our header — return empty to fall through
            // to the next parser.
            return Ok(Vec::new());
        }
        let h = header.as_ref().expect("header set above");
        let type_idx = h.iter().position(|c| c == "type");
        let value_idx = h.iter().position(|c| c == "value");
        if let (Some(ti), Some(vi)) = (type_idx, value_idx) {
            if ti >= parts.len() || vi >= parts.len() {
                continue;
            }
            let kind = match IocType::from_label(parts[ti]) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let val = parts[vi].to_ascii_lowercase();
            if val.len() == kind.expected_hex_len()
                && val.chars().all(|c| c.is_ascii_hexdigit())
            {
                iocs.push(Ioc { kind, value: val });
            }
        }
    }
    Ok(iocs)
}

#[derive(Debug, Deserialize)]
struct StixIndicator {
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default, rename = "type")]
    obj_type: Option<String>,
}

fn parse_stix_json(text: &str) -> Result<Vec<Ioc>, IocError> {
    let v: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return Ok(Vec::new()),
    };
    // STIX 2.1 can be either a single bundle object or a bare
    // array of indicators.
    let arr: Vec<serde_json::Value> = match v {
        serde_json::Value::Array(a) => a,
        serde_json::Value::Object(mut o) => match o.remove("objects") {
            Some(serde_json::Value::Array(a)) => a,
            _ => return Ok(Vec::new()),
        },
        _ => return Ok(Vec::new()),
    };
    let mut iocs = Vec::new();
    for obj in arr {
        let ind: StixIndicator = match serde_json::from_value(obj) {
            Ok(i) => i,
            Err(_) => continue,
        };
        if ind.obj_type.as_deref() != Some("indicator") {
            continue;
        }
        let Some(pattern) = ind.pattern else {
            continue;
        };
        // Minimal STIX pattern parse:
        //   [file:hashes.'MD5' = 'deadbeef…']
        //   [file:hashes.SHA-256 = '…']
        for (label, kind) in &[
            ("MD5", IocType::Md5),
            ("SHA-1", IocType::Sha1),
            ("SHA-256", IocType::Sha256),
            ("BLAKE3", IocType::Blake3),
        ] {
            if let Some(idx) = pattern.to_ascii_uppercase().find(label)
                && let Some(start) = pattern[idx..].find('\'')
                && let Some(end_rel) = pattern[idx + start + 1..].find('\'')
            {
                let v = pattern[idx + start + 1..idx + start + 1 + end_rel]
                    .to_ascii_lowercase();
                if v.len() == kind.expected_hex_len()
                    && v.chars().all(|c| c.is_ascii_hexdigit())
                {
                    iocs.push(Ioc { kind: *kind, value: v });
                }
            }
        }
    }
    Ok(iocs)
}

#[derive(Debug, Deserialize)]
struct MispEvent {
    #[serde(default)]
    #[serde(rename = "Event")]
    event: Option<MispEventInner>,
}

#[derive(Debug, Deserialize)]
struct MispEventInner {
    #[serde(default, rename = "Attribute")]
    attributes: Vec<MispAttribute>,
}

#[derive(Debug, Deserialize)]
struct MispAttribute {
    #[serde(default, rename = "type")]
    attr_type: String,
    #[serde(default)]
    value: String,
}

fn parse_misp_json(text: &str) -> Result<Vec<Ioc>, IocError> {
    let parsed: MispEvent = match serde_json::from_str(text) {
        Ok(p) => p,
        Err(_) => return Ok(Vec::new()),
    };
    let Some(event) = parsed.event else {
        return Ok(Vec::new());
    };
    let mut iocs = Vec::new();
    for a in event.attributes {
        let kind = match a.attr_type.to_ascii_lowercase().as_str() {
            "md5" => IocType::Md5,
            "sha1" => IocType::Sha1,
            "sha256" => IocType::Sha256,
            "blake3" => IocType::Blake3,
            _ => continue,
        };
        let v = a.value.to_ascii_lowercase();
        if v.len() == kind.expected_hex_len()
            && v.chars().all(|c| c.is_ascii_hexdigit())
        {
            iocs.push(Ioc { kind, value: v });
        }
    }
    Ok(iocs)
}

/// Bulk insert parsed IOCs under `bundle_label`. Idempotent on the
/// `(ioc_type, value)` UNIQUE constraint. Returns the count of newly
/// inserted rows.
pub fn insert_bundle(
    conn: &mut Connection,
    bundle_label: &str,
    iocs: &[Ioc],
) -> Result<usize, IocError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let tx = conn.transaction()?;
    let mut inserted = 0usize;
    {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO user_iocs (bundle, ioc_type, value, created_at_utc)
             VALUES (?1, ?2, ?3, ?4)",
        )?;
        for ioc in iocs {
            inserted += stmt.execute(params![
                bundle_label,
                ioc.kind.as_str(),
                &ioc.value,
                now,
            ])?;
        }
    }
    tx.commit()?;
    Ok(inserted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_hash_list() {
        // 32 hex = md5, 40 hex = sha1, 64 hex = sha256.
        let text = "
# A comment
deadbeefdeadbeefdeadbeefdeadbeef
0123456789abcdef0123456789abcdef01234567
00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
not-a-hash
";
        let iocs = parse_bundle_text(text).unwrap();
        assert_eq!(iocs.len(), 3);
        assert_eq!(iocs[0].kind, IocType::Md5);
        assert_eq!(iocs[1].kind, IocType::Sha1);
        assert_eq!(iocs[2].kind, IocType::Sha256);
    }

    #[test]
    fn parses_csv_with_type_column() {
        let csv = "type,value
md5,deadbeefdeadbeefdeadbeefdeadbeef
sha256,00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
";
        let iocs = parse_bundle_text(csv).unwrap();
        assert_eq!(iocs.len(), 2);
    }

    #[test]
    fn parses_misp_json() {
        let json = r#"{"Event": {"Attribute": [
            {"type": "md5", "value": "deadbeefdeadbeefdeadbeefdeadbeef"},
            {"type": "sha256", "value": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"},
            {"type": "url", "value": "http://example.com"}
        ]}}"#;
        let iocs = parse_bundle_text(json).unwrap();
        assert_eq!(iocs.len(), 2);
    }

    #[test]
    fn parses_stix_indicator() {
        let json = r#"{"objects": [
            {"type": "indicator", "pattern": "[file:hashes.MD5 = 'deadbeefdeadbeefdeadbeefdeadbeef']"}
        ]}"#;
        let iocs = parse_bundle_text(json).unwrap();
        assert_eq!(iocs.len(), 1);
        assert_eq!(iocs[0].kind, IocType::Md5);
    }

    #[test]
    fn unrecognised_format_errors() {
        let err = parse_bundle_text("just random English text").unwrap_err();
        assert!(matches!(err, IocError::UnrecognisedFormat));
    }

    #[test]
    fn insert_bundle_idempotent() {
        let mut conn = crate::db::open_in_memory().unwrap();
        let iocs = vec![Ioc {
            kind: IocType::Md5,
            value: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        }];
        let n = insert_bundle(&mut conn, "bundle1", &iocs).unwrap();
        assert_eq!(n, 1);
        let n2 = insert_bundle(&mut conn, "bundle2", &iocs).unwrap();
        assert_eq!(n2, 0); // UNIQUE collision
    }
}
