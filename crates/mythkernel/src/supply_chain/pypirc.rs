//! `.pypirc` token-leak detector (TASK-325).
//!
//! Parses `~/.pypirc` for `password = pypi-…` token fields. Any
//! password whose value starts with the standard PyPI upload-
//! token prefix is recorded; the file `mtime` then drives a
//! 90-day staleness threshold.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PypircFindingKind {
    UploadToken,
    StaleUploadToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PypircFinding {
    pub kind: PypircFindingKind,
    pub source: PathBuf,
    pub repository: String,
    /// Age of the underlying `.pypirc` file in days.
    pub age_days: i64,
}

pub const STALE_TOKEN_THRESHOLD_DAYS: i64 = 90;

/// Cap the surfaced `repository` field at this many bytes — a
/// pathological `.pypirc` with a giant `[section]` header
/// shouldn't allocate unbounded strings into every finding.
const REPO_FIELD_BYTE_CAP: usize = 256;

pub fn audit(config_path: &Path, now_unix_s: i64) -> Vec<PypircFinding> {
    let Ok(body) = std::fs::read_to_string(config_path) else {
        return Vec::new();
    };
    let age_days = file_age_days(config_path, now_unix_s);
    audit_body(config_path, &body, age_days)
}

fn audit_body(source: &Path, body: &str, age_days: i64) -> Vec<PypircFinding> {
    let mut out = Vec::new();
    let mut current_section: Option<String> = None;
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            let inner = line.trim_matches(['[', ']']).trim();
            // Bound the section name so a 100-MB header in a
            // hostile `.pypirc` doesn't propagate into every
            // finding's `repository` field.
            let bounded = if inner.len() > REPO_FIELD_BYTE_CAP {
                let mut cut = REPO_FIELD_BYTE_CAP;
                while cut > 0 && !inner.is_char_boundary(cut) {
                    cut -= 1;
                }
                &inner[..cut]
            } else {
                inner
            };
            current_section = Some(bounded.to_string());
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if !k.trim().eq_ignore_ascii_case("password") {
            continue;
        }
        let value = v.trim().trim_matches(['"', '\'']);
        if !value.starts_with("pypi-") {
            continue;
        }
        let repo = current_section
            .clone()
            .unwrap_or_else(|| "<global>".to_string());
        let kind = if age_days > STALE_TOKEN_THRESHOLD_DAYS {
            PypircFindingKind::StaleUploadToken
        } else {
            PypircFindingKind::UploadToken
        };
        out.push(PypircFinding {
            kind,
            source: source.to_path_buf(),
            repository: repo,
            age_days,
        });
    }
    out
}

fn file_age_days(path: &Path, now_unix_s: i64) -> i64 {
    let Ok(meta) = std::fs::metadata(path) else {
        return 0;
    };
    let Ok(modified) = meta.modified() else {
        return 0;
    };
    let dur = match modified.duration_since(std::time::SystemTime::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => return 0,
    };
    ((now_unix_s - dur).max(0)) / 86_400
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn flags_fresh_upload_token() {
        let dir = tempdir().unwrap();
        let p = dir.path().join(".pypirc");
        std::fs::write(
            &p,
            "[pypi]\nusername = __token__\npassword = pypi-AgEIc2hvdXRzMQ\n",
        )
        .unwrap();
        // Use the file's own mtime so age is ~0.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let out = audit(&p, now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, PypircFindingKind::UploadToken);
        assert_eq!(out[0].repository, "pypi");
    }

    #[test]
    fn flags_stale_token_via_synthetic_now() {
        let dir = tempdir().unwrap();
        let p = dir.path().join(".pypirc");
        std::fs::write(&p, "[pypi]\npassword = pypi-AAAA\n").unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 200 * 86_400;
        let out = audit(&p, now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, PypircFindingKind::StaleUploadToken);
        assert!(out[0].age_days >= STALE_TOKEN_THRESHOLD_DAYS);
    }

    #[test]
    fn non_pypi_password_silent() {
        let dir = tempdir().unwrap();
        let p = dir.path().join(".pypirc");
        std::fs::write(&p, "[pypi]\npassword = plaintext\n").unwrap();
        let out = audit(&p, 0);
        assert!(out.is_empty());
    }
}
