//! Per-process image-hash integrity (TASK-298).
//!
//! At process-start, the daemon snapshots the running image's
//! BLAKE3 (via the existing mythkernel hasher). The user's
//! known-good catalogue (NSRL / package-manager) provides the
//! expected hash for the same path. The two are then compared.
//!
//! Three states:
//!
//!   * `Match` — same hash; no finding
//!   * `UnknownPath` — daemon snapshotted a path the
//!     catalogue doesn't know about
//!   * `Mismatch` — known path, hash differs — the image on
//!     disk was replaced after install

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageHashStatus {
    Match,
    Mismatch,
    UnknownPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageHashFinding {
    pub status: ImageHashStatus,
    pub image_path: String,
    pub measured_hash: String,
    pub expected_hash: Option<String>,
}

pub fn evaluate_image_hash(
    image_path: &str,
    measured_hash: &str,
    expected_hash: Option<&str>,
) -> ImageHashFinding {
    let status = match expected_hash {
        None => ImageHashStatus::UnknownPath,
        Some(exp) => {
            if exp.eq_ignore_ascii_case(measured_hash) {
                ImageHashStatus::Match
            } else {
                ImageHashStatus::Mismatch
            }
        }
    };
    ImageHashFinding {
        status,
        image_path: image_path.to_string(),
        measured_hash: measured_hash.to_string(),
        expected_hash: expected_hash.map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_when_hashes_equal() {
        let f = evaluate_image_hash("/usr/bin/ls", "abc", Some("ABC"));
        assert_eq!(f.status, ImageHashStatus::Match);
    }

    #[test]
    fn mismatch_when_hashes_differ() {
        let f = evaluate_image_hash("/usr/bin/ls", "abc", Some("xyz"));
        assert_eq!(f.status, ImageHashStatus::Mismatch);
    }

    #[test]
    fn unknown_path_when_expected_absent() {
        let f = evaluate_image_hash("/usr/bin/unknown", "abc", None);
        assert_eq!(f.status, ImageHashStatus::UnknownPath);
        assert!(f.expected_hash.is_none());
    }
}
