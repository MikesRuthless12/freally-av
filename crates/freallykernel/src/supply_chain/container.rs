//! Container-image inventory shape (TASK-316).
//!
//! Detects whether `docker` / `podman` are available on PATH
//! (caller-supplied PATH split — keeps this module pure-logic)
//! and parses the read-only `docker images --format=…` output
//! the daemon captures at scan time. Layer extraction lives in
//! the per-OS daemon because the rootfs layout differs by
//! storage driver; this foundation owns the parsed image
//! inventory the closeout YARA pass consumes.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerEngine {
    pub binary: String,
    pub binary_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalImage {
    pub repository: String,
    pub tag: String,
    pub image_id: String,
    pub size_bytes: u64,
}

/// Look for `docker` / `podman` along the caller-supplied
/// `PATH` entries. Returns every binary that exists; the caller
/// decides which one to invoke (preference: docker first).
pub fn detect_engines(path_entries: &[PathBuf]) -> Vec<ContainerEngine> {
    let mut out = Vec::new();
    for binary in ["docker", "podman"] {
        for entry in path_entries {
            let candidate = entry.join(binary);
            if candidate.is_file() {
                out.push(ContainerEngine {
                    binary: binary.to_string(),
                    binary_path: candidate,
                });
                break;
            }
            // Windows .exe suffix.
            let candidate_exe = entry.join(format!("{binary}.exe"));
            if candidate_exe.is_file() {
                out.push(ContainerEngine {
                    binary: binary.to_string(),
                    binary_path: candidate_exe,
                });
                break;
            }
        }
    }
    out
}

/// Parse the tab-separated output the daemon captures by
/// calling `docker images --format '{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}'`.
///
/// Size is decoded from human-readable form (`123MB`, `1.2GB`)
/// into bytes — `docker images` does not expose raw bytes
/// via its default format.
pub fn parse_image_list(output: &str) -> Vec<LocalImage> {
    let mut out = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 4 {
            continue;
        }
        let repo = parts[0].trim();
        let tag = parts[1].trim();
        let id = parts[2].trim();
        let size_bytes = parse_size(parts[3].trim()).unwrap_or(0);
        if repo.is_empty() || id.is_empty() {
            continue;
        }
        out.push(LocalImage {
            repository: repo.to_string(),
            tag: tag.to_string(),
            image_id: id.to_string(),
            size_bytes,
        });
    }
    out
}

fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(s.len()));
    let num: f64 = num.trim().parse().ok()?;
    let mult: f64 = match unit.trim().to_ascii_uppercase().as_str() {
        "B" | "" => 1.0,
        "KB" => 1_000.0,
        "MB" => 1_000_000.0,
        "GB" => 1_000_000_000.0,
        "KIB" => 1_024.0,
        "MIB" => 1_024.0 * 1_024.0,
        "GIB" => 1_024.0 * 1_024.0 * 1_024.0,
        _ => return None,
    };
    Some((num * mult) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn detects_docker_when_present() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("docker"), b"#!/bin/sh\n").unwrap();
        let engines = detect_engines(&[dir.path().to_path_buf()]);
        assert!(engines.iter().any(|e| e.binary == "docker"));
    }

    #[test]
    fn empty_when_no_engine_found() {
        let dir = tempdir().unwrap();
        assert!(detect_engines(&[dir.path().to_path_buf()]).is_empty());
    }

    #[test]
    fn parses_image_list_with_sizes() {
        let raw = "alpine\tlatest\tsha256:abc\t8MB\nubuntu\t22.04\tsha256:def\t77.8MB\n";
        let images = parse_image_list(raw);
        assert_eq!(images.len(), 2);
        assert_eq!(images[0].repository, "alpine");
        assert_eq!(images[1].size_bytes, 77_800_000);
    }

    #[test]
    fn parses_gib_suffix() {
        assert_eq!(parse_size("1.5GiB").unwrap(), 1_610_612_736);
    }
}
