//! UEFI / EFI System Partition scan (TASK-145, FR-138, Phase 10).
//!
//! The ESP is a tiny FAT32 partition every UEFI system carries, holding
//! the boot loaders, vendor firmware capsules, and on some systems a
//! signed shim for Linux. Recent bootkits (BlackLotus, ESPecter,
//! MosaicRegressor) drop their first-stage payload here so it executes
//! before Windows / Linux loads. Scanning the ESP catches these even
//! though they live below the OS-managed filesystem.
//!
//! ## Approach
//!
//! Detect the ESP mount point per-OS, walk it, and run two checks
//! against each file:
//!
//!  1. SHA-256 against a small curated list of known-bootkit hashes
//!     compiled into the binary (`KNOWN_BOOTKIT_HASHES`).
//!  2. YARA-x against the engine's rule pack (delegated to the normal
//!     detection pipeline; the ESP walker just yields paths).
//!
//! ## ESP location per OS
//!
//!  - **Windows:** typically `\\?\GLOBALROOT\Device\Harddisk0\Partition1\`
//!    or — when mounted — `Z:\` after `mountvol Z: /S`. Access requires
//!    administrator; without it the walker returns
//!    `EspError::AccessDenied`.
//!  - **Linux:** standard mount point `/boot/efi` or `/efi`
//!    (mountpoint discovery via `/proc/self/mountinfo`).
//!  - **macOS:** deferred per the roadmap (sealed system volume +
//!    rootless prevents read access without disabling SIP, which is
//!    out of scope for the free-tier user-mode posture).
//!
//! ## Scope
//!
//! Phase 10 wave 1 ships the cross-platform types, the mount-point
//! discovery helpers, and the curated known-bootkit hash list. The
//! actual file walk + scan loop runs through the existing scan engine
//! — call `enumerate_esp_roots()` and feed the result paths to a
//! scan_session with `scan_options.scan_esp = true`. macOS deferred.

use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::path::Path;

use serde::{Deserialize, Serialize};

/// One ESP root path discovered on this host. Multiple ESPs are
/// possible on dual-boot systems; the enumerator returns every
/// reachable one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EspMount {
    pub path: PathBuf,
    /// Filesystem reported by the OS (`vfat`, `msdosfs`, `FAT32`, …).
    pub fs_type: String,
    /// `true` when the engine has read access; `false` when discovery
    /// resolved the path but a regular-user walker can't enter (e.g.
    /// Windows ESP without admin, macOS sealed SSV).
    pub readable: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum EspError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("ESP not present on this host")]
    NotPresent,
    #[error("ESP requires elevated privileges on this OS")]
    AccessDenied,
    #[error("macOS ESP scan is deferred (sealed system volume)")]
    DeferredMacos,
}

/// Length of a SHA-256 in hex characters. Every entry in
/// [`KNOWN_BOOTKIT_HASHES`] must be exactly this long; the lookup
/// rejects anything else up front so a malformed entry can't silently
/// no-match.
pub const SHA256_HEX_LEN: usize = 64;

/// Curated known-bootkit SHA-256 hashes compiled into the binary. Each
/// entry is `(sha256_hex, family_label, severity)`.
///
/// **Intentionally empty in this commit**: an earlier curated list
/// shipped malformed entries (one 40-char SHA-1 and two truncated
/// 8-char values) which `match_known_bootkit_hash` could never match
/// because `str::eq_ignore_ascii_case` requires identical length. The
/// silent false-negative was caught in code review. Real curated
/// SHA-256s for BlackLotus / ESPecter / MosaicRegressor land via the
/// bootkit updater feed in a follow-up — the published research
/// papers redact full hashes for responsible-disclosure reasons.
///
/// Add new rows here only with exactly 64 lower-case hex characters;
/// the `curated_list_entries_are_64_char_lower_hex` test enforces it.
pub const KNOWN_BOOTKIT_HASHES: &[(&str, &str, &str)] = &[];

/// Enumerate ESPs reachable on this host.
pub fn enumerate_esp_roots() -> Result<Vec<EspMount>, EspError> {
    enumerate_inner()
}

#[cfg(target_os = "linux")]
fn enumerate_inner() -> Result<Vec<EspMount>, EspError> {
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
    let mut roots = Vec::new();
    for line in mounts.lines() {
        // /proc/self/mountinfo column layout (man 5 proc):
        //   id parentid major:minor root mountpoint options ...
        //   - fs_type source super_opts
        let parts: Vec<&str> = line.split(' ').collect();
        let mountpoint = match parts.get(4) {
            Some(p) => *p,
            None => continue,
        };
        // Look for the canonical ESP mount points.
        if mountpoint != "/boot/efi" && mountpoint != "/efi" && mountpoint != "/boot" {
            continue;
        }
        let dash = parts.iter().position(|p| *p == "-").unwrap_or(0);
        let fs_type = parts.get(dash + 1).copied().unwrap_or("vfat");
        if !fs_type.eq_ignore_ascii_case("vfat") && !fs_type.eq_ignore_ascii_case("msdos") {
            continue;
        }
        let path = PathBuf::from(mountpoint);
        let readable = path.exists();
        roots.push(EspMount {
            path,
            fs_type: fs_type.to_string(),
            readable,
        });
    }
    Ok(roots)
}

#[cfg(target_os = "windows")]
fn enumerate_inner() -> Result<Vec<EspMount>, EspError> {
    // Windows hides the ESP unless mounted with `mountvol`. We don't
    // run `mountvol` ourselves (would require admin + would mutate
    // system state); instead, we look for an existing mount under a
    // drive letter and treat the volume as readable if the path is
    // accessible. The user-facing flow on Windows: an "Enable ESP scan"
    // toggle in the Phase 10 Settings sub-tab launches an elevated
    // helper that mounts the ESP read-only, runs the scan, and
    // un-mounts. Until that helper lands we surface the partition's
    // shape but mark it unreadable.
    let candidates = ["Z:\\EFI", "S:\\EFI", "P:\\EFI"];
    let mut roots = Vec::new();
    for cand in candidates {
        let p = Path::new(cand);
        if p.exists() {
            roots.push(EspMount {
                path: p.to_path_buf(),
                fs_type: "FAT32".to_string(),
                readable: true,
            });
        }
    }
    if roots.is_empty() {
        // Document the presence of an unmounted ESP via a non-readable
        // placeholder. The UI can render this as "ESP detected but not
        // mounted — enable scanning in Settings".
        roots.push(EspMount {
            path: PathBuf::from(r"\\?\GLOBALROOT\Device\HarddiskVolume1"),
            fs_type: "FAT32".to_string(),
            readable: false,
        });
    }
    Ok(roots)
}

#[cfg(target_os = "macos")]
fn enumerate_inner() -> Result<Vec<EspMount>, EspError> {
    // Deferred — see module doc comment.
    Err(EspError::DeferredMacos)
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn enumerate_inner() -> Result<Vec<EspMount>, EspError> {
    Ok(Vec::new())
}

/// Returns the matching [`KNOWN_BOOTKIT_HASHES`] row when `sha256_hex`
/// (no `0x` prefix) lines up with a known family.
///
/// Rejects inputs whose length isn't [`SHA256_HEX_LEN`] up front — the
/// curated list is SHA-256-only by contract, so a SHA-1 or truncated
/// input always means "no match," and silently returning None here is
/// the same outcome as letting the loop fall through, but failing fast
/// surfaces caller bugs earlier in the trace.
pub fn match_known_bootkit_hash(sha256_hex: &str) -> Option<(&'static str, &'static str)> {
    if sha256_hex.len() != SHA256_HEX_LEN {
        return None;
    }
    let needle = sha256_hex.to_ascii_lowercase();
    for (hash, family, severity) in KNOWN_BOOTKIT_HASHES {
        if hash.eq_ignore_ascii_case(&needle) {
            return Some((family, severity));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerate_does_not_panic() {
        let _ = enumerate_esp_roots();
    }

    #[test]
    fn match_rejects_inputs_with_wrong_length() {
        // SHA-1 (40 hex) — too short for a SHA-256 lookup.
        assert!(match_known_bootkit_hash("0c45663dbb1ac21ff2c64ed5e74cc26d4787c4cc").is_none());
        // Truncated 8-char input.
        assert!(match_known_bootkit_hash("a99c5e7d").is_none());
        // 65 chars — one too many.
        assert!(match_known_bootkit_hash(&"0".repeat(65)).is_none());
        // Empty.
        assert!(match_known_bootkit_hash("").is_none());
    }

    #[test]
    fn match_known_bootkit_hash_returns_none_for_unknown_well_formed_sha256() {
        let needle = "f".repeat(SHA256_HEX_LEN);
        assert!(match_known_bootkit_hash(&needle).is_none());
    }

    #[test]
    fn curated_list_entries_are_64_char_lower_hex() {
        for (hash, family, _) in KNOWN_BOOTKIT_HASHES {
            assert_eq!(
                hash.len(),
                SHA256_HEX_LEN,
                "entry for {family} is not {SHA256_HEX_LEN} chars: {hash:?}"
            );
            assert!(
                hash.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "entry for {family} contains non-lower-hex chars: {hash:?}"
            );
        }
    }

    #[test]
    fn curated_list_has_no_duplicates() {
        let mut hashes: Vec<&str> = KNOWN_BOOTKIT_HASHES.iter().map(|(h, _, _)| *h).collect();
        hashes.sort();
        let before = hashes.len();
        hashes.dedup();
        assert_eq!(
            hashes.len(),
            before,
            "duplicate hash in KNOWN_BOOTKIT_HASHES"
        );
    }
}
