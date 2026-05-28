//! Memory-region shape + suspicious-region heuristic (TASK-292).
//!
//! A region is **suspicious** when it satisfies any of:
//!
//!   * `RWX` (read + write + execute) protection — almost
//!     never seen in a legitimate static binary's image
//!   * `R-X` private (non-backed) — process allocated an
//!     executable page that isn't mapped from a file (shellcode
//!     or JIT spray). JIT exemption flag suppresses this
//!     finding when the caller knows the pid is a JIT host
//!     (Chromium / Node.js / SpiderMonkey).
//!   * `R-X` backed by a file with extension != .exe / .dll /
//!     .so / .dylib / .node — executable page mapped from an
//!     unusual extension
//!
//! Heuristic is intentionally conservative; daemon UI surfaces
//! the finding as P1 with a "review pages" deep-link, not an
//! auto-quarantine.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MemoryProtection(pub u32);

impl MemoryProtection {
    pub const READ: Self = Self(0b0000_0001);
    pub const WRITE: Self = Self(0b0000_0010);
    pub const EXECUTE: Self = Self(0b0000_0100);
    pub const GUARD: Self = Self(0b0000_1000);
    pub const PRIVATE: Self = Self(0b0001_0000);

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for MemoryProtection {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub protection: MemoryProtection,
    /// `None` for anonymous / non-backed regions; the file
    /// path the region is mapped from otherwise.
    pub mapped_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuspiciousRegionFinding {
    pub base: u64,
    pub size: u64,
    pub reason: SuspiciousReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspiciousReason {
    Rwx,
    PrivateExecutable,
    ExecutableFromUnusualExtension,
}

const RECOGNISED_EXEC_EXTENSIONS: &[&str] =
    &[".exe", ".dll", ".so", ".dylib", ".node", ".bundle"];

/// Recognise versioned shared-library names like `libc.so.6`
/// or `libfoo.dylib.1.0` that don't end in the bare extension.
fn versioned_so_or_dylib(lc_path: &str) -> bool {
    for ext in [".so.", ".dylib."] {
        if let Some(rest) = lc_path.rfind(ext) {
            let after = &lc_path[rest + ext.len()..];
            // All characters after the extension must be digits
            // or dots — anything else (e.g. `.solib`) doesn't
            // qualify.
            if !after.is_empty() && after.chars().all(|c| c.is_ascii_digit() || c == '.') {
                return true;
            }
        }
    }
    false
}

pub fn is_suspicious_region(
    region: &MemoryRegion,
    is_jit_host: bool,
) -> Option<SuspiciousRegionFinding> {
    let prot = region.protection;
    let rwx_protection = prot.contains(MemoryProtection::READ)
        && prot.contains(MemoryProtection::WRITE)
        && prot.contains(MemoryProtection::EXECUTE);
    if rwx_protection {
        return Some(SuspiciousRegionFinding {
            base: region.base,
            size: region.size,
            reason: SuspiciousReason::Rwx,
        });
    }
    let exec_only = prot.contains(MemoryProtection::READ)
        && prot.contains(MemoryProtection::EXECUTE)
        && !prot.contains(MemoryProtection::WRITE);
    if !exec_only {
        return None;
    }
    match &region.mapped_path {
        None => {
            if is_jit_host {
                None
            } else {
                Some(SuspiciousRegionFinding {
                    base: region.base,
                    size: region.size,
                    reason: SuspiciousReason::PrivateExecutable,
                })
            }
        }
        Some(path) => {
            let lc = path.to_ascii_lowercase();
            // Direct extension hit, or versioned `.so.N[.M]…`
            // / `.dylib.N` Linux/macOS shared-library suffix.
            let recognised = RECOGNISED_EXEC_EXTENSIONS
                .iter()
                .any(|ext| lc.ends_with(ext))
                || versioned_so_or_dylib(&lc);
            if recognised {
                None
            } else {
                Some(SuspiciousRegionFinding {
                    base: region.base,
                    size: region.size,
                    reason: SuspiciousReason::ExecutableFromUnusualExtension,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(prot: MemoryProtection, path: Option<&str>) -> MemoryRegion {
        MemoryRegion {
            base: 0x1000_0000,
            size: 0x1000,
            protection: prot,
            mapped_path: path.map(str::to_string),
        }
    }

    #[test]
    fn rwx_anon_flagged() {
        let r = region(
            MemoryProtection::READ | MemoryProtection::WRITE | MemoryProtection::EXECUTE,
            None,
        );
        let f = is_suspicious_region(&r, false).unwrap();
        assert_eq!(f.reason, SuspiciousReason::Rwx);
    }

    #[test]
    fn r_x_anon_flagged_unless_jit_host() {
        let r = region(MemoryProtection::READ | MemoryProtection::EXECUTE, None);
        assert!(is_suspicious_region(&r, false).is_some());
        // JIT host exemption suppresses the private-exec finding.
        assert!(is_suspicious_region(&r, true).is_none());
    }

    #[test]
    fn r_x_backed_by_dll_is_clean() {
        let r = region(
            MemoryProtection::READ | MemoryProtection::EXECUTE,
            Some("C:\\Windows\\System32\\kernel32.dll"),
        );
        assert!(is_suspicious_region(&r, false).is_none());
    }

    #[test]
    fn r_x_backed_by_unusual_extension_flagged() {
        let r = region(
            MemoryProtection::READ | MemoryProtection::EXECUTE,
            Some("/tmp/data.bin"),
        );
        let f = is_suspicious_region(&r, false).unwrap();
        assert_eq!(f.reason, SuspiciousReason::ExecutableFromUnusualExtension);
    }

    #[test]
    fn rw_only_is_clean() {
        let r = region(MemoryProtection::READ | MemoryProtection::WRITE, None);
        assert!(is_suspicious_region(&r, false).is_none());
    }

    #[test]
    fn dylib_extension_clean_on_macos() {
        let r = region(
            MemoryProtection::READ | MemoryProtection::EXECUTE,
            Some("/usr/lib/libSystem.dylib"),
        );
        assert!(is_suspicious_region(&r, false).is_none());
    }

    #[test]
    fn so_extension_clean_on_linux() {
        let r = region(
            MemoryProtection::READ | MemoryProtection::EXECUTE,
            Some("/lib/x86_64-linux-gnu/libc.so.6"),
        );
        assert!(is_suspicious_region(&r, false).is_none());
    }
}
