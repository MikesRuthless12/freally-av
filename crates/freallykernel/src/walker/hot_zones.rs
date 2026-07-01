//! TASK-230 — User-defined hot-zone globs.
//!
//! Paths matching a hot-zone glob get priority scan attention: full
//! YARA pass, no verdict-cache short-circuit, no extension-policy
//! skip. Lets a paranoid user say "always deep-scan `~/Downloads/`
//! and `~/Documents/Tax/` no matter what the cache thinks."
//!
//! Glob syntax mirrors the existing exclusions matcher: `*` matches a
//! single path component, `**` matches across separators. Patterns
//! are stored in a `HotZones` set; lookup is O(n) over a small list
//! (users rarely add more than a handful).

use std::path::Path;

/// A user-defined hot zone — a glob pattern + an optional friendly
/// label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotZone {
    pub pattern: String,
    pub label: Option<String>,
}

/// Collection of hot zones. The engine consults [`HotZones::matches`]
/// per file; a match flips the per-file `scan_with_priority` flag.
#[derive(Debug, Clone, Default)]
pub struct HotZones {
    zones: Vec<HotZone>,
}

impl HotZones {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, pattern: impl Into<String>, label: Option<String>) {
        self.zones.push(HotZone {
            pattern: pattern.into(),
            label,
        });
    }

    pub fn len(&self) -> usize {
        self.zones.len()
    }

    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    /// Iterate the zones (for serializing to settings).
    pub fn iter(&self) -> impl Iterator<Item = &HotZone> {
        self.zones.iter()
    }

    /// Returns `Some(zone)` for the first matching pattern, or `None`
    /// when no hot zone covers `path`.
    pub fn matches(&self, path: &Path) -> Option<&HotZone> {
        let p = path.to_string_lossy();
        self.zones.iter().find(|z| glob_match(&z.pattern, &p))
    }
}

/// Lightweight glob matcher with `*` (segment-local) and `**` (deep
/// across separators) semantics. Adapted from the same algorithm used
/// by `crate::exclusions` so behavior matches the user's mental
/// model.
fn glob_match(pattern: &str, candidate: &str) -> bool {
    glob_recurse(pattern.as_bytes(), candidate.as_bytes())
}

fn glob_recurse(p: &[u8], c: &[u8]) -> bool {
    let mut pi = 0;
    let mut ci = 0;
    let mut star_p: Option<usize> = None;
    let mut star_c: usize = 0;
    let mut double_star_p: Option<usize> = None;
    let mut double_star_c: usize = 0;
    while ci < c.len() {
        if pi < p.len() && p[pi] == b'*' {
            if pi + 1 < p.len() && p[pi + 1] == b'*' {
                double_star_p = Some(pi + 2);
                double_star_c = ci;
                pi += 2;
                continue;
            }
            star_p = Some(pi + 1);
            star_c = ci;
            pi += 1;
            continue;
        }
        if pi < p.len() && (p[pi] == c[ci] || p[pi] == b'?') {
            pi += 1;
            ci += 1;
            continue;
        }
        if let Some(sp) = star_p {
            // Backtrack to the most recent `*`, advance candidate by
            // one char (but not past a `/` — segment-local).
            if c[star_c] != b'/' && c[star_c] != b'\\' {
                pi = sp;
                star_c += 1;
                ci = star_c;
                continue;
            }
        }
        if let Some(dsp) = double_star_p {
            pi = dsp;
            double_star_c += 1;
            ci = double_star_c;
            continue;
        }
        return false;
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn empty_zones_match_nothing() {
        let z = HotZones::new();
        assert!(z.matches(&PathBuf::from("/anywhere")).is_none());
    }

    #[test]
    fn exact_path_match() {
        let mut z = HotZones::new();
        z.add("/home/user/Downloads/setup.exe", Some("downloads".into()));
        assert!(
            z.matches(&PathBuf::from("/home/user/Downloads/setup.exe"))
                .is_some()
        );
        assert!(
            z.matches(&PathBuf::from("/home/user/Downloads/other.exe"))
                .is_none()
        );
    }

    #[test]
    fn single_star_segment_local() {
        let mut z = HotZones::new();
        z.add("/home/user/Downloads/*.exe", None);
        assert!(
            z.matches(&PathBuf::from("/home/user/Downloads/setup.exe"))
                .is_some()
        );
        // `*` shouldn't cross `/`.
        assert!(
            z.matches(&PathBuf::from("/home/user/Downloads/nested/setup.exe"))
                .is_none()
        );
    }

    #[test]
    fn double_star_crosses_separators() {
        // Standard glob semantics: `**/x` requires at least one
        // intermediate directory. To also match the no-subdir case
        // the user adds the bare `Documents/*.pdf` pattern alongside.
        let mut z = HotZones::new();
        z.add("/home/user/Documents/**/*.pdf", None);
        assert!(
            z.matches(&PathBuf::from("/home/user/Documents/Tax/2025/return.pdf"))
                .is_some()
        );
        assert!(
            z.matches(&PathBuf::from("/home/user/Other/x.pdf"))
                .is_none()
        );
    }

    #[test]
    fn returns_first_matching_zone() {
        let mut z = HotZones::new();
        z.add("/a/**", Some("zone-a".into()));
        z.add("/a/b/c", Some("zone-c".into()));
        let m = z.matches(&PathBuf::from("/a/b/c")).unwrap();
        assert_eq!(m.label.as_deref(), Some("zone-a"));
    }
}
