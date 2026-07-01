//! RTL-override hidden-executable heuristic (TASK-248, Phase 8 Wave 2).
//!
//! Flags filenames containing Unicode bidirectional-override controls
//! that disguise an executable extension. Classic example:
//! `photo\u{202E}txe.exe` renders visually as `photoexe.txt` while
//! the OS sees `photo<RLO>txe.exe` and executes it.
//!
//! Pure path-string check — does NOT execute, hash, or open the file
//! beyond the stat the caller already did to learn the path. The
//! heuristic only fires when a bidi-override is present **and** the
//! logical-byte form ends in a known-dangerous extension, so plain
//! Arabic / Hebrew filenames do not match.

use serde::{Deserialize, Serialize};

const SUSPICIOUS_EXTENSIONS: &[&str] = &[
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js", ".sh", ".command",
];

/// Unicode bidi controls considered hostile for filename rendering.
/// U+202E is the classic RLO; the others (RLE, LRE, FSI, LRI, RLI,
/// PDI) are rarer but trip the same heuristic when paired with an
/// executable extension.
pub const BIDI_OVERRIDES: &[char] = &[
    '\u{202A}', // LRE
    '\u{202B}', // RLE
    '\u{202C}', // PDF (pop directional formatting)
    '\u{202D}', // LRO
    '\u{202E}', // RLO
    '\u{2066}', // LRI
    '\u{2067}', // RLI
    '\u{2068}', // FSI
    '\u{2069}', // PDI
];

/// Severity hint the daemon uses when building the finding row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RtlSeverity {
    /// Bidi-override present AND extension is in [`SUSPICIOUS_EXTENSIONS`].
    P0,
    /// Bidi-override present but extension is benign (e.g. .txt). The
    /// daemon may still surface this at low severity for forensics.
    P2,
}

/// One RTL-override finding shape. `visual` is the rendered form the
/// user sees (left-to-right interpretation under the override);
/// `logical` is the raw byte order the OS uses for the syscall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RtlFinding {
    pub severity: RtlSeverity,
    pub visual: String,
    pub logical: String,
    /// Bidi-override codepoints found (each as a string for JSON).
    pub overrides: Vec<String>,
    /// Extension matched against [`SUSPICIOUS_EXTENSIONS`] (lowercased,
    /// including the dot). None when no dangerous extension was found.
    pub matched_extension: Option<String>,
}

/// Inspect one filename for the RTL-override shape. Returns `Some`
/// when a bidi-override is present.
pub fn inspect_name(name: &str) -> Option<RtlFinding> {
    let overrides: Vec<char> = name
        .chars()
        .filter(|c| BIDI_OVERRIDES.contains(c))
        .collect();
    if overrides.is_empty() {
        return None;
    }
    let matched_extension = SUSPICIOUS_EXTENSIONS
        .iter()
        .find(|ext| name.to_ascii_lowercase().ends_with(*ext))
        .map(|s| (*s).to_string());
    let severity = if matched_extension.is_some() {
        RtlSeverity::P0
    } else {
        RtlSeverity::P2
    };
    Some(RtlFinding {
        severity,
        visual: visualize(name),
        logical: name.to_string(),
        overrides: overrides.iter().map(|c| c.to_string()).collect(),
        matched_extension,
    })
}

/// Produce the **visual** form a user would see if their text shaper
/// honored the embedded overrides. The shaper logic is approximate
/// (full Unicode bidi is involved); for the UI explainer we just
/// strip the override codepoints and reverse the substring between
/// each RLO / RLE / LRI and its closing PDF / PDI. Good enough for
/// the modal's "this file actually says `photo.exe`" preview.
pub fn visualize(name: &str) -> String {
    // Minimal shaper: split on the first override; reverse the tail.
    // Production text shaping is in the OS — this is a best-effort
    // preview for the explainer modal.
    if let Some(pos) = name.find(|c: char| BIDI_OVERRIDES.contains(&c)) {
        let head = &name[..pos];
        let tail_no_override: String = name[pos..]
            .chars()
            .filter(|c| !BIDI_OVERRIDES.contains(c))
            .collect();
        let reversed: String = tail_no_override.chars().rev().collect();
        return format!("{head}{reversed}");
    }
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rlo_with_exe_is_p0() {
        let name = "photo\u{202E}txe.exe";
        let f = inspect_name(name).expect("expected finding");
        assert_eq!(f.severity, RtlSeverity::P0);
        assert_eq!(f.logical, name);
        assert_eq!(f.matched_extension.as_deref(), Some(".exe"));
    }

    #[test]
    fn rlo_with_txt_is_p2() {
        let name = "report\u{202E}lmth.txt";
        let f = inspect_name(name).expect("expected finding");
        assert_eq!(f.severity, RtlSeverity::P2);
        assert!(f.matched_extension.is_none());
    }

    #[test]
    fn no_override_returns_none() {
        assert!(inspect_name("document.pdf").is_none());
    }

    #[test]
    fn arabic_filename_without_override_does_not_match() {
        // Arabic letters by themselves are not bidi overrides — they
        // are letter codepoints with intrinsic bidi class. The
        // detector must NOT fire on plain Arabic / Hebrew filenames.
        assert!(
            inspect_name("\u{0627}\u{0644}\u{0639}\u{0631}\u{0628}\u{064A}\u{0629}.pdf").is_none()
        );
    }

    #[test]
    fn visualize_strips_override_and_reverses_tail() {
        let visual = visualize("photo\u{202E}txe.exe");
        assert!(!visual.contains('\u{202E}'));
        assert!(visual.contains("photo"));
    }

    #[test]
    fn multiple_overrides_are_all_recorded() {
        let name = "a\u{202E}b\u{2067}c.exe";
        let f = inspect_name(name).unwrap();
        assert_eq!(f.overrides.len(), 2);
    }
}
