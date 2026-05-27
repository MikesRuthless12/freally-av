//! TASK-217 — Heuristic packer identification.
//!
//! In-tree signature table for the common executable packers. We scan
//! the first 64 KiB of an input for known magic sequences and known
//! section-name patterns. On hit we emit a `packer: <name>` annotation
//! that downstream YARA / unpacker stages key off.
//!
//! Deliberately minimal: no PE header parsing (that's TASK-216) — this
//! pass runs on every file the hasher already loaded, so it must be
//! cheap (sub-millisecond per file). Anything heavier belongs in a
//! later, header-aware stage.
//!
//! The detector returns `None` for unrecognised inputs; it does NOT
//! return a verdict severity — its single job is to label. The
//! existing detection pipeline turns that label into a finding when
//! paired with a YARA rule (or, in the future, a packer-only policy).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packer {
    Upx,
    Mpress,
    Themida,
    VmProtect,
    ASPack,
    Enigma,
    PeCompact,
    Petite,
}

impl Packer {
    pub fn name(self) -> &'static str {
        match self {
            Packer::Upx => "upx",
            Packer::Mpress => "mpress",
            Packer::Themida => "themida",
            Packer::VmProtect => "vmprotect",
            Packer::ASPack => "aspack",
            Packer::Enigma => "enigma",
            Packer::PeCompact => "pecompact",
            Packer::Petite => "petite",
        }
    }
}

/// Per-packer signature set. We match on either:
///   * a literal magic byte sequence anywhere in the scan window
///     (cheap; covers in-stream stub markers like `UPX!`), or
///   * a PE section name (which is a fixed 8-byte field in the
///     IMAGE_SECTION_HEADER; we look for it as a contiguous ASCII
///     run in the scan window).
struct Sig {
    packer: Packer,
    /// At least one of these patterns must appear in the scan window
    /// for the signature to match. ANY-match semantics.
    needles: &'static [&'static [u8]],
}

const SIGNATURES: &[Sig] = &[
    // UPX (BSD/Apache 2.0 — section names + magic byte sequence "UPX!").
    Sig {
        packer: Packer::Upx,
        needles: &[b"UPX!", b"UPX0", b"UPX1", b"UPX2"],
    },
    Sig {
        packer: Packer::Mpress,
        needles: &[b".MPRESS1", b".MPRESS2", b"MPRESS\x00"],
    },
    Sig {
        packer: Packer::Themida,
        needles: &[b".themida", b".Themida", b"WinLicense"],
    },
    Sig {
        packer: Packer::VmProtect,
        needles: &[b".vmp0", b".vmp1", b".vmp2", b"VMProtect"],
    },
    Sig {
        packer: Packer::ASPack,
        needles: &[b".aspack", b".adata"],
    },
    Sig {
        packer: Packer::Enigma,
        needles: &[b".enigma1", b".enigma2", b"\x45\x6e\x69\x67\x6d\x61"],
    },
    Sig {
        packer: Packer::PeCompact,
        needles: &[b"PEC2", b"pec1", b"pec2"],
    },
    Sig {
        packer: Packer::Petite,
        needles: &[b".petite", b"petite"],
    },
];

/// Maximum window we read into when scanning for signatures. Most
/// packer markers live within the first few section headers (offset
/// 0x400-0x800 in a typical PE); 64 KiB is generous headroom that
/// still keeps the pass cheap.
pub const SCAN_WINDOW_BYTES: usize = 64 * 1024;

/// Probe `bytes` for any known packer signature. Returns `Some` on
/// the first hit, `None` otherwise. Callers may truncate `bytes` to
/// [`SCAN_WINDOW_BYTES`] for a bounded scan; the function itself does
/// not cap (so a caller doing a full-file pass for forensic reasons
/// still works).
pub fn detect_packer(bytes: &[u8]) -> Option<Packer> {
    for sig in SIGNATURES {
        for needle in sig.needles {
            if contains_subslice(bytes, needle) {
                return Some(sig.packer);
            }
        }
    }
    None
}

/// Subslice search. `[u8]::windows` is `O(n*m)` in the worst case; for
/// our small needles (≤ 16 bytes) and 64 KiB window that's fine. We
/// stay byte-exact and case-sensitive — packer section names are
/// canonical.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_blob_with(needle: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 1024];
        v[256..256 + needle.len()].copy_from_slice(needle);
        v
    }

    #[test]
    fn detects_upx_via_marker() {
        let b = synth_blob_with(b"UPX!");
        assert_eq!(detect_packer(&b), Some(Packer::Upx));
    }

    #[test]
    fn detects_upx_via_section_name() {
        let b = synth_blob_with(b"UPX0");
        assert_eq!(detect_packer(&b), Some(Packer::Upx));
    }

    #[test]
    fn detects_themida() {
        let b = synth_blob_with(b".themida");
        assert_eq!(detect_packer(&b), Some(Packer::Themida));
        let b2 = synth_blob_with(b"WinLicense");
        assert_eq!(detect_packer(&b2), Some(Packer::Themida));
    }

    #[test]
    fn detects_vmprotect() {
        for needle in &[b".vmp0".as_ref(), b".vmp1", b".vmp2", b"VMProtect"] {
            let b = synth_blob_with(needle);
            assert_eq!(
                detect_packer(&b),
                Some(Packer::VmProtect),
                "missed needle {needle:?}"
            );
        }
    }

    #[test]
    fn clean_input_returns_none() {
        let b = vec![0u8; 4096];
        assert_eq!(detect_packer(&b), None);
    }

    #[test]
    fn case_sensitive_no_false_positive() {
        // Lowercase UPX shouldn't match; the canonical marker is
        // uppercase `UPX!`.
        let b = synth_blob_with(b"upx!");
        assert_eq!(detect_packer(&b), None);
    }

    #[test]
    fn names_round_trip() {
        for p in [
            Packer::Upx,
            Packer::Mpress,
            Packer::Themida,
            Packer::VmProtect,
            Packer::ASPack,
            Packer::Enigma,
            Packer::PeCompact,
            Packer::Petite,
        ] {
            // Each name is non-empty and lowercase ASCII.
            let n = p.name();
            assert!(!n.is_empty());
            assert!(n.chars().all(|c| c.is_ascii_lowercase()));
        }
    }
}
