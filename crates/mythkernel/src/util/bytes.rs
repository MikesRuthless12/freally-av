//! Byte-level helpers shared across mythkernel parsers.
//!
//! These are intentionally tiny — wrapping the standard
//! `windows().position(...)` shape in a single name avoids the
//! five-copy duplication that piled up in Phase 10 Wave 2 (PDF
//! action / stream walkers, SFX host detector, RTF object
//! extractor, MIME multipart splitter).
//!
//! Performance: `Vec<u8>::windows(n).position(|w| w == needle)` is
//! the same loop a manual byte-by-byte search would write, plus
//! the autovectorizer occasionally finds wider equality compares
//! at small `n`. If a future hot path needs SIMD, swap in
//! `memchr::memmem` here — every caller picks up the upgrade for
//! free.

/// Locate the first occurrence of `needle` in `haystack`. Returns
/// `None` when `needle` is empty or longer than `haystack`.
pub fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Locate the *last* occurrence of `needle` in `haystack`. Used by
/// PDF `%%EOF` location (must be the trailing one, since the format
/// allows comments containing `%%EOF` literally).
pub fn rfind_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_subslice_hits_first_occurrence() {
        assert_eq!(find_subslice(b"abcdefabc", b"abc"), Some(0));
    }

    #[test]
    fn find_subslice_misses() {
        assert_eq!(find_subslice(b"abcdef", b"xyz"), None);
    }

    #[test]
    fn find_subslice_empty_needle() {
        assert_eq!(find_subslice(b"abc", b""), None);
    }

    #[test]
    fn find_subslice_needle_longer_than_haystack() {
        assert_eq!(find_subslice(b"ab", b"abc"), None);
    }

    #[test]
    fn rfind_subslice_hits_last_occurrence() {
        assert_eq!(rfind_subslice(b"abcdefabc", b"abc"), Some(6));
    }
}
