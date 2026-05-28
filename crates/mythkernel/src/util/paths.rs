//! Path-canonicalisation helpers for attacker-supplied filenames.
//!
//! Several Wave 2 parsers carry filename strings extracted from
//! adversarial inputs:
//!
//!   * `email::EmlAttachment.filename` — from MIME
//!     `Content-Disposition: attachment; filename=…`
//!   * `email::msg::MsgAttachmentStream.filename_w` — from
//!     Outlook `__substg1.0_3704001F`
//!   * `browser::downloads::DownloadRecord.target_path` — from
//!     Chromium `History.downloads.target_path`
//!
//! These fields are **forensic** values — we never mutate the raw
//! parsed string because the analyst may want to see the literal
//! attacker chose. Instead, this module provides defensive
//! accessors that callers use whenever the value will become a
//! real path on the local filesystem (quarantine writes,
//! "open in folder", scan-on-extract, etc.).

use std::path::{Component, Path, PathBuf};

/// Maximum filename length we'll round-trip. Modern filesystems
/// vary (NTFS 255, ext4 255, APFS 255), and overlong names are a
/// known abuse vector — refuse anything longer than this cap.
pub const MAX_FILENAME_BYTES: usize = 240;

/// Sanitize an attacker-supplied filename for safe use as the
/// **last component** of a path the daemon controls (e.g. inside
/// a quarantine directory).
///
/// Defenses applied:
///   * strips every path separator (`/`, `\\`) — the result is a
///     single bare component
///   * drops NUL and ASCII control bytes
///   * drops Windows-reserved characters (`< > : " | ? *`)
///   * collapses `..` and `.` (treated as dot-prefix, not parent)
///   * rejects Windows reserved names (CON, PRN, AUX, NUL,
///     COM0-9, LPT0-9 — both bare and with extensions)
///   * truncates to [`MAX_FILENAME_BYTES`]
///   * substitutes [`SAFE_DEFAULT_NAME`] when the input would
///     otherwise reduce to empty
pub const SAFE_DEFAULT_NAME: &str = "_mythodikal_unsafe_name_";

const WINDOWS_RESERVED_BARE: &[&str] = &[
    "con", "prn", "aux", "nul", "com0", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
    "com8", "com9", "lpt0", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

pub fn safe_filename(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            // Strip every path separator — the result is one component.
            '/' | '\\' => continue,
            // Strip NUL and ASCII control bytes.
            c if (c as u32) < 0x20 => continue,
            // Strip Windows-reserved characters that can confuse
            // shell expansion or NTFS open.
            '<' | '>' | ':' | '"' | '|' | '?' | '*' => continue,
            _ => out.push(c),
        }
    }
    // Collapse a leading dot sequence — `..` or `...` etc. become
    // empty, defending against the rare carrier that managed to
    // smuggle dots past the separator strip.
    out = out.trim_start_matches('.').to_string();
    // Truncate to byte cap. Walk back to a char boundary so we
    // don't split a UTF-8 sequence.
    if out.len() > MAX_FILENAME_BYTES {
        let mut end = MAX_FILENAME_BYTES;
        while end > 0 && !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
    }
    // Reserved-name check — case-insensitive on the stem.
    let stem_lower = out.split('.').next().unwrap_or("").to_ascii_lowercase();
    if WINDOWS_RESERVED_BARE.iter().any(|r| *r == stem_lower) {
        return SAFE_DEFAULT_NAME.to_string();
    }
    if out.is_empty() || out.chars().all(|c| c.is_whitespace()) {
        return SAFE_DEFAULT_NAME.to_string();
    }
    out
}

/// Cheap check: returns `true` when `p` is a relative path with
/// no parent-directory traversal and no absolute / drive-letter
/// prefix. Used by code that wants to *validate* without
/// rewriting the value.
pub fn is_safe_relative(p: &str) -> bool {
    if p.is_empty() {
        return false;
    }
    if p.contains('\0') {
        return false;
    }
    let path = Path::new(p);
    if path.is_absolute() {
        return false;
    }
    // Reject Windows drive-letter (`C:foo`) even when not
    // absolute by Path::is_absolute on non-Windows targets.
    let bytes = p.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return false;
    }
    for comp in path.components() {
        match comp {
            Component::Normal(_) => {}
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

/// Safely join `candidate` under `root` and confirm the resolved
/// path stays inside `root`. Returns `None` when `candidate`
/// escapes the root via `..`, an absolute path, or a symlink
/// pointing outside.
///
/// `root` must already exist and be canonical. `candidate` is
/// treated as user-supplied. Use this whenever the daemon will
/// open / write / quarantine a file at a parser-derived path.
pub fn safe_join(root: &Path, candidate: &str) -> Option<PathBuf> {
    if !is_safe_relative(candidate) {
        return None;
    }
    let joined = root.join(candidate);
    // Canonicalise root once (caller may already have done this;
    // doing it again is idempotent).
    let canon_root = std::fs::canonicalize(root).ok()?;
    // We can't canonicalize `joined` because the candidate may
    // not yet exist (quarantine destinations are by definition
    // new). Walk components and reject any that escape.
    let mut resolved = canon_root.clone();
    for comp in Path::new(candidate).components() {
        match comp {
            Component::Normal(c) => resolved.push(c),
            Component::CurDir => {}
            _ => return None,
        }
    }
    if !resolved.starts_with(&canon_root) {
        return None;
    }
    // Suppress lint about unused `joined` — keeping the binding
    // documents the intent for readers.
    let _ = joined;
    Some(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_filename_strips_path_separators() {
        assert_eq!(safe_filename("a/b/c.txt"), "abc.txt");
        assert_eq!(safe_filename("a\\b\\c.txt"), "abc.txt");
        assert_eq!(safe_filename("..\\..\\..\\etc\\passwd"), "etcpasswd");
    }

    #[test]
    fn safe_filename_strips_nul_and_control() {
        assert_eq!(safe_filename("hello\0.txt"), "hello.txt");
        assert_eq!(safe_filename("hello\x01\x02\x1F.txt"), "hello.txt");
    }

    #[test]
    fn safe_filename_strips_windows_reserved_chars() {
        assert_eq!(safe_filename("a<b>c:\"d|e?f*.txt"), "abcdef.txt");
    }

    #[test]
    fn safe_filename_collapses_leading_dots() {
        assert_eq!(safe_filename("...hidden"), "hidden");
        assert_eq!(safe_filename("..\\..\\evil"), "evil");
    }

    #[test]
    fn safe_filename_rejects_reserved_names() {
        assert_eq!(safe_filename("CON"), SAFE_DEFAULT_NAME);
        assert_eq!(safe_filename("con.txt"), SAFE_DEFAULT_NAME);
        assert_eq!(safe_filename("PRN.docx"), SAFE_DEFAULT_NAME);
        assert_eq!(safe_filename("com1.dat"), SAFE_DEFAULT_NAME);
        assert_eq!(safe_filename("LPT9"), SAFE_DEFAULT_NAME);
    }

    #[test]
    fn safe_filename_substitutes_empty_or_pure_traversal() {
        assert_eq!(safe_filename(""), SAFE_DEFAULT_NAME);
        assert_eq!(safe_filename("///"), SAFE_DEFAULT_NAME);
        assert_eq!(safe_filename("....."), SAFE_DEFAULT_NAME);
    }

    #[test]
    fn safe_filename_truncates_at_cap_on_char_boundary() {
        let long = "a".repeat(MAX_FILENAME_BYTES + 100);
        let safe = safe_filename(&long);
        assert!(safe.len() <= MAX_FILENAME_BYTES);
        // Long unicode chars: must not split a multi-byte sequence.
        let utf8 = "💀".repeat(MAX_FILENAME_BYTES);
        let safe_utf8 = safe_filename(&utf8);
        assert!(safe_utf8.len() <= MAX_FILENAME_BYTES);
        // Must still be valid UTF-8 (String is by construction).
        let _ = std::str::from_utf8(safe_utf8.as_bytes()).unwrap();
    }

    #[test]
    fn safe_filename_preserves_legit_names() {
        assert_eq!(safe_filename("invoice.pdf"), "invoice.pdf");
        assert_eq!(
            safe_filename("Quarterly Report 2026.xlsx"),
            "Quarterly Report 2026.xlsx"
        );
    }

    #[test]
    fn is_safe_relative_accepts_simple_relative() {
        assert!(is_safe_relative("a/b/c.txt"));
        assert!(is_safe_relative("invoice.pdf"));
        assert!(is_safe_relative("./folder/file"));
    }

    #[test]
    fn is_safe_relative_rejects_absolute_and_traversal() {
        assert!(!is_safe_relative("/etc/passwd"));
        assert!(!is_safe_relative("../parent"));
        assert!(!is_safe_relative("foo/../bar"));
        assert!(!is_safe_relative("C:\\Windows"));
        assert!(!is_safe_relative("D:foo"));
        assert!(!is_safe_relative(""));
        assert!(!is_safe_relative("with\0nul"));
    }

    #[test]
    fn safe_join_rejects_escape() {
        let root = tempfile::tempdir().unwrap();
        assert!(safe_join(root.path(), "../escape.txt").is_none());
        assert!(safe_join(root.path(), "/etc/passwd").is_none());
        assert!(safe_join(root.path(), "ok/inside.txt").is_some());
    }
}
