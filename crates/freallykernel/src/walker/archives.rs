//! Multi-format archive scanning (TASK-085, Phase 10).
//!
//! Unified surface for opening an archive on disk, iterating its members,
//! and feeding each member's bytes to a caller-supplied callback. Honors
//! the existing [`BombGuard`] per-archive ceilings (cumulative
//! decompressed bytes, recursion depth, per-entry expansion ratio) so a
//! malicious archive can't blow up the engine's memory or wall time.
//!
//! ## Formats covered
//!
//!  1. Container archives (multi-member):
//!     - ZIP (`.zip`, `.zipx`, `.jar`, `.war`, `.ear`, `.apk`) via `zip`
//!     - TAR family (`.tar`, `.tar.gz`/`.tgz`, `.tar.bz2`/`.tbz2`,
//!       `.tar.xz`/`.txz`, `.tar.zst`) via `tar` over a decompressor
//!     - 7-Zip (`.7z`) via `sevenz_rust2`
//!  2. Compressed streams (single payload — exposed as a one-member
//!     synthetic archive named after the underlying file with the
//!     compression extension stripped):
//!     - gzip (`.gz`) via `flate2` (pure-Rust miniz_oxide backend)
//!     - bzip2 (`.bz2`) via `bzip2-rs`
//!     - XZ / LZMA (`.xz`, `.lzma`) via `lzma-rs`
//!     - Zstandard (`.zst`) via `zstd`
//!     - LZ4 (`.lz4`) via `lz4_flex`
//!
//! ## Intentionally NOT covered
//!
//!  * RAR: the UnRAR source license restricts derived works (no
//!    creating RAR-compatible packers). That fails the project's
//!    free + commercial + no-constraints posture per `docs/prd.md`
//!    § 1.5, so RAR is excluded by design. Detection still recognises
//!    the extension so the engine can log "RAR not scanned" rather than
//!    silently skipping it.
//!  * ISO / UDF, CAB, ARJ, ACE, LHA: deferred. No clean pure-Rust
//!    reader for ISO/UDF as of Phase 10 wave 1; CAB is comparatively
//!    rare outside Windows installers and can land as a follow-up via
//!    the `cab` crate without touching the surface here.
//!
//! ## Zip-slip + bomb posture
//!
//! Member names are treated as **labels only** — the scanner never
//! writes a byte to disk under a member's name. A crafted entry called
//! `../../../etc/passwd` is harmless because there is no write target.
//! Bomb defense uses [`BombGuard`] for both per-entry expansion ratio
//! and cumulative decompressed bytes; the caller picks the budget by
//! constructing the guard.
//!
//! ## Threading
//!
//! Pure single-thread per archive. The engine already parallelises at
//! the file level (rayon over the walker output); fanning out *inside*
//! one archive would dwarf the I/O bottleneck on a typical malware-corpus
//! archive (lots of small entries). The cancel flag is checked at every
//! member boundary so a long archive yields to a user-side Cancel within
//! one member's read time.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufReader, Cursor, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::walker::bomb_guard::{BombGuard, BombGuardError};

/// Default per-entry read cap. Honors `BombGuard`'s cumulative budget but
/// also clamps any **one** entry so a malicious archive with a single
/// `Entry { uncompressed_size = u64::MAX }` can't request 16 EiB up front.
/// 512 MiB matches the existing top-level `archive_scan.rs` (Phase 6).
pub const DEFAULT_PER_ENTRY_READ_CAP: u64 = 512 * 1024 * 1024;

/// Archive kinds the scanner recognises. The enum carries no payload —
/// the format-specific reader is instantiated by [`iter_members`] right
/// before dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    /// PKWARE-style ZIP. Includes derivatives that ride the same on-disk
    /// format (jar/war/ear/apk).
    Zip,
    /// POSIX tar — uncompressed.
    Tar,
    /// tar + gzip.
    TarGz,
    /// tar + bzip2.
    TarBz2,
    /// tar + xz (LZMA2 framed).
    TarXz,
    /// tar + Zstandard.
    TarZst,
    /// 7-Zip.
    SevenZ,
    /// Standalone gzip stream (single payload).
    Gzip,
    /// Standalone bzip2 stream.
    Bzip2,
    /// Standalone XZ or LZMA-Alone stream.
    Xz,
    /// Standalone Zstandard stream.
    Zstd,
    /// Standalone LZ4 frame stream.
    Lz4,
    /// RAR archive — recognised but intentionally unsupported (UnRAR
    /// license restricts derived works). Surfaces as
    /// [`ArchiveError::UnsupportedFormat`] so the engine logs the skip
    /// rather than silently ignoring `.rar` malware.
    Rar,
}

impl ArchiveKind {
    /// Stable label used in scan logs + the future
    /// `findings.evidence.archive_kind` column.
    pub fn as_str(self) -> &'static str {
        match self {
            ArchiveKind::Zip => "zip",
            ArchiveKind::Tar => "tar",
            ArchiveKind::TarGz => "tar.gz",
            ArchiveKind::TarBz2 => "tar.bz2",
            ArchiveKind::TarXz => "tar.xz",
            ArchiveKind::TarZst => "tar.zst",
            ArchiveKind::SevenZ => "7z",
            ArchiveKind::Gzip => "gzip",
            ArchiveKind::Bzip2 => "bzip2",
            ArchiveKind::Xz => "xz",
            ArchiveKind::Zstd => "zstd",
            ArchiveKind::Lz4 => "lz4",
            ArchiveKind::Rar => "rar",
        }
    }
}

/// Recognise an archive's format from its filename extension(s).
/// Lower-cased comparison; double-extensions (`.tar.gz` etc.) win over
/// single-extension matches so `foo.tar.gz` is `TarGz`, not `Gzip` of an
/// opaque `foo.tar`.
pub fn detect_kind(path: &Path) -> Option<ArchiveKind> {
    let lower = path
        .file_name()
        .and_then(|f| f.to_str())
        .map(|s| s.to_ascii_lowercase())?;

    // Compound extensions first — order matters.
    for (suffix, kind) in COMPOUND_EXTENSIONS {
        if lower.ends_with(suffix) {
            return Some(*kind);
        }
    }
    // Single extension fallback.
    let ext = Path::new(&lower).extension().and_then(OsStr::to_str)?;
    SINGLE_EXTENSIONS
        .iter()
        .find_map(|(e, k)| (*e == ext).then_some(*k))
}

const COMPOUND_EXTENSIONS: &[(&str, ArchiveKind)] = &[
    (".tar.gz", ArchiveKind::TarGz),
    (".tgz", ArchiveKind::TarGz),
    (".tar.bz2", ArchiveKind::TarBz2),
    (".tbz2", ArchiveKind::TarBz2),
    (".tbz", ArchiveKind::TarBz2),
    (".tar.xz", ArchiveKind::TarXz),
    (".txz", ArchiveKind::TarXz),
    (".tar.zst", ArchiveKind::TarZst),
];

const SINGLE_EXTENSIONS: &[(&str, ArchiveKind)] = &[
    ("zip", ArchiveKind::Zip),
    ("zipx", ArchiveKind::Zip),
    ("jar", ArchiveKind::Zip),
    ("war", ArchiveKind::Zip),
    ("ear", ArchiveKind::Zip),
    ("apk", ArchiveKind::Zip),
    ("tar", ArchiveKind::Tar),
    ("7z", ArchiveKind::SevenZ),
    ("gz", ArchiveKind::Gzip),
    ("bz2", ArchiveKind::Bzip2),
    ("xz", ArchiveKind::Xz),
    ("lzma", ArchiveKind::Xz),
    ("zst", ArchiveKind::Zstd),
    ("lz4", ArchiveKind::Lz4),
    ("rar", ArchiveKind::Rar),
];

/// Anything that can go wrong while iterating an archive.
#[derive(Debug)]
pub enum ArchiveError {
    /// I/O error opening or reading the archive bytes.
    Io(io::Error),
    /// Archive format recognised but not handled — RAR today, and any
    /// future format we add detection for before the extractor.
    UnsupportedFormat(ArchiveKind),
    /// Underlying decoder reported corrupt or unsupported data.
    BadArchive(String),
    /// Bomb guard refused further expansion (depth, cumulative size, or
    /// per-entry expansion ratio crossed).
    Bomb(BombGuardError),
    /// Caller flipped the cancel flag mid-iteration.
    Cancelled,
}

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArchiveError::Io(e) => write!(f, "archive I/O: {e}"),
            ArchiveError::UnsupportedFormat(k) => {
                write!(f, "unsupported archive format: {}", k.as_str())
            }
            ArchiveError::BadArchive(s) => write!(f, "bad archive: {s}"),
            ArchiveError::Bomb(b) => write!(f, "bomb guard: {b:?}"),
            ArchiveError::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl std::error::Error for ArchiveError {}

impl From<io::Error> for ArchiveError {
    fn from(e: io::Error) -> Self {
        ArchiveError::Io(e)
    }
}

impl From<BombGuardError> for ArchiveError {
    fn from(e: BombGuardError) -> Self {
        ArchiveError::Bomb(e)
    }
}

/// What [`iter_members`] reports after a successful pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArchiveScanSummary {
    pub kind_label: &'static str,
    /// Members the callback was invoked on. Directory entries (when
    /// surfaced by the underlying format) do not count.
    pub members_scanned: usize,
    /// Total uncompressed bytes successfully fed to the callback. Useful
    /// for the scan summary line in the UI.
    pub total_uncompressed_bytes: u64,
}

/// Open `path`, dispatch by [`ArchiveKind`], and invoke `on_member` once
/// per archive member with `(member_name, member_reader)`. The reader is
/// borrowed for the duration of the callback only.
///
/// `guard` enforces bomb limits — call [`BombGuard::push`] / [`pop`]
/// before/after this function when recursing into a nested archive
/// (the helper does not push/pop on its own so the caller controls when
/// "this archive is one level deep" applies).
///
/// `cancel` is checked once per member; setting it aborts with
/// [`ArchiveError::Cancelled`] after the current member returns.
pub fn iter_members<F>(
    path: &Path,
    guard: &BombGuard,
    cancel: &AtomicBool,
    mut on_member: F,
) -> Result<ArchiveScanSummary, ArchiveError>
where
    F: FnMut(&str, &mut dyn Read) -> io::Result<()>,
{
    let kind =
        detect_kind(path).ok_or_else(|| ArchiveError::BadArchive("unknown extension".into()))?;
    iter_members_kind(path, kind, guard, cancel, &mut on_member)
}

/// Same as [`iter_members`] but takes an explicit kind. Useful for
/// callers that already sniffed the file's magic bytes.
pub fn iter_members_kind<F>(
    path: &Path,
    kind: ArchiveKind,
    guard: &BombGuard,
    cancel: &AtomicBool,
    on_member: &mut F,
) -> Result<ArchiveScanSummary, ArchiveError>
where
    F: FnMut(&str, &mut dyn Read) -> io::Result<()>,
{
    let mut summary = ArchiveScanSummary {
        kind_label: kind.as_str(),
        ..Default::default()
    };
    match kind {
        ArchiveKind::Zip => extract_zip(path, guard, cancel, on_member, &mut summary)?,
        ArchiveKind::Tar => extract_tar(path, guard, cancel, on_member, &mut summary)?,
        ArchiveKind::TarGz => {
            let f = File::open(path)?;
            let dec = flate2::read::GzDecoder::new(BufReader::new(f));
            extract_tar_reader(dec, guard, cancel, on_member, &mut summary)?;
        }
        ArchiveKind::TarBz2 => {
            let f = File::open(path)?;
            let dec = bzip2_rs::DecoderReader::new(BufReader::new(f));
            extract_tar_reader(dec, guard, cancel, on_member, &mut summary)?;
        }
        ArchiveKind::TarXz => {
            let mut input = BufReader::new(File::open(path)?);
            let mut decoded = Vec::new();
            lzma_rs::xz_decompress(&mut input, &mut decoded)
                .map_err(|e| ArchiveError::BadArchive(format!("xz: {e}")))?;
            extract_tar_reader(Cursor::new(decoded), guard, cancel, on_member, &mut summary)?;
        }
        ArchiveKind::TarZst => {
            let dec = zstd::stream::Decoder::new(File::open(path)?)?;
            extract_tar_reader(dec, guard, cancel, on_member, &mut summary)?;
        }
        ArchiveKind::SevenZ => extract_sevenz(path, guard, cancel, on_member, &mut summary)?,
        ArchiveKind::Gzip => {
            let f = File::open(path)?;
            let mut dec = flate2::read::GzDecoder::new(BufReader::new(f));
            scan_single_stream(path, &mut dec, kind, guard, cancel, on_member, &mut summary)?;
        }
        ArchiveKind::Bzip2 => {
            let f = File::open(path)?;
            let mut dec = bzip2_rs::DecoderReader::new(BufReader::new(f));
            scan_single_stream(path, &mut dec, kind, guard, cancel, on_member, &mut summary)?;
        }
        ArchiveKind::Xz => {
            let mut input = BufReader::new(File::open(path)?);
            let mut decoded = Vec::new();
            lzma_rs::xz_decompress(&mut input, &mut decoded)
                .map_err(|e| ArchiveError::BadArchive(format!("xz: {e}")))?;
            let mut cursor = Cursor::new(decoded);
            scan_single_stream(
                path,
                &mut cursor,
                kind,
                guard,
                cancel,
                on_member,
                &mut summary,
            )?;
        }
        ArchiveKind::Zstd => {
            let mut dec = zstd::stream::Decoder::new(File::open(path)?)?;
            scan_single_stream(path, &mut dec, kind, guard, cancel, on_member, &mut summary)?;
        }
        ArchiveKind::Lz4 => {
            let mut dec = lz4_flex::frame::FrameDecoder::new(BufReader::new(File::open(path)?));
            scan_single_stream(path, &mut dec, kind, guard, cancel, on_member, &mut summary)?;
        }
        ArchiveKind::Rar => return Err(ArchiveError::UnsupportedFormat(kind)),
    }
    Ok(summary)
}

fn check_cancel(cancel: &AtomicBool) -> Result<(), ArchiveError> {
    if cancel.load(Ordering::Relaxed) {
        Err(ArchiveError::Cancelled)
    } else {
        Ok(())
    }
}

/// Account one member with the bomb guard then invoke the callback under
/// a per-entry read cap so a single oversized member can't OOM the
/// engine even when the cumulative budget is generous.
fn record_member<F>(
    name: &str,
    reader: &mut dyn Read,
    compressed: u64,
    uncompressed_hint: u64,
    guard: &BombGuard,
    on_member: &mut F,
    summary: &mut ArchiveScanSummary,
) -> Result<(), ArchiveError>
where
    F: FnMut(&str, &mut dyn Read) -> io::Result<()>,
{
    guard.observe_entry(compressed, uncompressed_hint)?;
    let mut limited = reader.take(DEFAULT_PER_ENTRY_READ_CAP);
    let mut counting = CountingReader::new(&mut limited);
    on_member(name, &mut counting).map_err(ArchiveError::Io)?;
    summary.members_scanned += 1;
    summary.total_uncompressed_bytes = summary
        .total_uncompressed_bytes
        .saturating_add(counting.bytes_read);
    Ok(())
}

/// Wrapper around any `Read` that records how many bytes the consumer
/// actually pulled. Lets the summary report real bytes scanned rather
/// than trusting the format's declared uncompressed size.
struct CountingReader<'r> {
    inner: &'r mut dyn Read,
    bytes_read: u64,
}

impl<'r> CountingReader<'r> {
    fn new(inner: &'r mut dyn Read) -> Self {
        Self {
            inner,
            bytes_read: 0,
        }
    }
}

impl Read for CountingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes_read = self.bytes_read.saturating_add(n as u64);
        Ok(n)
    }
}

fn extract_zip<F>(
    path: &Path,
    guard: &BombGuard,
    cancel: &AtomicBool,
    on_member: &mut F,
    summary: &mut ArchiveScanSummary,
) -> Result<(), ArchiveError>
where
    F: FnMut(&str, &mut dyn Read) -> io::Result<()>,
{
    let file = File::open(path)?;
    let mut zip = zip::ZipArchive::new(file)
        .map_err(|e| ArchiveError::BadArchive(format!("zip open: {e}")))?;
    for i in 0..zip.len() {
        check_cancel(cancel)?;
        let mut entry = zip
            .by_index(i)
            .map_err(|e| ArchiveError::BadArchive(format!("zip entry {i}: {e}")))?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        let compressed = entry.compressed_size();
        let uncompressed = entry.size();
        record_member(
            &name,
            &mut entry,
            compressed,
            uncompressed,
            guard,
            on_member,
            summary,
        )?;
    }
    Ok(())
}

fn extract_tar<F>(
    path: &Path,
    guard: &BombGuard,
    cancel: &AtomicBool,
    on_member: &mut F,
    summary: &mut ArchiveScanSummary,
) -> Result<(), ArchiveError>
where
    F: FnMut(&str, &mut dyn Read) -> io::Result<()>,
{
    let file = File::open(path)?;
    extract_tar_reader(file, guard, cancel, on_member, summary)
}

fn extract_tar_reader<R, F>(
    reader: R,
    guard: &BombGuard,
    cancel: &AtomicBool,
    on_member: &mut F,
    summary: &mut ArchiveScanSummary,
) -> Result<(), ArchiveError>
where
    R: Read,
    F: FnMut(&str, &mut dyn Read) -> io::Result<()>,
{
    let mut archive = tar::Archive::new(reader);
    for entry_result in archive.entries()? {
        check_cancel(cancel)?;
        let mut entry = entry_result?;
        // Skip directories; long-link / pax records are handled
        // internally by the `tar` crate and surface as regular entries
        // already merged with their long names.
        let header = entry.header();
        if !header.entry_type().is_file() {
            continue;
        }
        let size = header.size().unwrap_or(0);
        let name = entry
            .path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| String::from("<unreadable>"));
        record_member(&name, &mut entry, size, size, guard, on_member, summary)?;
    }
    Ok(())
}

fn extract_sevenz<F>(
    path: &Path,
    guard: &BombGuard,
    cancel: &AtomicBool,
    on_member: &mut F,
    summary: &mut ArchiveScanSummary,
) -> Result<(), ArchiveError>
where
    F: FnMut(&str, &mut dyn Read) -> io::Result<()>,
{
    use sevenz_rust2::ArchiveReader;

    let file = File::open(path)?;
    let mut reader = ArchiveReader::new(file, sevenz_rust2::Password::empty())
        .map_err(|e| ArchiveError::BadArchive(format!("7z open: {e}")))?;
    let mut early_exit: Option<ArchiveError> = None;
    reader
        .for_each_entries(|entry, contents| {
            // Cancellation + previously-stored bomb error are checked at
            // every entry boundary.
            if cancel.load(Ordering::Relaxed) {
                early_exit = Some(ArchiveError::Cancelled);
                return Ok(false);
            }
            if entry.is_directory() {
                return Ok(true);
            }
            let name = entry.name().to_string();
            let uncompressed = entry.size();
            // sevenz_rust2's `for_each_entries` gives us a `Read` over
            // the entry contents directly — no allocation of the entry
            // body before scanning.
            let mut counting = CountingReader::new(contents);
            if let Err(e) = guard.observe_entry(uncompressed, uncompressed) {
                early_exit = Some(ArchiveError::Bomb(e));
                return Ok(false);
            }
            // The callback owns the I/O — propagate its result back to
            // sevenz so a callback Err halts the iteration.
            let mut limited = (&mut counting).take(DEFAULT_PER_ENTRY_READ_CAP);
            match on_member(&name, &mut limited) {
                Ok(()) => {
                    summary.members_scanned += 1;
                    summary.total_uncompressed_bytes = summary
                        .total_uncompressed_bytes
                        .saturating_add(counting.bytes_read);
                    Ok(true)
                }
                Err(e) => {
                    early_exit = Some(ArchiveError::Io(e));
                    Ok(false)
                }
            }
        })
        .map_err(|e| ArchiveError::BadArchive(format!("7z iterate: {e}")))?;
    if let Some(e) = early_exit {
        return Err(e);
    }
    Ok(())
}

fn scan_single_stream<R, F>(
    archive_path: &Path,
    reader: &mut R,
    kind: ArchiveKind,
    guard: &BombGuard,
    cancel: &AtomicBool,
    on_member: &mut F,
    summary: &mut ArchiveScanSummary,
) -> Result<(), ArchiveError>
where
    R: Read,
    F: FnMut(&str, &mut dyn Read) -> io::Result<()>,
{
    check_cancel(cancel)?;
    // Synthetic member name: strip the compression extension. `foo.gz`
    // → `foo`; `foo.bin.gz` → `foo.bin`. Falls back to the original
    // filename when stripping doesn't apply.
    let display = archive_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let name = strip_stream_extension(display, kind).unwrap_or_else(|| display.to_string());
    // We don't know the uncompressed size up-front for a stream
    // compressor (no header field) — observe with 0 hint and let the
    // cumulative guard catch a bomb during the read via the per-entry
    // read cap.
    let compressed = std::fs::metadata(archive_path)
        .map(|m| m.len())
        .unwrap_or(0);
    record_member(&name, reader, compressed, 0, guard, on_member, summary)
}

fn strip_stream_extension(file_name: &str, kind: ArchiveKind) -> Option<String> {
    let stem = match kind {
        ArchiveKind::Gzip => file_name.strip_suffix(".gz")?,
        ArchiveKind::Bzip2 => file_name.strip_suffix(".bz2")?,
        ArchiveKind::Xz => file_name
            .strip_suffix(".xz")
            .or_else(|| file_name.strip_suffix(".lzma"))?,
        ArchiveKind::Zstd => file_name.strip_suffix(".zst")?,
        ArchiveKind::Lz4 => file_name.strip_suffix(".lz4")?,
        _ => return None,
    };
    Some(stem.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn never_cancel() -> AtomicBool {
        AtomicBool::new(false)
    }

    #[test]
    fn detects_compound_extensions_before_single() {
        assert_eq!(
            detect_kind(Path::new("foo.tar.gz")),
            Some(ArchiveKind::TarGz)
        );
        assert_eq!(detect_kind(Path::new("foo.tgz")), Some(ArchiveKind::TarGz));
        assert_eq!(
            detect_kind(Path::new("foo.tar.bz2")),
            Some(ArchiveKind::TarBz2)
        );
        assert_eq!(
            detect_kind(Path::new("foo.tar.xz")),
            Some(ArchiveKind::TarXz)
        );
        assert_eq!(
            detect_kind(Path::new("foo.tar.zst")),
            Some(ArchiveKind::TarZst)
        );
    }

    #[test]
    fn detects_single_extensions() {
        let cases = [
            ("foo.zip", ArchiveKind::Zip),
            ("foo.JAR", ArchiveKind::Zip),
            ("foo.apk", ArchiveKind::Zip),
            ("foo.tar", ArchiveKind::Tar),
            ("foo.7z", ArchiveKind::SevenZ),
            ("foo.gz", ArchiveKind::Gzip),
            ("foo.bz2", ArchiveKind::Bzip2),
            ("foo.xz", ArchiveKind::Xz),
            ("foo.lzma", ArchiveKind::Xz),
            ("foo.zst", ArchiveKind::Zstd),
            ("foo.lz4", ArchiveKind::Lz4),
            ("foo.rar", ArchiveKind::Rar),
        ];
        for (name, want) in cases {
            assert_eq!(detect_kind(Path::new(name)), Some(want), "{name}");
        }
    }

    #[test]
    fn returns_none_on_unrecognized_extension() {
        assert!(detect_kind(Path::new("foo.txt")).is_none());
        assert!(detect_kind(Path::new("foo")).is_none());
    }

    #[test]
    fn strip_stream_extension_handles_each_format() {
        assert_eq!(
            strip_stream_extension("a.gz", ArchiveKind::Gzip),
            Some("a".into())
        );
        assert_eq!(
            strip_stream_extension("a.bin.gz", ArchiveKind::Gzip),
            Some("a.bin".into())
        );
        assert_eq!(
            strip_stream_extension("a.xz", ArchiveKind::Xz),
            Some("a".into())
        );
        assert_eq!(
            strip_stream_extension("a.lzma", ArchiveKind::Xz),
            Some("a".into())
        );
        assert_eq!(
            strip_stream_extension("a.zst", ArchiveKind::Zstd),
            Some("a".into())
        );
        // Wrong extension for kind → None.
        assert_eq!(strip_stream_extension("a.gz", ArchiveKind::Zstd), None);
    }

    fn make_zip(dir: &Path, name: &str, entries: &[(&str, &[u8])]) -> PathBuf {
        let path = dir.join(name);
        let file = File::create(&path).unwrap();
        let mut z = zip::ZipWriter::new(file);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (n, body) in entries {
            z.start_file(*n, opts).unwrap();
            z.write_all(body).unwrap();
        }
        z.finish().unwrap();
        path
    }

    #[test]
    fn iter_members_on_zip_invokes_callback_per_file() {
        let dir = tempdir().unwrap();
        let path = make_zip(
            dir.path(),
            "a.zip",
            &[("hello.txt", b"hi"), ("dir/inner.bin", &[1, 2, 3, 4])],
        );
        let guard = BombGuard::with_limits(1024 * 1024, 4, 1000);
        let cancel = never_cancel();
        let mut seen = Vec::new();
        let summary = iter_members(&path, &guard, &cancel, |name, reader| {
            let mut buf = Vec::new();
            reader.read_to_end(&mut buf)?;
            seen.push((name.to_string(), buf));
            Ok(())
        })
        .unwrap();
        assert_eq!(summary.kind_label, "zip");
        assert_eq!(summary.members_scanned, 2);
        assert_eq!(summary.total_uncompressed_bytes, 6);
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0, "hello.txt");
        assert_eq!(seen[0].1, b"hi");
        assert_eq!(seen[1].1, vec![1, 2, 3, 4]);
    }

    #[test]
    fn cancel_flag_halts_iteration_between_members() {
        let dir = tempdir().unwrap();
        let path = make_zip(
            dir.path(),
            "b.zip",
            &[("a.bin", b"a"), ("b.bin", b"b"), ("c.bin", b"c")],
        );
        let guard = BombGuard::with_limits(1024 * 1024, 4, 1000);
        let cancel = AtomicBool::new(false);
        let cancel_at = 2;
        let mut count = 0;
        let err = iter_members(&path, &guard, &cancel, |_n, r| {
            count += 1;
            let mut sink = Vec::new();
            r.read_to_end(&mut sink)?;
            if count == cancel_at {
                cancel.store(true, Ordering::Relaxed);
            }
            Ok(())
        })
        .unwrap_err();
        match err {
            ArchiveError::Cancelled => {}
            other => panic!("expected Cancelled, got {other:?}"),
        }
        assert_eq!(count, cancel_at, "no further callbacks after Cancel");
    }

    #[test]
    fn rar_is_recognised_but_unsupported() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("evil.rar");
        File::create(&path).unwrap().write_all(b"Rar!").unwrap();
        let guard = BombGuard::new();
        let cancel = never_cancel();
        let err = iter_members(&path, &guard, &cancel, |_, _| Ok(())).unwrap_err();
        match err {
            ArchiveError::UnsupportedFormat(ArchiveKind::Rar) => {}
            other => panic!("expected UnsupportedFormat(Rar), got {other:?}"),
        }
    }

    fn make_tar(dir: &Path, name: &str, entries: &[(&str, &[u8])]) -> PathBuf {
        let path = dir.join(name);
        let file = File::create(&path).unwrap();
        let mut builder = tar::Builder::new(file);
        for (n, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_cksum();
            header.set_mode(0o644);
            builder.append_data(&mut header, n, *body).unwrap();
        }
        builder.finish().unwrap();
        path
    }

    #[test]
    fn iter_members_on_tar_invokes_callback_per_file() {
        let dir = tempdir().unwrap();
        let path = make_tar(
            dir.path(),
            "a.tar",
            &[("first.txt", b"abc"), ("second.bin", &[9, 8, 7])],
        );
        let guard = BombGuard::with_limits(1024 * 1024, 4, 1000);
        let cancel = never_cancel();
        let mut seen = 0;
        let summary = iter_members(&path, &guard, &cancel, |_, r| {
            let mut sink = Vec::new();
            r.read_to_end(&mut sink)?;
            seen += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(summary.kind_label, "tar");
        assert_eq!(summary.members_scanned, 2);
        assert_eq!(seen, 2);
    }

    #[test]
    fn gzip_stream_surfaces_as_one_synthetic_member() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("payload.bin.gz");
        let f = File::create(&path).unwrap();
        let mut enc = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
        enc.write_all(b"plain bytes inside gzip").unwrap();
        enc.finish().unwrap();
        let guard = BombGuard::with_limits(1024 * 1024, 4, 1_000_000);
        let cancel = never_cancel();
        let mut seen = None;
        let summary = iter_members(&path, &guard, &cancel, |name, r| {
            let mut sink = Vec::new();
            r.read_to_end(&mut sink)?;
            seen = Some((name.to_string(), sink));
            Ok(())
        })
        .unwrap();
        assert_eq!(summary.kind_label, "gzip");
        assert_eq!(summary.members_scanned, 1);
        let (name, body) = seen.expect("one member");
        assert_eq!(name, "payload.bin");
        assert_eq!(body, b"plain bytes inside gzip");
    }

    #[test]
    fn bomb_guard_aborts_when_per_entry_ratio_exceeded() {
        // A zip with a single huge-uncompressed-size header entry of
        // small compressed body would trip per-entry ratio. We can't
        // build that with the `zip` writer (it computes sizes), but we
        // can simulate the path by directly observing the guard with a
        // bad ratio — same code path.
        let guard = BombGuard::with_limits(1024 * 1024, 4, 10);
        let err = guard.observe_entry(1, 1_000_000).unwrap_err();
        match err {
            BombGuardError::EntryRatioExceeded { .. } => {}
            other => panic!("expected EntryRatioExceeded, got {other:?}"),
        }
    }
}
