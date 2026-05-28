//! Diagnostic bundle export (TASK-088, Phase 10).
//!
//! Packs recent engine logs + the redacted runtime config + a manifest
//! into a single zip the user can attach to a GitHub issue. The redactor
//! enforces FR-088 "no scan paths included" by stripping any JSON
//! field whose name is in [`PATH_LIKE_KEYS`] before the line lands in
//! the bundle — the maintainer reviewing the bundle never sees the
//! user's files-on-disk.
//!
//! ## What's in the bundle
//!
//!  1. `manifest.json` — timestamps, OS, engine version. No host
//!     identifiers, no hashes of local files.
//!  2. `config.toml` — the engine's runtime config, serialised. The
//!     [`Config`] struct does not currently carry path fields, so this
//!     ships verbatim. Future additions that introduce paths must add
//!     themselves to the redactor.
//!  3. `logs/mythodikal.log.YYYY-MM-DD` for the most recent N days
//!     (default 7, matching FR-100's retention). Each JSON line is
//!     parsed; the redactor walks the value tree and replaces any
//!     string value at a `PATH_LIKE_KEYS` key with `"<REDACTED>"`. Non-
//!     JSON lines pass through unchanged (they're already free of
//!     structured paths by definition).
//!
//! ## Bundle size
//!
//! 7 days of normal-volume engine logs ≈ a few MB compressed. GitHub
//! issues accept attachments up to 25 MB; we don't enforce a ceiling
//! here, but a future Settings toggle could surface a smaller window if
//! a user's logs blew past that.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::Config;

/// Default count of most-recent rolling-log files included. Matches the
/// engine's FR-100 retention window.
pub const DEFAULT_LOG_DAYS: usize = 7;

/// JSON keys whose string values are treated as file paths and replaced
/// with `<REDACTED>`. The list is closed — adding a new structured-log
/// field that carries a path requires adding its key here in the same
/// PR. The redactor is depth-recursive so the keys match at any nesting
/// level.
pub const PATH_LIKE_KEYS: &[&str] = &[
    "path",
    "file",
    "filename",
    "file_path",
    "archive_path",
    "archive_member_path",
    "target",
    "target_path",
    "src",
    "src_path",
    "dst",
    "dst_path",
    "exe_path",
    "scan_root",
    "scan_roots",
    "root",
    "mountpoint",
    "device",
    "data_dir",
    "log_dir",
    "from",
    "to",
];

/// Caller-supplied options for one bundle build.
#[derive(Debug, Clone)]
pub struct BundleOptions {
    /// Directory the rolling appender writes into. See `logging::default_log_dir`.
    pub log_dir: PathBuf,
    /// Snapshot of the engine's current config. Caller passes this in so
    /// the diagnostics module doesn't have to re-read the on-disk TOML
    /// (which might have been edited between the build click and now).
    pub config: Config,
    /// How many most-recent daily log files to include.
    pub log_days: usize,
}

impl BundleOptions {
    pub fn with_defaults(log_dir: PathBuf, config: Config) -> Self {
        Self {
            log_dir,
            config,
            log_days: DEFAULT_LOG_DAYS,
        }
    }
}

/// Static metadata baked into every bundle's `manifest.json`. Fields are
/// owned `String` rather than `&'static str` so the struct can round-trip
/// through serde Deserialize (needed by the bug-report rendering path
/// where a maintainer reviews a JSON body the user already saved).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// UTC unix seconds when the bundle was built.
    pub generated_at_utc: i64,
    /// Engine version (`env!("CARGO_PKG_VERSION")` at the time of build).
    pub engine_version: String,
    /// OS family.
    pub os: String,
    /// Architecture (`x86_64`, `aarch64`, …).
    pub arch: String,
    /// Bundle-format version. Bump if the on-disk shape changes so a
    /// future maintainer-side parser can stay backward-compatible.
    pub bundle_format_version: u32,
}

/// Build a Manifest stamped with this build's static metadata.
pub fn current_manifest() -> Manifest {
    Manifest {
        generated_at_utc: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        bundle_format_version: BUNDLE_FORMAT_VERSION,
    }
}

pub const BUNDLE_FORMAT_VERSION: u32 = 1;

/// Maximum bytes [`build_bug_report`] reads from each log file's tail.
/// 256 KiB is enough to hold the most-recent ~2 000 typical JSON log
/// lines (~120 bytes each); larger and we risk OOM on memory-constrained
/// laptops when the appender file grew past rotation between bug-report
/// clicks.
pub const BUG_REPORT_TAIL_BYTES: u64 = 256 * 1024;

/// Read the last `cap` bytes of `path` as a UTF-8 string. Used by
/// [`build_bug_report`] to bound peak memory regardless of how large
/// the log file grew. On a file smaller than `cap`, returns the whole
/// file. On a file larger than `cap`, may return a partial first line
/// (the head is fine to discard because the caller iterates by line
/// and the first/partial line is dropped).
fn read_file_tail(path: &Path, cap: u64) -> io::Result<String> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    let skip = len.saturating_sub(cap);
    if skip > 0 {
        f.seek(SeekFrom::Start(skip))?;
    }
    let mut buf = Vec::with_capacity(cap.min(len) as usize);
    f.read_to_end(&mut buf)?;
    // From-utf8-lossy because a tail seek can land mid-codepoint.
    let s = String::from_utf8_lossy(&buf).into_owned();
    // Drop the (possibly partial) first line so callers iterating by
    // line don't pick up half a JSON object.
    if skip > 0 {
        if let Some(nl) = s.find('\n') {
            return Ok(s[nl + 1..].to_string());
        }
    }
    Ok(s)
}

#[derive(Debug, thiserror::Error)]
pub enum DiagError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("zip: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("toml: {0}")]
    Toml(#[from] toml::ser::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// Build a bundle and write it to `out_path`. Caller is responsible for
/// the directory existing.
pub fn build_bundle(out_path: &Path, opts: &BundleOptions) -> Result<(), DiagError> {
    let file = File::create(out_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let zopts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    // 1. manifest.json — fixed, tiny, comes first so a maintainer can
    // tell at a glance what they're looking at.
    let manifest = current_manifest();
    zip.start_file("manifest.json", zopts)?;
    zip.write_all(serde_json::to_string_pretty(&manifest)?.as_bytes())?;

    // 2. config.toml — serialise the in-memory snapshot.
    zip.start_file("config.toml", zopts)?;
    zip.write_all(toml::to_string_pretty(&opts.config)?.as_bytes())?;

    // 3. Recent logs, oldest-first so a maintainer's `unzip` lists them
    // in chronological order.
    let mut log_files = collect_recent_logs(&opts.log_dir, opts.log_days)?;
    log_files.sort();
    for log_path in log_files {
        let archive_name = match log_path.file_name().and_then(|s| s.to_str()) {
            Some(n) => format!("logs/{n}"),
            None => continue,
        };
        zip.start_file(archive_name, zopts)?;
        write_redacted_log(&log_path, &mut zip)?;
    }

    zip.finish()?;
    Ok(())
}

fn collect_recent_logs(log_dir: &Path, count: usize) -> io::Result<Vec<PathBuf>> {
    if !log_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<(PathBuf, SystemTime)> = std::fs::read_dir(log_dir)?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let path = e.path();
            if !path.is_file() {
                return None;
            }
            let mtime = e.metadata().ok()?.modified().ok()?;
            Some((path, mtime))
        })
        .collect();
    // Most-recent first, then truncate to `count`, then return paths.
    entries.sort_by(|a, b| b.1.cmp(&a.1));
    entries.truncate(count);
    Ok(entries.into_iter().map(|(p, _)| p).collect())
}

fn write_redacted_log<W: Write + Seek>(
    log_path: &Path,
    out: &mut zip::ZipWriter<W>,
) -> Result<(), DiagError> {
    let file = File::open(log_path)?;
    let reader = BufReader::new(file);
    for line_result in reader.lines() {
        let line = line_result?;
        let redacted = redact_log_line(&line);
        out.write_all(redacted.as_bytes())?;
        out.write_all(b"\n")?;
    }
    Ok(())
}

/// Redact one log line.
///
/// JSON lines have any string value at a [`PATH_LIKE_KEYS`] key replaced
/// with `"<REDACTED>"` at every nesting level.
///
/// Non-JSON lines (panic backtraces, plaintext appender output, any
/// future non-JSON layer) run through [`redact_path_substrings`] so a
/// path embedded in a free-text message can't slip past FR-088's "no
/// scan paths in bundle" guarantee.
pub fn redact_log_line(line: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(line) {
        Ok(mut v) => {
            redact_value(&mut v);
            serde_json::to_string(&v).unwrap_or_else(|_| redact_path_substrings(line))
        }
        Err(_) => redact_path_substrings(line),
    }
}

/// Replace path-like substrings in free text with `<REDACTED>`. Catches
/// the two shapes that show up in panic backtraces / plaintext logs:
///
///  * POSIX absolute paths: `/...` segments where every char is the
///    permissive path alphabet (alnum, dot, dash, underscore, slash).
///    The match stops at any non-path char so a single sentence with
///    one path in it has only the path scrubbed.
///  * Windows absolute paths: `<drive>:\...` where `<drive>` is a
///    single ASCII letter.
///
/// Mid-string relative paths (no leading slash / drive letter) are out
/// of scope — they're indistinguishable from arbitrary identifiers in
/// free text. The PRD's threat model targets absolute paths only.
pub fn redact_path_substrings(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        // Windows drive-letter prefix: `<letter>:\` at a word boundary
        // (start-of-line or after whitespace / typical punctuation).
        // Anchoring at a word boundary avoids matching the `s://` in a
        // URL like `https://...` where `s` is alphabetic and followed
        // by `:/`.
        if c.is_ascii_alphabetic()
            && is_drive_letter_anchor(&bytes[..i])
            && i + 2 < bytes.len()
            && bytes[i + 1] == b':'
            && (bytes[i + 2] == b'\\' || bytes[i + 2] == b'/')
        {
            let end = i + 2 + path_segment_len(&bytes[i + 2..]);
            out.push_str("<REDACTED>");
            i = end;
            continue;
        }
        // POSIX absolute path: `/x...` at a word boundary. Anchors are
        // deliberately narrow (whitespace / quote-like / open-bracket
        // only — NOT `:`) so a URL's `://` doesn't trigger.
        if c == b'/'
            && is_path_anchor(&bytes[..i])
            && i + 1 < bytes.len()
            && is_path_byte(bytes[i + 1])
        {
            let end = i + path_segment_len(&bytes[i..]);
            out.push_str("<REDACTED>");
            i = end;
            continue;
        }
        out.push(c as char);
        i += 1;
    }
    out
}

/// `true` when `prefix` ends just before a position where an absolute
/// POSIX path could plausibly begin in a free-text log line.
/// Deliberately conservative — does NOT match after `:` so a URL's
/// `://` segment isn't mistaken for a path opener.
fn is_path_anchor(prefix: &[u8]) -> bool {
    match prefix.last() {
        None => true,
        Some(&b) => {
            b.is_ascii_whitespace() || matches!(b, b'\'' | b'"' | b'`' | b'(' | b'[' | b'{' | b',')
        }
    }
}

/// `true` when `prefix` ends just before a position where a Windows
/// drive-letter path could plausibly begin. Same anchor set as
/// `is_path_anchor` — both rules are word-boundary-strict.
fn is_drive_letter_anchor(prefix: &[u8]) -> bool {
    is_path_anchor(prefix)
}

fn is_path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'/' | b'\\' | b'.' | b'-' | b'_' | b'~' | b' ')
}

fn path_segment_len(buf: &[u8]) -> usize {
    // Walk while bytes look like path characters, but cap at 4 KiB to
    // bound runaway matches on adversarial input.
    let mut n = 0;
    let cap = 4096.min(buf.len());
    while n < cap && is_path_byte(buf[n]) {
        n += 1;
    }
    // Trim trailing spaces so "scanned /Users/me/foo." doesn't eat the
    // sentence terminator. Trailing space is permitted mid-path but we
    // shouldn't keep it on the boundary.
    while n > 0 && (buf[n - 1] == b' ' || buf[n - 1] == b'.') {
        n -= 1;
    }
    n
}

fn redact_value(v: &mut serde_json::Value) {
    use serde_json::Value;
    match v {
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                if PATH_LIKE_KEYS.contains(&k.as_str()) {
                    redact_path_carrier(val);
                } else {
                    redact_value(val);
                }
            }
        }
        Value::Array(arr) => {
            for el in arr {
                redact_value(el);
            }
        }
        _ => {}
    }
}

/// At a path-carrier key, recursively replace every string with
/// `"<REDACTED>"`. Handles both string and array-of-string shapes
/// (e.g., `scan_roots: ["/Users/me/Documents", "/Users/me/Pictures"]`).
fn redact_path_carrier(v: &mut serde_json::Value) {
    use serde_json::Value;
    match v {
        Value::String(_) => *v = Value::String("<REDACTED>".into()),
        Value::Array(arr) => {
            for el in arr {
                redact_path_carrier(el);
            }
        }
        Value::Object(map) => {
            for val in map.values_mut() {
                redact_path_carrier(val);
            }
        }
        _ => {}
    }
}

/// One opt-in bug report the user reviews before submitting (TASK-150).
/// The frontend modal renders the JSON body (editable) and presents
/// the two submit targets — a GitHub-issue-draft URL or a
/// self-hosted dropbox URL the user controls.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BugReport {
    /// User-supplied free-text describing the issue.
    pub user_description: String,
    /// Static host metadata — same shape as [`Manifest`] so a maintainer
    /// can correlate against a separate diagnostic bundle.
    pub manifest: Manifest,
    /// Up to N most-recent log lines from the rolling appender, **already
    /// redacted** via [`redact_log_line`]. The redactor strips path-
    /// carrying field values before they reach this struct, so the JSON
    /// body the user reviews never contains a scan path.
    pub recent_log_lines: Vec<String>,
}

/// Build a [`BugReport`] from the engine's current state. Caller passes
/// the user description from the modal + a reference to the engine's
/// log directory + a cap on the number of log lines to include.
pub fn build_bug_report(
    user_description: String,
    log_dir: &Path,
    line_cap: usize,
) -> Result<BugReport, DiagError> {
    let manifest = current_manifest();
    let mut recent_log_lines = Vec::new();
    if log_dir.exists() {
        let mut log_files = collect_recent_logs(log_dir, 1)?;
        log_files.sort();
        for path in log_files {
            // Only read the tail. Caps the bug-report cost at ~256 KiB
            // per log file regardless of log size — without this, a
            // multi-hundred-MB rolling log allocated its full length in
            // a single String on the user's machine before `line_cap`
            // bounded the line count.
            let body = read_file_tail(&path, BUG_REPORT_TAIL_BYTES)?;
            for line in body.lines().rev().take(line_cap) {
                recent_log_lines.push(redact_log_line(line));
            }
        }
    }
    recent_log_lines.reverse();
    Ok(BugReport {
        user_description,
        manifest,
        recent_log_lines,
    })
}

/// Render `report` as a GitHub-issue-draft body. Caller posts this to
/// the issue-new URL with `?body=`. The shape matches the existing
/// `docs/launch-checklists/*.md` issue template so a maintainer sees
/// the same fields they're used to triaging.
pub fn render_github_issue_body(report: &BugReport) -> String {
    let mut out = String::new();
    out.push_str("## Description\n\n");
    out.push_str(report.user_description.trim());
    out.push_str("\n\n## Environment\n\n");
    out.push_str(&format!(
        "- Engine version: `{}`\n",
        report.manifest.engine_version
    ));
    out.push_str(&format!("- OS: `{}`\n", report.manifest.os));
    out.push_str(&format!("- Arch: `{}`\n", report.manifest.arch));
    out.push_str(&format!(
        "- Generated at (unix): `{}`\n",
        report.manifest.generated_at_utc
    ));
    out.push_str("\n## Recent logs (redacted)\n\n");
    out.push_str("```\n");
    for line in &report.recent_log_lines {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("```\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::tempdir;

    fn read_zip_entry(zip_path: &Path, entry_name: &str) -> Option<String> {
        let file = File::open(zip_path).ok()?;
        let mut zip = zip::ZipArchive::new(file).ok()?;
        let mut entry = zip.by_name(entry_name).ok()?;
        let mut out = String::new();
        entry.read_to_string(&mut out).ok()?;
        Some(out)
    }

    #[test]
    fn redact_strips_known_path_keys() {
        let line = r#"{"timestamp":"2026-05-27T12:00:00Z","level":"info","path":"/Users/me/secret.txt","msg":"scanned"}"#;
        let out = redact_log_line(line);
        assert!(out.contains("\"path\":\"<REDACTED>\""));
        assert!(!out.contains("/Users/me/secret.txt"));
        assert!(out.contains("scanned"));
    }

    #[test]
    fn redact_recurses_into_nested_objects() {
        let line = r#"{"event":{"finding":{"file_path":"/etc/passwd","rule":"yara-x:eicar"}}}"#;
        let out = redact_log_line(line);
        assert!(out.contains("\"file_path\":\"<REDACTED>\""));
        assert!(!out.contains("/etc/passwd"));
        assert!(out.contains("yara-x:eicar"));
    }

    #[test]
    fn redact_strips_array_of_paths() {
        let line = r#"{"scan_roots":["/a","/b","/c"]}"#;
        let out = redact_log_line(line);
        assert!(out.contains("[\"<REDACTED>\",\"<REDACTED>\",\"<REDACTED>\"]"));
        assert!(!out.contains("/a"));
    }

    #[test]
    fn redact_passes_through_pathless_non_json_lines() {
        let line = "===== engine started =====";
        assert_eq!(redact_log_line(line), line);
    }

    #[test]
    fn redact_scrubs_posix_paths_in_non_json_lines() {
        let line = "panicked at 'cannot open /Users/alice/Documents/secret.docx: PermissionDenied'";
        let out = redact_log_line(line);
        assert!(!out.contains("/Users/alice"));
        assert!(out.contains("<REDACTED>"));
        assert!(out.contains("panicked at"));
    }

    #[test]
    fn redact_scrubs_windows_paths_in_non_json_lines() {
        let line = r"opened C:\Users\bob\Documents\report.docx successfully";
        let out = redact_log_line(line);
        assert!(!out.contains(r"C:\Users"));
        assert!(out.contains("<REDACTED>"));
        assert!(out.contains("opened"));
    }

    #[test]
    fn redact_does_not_scrub_arbitrary_url_path_segments() {
        // URLs contain `/` segments but don't anchor at a path-start
        // — the prefix is alphanumeric ("https:") so the / isn't
        // recognised as an absolute-path opener. We don't want to
        // accidentally redact every URL in the bundle.
        let line = "https://example.com/foo/bar";
        assert_eq!(redact_log_line(line), line);
    }

    #[test]
    fn redact_leaves_non_path_keys_untouched() {
        let line = r#"{"path":"/secret","rule_id":"behavior:rapid_rename","count":42}"#;
        let out = redact_log_line(line);
        assert!(out.contains("behavior:rapid_rename"));
        assert!(out.contains("42"));
        assert!(out.contains("\"path\":\"<REDACTED>\""));
    }

    #[test]
    fn build_bundle_produces_manifest_config_and_logs() {
        let dir = tempdir().unwrap();
        let log_dir = dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).unwrap();
        // Plant two synthetic log files, one with a path field that
        // must be redacted in the output.
        let earlier = log_dir.join("mythodikal.log.2026-05-26");
        std::fs::write(
            &earlier,
            "{\"path\":\"/Users/me/keep\",\"level\":\"info\"}\nplain line\n",
        )
        .unwrap();
        let later = log_dir.join("mythodikal.log.2026-05-27");
        std::fs::write(&later, "{\"event\":\"clean\",\"file\":\"/secret\"}\n").unwrap();

        let opts = BundleOptions {
            log_dir,
            config: Config::default(),
            log_days: 7,
        };
        let out = dir.path().join("bundle.zip");
        build_bundle(&out, &opts).unwrap();
        assert!(out.exists());

        let manifest = read_zip_entry(&out, "manifest.json").unwrap();
        assert!(manifest.contains("\"bundle_format_version\": 1"));
        let config = read_zip_entry(&out, "config.toml").unwrap();
        assert!(config.contains("[general]"));
        let log_2027 = read_zip_entry(&out, "logs/mythodikal.log.2026-05-27").unwrap();
        assert!(log_2027.contains("<REDACTED>"));
        assert!(!log_2027.contains("/secret"));
        let log_2026 = read_zip_entry(&out, "logs/mythodikal.log.2026-05-26").unwrap();
        assert!(log_2026.contains("plain line"));
        assert!(!log_2026.contains("/Users/me/keep"));
    }

    #[test]
    fn collect_recent_logs_truncates_to_count() {
        let dir = tempdir().unwrap();
        // Plant 10 files; ask for 3 most-recent. Stagger mtimes via a
        // write-open handle so Windows allows `set_modified` (the
        // platform requires the file be opened with write to mutate
        // its metadata).
        for i in 0..10 {
            let p = dir.path().join(format!("mythodikal.log.2026-05-{i:02}"));
            std::fs::write(&p, "x").unwrap();
            let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
            f.set_modified(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(i as u64 + 1))
                .unwrap();
        }
        let chosen = collect_recent_logs(dir.path(), 3).unwrap();
        assert_eq!(chosen.len(), 3);
    }

    #[test]
    fn bug_report_redacts_path_fields_from_logs() {
        let dir = tempdir().unwrap();
        let log = dir.path().join("mythodikal.log.2026-05-27");
        std::fs::write(
            &log,
            "{\"event\":\"clean\",\"file\":\"/Users/me/secret.txt\"}\n",
        )
        .unwrap();
        let report = build_bug_report("repro: ran X then Y".into(), dir.path(), 100).unwrap();
        assert!(report.user_description.contains("repro"));
        assert!(
            !report
                .recent_log_lines
                .iter()
                .any(|l| l.contains("secret.txt"))
        );
        assert!(
            report
                .recent_log_lines
                .iter()
                .any(|l| l.contains("<REDACTED>"))
        );
    }

    #[test]
    fn github_issue_body_contains_description_and_env() {
        let report = BugReport {
            user_description: "Crash on scan start".into(),
            manifest: Manifest {
                generated_at_utc: 1_700_000_000,
                engine_version: "0.7.20".to_string(),
                os: "windows".to_string(),
                arch: "x86_64".to_string(),
                bundle_format_version: 1,
            },
            recent_log_lines: vec!["one line".into()],
        };
        let body = render_github_issue_body(&report);
        assert!(body.contains("Crash on scan start"));
        assert!(body.contains("0.7.20"));
        assert!(body.contains("windows"));
        assert!(body.contains("one line"));
    }

    #[test]
    fn empty_log_dir_produces_bundle_with_manifest_and_config_only() {
        let dir = tempdir().unwrap();
        let log_dir = dir.path().join("logs_does_not_exist");
        let opts = BundleOptions::with_defaults(log_dir, Config::default());
        let out = dir.path().join("empty.zip");
        build_bundle(&out, &opts).unwrap();
        assert!(read_zip_entry(&out, "manifest.json").is_some());
        assert!(read_zip_entry(&out, "config.toml").is_some());
    }
}
