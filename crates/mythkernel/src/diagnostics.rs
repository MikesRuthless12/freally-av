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

/// Static metadata baked into every bundle's `manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// UTC unix seconds when the bundle was built.
    pub generated_at_utc: i64,
    /// Engine version (`env!("CARGO_PKG_VERSION")` at compile time).
    pub engine_version: &'static str,
    /// OS family. `target_os` at compile time so a Linux binary always
    /// reports `linux` even if it's running under WSL.
    pub os: &'static str,
    /// Architecture (`x86_64`, `aarch64`, …).
    pub arch: &'static str,
    /// Bundle-format version. Bump if the on-disk shape changes so a
    /// future maintainer-side parser can stay backward-compatible.
    pub bundle_format_version: u32,
}

pub const BUNDLE_FORMAT_VERSION: u32 = 1;

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
    let manifest = Manifest {
        generated_at_utc: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        engine_version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        bundle_format_version: BUNDLE_FORMAT_VERSION,
    };
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

/// Redact one log line. Non-JSON lines pass through. JSON lines have
/// any string value at a [`PATH_LIKE_KEYS`] key replaced with
/// `"<REDACTED>"` at every nesting level.
pub fn redact_log_line(line: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(line) {
        Ok(mut v) => {
            redact_value(&mut v);
            serde_json::to_string(&v).unwrap_or_else(|_| line.to_string())
        }
        Err(_) => line.to_string(),
    }
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
    fn redact_passes_through_non_json_lines() {
        let line = "===== engine started =====";
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
