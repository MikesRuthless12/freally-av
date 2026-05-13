//! Pure-Rust YARA detector (TASK-065 / Phase 7 — wired in
//! commercial-friendly form for the YARA + Neo23x0/signature-base
//! stack).
//!
//! Compiles every `.yar` / `.yara` file in a feed directory at
//! startup, then scans each file's bytes (the same bytes the engine
//! already mmap'd for BLAKE3) against the compiled rule set. A
//! match emits `DetectorVerdict::Malicious` with the YARA rule's
//! `meta` description as evidence (`meta_description`,
//! `meta_severity`, etc. when present).
//!
//! Why yara-x: it's the official Rust port from VirusTotal, pure
//! Rust (no libyara C dep, no GPL contamination), MIT-licensed.
//! Lets Mythodikal ship public YARA rule packs (Neo23x0/
//! signature-base, Yara-Rules/rules, Elastic protections-artifacts)
//! under commercially-permissive terms.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use yara_x::{Compiler, Rules, Scanner};

use super::{Detector, DetectorVerdict, FileCtx, Severity};

pub const DETECTOR_ID: &str = "yara";
/// Priority sits with the hash blacklist (100). Allowlists (≤20) run
/// earlier so a YARA hit on a Microsoft-signed binary still defers
/// to the NSRL goodware shortcut.
pub const PRIORITY: u32 = 100;
pub const RULE_SOURCE: &str = "yara";

/// Per-instance compiled rule set + counter for "rules loaded" UI
/// surface. Clone is cheap because `rules` is wrapped in an `Arc`.
#[derive(Clone)]
pub struct YaraDetector {
    rules: Arc<Rules>,
    rule_count: usize,
}

impl YaraDetector {
    /// Compile every `.yar` / `.yara` file under `dir` into a single
    /// rule set. Returns `None` when the directory is missing or
    /// contains zero `.yar` files — the engine then skips registering
    /// the detector entirely (no overhead, no fake "0 rules loaded").
    /// Per-file parse errors are logged at WARN and skipped; one bad
    /// rule file does not poison the whole pack.
    pub fn from_dir<P: AsRef<Path>>(dir: P) -> Option<Self> {
        let dir = dir.as_ref();
        if !dir.is_dir() {
            return None;
        }
        let rule_files = collect_rule_files(dir);
        if rule_files.is_empty() {
            return None;
        }
        let mut compiler = Compiler::new();
        let mut compiled_paths: Vec<PathBuf> = Vec::with_capacity(rule_files.len());
        for path in &rule_files {
            let src = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(err) => {
                    tracing::warn!(
                        rule_file = %path.display(),
                        error = %err,
                        "yara rule file unreadable; skipped"
                    );
                    continue;
                }
            };
            if let Err(err) = compiler.add_source(src.as_str()) {
                tracing::warn!(
                    rule_file = %path.display(),
                    error = %err,
                    "yara rule file failed to compile; skipped"
                );
                continue;
            }
            compiled_paths.push(path.clone());
        }
        let rules = compiler.build();
        let rule_count = rules.iter().count();
        if rule_count == 0 {
            tracing::warn!(
                rule_dir = %dir.display(),
                "yara: every rule file failed to compile; detector disabled"
            );
            return None;
        }
        tracing::info!(
            rule_dir = %dir.display(),
            files = compiled_paths.len(),
            rules = rule_count,
            "YARA rule pack loaded"
        );
        Some(Self {
            rules: Arc::new(rules),
            rule_count,
        })
    }

    /// Number of rules in the compiled pack — surfaced in the
    /// `feed_versions` summary and the Settings → About panel.
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }
}

impl Detector for YaraDetector {
    fn id(&self) -> &str {
        DETECTOR_ID
    }

    fn priority(&self) -> u32 {
        PRIORITY
    }

    fn requires_sha256(&self) -> bool {
        false
    }

    fn check(&self, ctx: &FileCtx<'_>) -> DetectorVerdict {
        // YARA scans bytes, not hashes. The hot path mmap'd the file
        // when computing BLAKE3 — but that mmap isn't reachable from
        // here. Open + memory-map the file ourselves; the inner
        // scanner only reads up to `match_max_bytes` which the
        // default 32 MiB cap keeps cheap.
        //
        // Hard size cap: skip files >32 MiB. YARA rule packs are
        // tuned for executables (typ <20 MiB) and a 4 GB ISO will
        // both blow our scan budget and almost never match.
        const MAX_SCAN_BYTES: u64 = 32 * 1024 * 1024;
        if ctx.size_bytes > MAX_SCAN_BYTES {
            return DetectorVerdict::Clean;
        }
        let bytes = match std::fs::read(ctx.path) {
            Ok(b) => b,
            Err(_) => return DetectorVerdict::Clean,
        };
        let mut scanner = Scanner::new(&self.rules);
        let scan_results = match scanner.scan(&bytes) {
            Ok(r) => r,
            Err(_) => return DetectorVerdict::Clean,
        };
        let matching: Vec<_> = scan_results.matching_rules().collect();
        let Some(first) = matching.first() else {
            return DetectorVerdict::Clean;
        };
        let rule_name = first.identifier().to_string();
        let severity = severity_from_meta(first).unwrap_or(Severity::Medium);
        let evidence = build_evidence(first, &matching);
        DetectorVerdict::Malicious {
            rule_id: format!("yara:{rule_name}"),
            rule_source: RULE_SOURCE.to_string(),
            severity,
            evidence: Some(evidence),
        }
    }
}

/// Walk `dir` (one level deep + immediate subdirs) collecting every
/// `.yar` / `.yara` regular file. Single-level recursion is enough
/// for the common rule-pack layout (e.g. `signature-base/yara/*.yar`)
/// without descending into a `tests/` or `excluded/` folder full of
/// false-positive bait.
fn collect_rule_files(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    push_yar_files(dir, &mut out);
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                push_yar_files(&path, &mut out);
            }
        }
    }
    out
}

fn push_yar_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase());
        if matches!(ext.as_deref(), Some("yar") | Some("yara")) {
            out.push(path);
        }
    }
}

/// Read severity from the rule's `meta` block. Public rule packs
/// commonly set `severity = "high"` or `score = 75`. Map both into
/// our [`Severity`] enum.
fn severity_from_meta(rule: &yara_x::Rule<'_, '_>) -> Option<Severity> {
    for (key, value) in rule.metadata() {
        let key_lower = key.to_ascii_lowercase();
        if key_lower == "severity" {
            if let yara_x::MetaValue::String(s) = value {
                return Some(severity_from_str(s));
            }
        }
        if key_lower == "score" {
            if let yara_x::MetaValue::Integer(n) = value {
                return Some(severity_from_score(n));
            }
        }
    }
    None
}

fn severity_from_str(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "critical" | "high" => Severity::High,
        "low" => Severity::Low,
        _ => Severity::Medium,
    }
}

fn severity_from_score(n: i64) -> Severity {
    match n {
        x if x >= 80 => Severity::High,
        x if x <= 30 => Severity::Low,
        _ => Severity::Medium,
    }
}

fn build_evidence(first: &yara_x::Rule<'_, '_>, all: &[yara_x::Rule<'_, '_>]) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("rule={}", first.identifier()));
    for (key, value) in first.metadata() {
        let key_lower = key.to_ascii_lowercase();
        if matches!(
            key_lower.as_str(),
            "description" | "author" | "reference" | "date" | "hash"
        ) {
            let value_str = match value {
                yara_x::MetaValue::String(s) => s.to_string(),
                yara_x::MetaValue::Integer(n) => n.to_string(),
                yara_x::MetaValue::Float(f) => f.to_string(),
                yara_x::MetaValue::Bool(b) => b.to_string(),
                yara_x::MetaValue::Bytes(_) => "<bytes>".to_string(),
            };
            parts.push(format!("{key}={value_str}"));
        }
    }
    if all.len() > 1 {
        parts.push(format!("plus_{}_other_rules", all.len() - 1));
    }
    parts.join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// Smoke test: a directory with one tiny rule matches a file that
    /// contains the magic string. Builds the full Compiler → Rules →
    /// Scanner round trip so we don't regress on a yara-x major bump.
    #[test]
    fn matches_a_rule_against_real_bytes() {
        let dir = tempdir().unwrap();
        let rule_path = dir.path().join("mythkernel_smoke.yar");
        fs::write(
            &rule_path,
            r#"
            rule mythkernel_smoke_marker {
                meta:
                    description = "smoke test"
                    severity    = "medium"
                strings:
                    $a = "MYTHODIKAL_SMOKE_MARKER_42"
                condition:
                    $a
            }
            "#,
        )
        .unwrap();
        let det = YaraDetector::from_dir(dir.path()).expect("detector built");
        assert_eq!(det.rule_count(), 1);

        let target = dir.path().join("target.bin");
        fs::write(&target, b"junk before MYTHODIKAL_SMOKE_MARKER_42 junk after").unwrap();
        let ctx = FileCtx {
            path: &target,
            size_bytes: 50,
            blake3: &[0u8; 32],
            sha256: None,
        };
        match det.check(&ctx) {
            DetectorVerdict::Malicious {
                rule_id,
                rule_source,
                severity,
                evidence,
            } => {
                assert_eq!(rule_id, "yara:mythkernel_smoke_marker");
                assert_eq!(rule_source, "yara");
                assert_eq!(severity, Severity::Medium);
                let ev = evidence.expect("evidence present");
                assert!(ev.contains("rule=mythkernel_smoke_marker"), "got {ev}");
                assert!(ev.contains("description"), "got {ev}");
            }
            other => panic!("expected Malicious, got {other:?}"),
        }
    }

    #[test]
    fn empty_dir_returns_none() {
        let dir = tempdir().unwrap();
        assert!(YaraDetector::from_dir(dir.path()).is_none());
    }

    #[test]
    fn clean_file_returns_clean() {
        let dir = tempdir().unwrap();
        let rule_path = dir.path().join("r.yar");
        fs::write(
            &rule_path,
            r#"rule never_matches { strings: $a = "ZZZZZ_NEVER_MATCHES_ZZZZZ" condition: $a }"#,
        )
        .unwrap();
        let det = YaraDetector::from_dir(dir.path()).expect("detector built");
        let target = dir.path().join("clean.txt");
        fs::write(&target, b"hello world").unwrap();
        let ctx = FileCtx {
            path: &target,
            size_bytes: 11,
            blake3: &[0u8; 32],
            sha256: None,
        };
        assert_eq!(det.check(&ctx), DetectorVerdict::Clean);
    }

    #[test]
    fn oversized_file_short_circuits_to_clean() {
        // A 1-byte file passes the size gate, but we simulate a
        // >32 MiB file via the ctx's `size_bytes` field. The check
        // returns Clean without ever calling fs::read.
        let dir = tempdir().unwrap();
        let rule_path = dir.path().join("r.yar");
        fs::write(
            &rule_path,
            r#"rule any_byte { strings: $a = "x" condition: $a }"#,
        )
        .unwrap();
        let det = YaraDetector::from_dir(dir.path()).expect("detector built");
        let target = dir.path().join("oversize.bin");
        fs::write(&target, b"x").unwrap();
        let ctx = FileCtx {
            path: &target,
            size_bytes: 100 * 1024 * 1024, // pretend it's 100 MiB
            blake3: &[0u8; 32],
            sha256: None,
        };
        assert_eq!(det.check(&ctx), DetectorVerdict::Clean);
    }
}
