//! Mythodikal Anti-Virus engine core (`mythkernel`).
//!
//! Module structure mirrors `docs/prd.md` § 2.3. Most modules are stubs in
//! Phase 0 / TASK-004 and are filled in by later tasks (TASK-009 onward).

#![allow(dead_code)]

/// Phase 10 Wave 2 — archive-safety wrappers (TASK-280..285):
/// detonation-policy stub, zip-bomb compression-ratio guard,
/// password-protected entry surfacing, extended-format magic
/// sniffer, recursion-depth guard, self-extracting heuristic.
pub mod archive_safety;
pub mod archive_scan;
/// Phase 10 Wave 2 — browser forensics (TASK-256..270). Read-only
/// extension / download-history / cookie / cache / cert-store / autofill
/// readers across Chrome / Edge / Brave / Arc / Firefox / Safari.
pub mod browser;
pub mod config;
pub mod db;
pub mod diagnostics;
pub mod diff;
/// Phase 10 Wave 2 — document-payload extractors (TASK-276..279).
/// PDF action / stream-object scanners, RTF object-package extractor,
/// Microsoft Shell Link (`.lnk`) parser.
pub mod doc_payload;
/// Phase 10 Wave 2 — email forensics (TASK-271). In-tree `.eml` /
/// `.mbox` / `.msg` parsers + MIME multipart + base64/quoted-printable.
pub mod email;
pub mod engine;
pub mod error;
pub mod eta;
pub mod exclusions;
pub mod findings;
pub mod hasher;
pub mod hasher_fastcdc;
pub mod hasher_mmap;
pub mod hasher_sparse;
pub mod heuristics_scan;
pub mod history;
pub mod logging;
/// Phase 10 Wave 2 — per-process memory-sweep foundations
/// (TASK-291..295). YARA region request shape + suspicious-region
/// heuristic + shellcode shape detector + reflective-DLL detector
/// + Mach-O in-memory load detector.
pub mod memory_scan;
/// Phase 10 Wave 2 — Office forensics (TASK-272..275). CFB/OLE
/// directory walker + VBA auto-exec + Excel suspicious-formula +
/// MS-OFFCRYPTO encrypted-doc fingerprint.
pub mod office;
/// Phase 10 Wave 2 — cross-cutting payload anomaly detectors
/// (TASK-286..290): image stego LSB heuristic, hidden-data-after-
/// EOF, ISO autorun.inf, LNK working-dir anomaly, Office remote-
/// template injection.
pub mod payload_anomaly;
/// Phase 10 Wave 2 — process-integrity detectors (TASK-296..300):
/// process-hollowing, hijacked-thread, image-hash integrity,
/// killed-process autopsy ring-buffer, core-dump YARA request shape.
pub mod process_integrity;
pub mod process_scan;
pub mod quarantine;
pub mod registry_scan;
pub mod scan;
pub mod scheduler;
pub mod store;
pub mod sysload;
pub mod telemetry;
pub mod throttle;

pub mod detect;
/// Phase 9 Wave 2 — per-app real-time exemption registry (TASK-253).
/// macOS backend is Keychain-backed and biometric-gated; the
/// cross-platform shape and in-memory registry live here.
pub mod exempt;
pub mod ipc;
pub mod platform;
pub mod realtime;
pub mod updater;
/// Phase 8 Wave 2 — cross-platform USB / removable-media surface
/// (TASK-241..250). Per-OS daemon glue (udev / IOKit / SetupDi) lives
/// under `daemon/mythd-{linux,macos,windows}/src/usb.rs`; the shared
/// types, allowlist, BadUSB detector, RTL-override heuristic, and
/// per-device scan history all live here.
pub mod usb;
pub mod walker;

pub use error::EngineError;
