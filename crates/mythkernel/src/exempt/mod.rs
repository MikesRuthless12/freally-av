//! Per-app real-time exemption registry (TASK-253, Phase 9 Wave 2).
//!
//! Cross-platform contract for "skip the engine for events from this
//! specific signed app." Platform daemons consult
//! [`per_app::PerAppExemption::matches`] before pushing a NOTIFY event
//! to the engine; a match short-circuits the entire detection
//! pipeline for that one event.
//!
//! macOS backend lives at
//! `daemon/mythd-macos/src/exemption_keychain.rs` (Keychain-backed,
//! biometric-gated). Linux + Windows backends are deferred; the
//! cross-platform shape is defined here so the engine never needs to
//! know which OS it's running on to consult the registry.

pub mod per_app;
