//! IPC types shared with the frontend (TASK-029, Phase 3).
//!
//! Hand-written serde-serializable types. The TypeScript mirror lives at
//! `apps/mythodikal/frontend/src/ipc/types.ts` and is kept in lockstep
//! manually for Phase 3. A `specta`-driven generator is on the table for
//! Phase 7+ when the type surface grows further.
//!
//! All Tauri commands return `Result<T, String>` (the error path is a
//! plain message — Tauri serializes Rust `Result` natively).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub type ScanId = i64;
pub type FindingId = i64;
pub type QuarantineId = i64;
pub type BatchOpId = i64;

/// What the user picked from the Scan page's target chooser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub target_path: PathBuf,
    /// Compute SHA-256 alongside BLAKE3. Forced to `true` when any
    /// SHA-256-keyed detector (abuse.ch / NSRL) is loaded so the
    /// pipeline can query the right digest. The UI's default is
    /// `false` when no feeds are loaded, `true` otherwise.
    pub compute_sha256: bool,
    pub follow_symlinks: bool,
}

/// Lightweight row used by the History page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub id: ScanId,
    pub started_at_utc: i64,
    pub ended_at_utc: Option<i64>,
    pub trigger: String,
    pub target_paths: String,
    pub status: String,
    pub files_visited: i64,
    pub findings_count: i64,
    pub bytes_visited: i64,
}

/// Full payload for the History detail view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDetail {
    pub summary: ScanSummary,
    pub findings: Vec<FindingView>,
}

/// View type for a single `findings` row. Hex-encodes blake3 / sha256
/// for direct UI display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingView {
    pub id: FindingId,
    pub scan_id: ScanId,
    pub path: String,
    pub size_bytes: Option<i64>,
    pub blake3_hex: Option<String>,
    pub sha256_hex: Option<String>,
    pub rule_id: String,
    pub rule_source: String,
    pub severity: String,
    pub detected_at_utc: i64,
    pub action_taken: String,
    pub evidence: Option<String>,
    pub notes: Option<String>,
}

/// Action the user wants to apply to a finding. Mirrors
/// [`mythkernel::findings::FindingAction`] for IPC.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingAction {
    Quarantine,
    Restore,
    Delete,
    Ignore,
}

/// One row from the `quarantine` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineItem {
    pub id: QuarantineId,
    pub finding_id: Option<FindingId>,
    pub original_path: String,
    pub vault_path: String,
    pub size_bytes: i64,
    pub quarantined_at_utc: i64,
}

/// Per-item error inside a bulk op.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchItemErr {
    pub quarantine_id: QuarantineId,
    pub error: String,
}

/// Discriminator for which kind of batch op was run. Serialized as
/// lowercase `"restore"` / `"delete"` to match the TS narrow union
/// in `apps/mythodikal/frontend/src/ipc/types.ts`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BatchKindWire {
    Restore,
    Delete,
}

impl From<mythkernel::quarantine::BatchKind> for BatchKindWire {
    fn from(k: mythkernel::quarantine::BatchKind) -> Self {
        match k {
            mythkernel::quarantine::BatchKind::Restore => BatchKindWire::Restore,
            mythkernel::quarantine::BatchKind::Delete => BatchKindWire::Delete,
        }
    }
}

/// Final report of a bulk op. Mirrors
/// [`mythkernel::quarantine::BatchReport`] for IPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOpReport {
    pub batch_id: BatchOpId,
    pub kind: BatchKindWire,
    pub items_total: u64,
    pub items_done: u64,
    pub bytes_total: u64,
    pub bytes_done: u64,
    pub errors: Vec<BatchItemErr>,
}

/// Progress event for bulk quarantine ops. Emitted as the
/// `quarantine:batch_progress` Tauri event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProgressEvent {
    pub batch_id: BatchOpId,
    pub kind: BatchKindWire,
    pub items_done: u64,
    pub items_total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub last_error: Option<BatchItemErr>,
}

/// One feed's state (path on disk, count, last update). Used by both
/// `feed_status` and aggregated into `DefinitionCount` for the About
/// page (FR-157).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedState {
    pub feed_id: String,
    pub path: String,
    pub hash_count: u64,
    pub last_updated_utc: Option<i64>,
}

/// Result of one feed-update call. Returned as a `Vec` by
/// `feed_update_now` per FR-156.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedUpdateResult {
    pub feed_id: String,
    pub parsed_count: u64,
    pub merged_count: u64,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}

/// Definition counts surfaced on the About page (FR-157).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefinitionCount {
    pub abusech_hashes: u64,
    pub nsrl_hashes: u64,
    pub yara_rules_compiled: u64,
    pub byovd_entries: u64,
    pub user_rules: u64,
    pub total: u64,
}

/// Snapshot of every user-configurable setting. Phase 3 stub returns
/// hardcoded defaults per the roadmap note on TASK-028.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsSnapshot {
    pub general: GeneralSettings,
    pub privacy: PrivacySettings,
    pub scanning: ScanningSettings,
    pub about: AboutInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralSettings {
    /// FR-161 autostart toggle (read from the OS in Phase 4).
    pub start_with_os: bool,
    /// FR-162 tray icon visibility (Phase 4).
    pub show_tray_icon: bool,
    /// FR-088 close action: `quit` | `minimize_to_tray`.
    pub close_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacySettings {
    /// FR-110 — off by default, mandatory display in onboarding.
    pub telemetry_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanningSettings {
    /// FR-018 archives toggle (default on).
    pub archives_enabled: bool,
    pub follow_symlinks: bool,
    pub skip_hidden: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AboutInfo {
    pub engine_version: String,
    pub definition_count: DefinitionCount,
}

/// Partial patch applied via `settings_update`. Phase 3 accepts the
/// shape but mutates nothing — the stub stays stub until Phase 4 ships
/// real persistence (TASK-041).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SettingsPatch {
    pub general: Option<GeneralPatch>,
    pub privacy: Option<PrivacyPatch>,
    pub scanning: Option<ScanningPatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeneralPatch {
    pub start_with_os: Option<bool>,
    pub show_tray_icon: Option<bool>,
    pub close_action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PrivacyPatch {
    pub telemetry_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanningPatch {
    pub archives_enabled: Option<bool>,
    pub follow_symlinks: Option<bool>,
    pub skip_hidden: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineVersionInfo {
    pub version: String,
}

/// Mapping helper — converts a kernel-level `FindingAction` from the IPC
/// wire to the kernel enum.
impl From<FindingAction> for mythkernel::findings::FindingAction {
    fn from(a: FindingAction) -> Self {
        match a {
            FindingAction::Quarantine => mythkernel::findings::FindingAction::Quarantine,
            FindingAction::Restore => mythkernel::findings::FindingAction::Restore,
            FindingAction::Delete => mythkernel::findings::FindingAction::Delete,
            FindingAction::Ignore => mythkernel::findings::FindingAction::Ignore,
        }
    }
}
