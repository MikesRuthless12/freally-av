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
    /// Phase 6 — Quick Scan supplies the canonical malware-hotspot
    /// directories here (TEMP / APPDATA / Downloads / etc.). When
    /// non-empty, the engine walks every path; `target_path` is then
    /// just the first entry. `all_volumes` and `extra_paths` are
    /// mutually exclusive on the IPC boundary.
    #[serde(default)]
    pub extra_paths: Vec<PathBuf>,
    /// Compute SHA-256 alongside BLAKE3. Forced to `true` when any
    /// SHA-256-keyed detector (abuse.ch / NSRL) is loaded so the
    /// pipeline can query the right digest. The UI's default is
    /// `false` when no feeds are loaded, `true` otherwise.
    pub compute_sha256: bool,
    pub follow_symlinks: bool,
    /// FR-136 / TASK-134 — emit `scan:partial_hash` events at ≤ 10 Hz.
    /// Off by default; the Scan dashboard's operator-mode toggle flips
    /// this on per-scan.
    #[serde(default)]
    pub emit_partial_hash: bool,
    /// TASK-053 / TASK-056 — fan out across every detected volume.
    /// Windows-only effect; on other platforms the engine's
    /// `MultiVolumeWalker` discovery falls back to the requested
    /// `target_path`.
    #[serde(default)]
    pub all_volumes: bool,
    /// Phase 6 — turn on the Windows registry persistence-key sweep
    /// as the first phase of the scan. Quick Scan defaults this true.
    #[serde(default)]
    pub include_registry: bool,
    /// Phase 6 — turn on the running-process sweep as the second
    /// phase. Quick Scan defaults this true.
    #[serde(default)]
    pub include_processes: bool,
    /// Phase 6 — recurse into ZIP archive entries (off by default;
    /// per-archive open + per-entry hash adds real latency).
    #[serde(default)]
    pub include_archives: bool,
    /// Phase 6 — when set, skip the file walker entirely (no
    /// `target_path` validation required, no producer thread). Used
    /// for Registry-only / Process-only / Reg+Proc scans, which have
    /// no file target at all.
    #[serde(default)]
    pub files_disabled: bool,
    /// Phase 6 (preview) — run heuristic pattern matchers after the
    /// main scan completes. Accepted on the IPC boundary so the
    /// renderer's toggle round-trips; backend pipeline implementation
    /// lands in a follow-up wave.
    #[serde(default)]
    pub run_heuristics: bool,
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

/// Definition counts surfaced on the About page (FR-157, TASK-132).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefinitionCount {
    pub abusech_hashes: u64,
    pub nsrl_hashes: u64,
    pub yara_rules_compiled: u64,
    pub byovd_entries: u64,
    pub user_rules: u64,
    pub total: u64,
    /// Per-feed last-updated unix timestamps. Populated for whichever
    /// feed files exist on disk; missing feeds report `None`.
    #[serde(default)]
    pub abusech_last_updated_utc: Option<i64>,
    #[serde(default)]
    pub nsrl_last_updated_utc: Option<i64>,
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

/// Most-recent feed updater run (TASK-043). Mirrors
/// `mythkernel::updater::scheduler::LastRun` field-for-field; we re-
/// declare here so the IPC boundary doesn't leak the internal type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdaterStatusView {
    pub started_at_utc: i64,
    pub finished_at_utc: i64,
    pub outcome: String,
    pub detail: String,
    pub next_run_at_utc: i64,
}

// ---------------------------------------------------------------------------
// Updater channels (TASK-129/130/131/132/133)
// ---------------------------------------------------------------------------

/// Generic channel-state view (engine or database). Mirrors
/// `mythkernel::updater::channels::ChannelState`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateChannelStateView {
    pub kind: String, // "engine" | "database"
    pub auto_update_enabled: bool,
    pub channel: String,
    pub interval_hours: u32,
    pub last_check_at_utc: i64,
    pub last_install_at_utc: i64,
    /// One of `"never" | "up_to_date" | "update_available" | "installed" | "failed"`.
    pub last_outcome: String,
    pub last_error: String,
}

/// Per-feed metadata inside the database channel state (TASK-131).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedMetaView {
    pub feed_id: String,
    pub last_check_at_utc: i64,
    pub last_install_at_utc: i64,
    pub entry_count: u64,
    pub last_outcome: String,
    pub last_error: String,
}

/// Full database-channel snapshot — channel-level state plus the
/// per-feed map flattened into a vec the frontend can iterate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseChannelStateView {
    pub state: UpdateChannelStateView,
    pub feeds: Vec<FeedMetaView>,
}

/// What `engine_check_for_updates` returns. `None` (TS `null`) means the
/// running binary is the latest release.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineUpdateAvailableView {
    pub current_version: String,
    pub latest_version: String,
    pub release_url: String,
    pub release_notes: String,
    pub published_at_utc: i64,
}

/// Progress event emitted to `engine_update:progress`. Mirrors
/// `mythkernel::updater::engine::EngineUpdateProgress`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineUpdateProgressEvent {
    /// `"download" | "verify" | "install" | "restart_pending"`.
    pub phase: String,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub message: String,
}

/// Progress event emitted to `db_update:progress`. Mirrors
/// `mythkernel::updater::database::DatabaseUpdateProgress`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseUpdateProgressEvent {
    pub feed_id: String,
    /// `"download" | "decompress" | "rebuild_index" | "swap"`.
    pub phase: String,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Autostart (FR-161 / TASK-157) + Tray (FR-162 / TASK-158)
// ---------------------------------------------------------------------------

/// Reflects the OS autostart state for the Mythodikal app (FR-161).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutostartState {
    pub enabled: bool,
    /// Free-text description of the OS mechanism used (e.g.
    /// `"~/.config/autostart/mythodikal.desktop"` on Linux). Empty when
    /// the plugin reports an unknown mechanism.
    pub mechanism: String,
}

/// Tray icon high-level state (FR-162 priority machine).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrayState {
    /// One of `"idle" | "scanning" | "shields_off" | "update_available"`.
    pub icon: String,
    pub tooltip: String,
}

// ---------------------------------------------------------------------------
// Volumes (TASK-052 / TASK-056) — Windows per-volume scan-target chooser
// ---------------------------------------------------------------------------

/// One row in the Windows scan-target chooser. Mirrors
/// [`mythkernel::platform::win::volumes::VolumeInfo`] for IPC. On
/// non-Windows hosts the command returns an empty `Vec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeView {
    /// Primary user-visible mount path (e.g. `C:\`).
    pub mount_path: String,
    /// All mount paths the volume is reachable through. Always contains
    /// `mount_path` as the first element.
    pub all_mount_paths: Vec<String>,
    /// Filesystem name reported by `GetVolumeInformationW` (NTFS / FAT32
    /// / exFAT / ReFS). Always uppercase.
    pub fs_name: String,
    /// Volume serial number from `GetVolumeInformationW` — same number
    /// the vendored journal subscriber uses to key its cursor file.
    pub serial: u32,
    pub is_ntfs: bool,
    pub is_removable: bool,
}

// ---------------------------------------------------------------------------
// Publisher whitelist (FR-146 / TASK-136)
// ---------------------------------------------------------------------------

/// Reported signer identity for a given file path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublisherView {
    pub path: String,
    pub identity: String,
    /// `"authenticode" | "codesign" | "gpg" | "unsigned"`.
    pub kind: String,
}

// ---------------------------------------------------------------------------
// Exclusions (TASK-042 / FR-060/061/062/134)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionView {
    pub id: i64,
    pub kind: String, // "path" | "glob" | "hash_blake3" | "hash_sha256"
    pub value: String,
    pub scope: String, // "scan_only" | "realtime_only" | "both"
    pub expires_at_utc: Option<i64>,
    pub created_at_utc: i64,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionRequest {
    pub kind: String,
    pub value: String,
    pub scope: String,
    pub expires_at_utc: Option<i64>,
    pub reason: Option<String>,
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
