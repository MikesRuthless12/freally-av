// IPC type mirror (TASK-029 frontend half).
//
// HAND-WRITTEN MIRROR of `crates/ui-bridge/src/types.rs`. Any field
// added or removed in the Rust source-of-truth MUST also be applied
// here. We defer a `specta`-driven generator to Phase 7+ when the
// type surface grows further.
//
// Source-of-truth: see commit messages on `crates/ui-bridge/src/types.rs`.

export type ScanId = number;
export type FindingId = number;
export type QuarantineId = number;
export type BatchOpId = number;

export interface ScanRequest {
  target_path: string;
  compute_sha256: boolean;
  follow_symlinks: boolean;
  /** FR-136 / TASK-134 — emit `scan:partial_hash` events at ≤ 10 Hz. */
  emit_partial_hash?: boolean;
  /** TASK-053 / TASK-056 — fan out across every detected volume (Windows). */
  all_volumes?: boolean;
}

/**
 * One row in the Windows scan-target chooser. Mirrors
 * `ui-bridge::types::VolumeView`. Non-Windows hosts return an empty list
 * from `enumerate_volumes` so the UI degrades cleanly to path-only.
 */
export interface VolumeView {
  mount_path: string;
  all_mount_paths: string[];
  fs_name: string;
  serial: number;
  is_ntfs: boolean;
  is_removable: boolean;
}

export interface ScanSummary {
  id: ScanId;
  started_at_utc: number;
  ended_at_utc: number | null;
  trigger: string;
  target_paths: string;
  status: string;
  files_visited: number;
  findings_count: number;
  bytes_visited: number;
}

export interface ScanDetail {
  summary: ScanSummary;
  findings: FindingView[];
}

export interface FindingView {
  id: FindingId;
  scan_id: ScanId;
  path: string;
  size_bytes: number | null;
  blake3_hex: string | null;
  sha256_hex: string | null;
  rule_id: string;
  rule_source: string;
  severity: string;
  detected_at_utc: number;
  action_taken: string;
  evidence: string | null;
  notes: string | null;
}

export type FindingAction = "quarantine" | "restore" | "delete" | "ignore";

export interface QuarantineItem {
  id: QuarantineId;
  finding_id: FindingId | null;
  original_path: string;
  vault_path: string;
  size_bytes: number;
  quarantined_at_utc: number;
}

export interface BatchItemErr {
  quarantine_id: QuarantineId;
  error: string;
}

export interface BatchOpReport {
  batch_id: BatchOpId;
  kind: "restore" | "delete";
  items_total: number;
  items_done: number;
  bytes_total: number;
  bytes_done: number;
  errors: BatchItemErr[];
}

export interface BatchProgressEvent {
  batch_id: BatchOpId;
  kind: "restore" | "delete";
  items_done: number;
  items_total: number;
  bytes_done: number;
  bytes_total: number;
  last_error: BatchItemErr | null;
}

export interface FeedState {
  feed_id: string;
  path: string;
  hash_count: number;
  last_updated_utc: number | null;
}

export interface FeedUpdateResult {
  feed_id: string;
  parsed_count: number;
  merged_count: number;
  elapsed_ms: number;
  error: string | null;
}

export interface DefinitionCount {
  abusech_hashes: number;
  nsrl_hashes: number;
  yara_rules_compiled: number;
  byovd_entries: number;
  user_rules: number;
  total: number;
  /** TASK-132 — per-feed last-updated timestamps (unix seconds). null
   *  when the feed file isn't on disk yet (first-run). */
  abusech_last_updated_utc?: number | null;
  nsrl_last_updated_utc?: number | null;
}

export interface SettingsSnapshot {
  general: GeneralSettings;
  privacy: PrivacySettings;
  scanning: ScanningSettings;
  about: AboutInfo;
}

export interface GeneralSettings {
  start_with_os: boolean;
  show_tray_icon: boolean;
  close_action: string;
}

export interface PrivacySettings {
  telemetry_enabled: boolean;
}

export interface ScanningSettings {
  archives_enabled: boolean;
  follow_symlinks: boolean;
  skip_hidden: boolean;
}

export interface AboutInfo {
  engine_version: string;
  definition_count: DefinitionCount;
}

export interface SettingsPatch {
  general?: Partial<GeneralSettings>;
  privacy?: Partial<PrivacySettings>;
  scanning?: Partial<ScanningSettings>;
}

export interface EngineVersionInfo {
  version: string;
}

export interface UpdaterStatusView {
  started_at_utc: number;
  finished_at_utc: number;
  outcome: string;
  detail: string;
  next_run_at_utc: number;
}

// Exclusions (TASK-042 / FR-060/061/062/134, TASK-136 added "publisher").
export type ExclusionKind =
  | "path"
  | "glob"
  | "hash_blake3"
  | "hash_sha256"
  | "publisher";
export type ExclusionScope = "scan_only" | "realtime_only" | "both";

export interface ExclusionView {
  id: number;
  kind: ExclusionKind | string;
  value: string;
  scope: ExclusionScope | string;
  expires_at_utc: number | null;
  created_at_utc: number;
  reason: string | null;
}

export interface ExclusionRequest {
  kind: ExclusionKind;
  value: string;
  scope: ExclusionScope;
  expires_at_utc?: number | null;
  reason?: string | null;
}

// ScanProgress mirrors the tagged enum from
// mythkernel::scan::ScanProgress (also re-exported through
// ui-bridge::types). The Tauri Emitter serializes the enum with the
// `kind` discriminator, so the TS union is keyed on `kind`.

export type ScanProgress =
  | { kind: "started"; scan_id: ScanId; started_at_utc: number }
  | {
      kind: "file";
      path: string;
      blake3: string;
      size: number;
      /** ETA in seconds (post-3%-baseline clamp). null while warming up. */
      eta_secs: number | null;
      /** TASK-137 / FR-135 — running enumeration count, **unlocked**.
       *  Set during the enumeration phase; null after the
       *  `enumeration_complete` event fires (use `files_total_locked`). */
      files_total_running?: number | null;
      /** TASK-137 / FR-135 — locked total after enumeration completed.
       *  null until the `enumeration_complete` event fires; from then on
       *  this carries the canonical Y in the X/Y UI presentation. */
      files_total_locked?: number | null;
    }
  | {
      /** TASK-134 / FR-136 — live mid-flight BLAKE3 prefix at ≤ 10 Hz. */
      kind: "partial_hash";
      scan_id: ScanId;
      path: string;
      blake3_partial: string;
      bytes_done: number;
    }
  | {
      kind: "finding";
      scan_id: ScanId;
      finding_id: FindingId;
      path: string;
      rule_id: string;
      rule_source: string;
      severity: string;
    }
  | { kind: "error"; path: string; message: string }
  | {
      kind: "completed";
      scan_id: ScanId;
      files_visited: number;
      files_hashed: number;
      bytes_visited: number;
      findings_count: number;
      duration_ms: number;
    }
  | { kind: "failed"; scan_id: ScanId; message: string }
  | {
      kind: "paused";
      scan_id: ScanId;
      files_visited: number;
      files_hashed: number;
      bytes_visited: number;
      findings_count: number;
    }
  | {
      /** TASK-137 / FR-135 — producer locked Y. Fires exactly once per
       *  scan. After this event the UI switches its denominator from
       *  the running counter to `files_total_locked`. */
      kind: "enumeration_complete";
      scan_id: ScanId;
      files_total_locked: number;
      bytes_total_locked: number;
    };

// ---------------------------------------------------------------------------
// Updater channels (TASK-129/130/131/132/133)
// ---------------------------------------------------------------------------

export type UpdateOutcome =
  | "never"
  | "up_to_date"
  | "update_available"
  | "installed"
  | "failed";

/** TASK-129/130/131 — code-review CR-I14: typed as a narrow union so
 *  consumers can switch on `kind` without losing exhaustiveness. */
export type ChannelKind = "engine" | "database";

export interface UpdateChannelStateView {
  kind: ChannelKind;
  auto_update_enabled: boolean;
  channel: string;
  interval_hours: number;
  last_check_at_utc: number;
  last_install_at_utc: number;
  last_outcome: UpdateOutcome | string;
  last_error: string;
}

export interface FeedMetaView {
  feed_id: string;
  last_check_at_utc: number;
  last_install_at_utc: number;
  entry_count: number;
  last_outcome: string;
  last_error: string;
}

export interface DatabaseChannelStateView {
  state: UpdateChannelStateView;
  feeds: FeedMetaView[];
}

export interface EngineUpdateAvailableView {
  current_version: string;
  latest_version: string;
  release_url: string;
  release_notes: string;
  published_at_utc: number;
}

export type EngineUpdatePhase =
  | "download"
  | "verify"
  | "install"
  | "restart_pending";

export interface EngineUpdateProgressEvent {
  phase: EngineUpdatePhase | string;
  bytes_done: number;
  bytes_total: number;
  message: string;
}

export type DatabaseUpdatePhase =
  | "download"
  | "decompress"
  | "rebuild_index"
  | "swap";

export interface DatabaseUpdateProgressEvent {
  feed_id: string;
  phase: DatabaseUpdatePhase | string;
  bytes_done: number;
  bytes_total: number;
  message: string;
}

// ---------------------------------------------------------------------------
// Autostart (FR-161 / TASK-157) + Publisher (FR-146 / TASK-136)
// ---------------------------------------------------------------------------

export interface AutostartState {
  enabled: boolean;
  mechanism: string;
}

export interface PublisherView {
  path: string;
  identity: string;
  /** "authenticode" | "codesign" | "gpg" | "unsigned" */
  kind: string;
}

// Severity ordering used by the UI for sort + color.
export const SEVERITY_RANK: Record<string, number> = {
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

export function severityRank(s: string): number {
  return SEVERITY_RANK[s] ?? 0;
}
