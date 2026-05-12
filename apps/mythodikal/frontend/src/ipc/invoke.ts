// Typed invoke wrapper around Tauri's @tauri-apps/api/core
// (TASK-029 frontend half).
//
// Each function here corresponds 1:1 to a `#[tauri::command]` in
// `crates/ui-bridge/src/commands.rs`. Keep this file in lockstep with
// that source-of-truth.

import { invoke } from "@tauri-apps/api/core";
import { listen, type Event, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AutostartState,
  BatchOpReport,
  BatchProgressEvent,
  DatabaseChannelStateView,
  DatabaseUpdateProgressEvent,
  DefinitionCount,
  EngineUpdateAvailableView,
  EngineUpdateProgressEvent,
  EngineVersionInfo,
  ExclusionRequest,
  ExclusionView,
  FeedState,
  FeedUpdateResult,
  FindingAction,
  FindingId,
  FindingView,
  PublisherView,
  QuarantineId,
  QuarantineItem,
  ScanDetail,
  ScanId,
  ScanProgress,
  ScanRequest,
  ScanSummary,
  SettingsPatch,
  SettingsSnapshot,
  UpdateChannelStateView,
  UpdaterStatusView,
  VolumeView,
} from "./types";

// ============================================================================
// Scan
// ============================================================================

export function scanStart(request: ScanRequest): Promise<ScanId> {
  return invoke<ScanId>("scan_start", { request });
}

export function scanStatus(scanId: ScanId): Promise<ScanSummary> {
  return invoke<ScanSummary>("scan_status", { scanId });
}

export function scanCancel(scanId: ScanId): Promise<void> {
  return invoke<void>("scan_cancel", { scanId });
}

export function scanPause(scanId: ScanId): Promise<void> {
  return invoke<void>("scan_pause", { scanId });
}

export function scanResume(scanId: ScanId): Promise<ScanId> {
  return invoke<ScanId>("scan_resume", { scanId });
}

// ============================================================================
// History + findings
// ============================================================================

export function historyList(
  limit?: number,
  offset?: number,
): Promise<ScanSummary[]> {
  return invoke<ScanSummary[]>("history_list", { limit, offset });
}

export function historyGet(scanId: ScanId): Promise<ScanDetail> {
  return invoke<ScanDetail>("history_get", { scanId });
}

export function findingList(scanId: ScanId): Promise<FindingView[]> {
  return invoke<FindingView[]>("finding_list", { scanId });
}

export function findingAction(
  findingId: FindingId,
  action: FindingAction,
): Promise<string> {
  return invoke<string>("finding_action", { findingId, action });
}

// ============================================================================
// Quarantine
// ============================================================================

export function quarantineList(): Promise<QuarantineItem[]> {
  return invoke<QuarantineItem[]>("quarantine_list");
}

export function quarantineRestore(id: QuarantineId): Promise<string> {
  return invoke<string>("quarantine_restore", { id });
}

export function quarantineDelete(id: QuarantineId): Promise<void> {
  return invoke<void>("quarantine_delete", { id });
}

export function quarantineRestoreAll(): Promise<BatchOpReport> {
  return invoke<BatchOpReport>("quarantine_restore_all");
}

/**
 * `confirm` must be `true` to proceed — mirrors the GUI's typed-DELETE
 * gate from FR-046. The CLI uses `--confirm`; this is the equivalent.
 */
export function quarantineDeleteAll(confirm: boolean): Promise<BatchOpReport> {
  return invoke<BatchOpReport>("quarantine_delete_all", { confirm });
}

export function quarantineRestoreMany(
  ids: QuarantineId[],
): Promise<BatchOpReport> {
  return invoke<BatchOpReport>("quarantine_restore_many", { ids });
}

export function quarantineDeleteMany(
  ids: QuarantineId[],
): Promise<BatchOpReport> {
  return invoke<BatchOpReport>("quarantine_delete_many", { ids });
}

// ============================================================================
// Feed / settings / system
// ============================================================================

export function feedStatus(): Promise<FeedState[]> {
  return invoke<FeedState[]>("feed_status");
}

export interface FeedUpdateArgs {
  abusech_auth_key?: string | null;
  nsrl_local?: string | null;
  nsrl_url?: string | null;
}

export function feedUpdateNow(
  args: FeedUpdateArgs = {},
): Promise<FeedUpdateResult[]> {
  // Cast to Record so tauri's InvokeArgs accepts our typed shape —
  // the camelCase invoke wrapper does its own JSON conversion.
  return invoke<FeedUpdateResult[]>(
    "feed_update_now",
    args as Record<string, unknown>,
  );
}

export function definitionCount(): Promise<DefinitionCount> {
  return invoke<DefinitionCount>("definition_count");
}

export function settingsGet(): Promise<SettingsSnapshot> {
  return invoke<SettingsSnapshot>("settings_get");
}

export function settingsUpdate(patch: SettingsPatch): Promise<void> {
  return invoke<void>("settings_update", { patch });
}

export function engineVersion(): Promise<EngineVersionInfo> {
  return invoke<EngineVersionInfo>("engine_version");
}

export function updaterStatus(): Promise<UpdaterStatusView | null> {
  return invoke<UpdaterStatusView | null>("updater_status");
}

// Exclusions
export function exclusionList(): Promise<ExclusionView[]> {
  return invoke<ExclusionView[]>("exclusion_list");
}

export function exclusionAdd(
  request: ExclusionRequest,
): Promise<ExclusionView> {
  return invoke<ExclusionView>("exclusion_add", { request });
}

export function exclusionRemove(id: number): Promise<void> {
  return invoke<void>("exclusion_remove", { id });
}

// ============================================================================
// Events
// ============================================================================

type Handler<T> = (payload: T, event: Event<T>) => void;

/**
 * Subscribe to a Tauri event. Returns an unlisten function the caller
 * must invoke on cleanup (typically inside a Solid `onCleanup`).
 */
export function on<T>(topic: string, handler: Handler<T>): Promise<UnlistenFn> {
  return listen<T>(topic, (event) => handler(event.payload, event));
}

export function onScanStarted(
  handler: Handler<Extract<ScanProgress, { kind: "started" }>>,
): Promise<UnlistenFn> {
  return on("scan:started", handler);
}

export function onScanProgress(
  handler: Handler<Extract<ScanProgress, { kind: "file" }>>,
): Promise<UnlistenFn> {
  return on("scan:progress", handler);
}

export function onScanFinding(
  handler: Handler<Extract<ScanProgress, { kind: "finding" }>>,
): Promise<UnlistenFn> {
  return on("scan:finding", handler);
}

export function onScanError(
  handler: Handler<Extract<ScanProgress, { kind: "error" }>>,
): Promise<UnlistenFn> {
  return on("scan:error", handler);
}

export function onScanCompleted(
  handler: Handler<Extract<ScanProgress, { kind: "completed" }>>,
): Promise<UnlistenFn> {
  return on("scan:completed", handler);
}

export function onScanFailed(
  handler: Handler<Extract<ScanProgress, { kind: "failed" }>>,
): Promise<UnlistenFn> {
  return on("scan:failed", handler);
}

export function onScanPaused(
  handler: Handler<Extract<ScanProgress, { kind: "paused" }>>,
): Promise<UnlistenFn> {
  return on("scan:paused", handler);
}

/**
 * TASK-137 — Producer locked Y. UI switches from three-piece
 * `X scanned · Y enumerated · counting…` to `X/Y`.
 */
export function onScanEnumerationComplete(
  handler: Handler<Extract<ScanProgress, { kind: "enumeration_complete" }>>,
): Promise<UnlistenFn> {
  return on("scan:enumeration_complete", handler);
}

export function onQuarantineBatchProgress(
  handler: Handler<BatchProgressEvent>,
): Promise<UnlistenFn> {
  return on("quarantine:batch_progress", handler);
}

export function onFindingUpdated(
  handler: Handler<{ finding_id: FindingId; state: string }>,
): Promise<UnlistenFn> {
  return on("finding:updated", handler);
}

// ============================================================================
// Updater channels (TASK-129/130/131/132/133)
// ============================================================================

export function updaterEngineState(): Promise<UpdateChannelStateView> {
  return invoke<UpdateChannelStateView>("updater_engine_state");
}

export function updaterEngineCheckNow(): Promise<EngineUpdateAvailableView | null> {
  return invoke<EngineUpdateAvailableView | null>("updater_engine_check_now");
}

export function updaterEngineSetAuto(enabled: boolean): Promise<void> {
  return invoke<void>("updater_engine_set_auto", { enabled });
}

/** Drives the Tauri Updater plugin's download_and_install. Emits
 *  `engine_update:progress` events along the way. Returns the new
 *  version on success. */
export function engineInstallUpdate(): Promise<string> {
  return invoke<string>("engine_install_update");
}

export function updaterDbState(): Promise<DatabaseChannelStateView> {
  return invoke<DatabaseChannelStateView>("updater_db_state");
}

export function updaterDbCheckNow(): Promise<DatabaseChannelStateView> {
  return invoke<DatabaseChannelStateView>("updater_db_check_now");
}

export function updaterDbSetAuto(enabled: boolean): Promise<void> {
  return invoke<void>("updater_db_set_auto", { enabled });
}

export function onEngineUpdateProgress(
  handler: Handler<EngineUpdateProgressEvent>,
): Promise<UnlistenFn> {
  return on("engine_update:progress", handler);
}

export function onDbUpdateProgress(
  handler: Handler<DatabaseUpdateProgressEvent>,
): Promise<UnlistenFn> {
  return on("db_update:progress", handler);
}

export function onScanPartialHash(
  handler: Handler<Extract<ScanProgress, { kind: "partial_hash" }>>,
): Promise<UnlistenFn> {
  return on("scan:partial_hash", handler);
}

// ============================================================================
// Publisher whitelist (FR-146 / TASK-136)
// ============================================================================

export function publisherSignerForPath(path: string): Promise<PublisherView> {
  return invoke<PublisherView>("publisher_signer_for_path", { path });
}

export function publisherPruneCache(): Promise<number> {
  return invoke<number>("publisher_prune_cache");
}

// ============================================================================
// Autostart (FR-161 / TASK-157)
// ============================================================================

export function autostartGet(): Promise<AutostartState> {
  return invoke<AutostartState>("autostart_get");
}

export function autostartSet(enabled: boolean): Promise<AutostartState> {
  return invoke<AutostartState>("autostart_set", { enabled });
}

// ============================================================================
// Volumes (TASK-052 / TASK-056) — Windows per-volume scan-target chooser
// ============================================================================

/**
 * List every mounted volume on the host. Returns an empty array on
 * non-Windows platforms so the UI degrades cleanly to its path-only
 * chooser.
 */
export function enumerateVolumes(): Promise<VolumeView[]> {
  return invoke<VolumeView[]>("enumerate_volumes");
}
