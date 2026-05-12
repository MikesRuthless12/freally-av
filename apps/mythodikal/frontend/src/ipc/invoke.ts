// Typed invoke wrapper around Tauri's @tauri-apps/api/core
// (TASK-029 frontend half).
//
// Each function here corresponds 1:1 to a `#[tauri::command]` in
// `crates/ui-bridge/src/commands.rs`. Keep this file in lockstep with
// that source-of-truth.

import { invoke } from "@tauri-apps/api/core";
import { listen, type Event, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  BatchOpReport,
  BatchProgressEvent,
  DefinitionCount,
  EngineVersionInfo,
  ExclusionRequest,
  ExclusionView,
  FeedState,
  FeedUpdateResult,
  FindingAction,
  FindingId,
  FindingView,
  QuarantineId,
  QuarantineItem,
  ScanDetail,
  ScanId,
  ScanProgress,
  ScanRequest,
  ScanSummary,
  SettingsPatch,
  SettingsSnapshot,
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
