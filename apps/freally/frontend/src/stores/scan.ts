// Scan store (TASK-030).
//
// Holds the currently-running scan's state and re-renders the UI on
// Tauri events. Designed so the Scan page mounts/unmounts cleanly
// without leaking event listeners.

import { createSignal, onCleanup } from "solid-js";
import type { UnlistenFn } from "@tauri-apps/api/event";
import {
  onArchiveEntry,
  onHeuristicPhaseComplete,
  onHeuristicPhaseStarted,
  onHeuristicProgress,
  onProcessPhaseComplete,
  onProcessPhaseStarted,
  onProcessProgress,
  onRegistryPhaseComplete,
  onRegistryPhaseStarted,
  onRegistryProgress,
  onScanCancelled,
  onScanCompleted,
  onScanEnumerationComplete,
  onScanError,
  onScanFailed,
  onScanFinding,
  onScanPartialHash,
  onScanPaused,
  onScanProgress,
  onScanStarted,
  scanCancel as ipcScanCancel,
  scanPause as ipcScanPause,
  scanStart,
  scanResume as ipcScanResume,
} from "@/ipc/invoke";
import { setTrayScanning } from "@/stores/tray";
import type { FindingView, ScanId, ScanRequest } from "@/ipc/types";

export type ScanState =
  | { kind: "idle" }
  | { kind: "running"; scanId: ScanId; startedAt: number }
  | { kind: "paused"; scanId: ScanId; startedAt: number }
  | { kind: "cancelled"; scanId: ScanId }
  | { kind: "completed"; scanId: ScanId; durationMs: number }
  | { kind: "failed"; scanId: ScanId; message: string };

/** Which phase is currently running. UI uses this to highlight the
 *  active tile / chart / progress bar. */
export type ScanPhase = "registry" | "processes" | "files" | "heuristics";

interface ScanCounters {
  filesVisited: number;
  filesHashed: number;
  findingsCount: number;
  bytesVisited: number;
  currentPath: string | null;
  lastError: string | null;
  // Phase 6 — registry phase counters.
  registryItemsScanned: number;
  registryItemsExpected: number | null;
  registryCurrentKey: string | null;
  registryPhaseComplete: boolean;
  // Phase 6 — process phase counters.
  processesScanned: number;
  processesExpected: number | null;
  processCurrentName: string | null;
  processCurrentExe: string | null;
  processPhaseComplete: boolean;
  /** Active phase highlight. Defaults to "files" (legacy file-only
   *  scans never see registry/process events; the UI keeps the file
   *  tile highlighted). Quick Scan/All Volumes flips this through
   *  registry → processes → files as the engine progresses. */
  activePhase: ScanPhase;
  /** Phase 6 — running count of entries extracted+hashed from inside
   *  ZIP/ZIPX archives. The archive itself counts as one entry in
   *  `filesVisited`; entries inside accumulate here. */
  archiveEntriesScanned: number;
  /** Phase 6 — the archive currently being scanned (or null when not
   *  currently inside an archive). Cleared on the next non-archive
   *  File event. */
  archiveCurrentPath: string | null;
  /** Phase 6 — the entry name inside the current archive being
   *  hashed right now. */
  archiveCurrentEntry: string | null;
  /** Phase 6 — heuristics phase counters. Item count tracked
   *  separately from filesVisited / filesHashed so the user sees
   *  the post-pass tile fill independently. */
  heuristicsScanned: number;
  heuristicsExpected: number | null;
  heuristicsFlagged: number;
  heuristicsCurrentPath: string | null;
  heuristicsPhaseComplete: boolean;
  /** Calibrated ETA seconds from the engine (null while warming up). */
  etaSecs: number | null;
  /** Local timestamp (ms) when the most recent ETA was received — used
   *  by the UI to count down between engine events. */
  etaReceivedAt: number | null;
  /** TASK-134 / FR-136 — live mid-flight BLAKE3 hex from the engine.
   *  null when the operator-mode toggle is off, or while between
   *  files. */
  partialHash: string | null;
  partialBytesDone: number;
  /** TASK-137 / FR-135 — running enumeration count (Y unlocked).
   *  Increments while the producer is still discovering files; the
   *  UI shows three-piece `X · Y · counting…` until enumerationLocked
   *  flips. */
  filesTotalRunning: number;
  /** TASK-137 / FR-135 — locked Y after `enumeration_complete`. */
  filesTotalLocked: number | null;
  /** TASK-137 — true after `enumeration_complete` fires. UI uses this
   *  to swap the three-piece presentation for the canonical `X/Y`. */
  enumerationLocked: boolean;
}

/** One throughput sample = files-per-second over the prior ~1 s window
 *  plus the local timestamp. Stored in a fixed-length ring so the chart
 *  renders a sliding window without unbounded growth on a long scan
 *  (TASK-045). */
export interface ThroughputSample {
  tMs: number;
  filesPerSec: number;
  bytesPerSec: number;
}

/** Sliding window length. 30 samples × 1 s ≈ a 30 s view, which matches
 *  the operator-feedback target ("show me the last half-minute of
 *  activity"). Larger windows blur the spike that signals an I/O stall. */
const THROUGHPUT_WINDOW = 30;

const initialCounters: ScanCounters = {
  filesVisited: 0,
  filesHashed: 0,
  findingsCount: 0,
  bytesVisited: 0,
  currentPath: null,
  lastError: null,
  etaSecs: null,
  etaReceivedAt: null,
  partialHash: null,
  partialBytesDone: 0,
  filesTotalRunning: 0,
  filesTotalLocked: null,
  enumerationLocked: false,
  registryItemsScanned: 0,
  registryItemsExpected: null,
  registryCurrentKey: null,
  registryPhaseComplete: false,
  processesScanned: 0,
  processesExpected: null,
  processCurrentName: null,
  processCurrentExe: null,
  processPhaseComplete: false,
  activePhase: "files",
  archiveEntriesScanned: 0,
  archiveCurrentPath: null,
  archiveCurrentEntry: null,
  heuristicsScanned: 0,
  heuristicsExpected: null,
  heuristicsFlagged: 0,
  heuristicsCurrentPath: null,
  heuristicsPhaseComplete: false,
};

const [state, setState] = createSignal<ScanState>({ kind: "idle" });
const [counters, setCounters] = createSignal<ScanCounters>(initialCounters);
const [findings, setFindings] = createSignal<FindingView[]>([]);
const [throughput, setThroughput] = createSignal<ThroughputSample[]>([]);

export const scanState = state;
export const scanCounters = counters;
export const scanFindings = findings;
/** Rolling files/sec + bytes/sec window for the Scan throughput chart. */
export const scanThroughput = throughput;

export async function startScan(request: ScanRequest): Promise<ScanId> {
  setState({ kind: "idle" });
  setCounters(initialCounters);
  setFindings([]);
  setThroughput([]);
  const id = await scanStart(request);
  setState({ kind: "running", scanId: id, startedAt: Date.now() });
  return id;
}

/** Pause an in-flight scan. In-place: the engine workers park on the
 *  pause flag without writing a resume token, so the same scan_id
 *  carries through to resume.
 *
 *  Optimistic UI: flip to "paused" **synchronously** so the button
 *  label changes the instant the user clicks. The IPC just sets the
 *  backend flag; there's no Paused event to wait for in the new
 *  in-place model. */
export async function pauseScan(scanId: ScanId): Promise<void> {
  const prev = scanState();
  const startedAt =
    prev.kind === "running" || prev.kind === "paused"
      ? prev.startedAt
      : Date.now();
  setState({ kind: "paused", scanId, startedAt });
  void setTrayScanning(false);
  await ipcScanPause(scanId);
}

/** Resume a paused scan in place. Same scan_id; the backend just
 *  clears the pause flag and the parked workers wake up.
 *
 *  Optimistic UI: flip back to "running" synchronously and carry the
 *  original `startedAt` forward so the elapsed-time clock doesn't
 *  reset for a brief pause. */
export async function resumeScan(scanId: ScanId): Promise<ScanId> {
  const prev = scanState();
  const startedAt =
    prev.kind === "paused" || prev.kind === "running"
      ? prev.startedAt
      : Date.now();
  setState({ kind: "running", scanId, startedAt });
  void setTrayScanning(true);
  const id = await ipcScanResume(scanId);
  return id;
}

/** Cancel a running or paused scan. Final — no resume token is
 *  written. The backend marks the scan row `cancelled` and fires
 *  `scan:cancelled`.
 *
 *  Optimistic UI: flip the state **synchronously** so the user sees
 *  instant feedback the moment they click. Counters are *frozen*
 *  (not zeroed) so the user can see "I scanned 10,870 files before
 *  cancelling" — far more useful than `0`. In-flight UI bits
 *  (current path, partial hash, ETA) are cleared because they're
 *  stale by definition. The eventual `scan:cancelled` event from
 *  the engine just re-affirms the state we already set. */
export async function cancelScan(scanId: ScanId): Promise<void> {
  setState({ kind: "cancelled", scanId });
  setCounters((c) => ({
    ...c,
    currentPath: null,
    partialHash: null,
    partialBytesDone: 0,
    etaSecs: null,
    etaReceivedAt: null,
  }));
  void setTrayScanning(false);
  await ipcScanCancel(scanId);
}

/** Return true iff `eventScanId` matches the scan currently mounted in
 *  the UI state. Used by every Tauri event handler to drop *stale*
 *  events — i.e. progress / terminal events that belong to a prior
 *  scan that the user has already cancelled-and-restarted. Without
 *  this filter the old scan's late `scan:cancelled` event would clobber
 *  the new running scan's state (issue: "cancel + immediate restart
 *  stays at 0 files counted"). */
function isCurrentScan(eventScanId: ScanId): boolean {
  const s = state();
  return "scanId" in s && s.scanId === eventScanId;
}

/**
 * Wire all six scan-event subscriptions for as long as the calling
 * component is mounted. Solid `onCleanup` un-listens on unmount so
 * we don't leak listeners or fight stale state.
 */
export function attachScanEvents(): void {
  const handles: Promise<UnlistenFn>[] = [];
  // Sample throughput once per second from the counter deltas. We do
  // this client-side rather than over the wire because the engine
  // already throttles File events to 10 Hz; computing a per-second
  // figure here is cheap and avoids inflating IPC traffic.
  let lastSampleAt = Date.now();
  let lastFiles = 0;
  let lastBytes = 0;
  const samplerId = setInterval(() => {
    if (state().kind !== "running") return;
    const now = Date.now();
    const c = counters();
    const dtS = Math.max(0.001, (now - lastSampleAt) / 1000);
    const filesPerSec = Math.max(0, (c.filesHashed - lastFiles) / dtS);
    const bytesPerSec = Math.max(0, (c.bytesVisited - lastBytes) / dtS);
    lastSampleAt = now;
    lastFiles = c.filesHashed;
    lastBytes = c.bytesVisited;
    setThroughput((prev) => {
      const next = prev.concat([{ tMs: now, filesPerSec, bytesPerSec }]);
      return next.length > THROUGHPUT_WINDOW
        ? next.slice(next.length - THROUGHPUT_WINDOW)
        : next;
    });
  }, 1000);
  onCleanup(() => clearInterval(samplerId));

  handles.push(
    onScanStarted((payload) => {
      // Stale-event guard: only apply if this Started belongs to the
      // scan currently mounted in state. (Old scans that finalize
      // after a quick cancel+restart should not seed the new scan's
      // counters with the old run's resume carry.)
      if (!isCurrentScan(payload.scan_id)) return;
      // Carry the prior run's counters when this Started event is
      // from a resumed scan — otherwise the UI visually resets to
      // zero between the user's Resume click and the worker's first
      // File event, even though the engine internally continues from
      // the resume token. Fresh starts have these set to 0.
      const carried = {
        ...initialCounters,
        filesVisited: payload.resumed_files_visited ?? 0,
        filesHashed: payload.resumed_files_hashed ?? 0,
        bytesVisited: payload.resumed_bytes_visited ?? 0,
        findingsCount: payload.resumed_findings_count ?? 0,
      };
      setCounters(carried);
      setFindings([]);
      // TASK-158 — drive the tray icon while a scan is running.
      void setTrayScanning(true);
    }),
  );

  handles.push(
    onScanProgress((payload) => {
      // File events carry no scan_id, so we gate on the *state kind*:
      // drop progress for any scan that's no longer running or paused.
      // Without this, cancel-in-flight File events would re-populate
      // the optimistically-frozen counters with stale data.
      const s = state();
      if (s.kind !== "running" && s.kind !== "paused") return;
      setCounters((c) => {
        // TASK-137: the engine sends `files_total_running` while Y is
        // still moving, and `files_total_locked` after the producer
        // emitted `enumeration_complete`. Trust whichever is present
        // on the event so the denominator stays accurate even if the
        // standalone `enumeration_complete` listener fires later.
        const running =
          payload.files_total_running ?? c.filesTotalRunning;
        const locked = payload.files_total_locked ?? c.filesTotalLocked;
        const enumerationLocked = c.enumerationLocked || locked !== null;
        // The forwarder coalesces File events to ≤ 10 Hz, so a per-event
        // `+1` would massively undercount a 1000-file/sec scan. SET to
        // the engine-side cumulative counter instead. Falls back to
        // `+1`/+size if the payload is missing the fields (old backend).
        const filesVisitedNext =
          payload.files_visited_total !== undefined
            ? payload.files_visited_total
            : c.filesVisited + 1;
        const filesHashedNext =
          payload.files_hashed_total !== undefined
            ? payload.files_hashed_total
            : c.filesHashed + 1;
        const bytesVisitedNext =
          payload.bytes_visited_total !== undefined
            ? payload.bytes_visited_total
            : c.bytesVisited + payload.size;
        const findingsCountNext =
          payload.findings_count_total !== undefined
            ? payload.findings_count_total
            : c.findingsCount;
        // Fast-path File events (MS-signed sentinel, verdict-cache
        // replay) carry `eta_secs = null` because no ETA sample is
        // taken when we skip the hash. Overwriting the live ETA with
        // null causes the display to flicker between a number and
        // "calibrating…" on every alternating event. Preserve the
        // last non-null sample instead.
        const etaSecsNext = payload.eta_secs !== null ? payload.eta_secs : c.etaSecs;
        const etaReceivedAtNext =
          payload.eta_secs !== null ? Date.now() : c.etaReceivedAt;
        return {
          ...c,
          filesVisited: filesVisitedNext,
          filesHashed: filesHashedNext,
          bytesVisited: bytesVisitedNext,
          findingsCount: findingsCountNext,
          currentPath: payload.path,
          etaSecs: etaSecsNext,
          etaReceivedAt: etaReceivedAtNext,
          // A `file` event always means a file just finalized — the
          // partial-hash field belongs to the *next* file. Clear it.
          partialHash: null,
          partialBytesDone: 0,
          filesTotalRunning: running,
          filesTotalLocked: locked,
          enumerationLocked,
        };
      });
    }),
  );

  handles.push(
    onScanEnumerationComplete((payload) => {
      if (!isCurrentScan(payload.scan_id)) return;
      setCounters((c) => ({
        ...c,
        filesTotalRunning: payload.files_total_locked,
        filesTotalLocked: payload.files_total_locked,
        enumerationLocked: true,
      }));
    }),
  );

  handles.push(
    onScanPartialHash((payload) => {
      if (!isCurrentScan(payload.scan_id)) return;
      // TASK-134 — events are throttled to ≤ 10 Hz on the engine side,
      // so we don't add a frontend rate-limiter here.
      setCounters((c) => ({
        ...c,
        currentPath: payload.path,
        partialHash: payload.blake3_partial,
        partialBytesDone: payload.bytes_done,
      }));
    }),
  );

  handles.push(
    onScanFinding((payload) => {
      if (!isCurrentScan(payload.scan_id)) return;
      const placeholder: FindingView = {
        id: payload.finding_id,
        scan_id: payload.scan_id,
        path: payload.path,
        size_bytes: null,
        blake3_hex: null,
        sha256_hex: null,
        rule_id: payload.rule_id,
        rule_source: payload.rule_source,
        severity: payload.severity,
        detected_at_utc: Math.floor(Date.now() / 1000),
        action_taken: "none",
        evidence: null,
        notes: null,
      };
      // Cap the rendered list at 200 most-recent findings. A noisy
      // heuristic rule can emit 10K+ matches and rendering all of
      // them quadratically chokes the page (every new finding forces
      // an O(N) array copy AND an O(N) re-render of the table).
      // `findingsCount` still tracks the true total — the History
      // detail panel later loads the full set from SQLite.
      const FINDINGS_DISPLAY_CAP = 200;
      setFindings((prev) =>
        prev.length >= FINDINGS_DISPLAY_CAP
          ? [placeholder, ...prev.slice(0, FINDINGS_DISPLAY_CAP - 1)]
          : [placeholder, ...prev],
      );
      setCounters((c) => ({ ...c, findingsCount: c.findingsCount + 1 }));
    }),
  );

  handles.push(
    onScanError((payload) => {
      // Error events carry no scan_id — gate on state.kind so we don't
      // light up a "Last error" line on an idle/cancelled UI.
      const s = state();
      if (s.kind !== "running" && s.kind !== "paused") return;
      setCounters((c) => ({ ...c, lastError: payload.message }));
    }),
  );

  handles.push(
    onScanCompleted((payload) => {
      if (!isCurrentScan(payload.scan_id)) return;
      setState({
        kind: "completed",
        scanId: payload.scan_id,
        durationMs: payload.duration_ms,
      });
      setCounters((c) => ({
        ...c,
        filesVisited: payload.files_visited,
        filesHashed: payload.files_hashed,
        bytesVisited: payload.bytes_visited,
        findingsCount: payload.findings_count,
        currentPath: null,
      }));
      void setTrayScanning(false);
    }),
  );

  handles.push(
    onScanFailed((payload) => {
      if (!isCurrentScan(payload.scan_id)) return;
      setState({
        kind: "failed",
        scanId: payload.scan_id,
        message: payload.message,
      });
      void setTrayScanning(false);
    }),
  );

  handles.push(
    onScanPaused((payload) => {
      if (!isCurrentScan(payload.scan_id)) return;
      // Belt-and-suspenders: with in-place pause the engine no longer
      // fires this event, but if a legacy scan / crash-recovery path
      // ever does, preserve the existing startedAt so the live ETA
      // clock doesn't drift backward.
      const prev = state();
      const startedAt =
        prev.kind === "running" || prev.kind === "paused"
          ? prev.startedAt
          : Date.now();
      setState({ kind: "paused", scanId: payload.scan_id, startedAt });
      setCounters((c) => ({
        ...c,
        filesVisited: payload.files_visited,
        filesHashed: payload.files_hashed,
        bytesVisited: payload.bytes_visited,
        findingsCount: payload.findings_count,
        currentPath: null,
        etaSecs: null,
        etaReceivedAt: null,
      }));
      void setTrayScanning(false);
    }),
  );

  handles.push(
    onScanCancelled((payload) => {
      // CRITICAL stale-event guard: when the user cancel-restarts
      // quickly, the old scan's late Cancelled event will arrive
      // while the new scan is already running. Without this check it
      // would overwrite state to "cancelled" and the new scan would
      // appear frozen at 0 files. Reject any Cancelled event that
      // doesn't belong to the scan currently mounted.
      if (!isCurrentScan(payload.scan_id)) return;
      setState({ kind: "cancelled", scanId: payload.scan_id });
      setCounters((c) => ({
        ...c,
        filesVisited: payload.files_visited,
        filesHashed: payload.files_hashed,
        bytesVisited: payload.bytes_visited,
        findingsCount: payload.findings_count,
        currentPath: null,
        etaSecs: null,
        etaReceivedAt: null,
      }));
      void setTrayScanning(false);
    }),
  );

  // ----- Phase 6: registry phase handlers -----
  handles.push(
    onRegistryPhaseStarted((payload) => {
      if (!isCurrentScan(payload.scan_id)) return;
      setCounters((c) => ({
        ...c,
        registryItemsScanned: 0,
        registryItemsExpected: payload.expected_items,
        registryCurrentKey: null,
        registryPhaseComplete: false,
        activePhase: "registry",
      }));
    }),
  );
  handles.push(
    onRegistryProgress((payload) => {
      if (!isCurrentScan(payload.scan_id)) return;
      setCounters((c) => ({
        ...c,
        registryItemsScanned: payload.items_scanned_total,
        registryCurrentKey: payload.current_key,
        activePhase: "registry",
      }));
    }),
  );
  handles.push(
    onRegistryPhaseComplete((payload) => {
      if (!isCurrentScan(payload.scan_id)) return;
      setCounters((c) => ({
        ...c,
        registryItemsScanned: payload.items_total,
        // Lock the denominator to the real total so the bar reads
        // 100% even if our pre-pass undercounted.
        registryItemsExpected: Math.max(
          c.registryItemsExpected ?? 0,
          payload.items_total,
        ),
        registryPhaseComplete: true,
      }));
    }),
  );

  // ----- Phase 6: process phase handlers -----
  handles.push(
    onProcessPhaseStarted((payload) => {
      if (!isCurrentScan(payload.scan_id)) return;
      setCounters((c) => ({
        ...c,
        processesScanned: 0,
        processesExpected: payload.expected_processes,
        processCurrentName: null,
        processCurrentExe: null,
        processPhaseComplete: false,
        activePhase: "processes",
      }));
    }),
  );
  handles.push(
    onProcessProgress((payload) => {
      if (!isCurrentScan(payload.scan_id)) return;
      setCounters((c) => ({
        ...c,
        processesScanned: payload.processes_scanned_total,
        processCurrentName: payload.name,
        processCurrentExe: payload.exe_path,
        activePhase: "processes",
      }));
    }),
  );
  handles.push(
    onProcessPhaseComplete((payload) => {
      if (!isCurrentScan(payload.scan_id)) return;
      setCounters((c) => ({
        ...c,
        processesScanned: payload.processes_total,
        processesExpected: Math.max(
          c.processesExpected ?? 0,
          payload.processes_total,
        ),
        processPhaseComplete: true,
        // Hand off to the files phase.
        activePhase: "files",
      }));
    }),
  );

  // Phase 6 — heuristics phase handlers.
  handles.push(
    onHeuristicPhaseStarted((payload) => {
      if (!isCurrentScan(payload.scan_id)) return;
      setCounters((c) => ({
        ...c,
        heuristicsScanned: 0,
        heuristicsExpected: payload.expected_items,
        heuristicsFlagged: 0,
        heuristicsCurrentPath: null,
        heuristicsPhaseComplete: false,
        activePhase: "heuristics",
      }));
    }),
  );
  handles.push(
    onHeuristicProgress((payload) => {
      if (!isCurrentScan(payload.scan_id)) return;
      setCounters((c) => ({
        ...c,
        heuristicsScanned: payload.items_scanned_total,
        heuristicsCurrentPath: payload.current_path,
        activePhase: "heuristics",
      }));
    }),
  );
  handles.push(
    onHeuristicPhaseComplete((payload) => {
      if (!isCurrentScan(payload.scan_id)) return;
      setCounters((c) => ({
        ...c,
        heuristicsScanned: payload.items_total,
        heuristicsExpected: Math.max(
          c.heuristicsExpected ?? 0,
          payload.items_total,
        ),
        heuristicsFlagged: payload.flagged_total,
        heuristicsPhaseComplete: true,
      }));
    }),
  );

  // Phase 6 — archive entry events. Updates the running count + the
  // archive/entry breadcrumb so the UI can show
  // "Inside backup.zip → kernel32.dll".
  handles.push(
    onArchiveEntry((payload) => {
      if (!isCurrentScan(payload.scan_id)) return;
      setCounters((c) => ({
        ...c,
        archiveEntriesScanned: payload.archive_entries_scanned_total,
        archiveCurrentPath: payload.archive_path,
        archiveCurrentEntry: payload.entry_name,
      }));
    }),
  );

  onCleanup(() => {
    for (const h of handles) {
      void h.then((fn) => fn());
    }
  });
}
