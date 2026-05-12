// Scan store (TASK-030).
//
// Holds the currently-running scan's state and re-renders the UI on
// Tauri events. Designed so the Scan page mounts/unmounts cleanly
// without leaking event listeners.

import { createSignal, onCleanup } from "solid-js";
import type { UnlistenFn } from "@tauri-apps/api/event";
import {
  onScanCompleted,
  onScanError,
  onScanFailed,
  onScanFinding,
  onScanProgress,
  onScanStarted,
  scanStart,
} from "@/ipc/invoke";
import type { FindingView, ScanId, ScanRequest } from "@/ipc/types";

export type ScanState =
  | { kind: "idle" }
  | { kind: "running"; scanId: ScanId; startedAt: number }
  | { kind: "completed"; scanId: ScanId; durationMs: number }
  | { kind: "failed"; scanId: ScanId; message: string };

interface ScanCounters {
  filesVisited: number;
  filesHashed: number;
  findingsCount: number;
  bytesVisited: number;
  currentPath: string | null;
  lastError: string | null;
  /** Calibrated ETA seconds from the engine (null while warming up). */
  etaSecs: number | null;
  /** Local timestamp (ms) when the most recent ETA was received — used
   *  by the UI to count down between engine events. */
  etaReceivedAt: number | null;
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
    onScanStarted(() => {
      setCounters(initialCounters);
      setFindings([]);
    }),
  );

  handles.push(
    onScanProgress((payload) => {
      setCounters((c) => ({
        ...c,
        filesVisited: c.filesVisited + 1,
        filesHashed: c.filesHashed + 1,
        bytesVisited: c.bytesVisited + payload.size,
        currentPath: payload.path,
        etaSecs: payload.eta_secs,
        etaReceivedAt: payload.eta_secs !== null ? Date.now() : c.etaReceivedAt,
      }));
    }),
  );

  handles.push(
    onScanFinding((payload) => {
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
      setFindings((prev) => [placeholder, ...prev]);
      setCounters((c) => ({ ...c, findingsCount: c.findingsCount + 1 }));
    }),
  );

  handles.push(
    onScanError((payload) => {
      setCounters((c) => ({ ...c, lastError: payload.message }));
    }),
  );

  handles.push(
    onScanCompleted((payload) => {
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
    }),
  );

  handles.push(
    onScanFailed((payload) => {
      setState({
        kind: "failed",
        scanId: payload.scan_id,
        message: payload.message,
      });
    }),
  );

  onCleanup(() => {
    for (const h of handles) {
      void h.then((fn) => fn());
    }
  });
}
