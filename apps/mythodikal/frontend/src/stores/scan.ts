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
}

const initialCounters: ScanCounters = {
  filesVisited: 0,
  filesHashed: 0,
  findingsCount: 0,
  bytesVisited: 0,
  currentPath: null,
  lastError: null,
};

const [state, setState] = createSignal<ScanState>({ kind: "idle" });
const [counters, setCounters] = createSignal<ScanCounters>(initialCounters);
const [findings, setFindings] = createSignal<FindingView[]>([]);

export const scanState = state;
export const scanCounters = counters;
export const scanFindings = findings;

export async function startScan(request: ScanRequest): Promise<ScanId> {
  setState({ kind: "idle" });
  setCounters(initialCounters);
  setFindings([]);
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
