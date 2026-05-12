// Scan page (TASK-032).
//
// Single primary action (Start scan). When a scan is running the
// button row swaps to Pause / Cancel (both wired to the Phase 4 stubs
// in commands.rs — they return clear "Phase 4" errors today). After
// completion the user can start a new scan.

import type { Component } from "solid-js";
import { Show, createSignal } from "solid-js";
import type { FindingAction, FindingView } from "@/ipc/types";
import { findingAction, scanPause } from "@/ipc/invoke";
import {
  resumeScan,
  scanCounters,
  scanFindings,
  scanState,
  startScan,
} from "@/stores/scan";
import { EtaDisplay } from "@/components/EtaDisplay";
import { FindingRow } from "@/components/FindingRow";
import { PathDisplay } from "@/components/PathDisplay";
import { ProgressBar } from "@/components/ProgressBar";
import { StatusPill } from "@/components/StatusPill";
import { ThroughputChart } from "@/components/ThroughputChart";

const PARTIAL_HASH_STORAGE_KEY = "mythodikal.scan.operatorMode";

const Scan: Component = () => {
  const [target, setTarget] = createSignal("");
  const [computeSha, setComputeSha] = createSignal(true);
  const [followSymlinks, setFollowSymlinks] = createSignal(false);
  // TASK-134 — operator-mode toggle. Persists in localStorage so the
  // setting survives page reloads.
  const [operatorMode, setOperatorMode] = createSignal(
    typeof window !== "undefined"
      ? window.localStorage.getItem(PARTIAL_HASH_STORAGE_KEY) === "1"
      : false,
  );
  const setOperatorModePersistent = (v: boolean) => {
    setOperatorMode(v);
    if (typeof window !== "undefined") {
      window.localStorage.setItem(PARTIAL_HASH_STORAGE_KEY, v ? "1" : "0");
    }
  };
  const [error, setError] = createSignal<string | null>(null);
  const [busyAction, setBusyAction] = createSignal<number | null>(null);

  // Event subscriptions live in App.tsx so they survive route changes
  // (PRD § review fix: a scan kicked off here keeps emitting events even
  // after the user navigates to History — the singleton store must
  // catch them).

  const onStart = async () => {
    setError(null);
    try {
      await startScan({
        target_path: target(),
        compute_sha256: computeSha(),
        follow_symlinks: followSymlinks(),
        emit_partial_hash: operatorMode(),
      });
    } catch (err) {
      setError(String(err));
    }
  };

  const onFindingAction = async (f: FindingView, action: FindingAction) => {
    setBusyAction(f.id);
    setError(null);
    try {
      await findingAction(f.id, action);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusyAction(null);
    }
  };

  const stateLabel = () => {
    const s = scanState();
    switch (s.kind) {
      case "idle":
        return "idle";
      case "running":
        return "running";
      case "paused":
        return "paused";
      case "completed":
        return "completed";
      case "failed":
        return "failed";
    }
  };

  const startDisabled = () =>
    target().trim().length === 0 || scanState().kind === "running";

  const onPause = async () => {
    setError(null);
    const s = scanState();
    if (s.kind !== "running") return;
    try {
      await scanPause(s.scanId);
    } catch (err) {
      setError(String(err));
    }
  };

  const onResume = async () => {
    setError(null);
    const s = scanState();
    if (s.kind !== "paused") return;
    try {
      await resumeScan(s.scanId);
    } catch (err) {
      setError(String(err));
    }
  };

  return (
    <div class="flex h-full flex-col gap-4 p-6">
      <header class="flex items-center justify-between">
        <h1 class="font-display text-2xl font-semibold tracking-tight text-myth-text-hi">
          Scan
        </h1>
        <StatusPill status={stateLabel()} />
      </header>

      <section class="rounded-md border border-myth-line bg-myth-bg-1 p-4">
        <label class="block text-sm font-medium text-myth-text-hi">
          Target path
        </label>
        <input
          type="text"
          placeholder="/path/to/scan"
          class="mt-1 w-full rounded-sm border border-myth-line bg-myth-bg-0 px-3 py-2 font-mono text-sm text-myth-text-hi placeholder-myth-text-lo focus:border-myth-accent focus:outline-none"
          value={target()}
          onInput={(e) => setTarget(e.currentTarget.value)}
        />

        <div class="mt-3 flex flex-wrap gap-6 text-sm text-myth-text-md">
          <label class="flex items-center gap-2">
            <input
              type="checkbox"
              checked={computeSha()}
              onChange={(e) => setComputeSha(e.currentTarget.checked)}
            />
            <span>Compute SHA-256 (required for abuse.ch / NSRL feeds)</span>
          </label>
          <label class="flex items-center gap-2">
            <input
              type="checkbox"
              checked={followSymlinks()}
              onChange={(e) => setFollowSymlinks(e.currentTarget.checked)}
            />
            <span>Follow symlinks</span>
          </label>
          <label
            class="flex items-center gap-2"
            title="FR-136 / TASK-134 — live mid-flight BLAKE3 prefix at ≤ 10 Hz. Off by default; slight CPU cost during scan."
          >
            <input
              type="checkbox"
              checked={operatorMode()}
              onChange={(e) =>
                setOperatorModePersistent(e.currentTarget.checked)
              }
            />
            <span>Operator mode (live hash preview)</span>
          </label>
        </div>

        <div class="mt-4 flex gap-2">
          <button
            type="button"
            class="rounded-sm border border-myth-accent bg-myth-accent px-4 py-1.5 font-mono text-sm font-medium uppercase tracking-wide text-white hover:bg-myth-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
            disabled={startDisabled()}
            onClick={onStart}
          >
            Start scan
          </button>
          <Show when={scanState().kind === "running"}>
            <button
              type="button"
              class="rounded-sm border border-myth-line bg-myth-bg-0 px-4 py-1.5 font-mono text-sm uppercase tracking-wide text-myth-text-hi hover:border-myth-accent"
              onClick={onPause}
            >
              Pause
            </button>
          </Show>
          <Show when={scanState().kind === "paused"}>
            <button
              type="button"
              class="rounded-sm border border-myth-accent bg-myth-accent px-4 py-1.5 font-mono text-sm font-medium uppercase tracking-wide text-white hover:bg-myth-accent/90"
              onClick={onResume}
            >
              Resume scan
            </button>
          </Show>
        </div>
      </section>

      <Show when={scanState().kind !== "idle"}>
        <section class="rounded-md border border-myth-line bg-myth-bg-1 p-4">
          <h2 class="mb-2 text-sm font-semibold uppercase tracking-wide text-myth-text-md">
            Progress
          </h2>
          <ProgressBar done={scanCounters().filesVisited} total={null} />
          <div class="mt-3 grid grid-cols-4 gap-4 text-sm text-myth-text-md">
            <Stat
              label="Files visited"
              value={scanCounters().filesVisited.toLocaleString("en-US")}
            />
            <Stat
              label="Files hashed"
              value={scanCounters().filesHashed.toLocaleString("en-US")}
            />
            <Stat
              label="Findings"
              value={scanCounters().findingsCount.toLocaleString("en-US")}
            />
            <EtaDisplay />
          </div>
          <div class="mt-3">
            <div class="text-xs uppercase tracking-wide text-myth-text-lo">
              Current path
            </div>
            <Show
              when={scanCounters().currentPath}
              fallback={
                <span class="font-mono text-xs text-myth-text-lo">—</span>
              }
            >
              <PathDisplay path={scanCounters().currentPath!} />
            </Show>
          </div>
          <Show when={operatorMode() && scanCounters().partialHash}>
            <div class="mt-3">
              <div class="text-xs uppercase tracking-wide text-myth-text-lo">
                Live BLAKE3 (operator mode)
              </div>
              <div class="break-all font-mono text-xs text-myth-text-hi">
                {scanCounters().partialHash}
              </div>
              <div class="mt-0.5 font-mono text-xs tabular-nums text-myth-text-lo">
                {scanCounters().partialBytesDone.toLocaleString("en-US")} bytes
                hashed
              </div>
            </div>
          </Show>
          <Show when={scanState().kind === "completed"}>
            <div class="mt-3 font-mono text-xs text-myth-text-md tabular-nums">
              completed in{" "}
              {scanState().kind === "completed"
                ? `${((scanState() as { durationMs: number }).durationMs / 1000).toFixed(1)}s`
                : ""}
            </div>
          </Show>
          <Show when={scanState().kind === "failed"}>
            <div class="mt-3 font-mono text-xs text-myth-bad">
              failed:{" "}
              {(scanState() as { message: string }).message}
            </div>
          </Show>
        </section>
        <ThroughputChart />
      </Show>

      <Show when={error()}>
        <div class="rounded-md border border-myth-bad/50 bg-myth-bad/10 p-3 font-mono text-xs text-myth-bad">
          {error()}
        </div>
      </Show>

      <Show when={scanFindings().length > 0}>
        <section class="overflow-hidden rounded-md border border-myth-line bg-myth-bg-1">
          <header class="flex items-center justify-between border-b border-myth-line px-4 py-2">
            <h2 class="text-sm font-semibold uppercase tracking-wide text-myth-text-md">
              Findings
            </h2>
            <span class="font-mono text-xs tabular-nums text-myth-text-lo">
              {scanFindings().length} surfaced
            </span>
          </header>
          {scanFindings().map((f) => (
            <FindingRow
              finding={f}
              busy={busyAction() === f.id}
              onAction={(a) => onFindingAction(f, a)}
            />
          ))}
        </section>
      </Show>
    </div>
  );
};

const Stat: Component<{ label: string; value: string }> = (props) => (
  <div>
    <div class="text-xs uppercase tracking-wide text-myth-text-lo">
      {props.label}
    </div>
    <div class="font-mono text-lg tabular-nums text-myth-text-hi">
      {props.value}
    </div>
  </div>
);

export default Scan;
