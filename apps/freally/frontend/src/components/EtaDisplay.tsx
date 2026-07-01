// EtaDisplay (TASK-038 UI).
//
// Renders the engine's calibrated ETA as `3h 25m 30s` and ticks down
// once per second between server events. The engine's ETA is monotone-
// non-increasing post-3%-baseline (PRD § 7 / FR-085); the client-side
// decrement keeps the display from looking frozen between the engine's
// progress events.
//
// When `etaSecs` is null we show "calibrating…" instead of a number —
// matches the EtaEstimator's "below baseline" state.

import { Show, createSignal, onCleanup, onMount } from "solid-js";
import { scanCounters, scanState } from "@/stores/scan";

export const EtaDisplay = () => {
  const [now, setNow] = createSignal(Date.now());

  onMount(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    onCleanup(() => clearInterval(id));
  });

  /** Frontend-computed ETA — `elapsed × total / visited - elapsed`.
   *
   *  We ignore the engine's `etaSecs` entirely. The engine uses a
   *  bytes-based EMA with a monotone-non-increasing clamp post-3%
   *  baseline. That clamp locks low whenever the early scan happens
   *  to be cache-replay or small-file heavy — and from then on it
   *  refuses to climb back to reality, so the UI shows "0s" forever
   *  on a long scan. A simple "average rate so far" projection is
   *  cruder but always honest: it converges to the right value as
   *  progress increases, and it gracefully refines downward if the
   *  rate accelerates. */
  const liveEta = (): number | null => {
    const s = scanState();
    if (s.kind !== "running" && s.kind !== "paused") return null;
    const c = scanCounters();
    const total = c.filesTotalLocked;
    if (total === null || total === 0) return null;
    if (c.filesVisited <= 0) return null;
    if (c.filesVisited >= total) return 0;
    // Use the scan's own start timestamp as the elapsed baseline.
    // Multi-phase scans count the registry + process time toward
    // this elapsed; those phases are fast enough that the projection
    // converges quickly once the files phase ramps up.
    const startedAt =
      (s as { startedAt?: number }).startedAt ?? c.etaReceivedAt;
    if (startedAt === null || startedAt === undefined) return null;
    const elapsedSec = (now() - startedAt) / 1000;
    if (elapsedSec < 1) return null;
    const rate = c.filesVisited / elapsedSec;
    if (rate <= 0) return null;
    const remaining = (total - c.filesVisited) / rate;
    return Math.max(0, remaining);
  };

  // Phase 6 — ETA is meaningful only during the file phase. During
  // registry / process sweeps we don't bother calibrating (those
  // phases have their own deterministic X/Y counters). Treat the
  // ETA as inactive whenever the engine has moved off the files
  // phase or hasn't entered it yet.
  const running = () =>
    scanState().kind === "running" && scanCounters().activePhase === "files";
  // The estimator returns null for the first ~3% of a scan (the
  // baseline-monotone clamp warm-up). Show "calibrating…" only while
  // we have at least one File event so a brand-new scan doesn't flash
  // the calibrating string before any progress is reported.
  const seenProgress = () => scanCounters().filesHashed > 0;
  // TASK-137 / wave-3 follow-up: until the producer locks Y, the ETA
  // estimator's denominator is a moving target — every File event
  // sees a larger total and the "X seconds remaining" number jumps
  // around as enumeration continues. Suppress the number entirely in
  // that window and show "calculating…" so the user understands the
  // engine is still discovering files.
  const enumerationLocked = () => scanCounters().enumerationLocked;

  const placeholder = () => {
    if (!running()) return "—";
    if (!seenProgress()) return "starting…";
    if (!enumerationLocked()) return "calculating…";
    return "calibrating…";
  };

  const showLiveEta = () => running() && enumerationLocked() && liveEta() !== null;

  return (
    <div>
      <div class="text-xs uppercase tracking-wide text-myth-text-lo">
        Time remaining
      </div>
      <Show
        when={showLiveEta()}
        fallback={
          <div class="font-mono text-lg tabular-nums text-myth-text-lo">
            {placeholder()}
          </div>
        }
      >
        <div class="font-mono text-lg tabular-nums text-myth-text-hi">
          {formatEta(liveEta()!)}
        </div>
      </Show>
    </div>
  );
};

/** Format a duration in seconds as `Hh Mm Ss` (e.g. `3h 25m 30s`). For
 *  durations < 1 minute, returns `Ss` only. For < 1 hour, returns
 *  `Mm Ss`. Always pads minutes/seconds to two digits inside an hours
 *  block so the width stays stable as it ticks down. */
export function formatEta(secs: number): string {
  const totalS = Math.max(0, Math.round(secs));
  const h = Math.floor(totalS / 3600);
  const m = Math.floor((totalS % 3600) / 60);
  const s = totalS % 60;
  if (h > 0) {
    return `${h}h ${pad(m)}m ${pad(s)}s`;
  }
  if (m > 0) {
    return `${m}m ${pad(s)}s`;
  }
  return `${s}s`;
}

function pad(n: number): string {
  return n < 10 ? `0${n}` : `${n}`;
}
