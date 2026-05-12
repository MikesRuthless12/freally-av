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

  /** Effective ETA after subtracting the time elapsed since the engine
   *  reported `etaSecs`. Floors at 0 so the UI never shows negative
   *  numbers. */
  const liveEta = (): number | null => {
    const c = scanCounters();
    if (c.etaSecs === null || c.etaReceivedAt === null) return null;
    const elapsed = Math.max(0, (now() - c.etaReceivedAt) / 1000);
    return Math.max(0, c.etaSecs - elapsed);
  };

  const running = () => scanState().kind === "running";
  // The estimator returns null for the first ~3% of a scan (the
  // baseline-monotone clamp warm-up). Show "calibrating…" only while
  // we have at least one File event so a brand-new scan doesn't flash
  // the calibrating string before any progress is reported.
  const seenProgress = () => scanCounters().filesHashed > 0;

  const placeholder = () => {
    if (!running()) return "—";
    if (!seenProgress()) return "starting…";
    return "calibrating…";
  };

  return (
    <div>
      <div class="text-xs uppercase tracking-wide text-myth-text-lo">
        Time remaining
      </div>
      <Show
        when={running() && liveEta() !== null}
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
