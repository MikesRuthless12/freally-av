// ThroughputChart (TASK-045).
//
// Zero-dependency SVG sparkline of files/sec over the last ~30 seconds.
// We deliberately avoid uPlot / d3 / recharts: every dep adds bundle
// weight and supply-chain surface, and the chart we need (one line,
// one axis, one tooltip-free hover) is ~70 lines of SVG path math.
//
// The samples ring is fed by `scanStore`'s 1Hz interval; this component
// just maps it to an SVG `<polyline>`. When fewer than two samples are
// present we show a "waiting for data…" stub instead of a flat line
// so the empty state isn't misread as "engine stalled at 0".

import { Show } from "solid-js";
import { scanState, scanThroughput } from "@/stores/scan";

const WIDTH = 320;
const HEIGHT = 80;
const PAD = 6;

export const ThroughputChart = () => {
  const samples = scanThroughput;

  const peak = () => {
    const arr = samples();
    let p = 0;
    for (const s of arr) if (s.filesPerSec > p) p = s.filesPerSec;
    // Floor at 1 fps to avoid a divide-by-zero / completely-flat line
    // when the engine is idle; visually equivalent to "no activity".
    return p < 1 ? 1 : p;
  };

  const points = (): string => {
    const arr = samples();
    if (arr.length < 2) return "";
    const usableW = WIDTH - PAD * 2;
    const usableH = HEIGHT - PAD * 2;
    const dx = usableW / (arr.length - 1);
    const top = peak();
    return arr
      .map((s, i) => {
        const x = PAD + i * dx;
        const y = PAD + usableH - (s.filesPerSec / top) * usableH;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
  };

  /** Closed polygon for the area-under-curve shade: the same points
   *  plus the bottom-right and bottom-left corners so the polygon
   *  fills everything beneath the line. */
  const areaPoints = (): string => {
    const arr = samples();
    if (arr.length < 2) return "";
    const usableW = WIDTH - PAD * 2;
    const dx = usableW / (arr.length - 1);
    const baselineY = (HEIGHT - PAD).toFixed(1);
    const firstX = PAD.toFixed(1);
    const lastX = (PAD + (arr.length - 1) * dx).toFixed(1);
    return `${firstX},${baselineY} ${points()} ${lastX},${baselineY}`;
  };

  const latest = () => {
    const arr = samples();
    const last = arr[arr.length - 1];
    return last ? last.filesPerSec : 0;
  };

  const hasData = () => samples().length >= 2;
  const running = () => scanState().kind === "running";

  return (
    <div class="rounded-md border border-myth-line bg-myth-bg-1 p-4">
      <header class="mb-2 flex items-center justify-between">
        <h2 class="text-sm font-semibold uppercase tracking-wide text-myth-text-md">
          Throughput
        </h2>
        <span class="font-mono text-xs tabular-nums text-myth-text-md">
          {Math.round(latest()).toLocaleString("en-US")} files/s
          <span class="ml-2 text-myth-text-lo">
            peak {Math.round(peak()).toLocaleString("en-US")}
          </span>
        </span>
      </header>
      <Show
        when={hasData()}
        fallback={
          <div class="flex h-20 items-center justify-center font-mono text-xs text-myth-text-lo">
            {running() ? "waiting for data…" : "—"}
          </div>
        }
      >
        <svg
          width={WIDTH}
          height={HEIGHT}
          viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
          class="w-full"
          preserveAspectRatio="none"
          role="img"
          aria-label="Scan throughput, files per second over the last 30 seconds"
        >
          <line
            x1={PAD}
            y1={HEIGHT - PAD}
            x2={WIDTH - PAD}
            y2={HEIGHT - PAD}
            stroke="currentColor"
            stroke-width="0.5"
            class="text-myth-line"
          />
          <polygon
            points={areaPoints()}
            class="fill-myth-accent"
            stroke="none"
          />
          <polyline
            points={points()}
            fill="none"
            stroke="currentColor"
            stroke-width="1.5"
            stroke-linejoin="round"
            stroke-linecap="round"
            class="text-myth-accent"
          />
        </svg>
      </Show>
    </div>
  );
};
