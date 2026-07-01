// ThroughputPill (TASK-031).
//
// Renders an ongoing bytes-per-second figure with a short SI suffix.
// Tabular-nums per FR-085. Phase 3 ships a static pill; the live
// chart (FR-086 / TASK-045) is Phase 4.

import type { Component } from "solid-js";

interface Props {
  bytesPerSecond: number;
}

export const ThroughputPill: Component<Props> = (props) => {
  return (
    <span class="inline-flex items-center rounded-sm border border-myth-line bg-myth-bg-2 px-2 py-0.5 font-mono text-xs tabular-nums text-myth-text-md">
      {formatBytesPerSec(props.bytesPerSecond)}
    </span>
  );
};

export function formatBytesPerSec(bps: number): string {
  if (!Number.isFinite(bps) || bps <= 0) return "0 B/s";
  const units = ["B/s", "KB/s", "MB/s", "GB/s"];
  let i = 0;
  let v = bps;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  const fixed = v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2);
  return `${fixed} ${units[i]}`;
}
