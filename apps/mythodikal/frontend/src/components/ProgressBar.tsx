// ProgressBar (TASK-031).
//
// Minimal token-styled bar. Tabular-nums on the numeric label so the
// "X / Y" form doesn't dance as the values change (FR-085).

import type { Component } from "solid-js";

interface Props {
  done: number;
  total: number | null;
  /** Optional label override (e.g. "1,234 scanned · 8,910 enumerated · counting…" per FR-135). */
  label?: string;
  class?: string;
}

export const ProgressBar: Component<Props> = (props) => {
  const ratio = () => {
    if (props.total === null || props.total === 0) return 0;
    return Math.min(1, props.done / props.total);
  };
  const percent = () => Math.round(ratio() * 100);
  return (
    <div class={`w-full ${props.class ?? ""}`}>
      <div class="flex items-baseline justify-between">
        <span class="font-mono text-sm tabular-nums text-myth-text-md">
          {props.label ??
            (props.total !== null
              ? `${formatNumber(props.done)} / ${formatNumber(props.total)}`
              : `${formatNumber(props.done)} scanned · counting…`)}
        </span>
        {props.total !== null && (
          <span class="font-mono text-xs tabular-nums text-myth-text-lo">
            {percent()}%
          </span>
        )}
      </div>
      <div class="mt-1 h-1.5 w-full rounded-sm bg-myth-bg-2">
        <div
          class="h-full rounded-sm bg-myth-accent transition-[width] duration-200 ease-out"
          style={{ width: `${ratio() * 100}%` }}
        />
      </div>
    </div>
  );
};

function formatNumber(n: number): string {
  return n.toLocaleString("en-US");
}
