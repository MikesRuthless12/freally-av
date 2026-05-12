// StatusPill (TASK-031).
//
// Colored badge for scan status / finding severity. Uses the design
// tokens directly (no per-severity Tailwind colors).

import type { Component } from "solid-js";

interface Props {
  status: string;
  /** Optional override of the visual category. */
  variant?: "neutral" | "ok" | "warn" | "bad";
}

export const StatusPill: Component<Props> = (props) => {
  const variant = () => props.variant ?? inferVariant(props.status);
  const style = () => {
    switch (variant()) {
      case "ok":
        return "bg-myth-bg-2 text-myth-ok border-myth-ok/30";
      case "warn":
        return "bg-myth-bg-2 text-myth-warn border-myth-warn/30";
      case "bad":
        return "bg-myth-bg-2 text-myth-bad border-myth-bad/30";
      case "neutral":
      default:
        return "bg-myth-bg-2 text-myth-text-md border-myth-line";
    }
  };
  return (
    <span
      class={`inline-flex items-center rounded-sm border px-2 py-0.5 font-mono text-xs uppercase tracking-wide ${style()}`}
    >
      {props.status}
    </span>
  );
};

function inferVariant(s: string): Props["variant"] {
  switch (s) {
    case "completed":
    case "restored":
    case "low":
    case "info":
      return "ok";
    case "running":
    case "paused":
    case "medium":
      return "warn";
    case "failed":
    case "cancelled":
    case "high":
    case "critical":
    case "quarantined":
    case "detected":
      return "bad";
    default:
      return "neutral";
  }
}
