// PathDisplay (TASK-031 subset of FR-085a).
//
// Phase 3 renders the full path with CSS-driven truncation and a tooltip
// on the canonical form. The full FR-085a algorithm (filename-preserving
// middle-out truncation via ResizeObserver) lands in Phase 10 TASK-085b.

import type { Component } from "solid-js";

export const PathDisplay: Component<{ path: string; class?: string }> = (
  props,
) => {
  return (
    <span
      class={`block max-w-full overflow-hidden text-ellipsis whitespace-nowrap font-mono text-myth-text-md ${props.class ?? ""}`}
      title={props.path}
    >
      {props.path}
    </span>
  );
};
