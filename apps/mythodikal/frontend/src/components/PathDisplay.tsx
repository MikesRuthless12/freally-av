// PathDisplay (TASK-031 subset of FR-085a).
//
// Phase 3 renders the full path with CSS-driven truncation and a tooltip
// on the canonical form. The full FR-085a algorithm (filename-preserving
// middle-out truncation via ResizeObserver) lands in Phase 10 TASK-085b.

import type { Component } from "solid-js";

/// Strip the Windows extended-length path prefix `\\?\` (and the rare
/// UNC-extended form `\\?\UNC\`) so the visible path is the
/// drive-letter form the user typed in. Internal callers still see the
/// canonical extended path via the `title` tooltip.
export function displayPath(raw: string): string {
  if (raw.startsWith("\\\\?\\UNC\\")) {
    // \\?\UNC\server\share\... → \\server\share\...
    return "\\\\" + raw.slice("\\\\?\\UNC\\".length);
  }
  if (raw.startsWith("\\\\?\\")) {
    return raw.slice(4);
  }
  return raw;
}

export const PathDisplay: Component<{ path: string; class?: string }> = (
  props,
) => {
  return (
    <span
      class={`block max-w-full overflow-hidden text-ellipsis whitespace-nowrap font-mono text-myth-text-md ${props.class ?? ""}`}
      title={displayPath(props.path)}
    >
      {displayPath(props.path)}
    </span>
  );
};
