// Sidebar (TASK-036).
//
// Left rail with the four main routes + a placeholder Shields badge.
// Real Shields wiring (FR-160) lands in Phase 4 / TASK-156 — for now
// the badge always reads "Shields: ON" so the UI shape matches the
// final design.

import type { Component } from "solid-js";
import { A } from "@solidjs/router";

const NAV: { path: string; label: string }[] = [
  { path: "/scan", label: "Scan" },
  { path: "/history", label: "History" },
  { path: "/quarantine", label: "Quarantine" },
  { path: "/settings", label: "Settings" },
];

export const Sidebar: Component = () => {
  return (
    <aside class="flex w-48 shrink-0 flex-col border-r border-myth-line bg-myth-bg-1">
      <div class="border-b border-myth-line px-4 py-4">
        <div class="font-display text-lg font-semibold tracking-tight text-myth-text-hi">
          Mythodikal
        </div>
        <div class="font-mono text-[10px] uppercase tracking-wide text-myth-text-lo">
          anti-virus
        </div>
      </div>
      <nav class="flex-1 px-2 py-3">
        {NAV.map((entry) => (
          <A
            href={entry.path}
            class="block rounded-sm px-3 py-1.5 font-mono text-xs uppercase tracking-wide text-myth-text-md hover:bg-myth-bg-2 hover:text-myth-text-hi"
            activeClass="bg-myth-bg-2 text-myth-text-hi"
          >
            {entry.label}
          </A>
        ))}
      </nav>
      <div class="border-t border-myth-line px-4 py-3">
        <div class="flex items-center gap-2">
          <span class="h-2 w-2 rounded-full bg-myth-ok" />
          <span class="font-mono text-xs uppercase tracking-wide text-myth-text-md">
            Shields: ON
          </span>
        </div>
        <div class="mt-1 font-mono text-[10px] text-myth-text-lo">
          Real toggle lands in Phase 4 (FR-160).
        </div>
      </div>
    </aside>
  );
};
