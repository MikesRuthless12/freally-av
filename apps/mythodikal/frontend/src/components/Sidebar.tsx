// Sidebar (TASK-036; Shields wiring TASK-156).
//
// Left rail with the four main routes + the live Shields badge. The
// badge subscribes to the `shields:changed` Tauri event via the
// shields store (mounted in App.tsx) and offers Pause 15 min / Pause
// 1 h / Turn OFF / Turn ON as a small menu.

import type { Component } from "solid-js";
import { A } from "@solidjs/router";
import { ShieldsBadge } from "./ShieldsBadge";

const NAV: { path: string; label: string }[] = [
  { path: "/scan", label: "Scan" },
  { path: "/realtime", label: "Real-time" },
  { path: "/history", label: "History" },
  { path: "/quarantine", label: "Quarantine" },
  { path: "/usb-devices", label: "USB" },
  { path: "/exclusions", label: "Exclusions" },
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
      <nav class="flex flex-1 flex-col justify-evenly px-2 py-4">
        {NAV.map((entry) => (
          <A
            href={entry.path}
            class="block rounded-sm px-3 py-2.5 font-mono text-xs uppercase tracking-wide text-myth-text-md transition-colors hover:bg-myth-bg-2 hover:text-myth-text-hi"
            activeClass="!bg-myth-accent !text-white hover:!bg-myth-accent"
          >
            {entry.label}
          </A>
        ))}
      </nav>
      <div class="border-t border-myth-line px-4 py-3">
        <ShieldsBadge />
      </div>
    </aside>
  );
};
