// Shields store (TASK-156).
//
// Subscribes to `shields:changed` Tauri events and exposes a
// {state, setShields} pair used by the header badge + Settings →
// Real-time page.

import { createSignal, onCleanup } from "solid-js";
import type { UnlistenFn } from "@tauri-apps/api/event";
import { on } from "@/ipc/invoke";
import { invoke } from "@tauri-apps/api/core";

export interface ShieldsState {
  enabled: boolean;
  pause_until_utc: number | null;
}

const [state, setState] = createSignal<ShieldsState>({
  enabled: true,
  pause_until_utc: null,
});

export const shieldsState = state;

/** Read-once snapshot — fired on app mount + after every set. */
export async function refreshShields(): Promise<void> {
  const fresh = await invoke<ShieldsState>("shields_get");
  setState(fresh);
}

export async function setShields(
  enabled: boolean,
  pauseMinutes?: number,
): Promise<ShieldsState> {
  const next = await invoke<ShieldsState>("shields_set", {
    enabled,
    pauseMinutes,
  });
  // Update local state directly — the broadcast event will also fire,
  // but a no-op setState of the same shape is harmless (Solid uses
  // referential equality) and this path gives an instant render in case
  // the event is delayed by the Tauri bridge.
  setState(next);
  return next;
}

export function attachShieldsEvents(): void {
  void refreshShields();
  const handle = on<ShieldsState>("shields:changed", (payload) => {
    setState(payload);
  });
  onCleanup(() => {
    void handle.then((fn: UnlistenFn) => fn());
  });
}

/** Format the badge label. `nowMs` defaults to `Date.now()` but callers
 *  with a 1Hz wall-clock signal (e.g. ShieldsBadge) pass their own so
 *  the displayed minute count is reactive. */
export function shieldsStatusText(s: ShieldsState, nowMs: number = Date.now()): string {
  if (s.enabled) return "ON";
  if (s.pause_until_utc) {
    const remainingMs = s.pause_until_utc * 1000 - nowMs;
    if (remainingMs > 0) {
      const minutes = Math.ceil(remainingMs / 60_000);
      return `PAUSED · ${minutes} min`;
    }
  }
  return "OFF";
}
