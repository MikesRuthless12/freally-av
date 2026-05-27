// MacRealtimeHeartbeat (TASK-254, Phase 9 Wave 2).
//
// Per-second polling chip on top of the Real-time page. The daemon's
// launchd job writes `~/Library/Application Support/Mythodikal/heartbeat.json`
// every second; the Tauri command `mac_heartbeat` returns the parsed
// JSON plus a derived `age_ms`.
//
// Tinting:
//   * age ≤  5 s  → green  (--myth-ok)
//   * age 5–30 s → amber  (--myth-warn)
//   * age > 30 s → red    (--myth-bad)
//
// macOS-only — on other platforms the component renders nothing so
// the Real-time page stays clean.

import { Show, createSignal, onCleanup, onMount, type Component } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { platform as detectPlatform } from "@tauri-apps/plugin-os";

interface MacHeartbeat {
  last_beat_at_ms: number;
  pid: number;
  restart_count: number;
  age_ms: number;
}

const AMBER_THRESHOLD_MS = 5_000;
const RED_THRESHOLD_MS = 30_000;

async function fetchHeartbeat(): Promise<MacHeartbeat | null> {
  try {
    return await invoke<MacHeartbeat>("mac_heartbeat");
  } catch {
    return null;
  }
}

function tintClass(ageMs: number): string {
  if (ageMs <= AMBER_THRESHOLD_MS) return "bg-myth-ok";
  if (ageMs <= RED_THRESHOLD_MS) return "bg-myth-warn";
  return "bg-myth-bad";
}

function formatAge(ageMs: number): string {
  if (ageMs < 1_000) return "just now";
  if (ageMs < 60_000) return `${Math.floor(ageMs / 1000)}s ago`;
  return `${Math.floor(ageMs / 60_000)}m ago`;
}

// JS Date is bounded to ±8.64e15 ms from epoch — anything outside
// throws RangeError on toISOString(). Corrupt/hostile heartbeat.json
// values are realistic here, so we render an explicit fallback rather
// than letting the page error out (review CR-7, 2026-05-27).
function safeIsoString(ms: number): string {
  if (!Number.isFinite(ms) || Math.abs(ms) > 8.64e15) return "out of range";
  try {
    return new Date(ms).toISOString();
  } catch {
    return "out of range";
  }
}

export const MacRealtimeHeartbeat: Component = () => {
  const [hb, setHb] = createSignal<MacHeartbeat | null>(null);
  const [isMac, setIsMac] = createSignal(false);
  const [expanded, setExpanded] = createSignal(false);

  onMount(async () => {
    try {
      setIsMac((await detectPlatform()) === "macos");
    } catch {
      setIsMac(false);
    }
    if (!isMac()) return;
    // In-flight guard: drop overlapping polls so a slow fetch can't
    // resolve out of order and let an older heartbeat overwrite a
    // newer one (review CR-9, 2026-05-27).
    let inFlight = false;
    let disposed = false;
    const tick = async () => {
      if (inFlight || disposed) return;
      inFlight = true;
      try {
        const h = await fetchHeartbeat();
        if (!disposed) setHb(h);
      } finally {
        inFlight = false;
      }
    };
    await tick();
    const id = setInterval(() => void tick(), 1_000);
    onCleanup(() => {
      disposed = true;
      clearInterval(id);
    });
  });

  return (
    <Show when={isMac()}>
      <section class="rounded-md border border-myth-line bg-myth-bg-1 p-4">
        <button
          type="button"
          class="flex w-full items-center justify-between gap-3 text-left"
          onClick={() => setExpanded((v) => !v)}
        >
          <div class="flex items-center gap-3">
            <Show
              when={hb()}
              fallback={
                <span class="h-2 w-2 rounded-full bg-myth-text-lo" />
              }
            >
              <span class={`h-2 w-2 rounded-full ${tintClass(hb()!.age_ms)}`} />
            </Show>
            <div class="flex flex-col">
              <span class="font-mono text-sm text-myth-text-hi">
                <Show
                  when={hb()}
                  fallback={"Mythodikal real-time: heartbeat not started"}
                >
                  Mythodikal real-time is alive: last beat {formatAge(hb()!.age_ms)}
                </Show>
              </span>
              <span class="font-mono text-[10px] uppercase tracking-wide text-myth-text-lo">
                TASK-254 · launchd KeepAlive
              </span>
            </div>
          </div>
        </button>
        <Show when={expanded() && hb()}>
          <dl class="mt-3 grid grid-cols-2 gap-y-1 font-mono text-xs text-myth-text-md">
            <dt class="text-myth-text-lo">pid</dt>
            <dd>{hb()!.pid}</dd>
            <dt class="text-myth-text-lo">restart count</dt>
            <dd>{hb()!.restart_count}</dd>
            <dt class="text-myth-text-lo">last beat</dt>
            <dd>{safeIsoString(hb()!.last_beat_at_ms)}</dd>
            <dt class="text-myth-text-lo">age</dt>
            <dd>{hb()!.age_ms} ms</dd>
          </dl>
        </Show>
      </section>
    </Show>
  );
};

export default MacRealtimeHeartbeat;
