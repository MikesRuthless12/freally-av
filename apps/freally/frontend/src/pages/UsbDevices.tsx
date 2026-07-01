// Per-device USB scan history (TASK-250, Phase 8 Wave 2).
//
// "Kingston DT100 G3 — seen 14 times, last verdict: clean 2026-05-19"

import { For, Show, createResource, type Component } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

interface DeviceRow {
  vid: string;
  pid: string;
  serial: string;
  first_seen_utc: number;
  last_seen_utc: number;
  scan_count: number;
  last_verdict: string;
}

async function fetchDevices(): Promise<DeviceRow[]> {
  try {
    return await invoke<DeviceRow[]>("usb_devices");
  } catch {
    return [];
  }
}

const verdictTone = (v: string): string => {
  if (v === "clean") return "text-myth-ok";
  if (v === "detected") return "text-myth-bad";
  return "text-myth-text-md";
};

const UsbDevices: Component = () => {
  const [devices] = createResource(fetchDevices);

  return (
    <div class="flex flex-col gap-4 p-6">
      <header>
        <h1 class="font-display text-2xl text-myth-text-hi">USB devices</h1>
        <p class="font-mono text-xs uppercase tracking-wide text-myth-text-lo">
          TASK-250 · per-device scan history · BLAKE3 quick-hash short-circuit
        </p>
      </header>

      <Show
        when={devices() && devices()!.length > 0}
        fallback={
          <p class="font-mono text-xs text-myth-text-lo">
            No USB devices have been seen yet.
          </p>
        }
      >
        <table class="w-full font-mono text-xs">
          <thead>
            <tr class="border-b border-myth-line text-left text-myth-text-lo">
              <th class="py-2">Device</th>
              <th class="py-2">First seen</th>
              <th class="py-2">Last seen</th>
              <th class="py-2 text-right">Scans</th>
              <th class="py-2 text-right">Last verdict</th>
            </tr>
          </thead>
          <tbody>
            <For each={devices()!}>
              {(d) => (
                <tr class="border-b border-myth-line/30">
                  <td class="py-2 text-myth-text-hi">
                    {d.vid}:{d.pid} · {d.serial}
                  </td>
                  <td class="py-2 text-myth-text-md">
                    {new Date(d.first_seen_utc * 1000).toLocaleDateString()}
                  </td>
                  <td class="py-2 text-myth-text-md">
                    {new Date(d.last_seen_utc * 1000).toLocaleString()}
                  </td>
                  <td class="py-2 text-right text-myth-text-hi">
                    {d.scan_count}
                  </td>
                  <td class={`py-2 text-right ${verdictTone(d.last_verdict)}`}>
                    {d.last_verdict || "(none)"}
                  </td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </Show>
    </div>
  );
};

export default UsbDevices;
