// USB write event log (TASK-249, Phase 8 Wave 2).
//
// Read-only audit trail of every write to a removable volume.
// Filterable by device serial; the daemon's ring-cap keeps the
// table bounded.

import { For, Show, createResource, createSignal, type Component } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

interface UsbWriteEvent {
  id: number | null;
  ts_utc: number;
  device_vid: string;
  device_pid: string;
  device_serial: string;
  pid: number | null;
  exe_path: string | null;
  target_path: string;
  bytes: number;
}

async function fetchEvents(serial: string): Promise<UsbWriteEvent[]> {
  if (!serial) return [];
  try {
    return await invoke<UsbWriteEvent[]>("usb_write_events", {
      serial,
      limit: 500,
    });
  } catch {
    return [];
  }
}

const UsbWrites: Component = () => {
  const [serial, setSerial] = createSignal("");
  const [events] = createResource(serial, fetchEvents);

  return (
    <div class="flex flex-col gap-4 p-6">
      <header>
        <h1 class="font-display text-2xl text-myth-text-hi">USB writes</h1>
        <p class="font-mono text-xs uppercase tracking-wide text-myth-text-lo">
          TASK-249 · audit trail · 100K-row ring buffer · 0 enforcement
        </p>
      </header>

      <label class="flex items-end gap-2">
        <div class="flex flex-col gap-1">
          <span class="font-mono text-[10px] uppercase tracking-wide text-myth-text-lo">
            Device serial
          </span>
          <input
            class="rounded-sm border border-myth-line bg-myth-bg-2 px-2 py-1 font-mono text-xs text-myth-text-hi"
            value={serial()}
            onInput={(e) => setSerial(e.currentTarget.value)}
            placeholder="AABB001122"
          />
        </div>
      </label>

      <Show
        when={events() && events()!.length > 0}
        fallback={
          <p class="font-mono text-xs text-myth-text-lo">
            Enter a serial to see its write events.
          </p>
        }
      >
        <table class="w-full font-mono text-xs">
          <thead>
            <tr class="border-b border-myth-line text-left text-myth-text-lo">
              <th class="py-2">Time</th>
              <th class="py-2">Process</th>
              <th class="py-2">Target</th>
              <th class="py-2 text-right">Bytes</th>
            </tr>
          </thead>
          <tbody>
            <For each={events()!}>
              {(row) => (
                <tr class="border-b border-myth-line/30">
                  <td class="py-2 text-myth-text-md">
                    {new Date(row.ts_utc * 1000).toLocaleString()}
                  </td>
                  <td class="py-2 text-myth-text-hi">
                    {row.exe_path ?? `pid ${row.pid ?? "?"}`}
                  </td>
                  <td class="py-2 text-myth-text-md">{row.target_path}</td>
                  <td class="py-2 text-right text-myth-text-hi">
                    {row.bytes.toLocaleString()}
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

export default UsbWrites;
