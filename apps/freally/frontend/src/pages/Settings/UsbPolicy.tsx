// USB policy settings (TASK-245, Phase 8 Wave 2).
//
// Global "auto-mount unknown USB read-only" toggle + per-port
// power-only (TASK-244) management. Per-device "allow read-write"
// per-device switch is in the per-device drill-down on UsbDevices.

import { For, Show, createResource, createSignal, type Component } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

interface PowerOnlyEntry {
  port_path: string;
  label: string;
  enabled: boolean;
}

async function fetchPowerOnly(): Promise<PowerOnlyEntry[]> {
  try {
    return await invoke<PowerOnlyEntry[]>("usb_power_only_list");
  } catch {
    return [];
  }
}

const UsbPolicy: Component = () => {
  const [autoRo, setAutoRo] = createSignal(true);
  const [items, { refetch }] = createResource(fetchPowerOnly);
  const [newPort, setNewPort] = createSignal("");
  const [newLabel, setNewLabel] = createSignal("");

  const enable = async () => {
    if (!newPort()) return;
    await invoke("usb_power_only_enable", {
      portPath: newPort(),
      label: newLabel(),
    });
    setNewPort("");
    setNewLabel("");
    await refetch();
  };

  const disable = async (port: string) => {
    await invoke("usb_power_only_disable", { portPath: port });
    await refetch();
  };

  return (
    <div class="flex flex-col gap-6 p-6">
      <header>
        <h1 class="font-display text-2xl text-myth-text-hi">USB policy</h1>
        <p class="font-mono text-xs uppercase tracking-wide text-myth-text-lo">
          TASK-244 / TASK-245 · Phase 8 Wave 2
        </p>
      </header>

      <section class="rounded-md border border-myth-line bg-myth-bg-1 p-4">
        <h2 class="font-display text-lg text-myth-text-hi">
          Read-only auto-mount
        </h2>
        <p class="mt-1 font-mono text-xs text-myth-text-md">
          Unknown USB volumes mount read-only on Linux / macOS. Windows
          surfaces a hint card pointing to Group Policy — never
          auto-applied per § 1.5.4.
        </p>
        <label class="mt-3 flex items-center gap-2 font-mono text-sm">
          <input
            type="checkbox"
            checked={autoRo()}
            onChange={(e) => setAutoRo(e.currentTarget.checked)}
          />
          <span class="text-myth-text-hi">
            Auto-mount unknown USB read-only
          </span>
        </label>
      </section>

      <section class="rounded-md border border-myth-line bg-myth-bg-1 p-4">
        <h2 class="font-display text-lg text-myth-text-hi">
          Power-only USB ports
        </h2>
        <p class="mt-1 font-mono text-xs text-myth-text-md">
          Flag a USB port so storage interfaces unbind on connect. The
          device keeps drawing power. Cosmetic — does NOT physically
          limit current.
        </p>

        <div class="mt-3 flex items-end gap-2">
          <label class="flex flex-col gap-1">
            <span class="font-mono text-[10px] uppercase tracking-wide text-myth-text-lo">
              Port path
            </span>
            <input
              class="rounded-sm border border-myth-line bg-myth-bg-2 px-2 py-1 font-mono text-xs text-myth-text-hi"
              value={newPort()}
              onInput={(e) => setNewPort(e.currentTarget.value)}
              placeholder="1-3.2 or USB\VID_0951..."
            />
          </label>
          <label class="flex flex-col gap-1">
            <span class="font-mono text-[10px] uppercase tracking-wide text-myth-text-lo">
              Label
            </span>
            <input
              class="rounded-sm border border-myth-line bg-myth-bg-2 px-2 py-1 font-mono text-xs text-myth-text-hi"
              value={newLabel()}
              onInput={(e) => setNewLabel(e.currentTarget.value)}
              placeholder="front-left port"
            />
          </label>
          <button
            type="button"
            class="rounded-sm bg-myth-accent px-3 py-1 font-mono text-xs uppercase tracking-wide text-white"
            onClick={() => void enable()}
          >
            Add
          </button>
        </div>

        <Show
          when={items() && items()!.length > 0}
          fallback={
            <p class="mt-3 font-mono text-xs text-myth-text-lo">
              No power-only ports configured.
            </p>
          }
        >
          <table class="mt-3 w-full font-mono text-xs">
            <thead>
              <tr class="border-b border-myth-line text-left text-myth-text-lo">
                <th class="py-2">Port</th>
                <th class="py-2">Label</th>
                <th class="py-2">Enabled</th>
                <th class="py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              <For each={items()!}>
                {(row) => (
                  <tr class="border-b border-myth-line/30">
                    <td class="py-2 text-myth-text-hi">{row.port_path}</td>
                    <td class="py-2 text-myth-text-md">{row.label}</td>
                    <td
                      class={`py-2 ${
                        row.enabled ? "text-myth-ok" : "text-myth-text-md"
                      }`}
                    >
                      {row.enabled ? "ON" : "off"}
                    </td>
                    <td class="py-2 text-right">
                      <button
                        type="button"
                        class="rounded-sm border border-myth-line px-2 py-1 uppercase tracking-wide text-myth-bad hover:bg-myth-bg-2"
                        onClick={() => void disable(row.port_path)}
                      >
                        Disable
                      </button>
                    </td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </Show>
      </section>
    </div>
  );
};

export default UsbPolicy;
