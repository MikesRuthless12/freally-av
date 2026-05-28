// USB allowlist settings page (TASK-242, Phase 8 Wave 2).
//
// VID:PID:Serial allowlist. Serial supports a single `*` wildcard
// so an operator can allow "every Kingston DT100 G3" with one row.

import { For, Show, createResource, createSignal, type Component } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

interface UsbAllowEntry {
  vid: string;
  pid: string;
  serial: string;
  label: string;
  added_at_utc: number;
}

async function fetchList(): Promise<UsbAllowEntry[]> {
  try {
    return await invoke<UsbAllowEntry[]>("usb_allowlist_list");
  } catch {
    return [];
  }
}

const UsbAllowlist: Component = () => {
  const [items, { refetch }] = createResource(fetchList);
  const [vid, setVid] = createSignal("");
  const [pid, setPid] = createSignal("");
  const [serial, setSerial] = createSignal("");
  const [label, setLabel] = createSignal("");
  const [busy, setBusy] = createSignal(false);

  const add = async (e: SubmitEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await invoke("usb_allowlist_add", {
        req: {
          vid: vid().trim().toLowerCase(),
          pid: pid().trim().toLowerCase(),
          serial: serial().trim() || "*",
          label: label().trim(),
        },
      });
      setVid("");
      setPid("");
      setSerial("");
      setLabel("");
      await refetch();
    } finally {
      setBusy(false);
    }
  };

  const remove = async (e: UsbAllowEntry) => {
    await invoke("usb_allowlist_remove", {
      vid: e.vid,
      pid: e.pid,
      serial: e.serial,
    });
    await refetch();
  };

  return (
    <div class="flex flex-col gap-6 p-6">
      <header>
        <h1 class="font-display text-2xl text-myth-text-hi">USB allowlist</h1>
        <p class="font-mono text-xs uppercase tracking-wide text-myth-text-lo">
          TASK-242 · Phase 8 Wave 2 · VID:PID:Serial
        </p>
      </header>

      <form
        class="grid grid-cols-[6rem_6rem_1fr_1fr_auto] items-end gap-2 rounded-md border border-myth-line bg-myth-bg-1 p-3"
        onSubmit={add}
      >
        <label class="flex flex-col gap-1">
          <span class="font-mono text-[10px] uppercase tracking-wide text-myth-text-lo">
            VID (hex)
          </span>
          <input
            class="rounded-sm border border-myth-line bg-myth-bg-2 px-2 py-1 font-mono text-xs text-myth-text-hi"
            value={vid()}
            onInput={(e) => setVid(e.currentTarget.value)}
            required
            pattern="[0-9a-fA-F]{4}"
            placeholder="0951"
          />
        </label>
        <label class="flex flex-col gap-1">
          <span class="font-mono text-[10px] uppercase tracking-wide text-myth-text-lo">
            PID (hex)
          </span>
          <input
            class="rounded-sm border border-myth-line bg-myth-bg-2 px-2 py-1 font-mono text-xs text-myth-text-hi"
            value={pid()}
            onInput={(e) => setPid(e.currentTarget.value)}
            required
            pattern="[0-9a-fA-F]{4}"
            placeholder="1665"
          />
        </label>
        <label class="flex flex-col gap-1">
          <span class="font-mono text-[10px] uppercase tracking-wide text-myth-text-lo">
            Serial (or * for any)
          </span>
          <input
            class="rounded-sm border border-myth-line bg-myth-bg-2 px-2 py-1 font-mono text-xs text-myth-text-hi"
            value={serial()}
            onInput={(e) => setSerial(e.currentTarget.value)}
            placeholder="*"
          />
        </label>
        <label class="flex flex-col gap-1">
          <span class="font-mono text-[10px] uppercase tracking-wide text-myth-text-lo">
            Label
          </span>
          <input
            class="rounded-sm border border-myth-line bg-myth-bg-2 px-2 py-1 font-mono text-xs text-myth-text-hi"
            value={label()}
            onInput={(e) => setLabel(e.currentTarget.value)}
            placeholder="Kingston DT100 G3"
          />
        </label>
        <button
          type="submit"
          disabled={busy()}
          class="rounded-sm bg-myth-accent px-3 py-1 font-mono text-xs uppercase tracking-wide text-white disabled:opacity-50"
        >
          Add
        </button>
      </form>

      <Show
        when={items() && items()!.length > 0}
        fallback={
          <p class="font-mono text-xs text-myth-text-lo">
            No devices allowlisted yet.
          </p>
        }
      >
        <table class="w-full font-mono text-xs">
          <thead>
            <tr class="border-b border-myth-line text-left text-myth-text-lo">
              <th class="py-2">VID:PID</th>
              <th class="py-2">Serial</th>
              <th class="py-2">Label</th>
              <th class="py-2 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            <For each={items()!}>
              {(row) => (
                <tr class="border-b border-myth-line/30">
                  <td class="py-2 text-myth-text-hi">
                    {row.vid}:{row.pid}
                  </td>
                  <td class="py-2 text-myth-text-md">{row.serial}</td>
                  <td class="py-2 text-myth-text-md">{row.label}</td>
                  <td class="py-2 text-right">
                    <button
                      type="button"
                      class="rounded-sm border border-myth-line px-2 py-1 uppercase tracking-wide text-myth-bad hover:bg-myth-bg-2"
                      onClick={() => void remove(row)}
                    >
                      Remove
                    </button>
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

export default UsbAllowlist;
