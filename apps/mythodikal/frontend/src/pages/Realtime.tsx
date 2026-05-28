// Real-time (TASK-075 + TASK-238 + TASK-240 Wave 2 + TASK-082/254 Wave 3).
//
// Sections:
//
//   1. Shields master switch — mirrors the sidebar `ShieldsBadge`
//      (FR-160).
//   2. macOS heartbeat chip (TASK-254) — green/amber/red liveness for
//      the launchd-managed daemon. Hidden off macOS.
//   3. macOS surface mode (TASK-082) — FSEvents observe / ESF notify.
//      No "ESF AUTH" string anywhere — AUTH does not exist on macOS
//      per § 1.5.4. Hidden off macOS.
//   4. Monitored mounts (TASK-238) — per-mountpoint on/off switch.
//      Daemon picks up the toggle on its next 5 s polling tick of
//      `daemon/mythd-linux/src/mounts.rs::diff`.
//   5. WSL distros (TASK-240) — only populated when running on Windows
//      with `wsl.exe` present; otherwise silently hidden.

import { For, Show, createResource, createSignal, onMount, type Component } from "solid-js";
import { A } from "@solidjs/router";
import { invoke } from "@tauri-apps/api/core";
import { setShields, shieldsState, shieldsStatusText } from "@/stores/shields";
import { MacRealtimeHeartbeat } from "@/components/MacRealtimeHeartbeat";

interface MountToggleRow {
  device: string;
  mountpoint: string;
  fs_type: string;
  enabled: boolean;
}

interface MacRealtimeMode {
  /// Either "fsevents (observe)" or "fsevents+esf (observe)" — there
  /// is no AUTH mode by design (§ 1.5.4).
  mode: string;
  esf_active: boolean;
  esf_unavailable_reason: string | null;
}

async function fetchMacMode(): Promise<MacRealtimeMode | null> {
  try {
    return await invoke<MacRealtimeMode>("mac_realtime_mode");
  } catch {
    return null;
  }
}

interface WslDistroRow {
  name: string;
  state: string;
  version: number;
}

async function fetchMounts(): Promise<MountToggleRow[]> {
  try {
    return await invoke<MountToggleRow[]>("realtime_mounts_list");
  } catch {
    return [];
  }
}

async function fetchWslDistros(): Promise<WslDistroRow[]> {
  try {
    return await invoke<WslDistroRow[]>("wsl_list_distros");
  } catch {
    return [];
  }
}

const Realtime: Component = () => {
  const [mounts, { refetch: refetchMounts }] = createResource(fetchMounts);
  const [distros] = createResource(fetchWslDistros);
  const [pendingMp, setPendingMp] = createSignal<string | null>(null);
  const [macMode, setMacMode] = createSignal<MacRealtimeMode | null>(null);
  const [isMac, setIsMac] = createSignal(false);

  onMount(async () => {
    try {
      setIsMac((await invoke<string>("host_os")) === "macos");
    } catch {
      setIsMac(false);
    }
    if (isMac()) {
      setMacMode(await fetchMacMode());
    }
  });

  const toggleMount = async (row: MountToggleRow) => {
    setPendingMp(row.mountpoint);
    try {
      await invoke("set_mount_enabled", {
        device: row.device,
        mountpoint: row.mountpoint,
        fsType: row.fs_type,
        enabled: !row.enabled,
      });
      await refetchMounts();
    } finally {
      setPendingMp(null);
    }
  };

  return (
    <div class="flex flex-col gap-6 p-6">
      <header>
        <h1 class="font-display text-2xl text-myth-text-hi">Real-time</h1>
        <p class="font-mono text-xs uppercase tracking-wide text-myth-text-lo">
          Linux fanotify daemon · TASK-075 · Phase 8
        </p>
      </header>

      <section class="rounded-md border border-myth-line bg-myth-bg-1 p-4">
        <h2 class="font-display text-lg text-myth-text-hi">Shields</h2>
        <p class="mt-1 font-mono text-xs text-myth-text-md">
          Master switch — honored by every platform daemon (FR-160).
        </p>
        <div class="mt-3 flex items-center gap-3">
          <span
            class={`h-2 w-2 rounded-full ${
              shieldsState().enabled ? "bg-myth-ok" : "bg-myth-bad"
            }`}
          />
          <span class="font-mono text-sm text-myth-text-hi">
            {shieldsStatusText(shieldsState())}
          </span>
          <Show when={shieldsState().enabled}>
            <button
              type="button"
              class="rounded-sm border border-myth-line px-2 py-1 font-mono text-xs uppercase tracking-wide hover:bg-myth-bg-2"
              onClick={() => void setShields(false, 60)}
            >
              Pause 1 h
            </button>
            <button
              type="button"
              class="rounded-sm border border-myth-line px-2 py-1 font-mono text-xs uppercase tracking-wide text-myth-bad hover:bg-myth-bg-2"
              onClick={() => void setShields(false)}
            >
              Turn OFF
            </button>
          </Show>
          <Show when={!shieldsState().enabled}>
            <button
              type="button"
              class="rounded-sm border border-myth-line px-2 py-1 font-mono text-xs uppercase tracking-wide text-myth-ok hover:bg-myth-bg-2"
              onClick={() => void setShields(true)}
            >
              Turn ON
            </button>
          </Show>
        </div>
      </section>

      <Show when={isMac()}>
        <MacRealtimeHeartbeat />
      </Show>

      <Show when={isMac() && macMode()}>
        <section class="rounded-md border border-myth-line bg-myth-bg-1 p-4">
          <h2 class="font-display text-lg text-myth-text-hi">macOS surface</h2>
          <p class="mt-1 font-mono text-xs text-myth-text-md">
            NOTIFY-only · TASK-082 · § 1.5.4
          </p>
          <dl class="mt-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 font-mono text-xs">
            <dt class="text-myth-text-lo">mode</dt>
            <dd class="text-myth-text-hi">{macMode()!.mode}</dd>
            <dt class="text-myth-text-lo">esf</dt>
            <dd
              class={
                macMode()!.esf_active ? "text-myth-ok" : "text-myth-text-md"
              }
            >
              {macMode()!.esf_active ? "active" : "unavailable"}
              <Show when={macMode()!.esf_unavailable_reason}>
                {" · "}
                <span class="text-myth-text-lo">
                  {macMode()!.esf_unavailable_reason}
                </span>
              </Show>
            </dd>
          </dl>
          <p class="mt-3 font-mono text-xs text-myth-text-md">
            <A
              href="/settings/mac-exemptions"
              class="underline decoration-myth-line underline-offset-2 hover:decoration-myth-text-hi hover:text-myth-text-hi"
            >
              Manage per-app exemptions (Touch-ID required) →
            </A>
          </p>
        </section>
      </Show>

      <section class="rounded-md border border-myth-line bg-myth-bg-1 p-4">
        <h2 class="font-display text-lg text-myth-text-hi">Monitored mounts</h2>
        <p class="mt-1 font-mono text-xs text-myth-text-md">
          Per-mountpoint real-time toggle · TASK-238 · daemon picks up
          changes within 5 s without a restart.
        </p>
        <Show
          when={mounts() && mounts()!.length > 0}
          fallback={
            <p class="mt-3 font-mono text-xs text-myth-text-lo">
              No mount preferences saved yet. Run the daemon to populate
              the list, or toggle rootfs on from the CLI.
            </p>
          }
        >
          <table class="mt-3 w-full font-mono text-xs">
            <thead>
              <tr class="border-b border-myth-line text-left text-myth-text-lo">
                <th class="py-2">Mountpoint</th>
                <th class="py-2">Filesystem</th>
                <th class="py-2">Device</th>
                <th class="py-2 text-right">Enabled</th>
              </tr>
            </thead>
            <tbody>
              <For each={mounts()!}>
                {(row) => (
                  <tr class="border-b border-myth-line/30">
                    <td class="py-2 text-myth-text-hi">{row.mountpoint}</td>
                    <td class="py-2 text-myth-text-md">{row.fs_type}</td>
                    <td class="py-2 text-myth-text-md">{row.device}</td>
                    <td class="py-2 text-right">
                      <button
                        type="button"
                        class={`rounded-sm border border-myth-line px-2 py-1 uppercase tracking-wide ${
                          row.enabled ? "text-myth-ok" : "text-myth-text-md"
                        } hover:bg-myth-bg-2 disabled:opacity-50`}
                        disabled={pendingMp() === row.mountpoint}
                        onClick={() => void toggleMount(row)}
                      >
                        {row.enabled ? "ON" : "OFF"}
                      </button>
                    </td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </Show>
      </section>

      <Show when={distros() && distros()!.length > 0}>
        <section class="rounded-md border border-myth-line bg-myth-bg-1 p-4">
          <h2 class="font-display text-lg text-myth-text-hi">WSL distros</h2>
          <p class="mt-1 font-mono text-xs text-myth-text-md">
            Cross-host real-time · TASK-240 · install a Mythodikal-Linux
            companion inside each distro to aggregate findings.
          </p>
          <ul class="mt-3 space-y-2 font-mono text-sm">
            <For each={distros()!}>
              {(d) => (
                <li class="flex items-center justify-between border-b border-myth-line/30 pb-2">
                  <span class="text-myth-text-hi">{d.name}</span>
                  <span class="font-mono text-xs uppercase tracking-wide text-myth-text-md">
                    {d.state} · v{d.version}
                  </span>
                </li>
              )}
            </For>
          </ul>
        </section>
      </Show>
    </div>
  );
};

export default Realtime;
