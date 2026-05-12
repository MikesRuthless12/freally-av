// Tray store (TASK-158).
//
// Mirrors the Tauri-shell `TrayManager` state. Subscribes to the tray
// menu events emitted by `apps/mythodikal/src-tauri/src/tray.rs` so the
// frontend can drive scans / updates / shields toggles from the tray
// menu without any custom plumbing on each page.

import { createSignal, onCleanup } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { startScan } from "@/stores/scan";
import {
  updaterDbCheckNow,
  updaterEngineCheckNow,
} from "@/ipc/invoke";

export type TrayIconState =
  | "idle"
  | "scanning"
  | "shields_off"
  | "update_available";

export interface TrayStateView {
  icon: TrayIconState | string;
  tooltip: string;
}

const [state, setState] = createSignal<TrayStateView>({
  icon: "idle",
  tooltip: "Mythodikal Anti-Virus — idle",
});

export const trayState = state;

/** Sync the local cache with whatever the Tauri shell currently
 *  reports. Called at app mount and after any state-changing menu
 *  click. */
export async function refreshTrayState(): Promise<TrayStateView> {
  const v = await invoke<TrayStateView>("tray_get_state");
  setState(v);
  return v;
}

/** Push a "scanning" state into the tray. The scan store calls this on
 *  `scan:started` and clears it on terminal events. */
export async function setTrayScanning(scanning: boolean): Promise<void> {
  const v = await invoke<TrayStateView>("tray_set_scanning", { scanning });
  setState(v);
}

export async function setTrayUpdateAvailable(
  available: boolean,
): Promise<void> {
  const v = await invoke<TrayStateView>("tray_set_update_available", {
    available,
  });
  setState(v);
}

/** Wire the tray-menu event subscriptions for as long as the calling
 *  component is mounted. Mirrors the shape of `attachScanEvents`. */
export function attachTrayEvents(): void {
  const handles: Promise<UnlistenFn>[] = [];

  // Initial sync — without this the tray store renders `idle` until
  // the first menu click fires.
  void refreshTrayState();

  handles.push(
    listen("tray:quick_scan_requested", async () => {
      // Quick scan target = the user's home dir on Linux/Mac, the user
      // profile on Windows. Front-end has no permission to query env
      // vars; we let the user pick from the Scan page if they want
      // something else. The tray click only opens the page with a
      // pre-filled hint.
      const target =
        navigator.platform.startsWith("Win") ?
          "C:/Users" :
          "/home";
      try {
        await startScan({
          target_path: target,
          compute_sha256: true,
          follow_symlinks: false,
          emit_partial_hash: false,
        });
      } catch (err) {
        console.warn("tray quick_scan failed:", err);
      }
    }),
  );

  handles.push(
    listen("tray:check_app_requested", async () => {
      try {
        const available = await updaterEngineCheckNow();
        await setTrayUpdateAvailable(available !== null);
      } catch (err) {
        console.warn("tray check_app failed:", err);
      }
    }),
  );

  handles.push(
    listen("tray:check_db_requested", async () => {
      try {
        await updaterDbCheckNow();
      } catch (err) {
        console.warn("tray check_db failed:", err);
      }
    }),
  );

  onCleanup(() => {
    for (const h of handles) {
      void h.then((fn) => fn());
    }
  });
}
