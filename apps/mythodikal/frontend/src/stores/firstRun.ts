// First-run flag store (TASK-046, wave-3 follow-up).
//
// Dual-layer persistence:
//   1. localStorage — fast, synchronous, survives Tauri Updater
//      restarts on the same profile.
//   2. `<data_dir>/first_run.json` via the backend `first_run_get` /
//      `first_run_set` Tauri commands — survives WebView2 profile
//      resets (the dev-mode rebuild quirk) AND survives a complete
//      uninstall+reinstall as long as the user data dir is left in
//      place.
//
// The store seeds itself from localStorage synchronously at module
// load (so the first paint has a sensible answer) and asynchronously
// reconciles with the backend file on App mount. Once either layer
// says "completed = true" the wizard is suppressed; writes go to both
// layers in parallel.

import { createSignal } from "solid-js";
import { firstRunGet, firstRunSet } from "@/ipc/invoke";

const STORAGE_KEY = "mythodikal.firstRunComplete";

function readLocal(): boolean {
  try {
    return localStorage.getItem(STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

const [completed, setCompletedSignal] = createSignal<boolean>(readLocal());

export const firstRunCompleted = completed;

/** Reconcile with the backend-persisted flag. Called once at App
 *  mount. If the backend file says "completed" but localStorage
 *  doesn't (e.g. fresh dev WebView2 profile), this flips the signal
 *  and writes the local cache so subsequent renders short-circuit. */
export async function reconcileFirstRunFlag(): Promise<void> {
  try {
    const backendCompleted = await firstRunGet();
    if (backendCompleted && !completed()) {
      try {
        localStorage.setItem(STORAGE_KEY, "1");
      } catch {
        // ignore
      }
      setCompletedSignal(true);
    }
  } catch {
    // Backend command may not be available in unusual contexts; the
    // localStorage signal already drives the UI in that case.
  }
}

export function markFirstRunComplete(): void {
  try {
    localStorage.setItem(STORAGE_KEY, "1");
  } catch {
    // ignore
  }
  setCompletedSignal(true);
  // Best-effort backend write so the flag survives WebView2 profile
  // resets in dev rebuilds. Errors are non-fatal — the localStorage
  // copy still satisfies the current session.
  void firstRunSet(true).catch(() => {});
}

/** Used by the Settings → About page to let the user re-run onboarding
 *  for debugging or a fresh profile. */
export function resetFirstRun(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
  setCompletedSignal(false);
  void firstRunSet(false).catch(() => {});
}
