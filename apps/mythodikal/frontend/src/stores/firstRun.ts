// First-run flag store (TASK-046).
//
// Persists a single boolean to localStorage so users see the welcome
// flow exactly once per profile. We use localStorage rather than the
// engine DB because the flag is purely a UI concern and survives even
// if the backend hasn't booted yet (e.g. an upgrade migration).
//
// Key is namespaced (`mythodikal.firstRunComplete`) so it doesn't
// collide with future per-user settings.

import { createSignal } from "solid-js";

const STORAGE_KEY = "mythodikal.firstRunComplete";

function read(): boolean {
  try {
    return localStorage.getItem(STORAGE_KEY) === "1";
  } catch {
    // Tauri webview without localStorage (rare); treat as first-run.
    return false;
  }
}

const [completed, setCompletedSignal] = createSignal<boolean>(read());

export const firstRunCompleted = completed;

export function markFirstRunComplete(): void {
  try {
    localStorage.setItem(STORAGE_KEY, "1");
  } catch {
    // Best-effort; the user will see first-run again next launch.
  }
  setCompletedSignal(true);
}

/** Used by the Settings → About page to let the user re-run onboarding
 *  for debugging or a fresh profile. Not surfaced anywhere in v0.4. */
export function resetFirstRun(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
  setCompletedSignal(false);
}
