// TASK-Phase-7B — First-scan NSRL download preference.
//
// End users opt into the NSRL whitelist on first scan. The choice
// has three shapes:
//   * "skipped"       — User declined; scanner runs without the
//                       known-good fast-skip. Blacklist still active.
//   * "per_os_slice"  — Download just the OS slice that matches the
//                       client's platform (~1.7 GB). Wave 2 TASK-183
//                       per-OS bins are the underlying transport;
//                       Wave 1 ships only "full" until those bins
//                       land — the choice is *recorded* now so the
//                       downloader can act on it when ready.
//   * "full"          — Download the union bin (~3.4 GB).
//
// Persistence parallels [`@/stores/firstRun`]: localStorage for the
// fast read-back, and we expose a `setNsrlPreference` for the
// first-run wizard to call. A backend Tauri command for cross-
// WebView2-profile persistence is a follow-up; for v0.7.x the choice
// is fine to keep purely client-side because the *act* of downloading
// is itself idempotent (the backend updater can re-check whenever
// the user re-runs the wizard from Settings → About).

import { createSignal } from "solid-js";

export type NsrlPreference = "unset" | "skipped" | "per_os_slice" | "full";

const STORAGE_KEY = "freally.nsrlPreference";

function readLocal(): NsrlPreference {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw === "skipped" || raw === "per_os_slice" || raw === "full") {
      return raw;
    }
  } catch {
    // localStorage may be disabled (private mode); fall through.
  }
  return "unset";
}

const [pref, setPrefSignal] = createSignal<NsrlPreference>(readLocal());

export const nsrlPreference = pref;

export function setNsrlPreference(next: NsrlPreference): void {
  if (next === "unset") {
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {
      // ignore
    }
  } else {
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // ignore
    }
  }
  setPrefSignal(next);
}
