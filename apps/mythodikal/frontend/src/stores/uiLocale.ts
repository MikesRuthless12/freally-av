// UI locale store (language-picker, Settings → General).
//
// Persists the user's chosen interface language so the picker survives
// reloads. Parallels [`@/stores/nsrlPreference`] and
// [`@/stores/firstRun`]: a localStorage-backed Solid signal seeded
// synchronously at module load (so the first paint reflects the saved
// choice) with an exported accessor + setter.
//
// The value is a BCP-47-ish locale code matching the `.ftl` files under
// `src/i18n/locales` (e.g. "en-US", "fr", "zh-CN"). The `LocalizationProvider`
// reads this signal to pick the active translation bundle; "en-US" is the
// guaranteed fallback.

import { createSignal } from "solid-js";

const STORAGE_KEY = "mythodikal_ui_locale";

const DEFAULT_LOCALE = "en-US";

function readLocal(): string {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return raw;
  } catch {
    // localStorage may be disabled (private mode); fall through.
  }
  return DEFAULT_LOCALE;
}

const [locale, setLocaleSignal] = createSignal<string>(readLocal());

/** Reactive accessor for the persisted UI locale code. */
export const uiLocale = locale;

/** Persist + apply a new UI locale code. */
export function setUiLocale(next: string): void {
  try {
    localStorage.setItem(STORAGE_KEY, next);
  } catch {
    // ignore — the in-memory signal still drives the current session.
  }
  setLocaleSignal(next);
}
