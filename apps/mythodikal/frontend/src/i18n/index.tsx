// Mythodikal Anti-Virus — localisation scaffolding (TASK-089).
//
// Solid.js context + `useLocalization()` hook. Loads the seed
// `en-US.ftl` at module init and exposes `t(id, fallback?, args?)` for
// components to call. The implementation is deliberately tiny so it
// adds **zero npm dependencies** — Fluent's full machinery (plural
// rules, term references, BiDi isolates) is overkill for the v0.10
// release and would require pinning @fluent/bundle + langneg + a
// CLDR data file.
//
// **Supported FTL subset.** This scaffolding deliberately parses only
// single-line `id = value` declarations with `{ $arg }` interpolation.
// Plural selector blocks (`{ $count -> [one] … *[other] … }`) are NOT
// parsed — the original code-review build had a regex+indent bug that
// silently dropped them, and shipping a half-working selector is worse
// than shipping none. Plurals are expressed today as separate keys
// (e.g. `scan-findings-summary-zero`, `-one`, `-other`); the caller
// picks the right key. The full Fluent selector grammar arrives when
// we adopt `@fluent/bundle` post-v0.10.
//
// Migration pattern for component authors:
//
// ```tsx
// const { t } = useLocalization();
// return <button>{t("button-scan-now", "Scan now")}</button>;
// ```
//
// `fallback` is the inline English copy that ships in the component
// today. It's surfaced so a missing-translation review only requires
// reading the component, not cross-referencing the .ftl file.

import { createContext, useContext, type Accessor, type JSX } from "solid-js";
import enUS from "./locales/en-US.ftl?raw";
import { setUiLocale, uiLocale } from "@/stores/uiLocale";

// The 18 canonical locales shipped under `./locales/*.ftl`. The picker in
// Settings → General switches between these; "en-US" is the guaranteed
// fallback (also imported statically below so it's always present even if
// the glob ever misses it).
export type LocaleId =
  | "en-US"
  | "ar"
  | "de"
  | "es"
  | "fr"
  | "hi"
  | "id"
  | "it"
  | "ja"
  | "ko"
  | "nl"
  | "pl"
  | "pt-BR"
  | "ru"
  | "tr"
  | "uk"
  | "vi"
  | "zh-CN";

// Eagerly load every locale file as raw text. Keys look like
// `./locales/fr.ftl`; we strip the prefix/suffix to recover the code.
const RAW_LOCALES = import.meta.glob("./locales/*.ftl", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

const KNOWN_LOCALES: Partial<Record<LocaleId, string>> = { "en-US": enUS };
for (const [path, source] of Object.entries(RAW_LOCALES)) {
  const code = path.replace(/^\.\/locales\//, "").replace(/\.ftl$/, "");
  KNOWN_LOCALES[code as LocaleId] = source;
}

/**
 * Parse a Fluent file's `id = value` lines into a flat map. Lines that
 * don't match the simple shape (comments, blank lines, selector blocks,
 * multi-line continuations) are skipped — selectors are explicitly out
 * of scope in this scaffolding pass (see file header).
 */
function parseFtl(source: string): Map<string, string> {
  const entries = new Map<string, string>();
  for (const rawLine of source.split("\n")) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) continue;
    const match = line.match(/^([a-z][a-z0-9-]*)\s*=\s*(.*)$/i);
    if (!match) continue;
    const id = match[1];
    const value = match[2];
    if (id === undefined || value === undefined) continue;
    // Skip selector openings (`= { $arg ->`) — we can't render them
    // without the full selector parser, and falling through with the
    // raw `{ $arg ->` would render that string literally to the user.
    if (value.trimStart().startsWith("{") && value.includes("->")) continue;
    entries.set(id, value);
  }
  return entries;
}

function interpolate(template: string, args?: Record<string, string | number>): string {
  if (!args) return template;
  return template.replace(/\{\s*\$(\w+)\s*\}/g, (_, name: string) => {
    const value = args[name];
    return value === undefined ? `{$${name}}` : String(value);
  });
}

interface LocalizationCtx {
  /** Reactive accessor for the active locale code. */
  locale: Accessor<LocaleId>;
  /** Persist + switch the active locale. */
  setLocale: (code: LocaleId) => void;
  t: (id: string, fallback?: string, args?: Record<string, string | number>) => string;
}

const PARSED: Map<LocaleId, Map<string, string>> = new Map();
for (const id of Object.keys(KNOWN_LOCALES) as LocaleId[]) {
  const source = KNOWN_LOCALES[id];
  if (source !== undefined) PARSED.set(id, parseFtl(source));
}

const Context = createContext<LocalizationCtx | undefined>(undefined);

function lookup(
  bundle: Map<string, string>,
  id: string,
  fallback: string | undefined,
  args: Record<string, string | number> | undefined,
): string {
  const value = bundle.get(id);
  if (value !== undefined) return interpolate(value, args);
  if (fallback !== undefined) return interpolate(fallback, args);
  return id;
}

/**
 * Provider that wraps the app. Reads the persisted UI-locale signal
 * (`@/stores/uiLocale`) so the Settings → General language picker can
 * switch languages reactively. Falls back to `en-US` when the stored
 * code isn't one of the bundled locales.
 *
 * NOTE: only components that call `t()` re-render on a locale change.
 * Wiring `t()` into the rest of the UI is a separate phase, so today the
 * picker persists + flips the active locale without visibly retranslating.
 */
export function LocalizationProvider(props: { children: JSX.Element }): JSX.Element {
  const locale: Accessor<LocaleId> = () => {
    const code = uiLocale();
    return PARSED.has(code as LocaleId) ? (code as LocaleId) : "en-US";
  };
  const ctx: LocalizationCtx = {
    locale,
    setLocale: (code) => setUiLocale(code),
    t: (id, fallback, args) =>
      lookup(PARSED.get(locale()) ?? PARSED.get("en-US")!, id, fallback, args),
  };
  return <Context.Provider value={ctx}>{props.children}</Context.Provider>;
}

/**
 * Hook for components. Returns `{ locale, t }`.
 *
 * Outside a provider — for example a unit test importing a leaf
 * component — `t(id, fallback)` falls back to the inline English copy
 * so the component still renders.
 */
export function useLocalization(): LocalizationCtx {
  const ctx = useContext(Context);
  if (ctx) return ctx;
  const bundle = PARSED.get("en-US")!;
  return {
    locale: () => "en-US",
    setLocale: () => {},
    t: (id, fallback, args) => lookup(bundle, id, fallback, args),
  };
}

// Re-export for ad-hoc lookups outside a Solid component (engine event
// handlers, etc.).
export function translate(
  id: string,
  fallback?: string,
  args?: Record<string, string | number>,
): string {
  const bundle = PARSED.get("en-US")!;
  return lookup(bundle, id, fallback, args);
}
