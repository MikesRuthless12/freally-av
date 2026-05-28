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

import { createContext, useContext, type JSX } from "solid-js";
import enUS from "./locales/en-US.ftl?raw";

type LocaleId = "en-US";

const KNOWN_LOCALES: Record<LocaleId, string> = {
  "en-US": enUS,
};

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
  locale: LocaleId;
  t: (id: string, fallback?: string, args?: Record<string, string | number>) => string;
}

const PARSED: Map<LocaleId, Map<string, string>> = new Map();
for (const id of Object.keys(KNOWN_LOCALES) as LocaleId[]) {
  PARSED.set(id, parseFtl(KNOWN_LOCALES[id]));
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
 * Provider that wraps the app. Today picks `en-US` unconditionally; the
 * locale-negotiation pass (future TASK) adds navigator.language matching.
 */
export function LocalizationProvider(props: { children: JSX.Element }): JSX.Element {
  const locale: LocaleId = "en-US";
  const bundle = PARSED.get(locale)!;
  const ctx: LocalizationCtx = {
    locale,
    t: (id, fallback, args) => lookup(bundle, id, fallback, args),
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
    locale: "en-US",
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
