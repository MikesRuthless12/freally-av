// i18n bridge for the vendored Central panel. Freally AV's own i18n is a custom
// single-line .ftl parser with a 3-arg t(id, fallback?, args?) that can't
// resolve the panel's fcp-* keys (nor its Fluent plural selectors). So the
// panel gets its OWN Fluent runtime here: real @fluent/bundle parsing over the
// vendored fcp-* catalogs (18 locales), keyed to AV's active locale. The panel
// never localizes through AV's t — only through this.
import { FluentBundle, FluentResource } from "@fluent/bundle";

const FCP_FILES = import.meta.glob<string>(
  "../../../../../vendor/freally-central/ui/src/panel/locales/*.ftl",
  { query: "?raw", import: "default", eager: true },
);

const BUNDLES = new Map<string, FluentBundle>();
for (const [path, src] of Object.entries(FCP_FILES)) {
  const code = path.match(/locales\/([^/]+)\.ftl$/)?.[1];
  if (!code) continue;
  const bundle = new FluentBundle(code, { useIsolating: false });
  bundle.addResource(new FluentResource(src));
  BUNDLES.set(code, bundle);
}

// AV ships "en-US"; the panel's catalog is "en". Other 17 codes match 1:1.
function panelCode(avLocale: string): string {
  return avLocale === "en-US" ? "en" : avLocale;
}

export type PanelT = (key: string, args?: Record<string, string | number>) => string;

/** A Fluent-backed t() for the panel, for AV's current locale (English underneath). */
export function fcpTranslate(avLocale: string): PanelT {
  const primary = BUNDLES.get(panelCode(avLocale));
  const en = BUNDLES.get("en");
  return (key, args) => {
    for (const bundle of [primary, en]) {
      const msg = bundle?.getMessage(key);
      if (msg?.value) {
        const errs: Error[] = [];
        const out = bundle!.formatPattern(msg.value, args, errs);
        if (errs.length === 0) return out;
      }
    }
    return key;
  };
}
