// The React island entry: mounts the vendored, view-only CentralPanel into a
// Solid-owned container. No JSX here (createElement), so this stays a .ts file
// and never touches Solid's/React's JSX transform boundary. Opens external
// links via the Tauri opener, http(s)-guarded.
import { createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { CentralPanel } from "@freally/central-panel";
import type { PanelHost } from "@freally/central-panel";
import type { PanelT } from "./i18n-bridge";

const HOST: PanelHost = {
  // Freally AV registers no Tauri opener/shell plugin (and its capability
  // allowlist grants none), so opening an external browser URL is not available
  // here yet — this is a guarded no-op. When AV adds tauri-plugin-opener + an
  // `opener:allow-open-url` grant, swap this for `openUrl(url)`. The panel's
  // "Visit site" links therefore do nothing in AV; the rest of the showcase
  // (cards, real counts, in-panel changelog) is unaffected.
  openExternal: (_url: string) => {
    // No opener plugin available in AV — see note above.
  },
};

function element(t: PanelT, locale: string) {
  return createElement(CentralPanel, { t, locale, host: HOST, allowDownloads: false });
}

export function mountPanel(el: HTMLElement, t: PanelT, locale: string): Root {
  const root = createRoot(el);
  root.render(element(t, locale));
  return root;
}

export function renderPanel(root: Root, t: PanelT, locale: string): void {
  root.render(element(t, locale));
}
