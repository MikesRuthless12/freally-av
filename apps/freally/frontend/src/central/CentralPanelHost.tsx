// Solid host for the "More Freally apps" React panel. Solid owns the container
// + lifecycle; React owns the panel subtree (mounted via ./mount). The panel is
// localized through the Fluent bridge keyed to AV's active locale, and
// re-rendered when that locale changes.
import { createEffect, onCleanup, onMount, type Component } from "solid-js";
import type { Root } from "react-dom/client";
import { useLocalization } from "@/i18n";
import { fcpTranslate } from "./i18n-bridge";

const CentralPanelHost: Component = () => {
  let el!: HTMLDivElement;
  let root: Root | null = null;
  // Lazily imported so React + the vendored panel are a separate async chunk,
  // loaded only when this host mounts (i.e. the dialog first opens).
  let island: typeof import("./mount") | null = null;
  const { locale } = useLocalization();

  onMount(async () => {
    island = await import("./mount");
    root = island.mountPanel(el, fcpTranslate(locale()), locale());
  });

  // Re-render the React tree when AV's locale changes.
  createEffect(() => {
    const l = locale();
    if (root && island) island.renderPanel(root, fcpTranslate(l), l);
  });

  onCleanup(() => {
    root?.unmount();
    root = null;
  });

  return (
    <div
      ref={el}
      style={{
        width: "min(900px, 86vw)",
        height: "min(680px, 78vh)",
        "max-height": "78vh",
        overflow: "auto",
      }}
    />
  );
};

export default CentralPanelHost;
