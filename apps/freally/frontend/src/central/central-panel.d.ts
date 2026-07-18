// Type surface for the vendored React panel imported via the Vite alias
// `@freally/central-panel` (built from vendor/freally-central/ui/src/panel).
// tsc type-checks against THIS declaration, not the vendored .tsx source —
// esbuild transforms the real source at build. Keeps this Solid project's
// strict typecheck decoupled from the panel's React internals.
declare module "@freally/central-panel" {
  import type { FC } from "react";

  export interface PanelHost {
    openExternal: (url: string) => void | Promise<void>;
    revealInFolder?: (path: string) => void | Promise<void>;
  }

  export type TranslateArgs = Record<string, string | number>;
  export type Translate = (id: string, args?: TranslateArgs) => string;

  export interface CentralPanelProps {
    t: Translate;
    locale: string;
    host: PanelHost;
    /** false → view-only showcase: no download/install controls. */
    allowDownloads?: boolean;
  }

  export const CentralPanel: FC<CentralPanelProps>;
}
