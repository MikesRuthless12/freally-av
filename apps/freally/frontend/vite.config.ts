import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import path from "node:path";

export default defineConfig({
  // The "More Freally apps" panel is React (vendored from freally-central).
  // Solid owns the app, so exclude the vendored React source from Solid's JSX
  // transform; esbuild's automatic React runtime (below) handles that .tsx.
  plugins: [solid({ exclude: ["**/vendor/freally-central/**"] })],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: false,
  },
  envPrefix: ["VITE_", "TAURI_"],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
      "@freally/central-panel": path.resolve(
        __dirname,
        "../../../vendor/freally-central/ui/src/panel",
      ),
    },
    // The vendored panel is out-of-tree, so force its bare imports onto this
    // app's single installed copy.
    dedupe: ["react", "react-dom", "@tauri-apps/api"],
  },
  // Transforms the vendored React .tsx (Solid-excluded above). Solid files are
  // already JSX-free by the time esbuild sees them, so this is inert for them.
  esbuild: {
    jsx: "automatic",
    jsxImportSource: "react",
  },
  build: {
    target: "es2022",
    sourcemap: true,
    minify: "esbuild",
  },
});
