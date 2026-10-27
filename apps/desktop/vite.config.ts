import { fileURLToPath } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Vite config for the Tauri webview. The Rust shell launches this dev server
// (see `src-tauri/tauri.conf.json` -> build.devUrl).
export default defineConfig({
  plugins: [react()],
  // Tauri runs its own output; don't wipe it.
  clearScreen: false,
  resolve: {
    alias: {
      "@kovanica/comms": fileURLToPath(new URL("../../packages/comms/src/index.ts", import.meta.url)),
      "@kovanica/signer": fileURLToPath(new URL("../../packages/signer/src/index.ts", import.meta.url)),
      "@kovanica/api-client": fileURLToPath(
        new URL("../../packages/api-client/src/index.ts", import.meta.url),
      ),
    },
  },
  server: {
    // Must match `build.devUrl` in tauri.conf.json.
    port: 5173,
    strictPort: true,
  },
  // Expose TAURI_* env vars to the frontend, on top of the default VITE_*.
  envPrefix: ["VITE_", "TAURI_"],
  build: {
    outDir: "dist",
    sourcemap: true,
    target: "es2021",
  },
});
