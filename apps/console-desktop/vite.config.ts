import { defineConfig } from "vite";

// Dev server for the Tauri webview. Port 5174 stays clear of the Comms shell
// and the hosted console, which both use 5173.
export default defineConfig({
  clearScreen: false,
  server: {
    port: 5174,
    strictPort: true,
  },
  envPrefix: ["VITE_", "TAURI_ENV_"],
  build: {
    outDir: "dist",
    sourcemap: false,
    target: "es2021",
  },
});
