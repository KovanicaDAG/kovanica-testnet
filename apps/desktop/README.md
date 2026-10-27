# @kovanica/desktop — Kovanica Comms desktop client

M0 scaffold for the Kovanica comms app: a **Tauri v2** desktop shell around a
**React 18 + Vite 5 + TypeScript** frontend. The webview uses
[`@kovanica/comms`](../../packages/comms) to derive the comms identity from a wallet
key and read the chain head over JSON-RPC.

```
apps/desktop/
├── index.html            Vite entry
├── src/                  React frontend (main.tsx, App.tsx, styles.css)
├── vite.config.ts
└── src-tauri/            Rust shell (Tauri v2)
    ├── Cargo.toml        package `kovanica-comms-desktop`
    ├── build.rs
    ├── tauri.conf.json
    ├── icons/            (placeholder — generate real icons)
    └── src/main.rs
```

## Prerequisites (real machine)

Tauri needs native toolchains:

- **Node.js >= 18 + npm** — frontend build/dev server
- **Rust (stable) + Cargo** — `src-tauri`
- **Linux:** `webkit2gtk-4.1`, `libgtk-3-dev`, `libayatana-appindicator3-dev`,
  `librsvg2-dev`, `build-essential`
- **macOS:** Xcode Command Line Tools
- **Windows:** WebView2 runtime + MSVC build tools

## Run

```sh
cd apps/desktop
npm install          # installs frontend deps (workspace `file:` deps too)
npm run tauri dev    # starts Vite and the Tauri shell together
```

Build a bundle:

```sh
npm run tauri build
```

Frontend-only typecheck / build:

```sh
npm run build        # tsc --noEmit && vite build
```

The dev server is pinned to `http://localhost:5173` and must match
`build.devUrl` in `src-tauri/tauri.conf.json`.

## Verified build

Frontend (`npm install` + `npm run build` = `tsc --noEmit && vite build`) is
verified clean with Node.js 20 and `webkit2gtk-4.1` installed. `npm run tauri
build` additionally needs the native prerequisites listed above.

## Rust core (wired)

`src-tauri` depends on **`kovanica-comms-core`**
(`path = "../../../crates/kovanica-comms-core"`) and exposes `derive_comms_id` over
the Tauri IPC bridge, so the webview (`@kovanica/comms`) and the Rust core derive the
*same* comms id. `src-tauri` declares its own empty `[workspace]` so it stays
independent of the repository-root Cargo workspace (whose `members` list is
explicit).

## Layer classification

Comms identity and chain reads here are **client-only** — no consensus or ledger
state is touched.
