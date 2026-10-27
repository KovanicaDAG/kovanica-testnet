# @kovanica/comms

TypeScript glue for the Kovanica comms app (M0 scaffold). It is the thin
client-side layer the Tauri webview talks to:

- **`src/identity.ts`** — derives the self-certifying comms id from a wallet's
  32-byte Ed25519 public key:
  ```text
  commsId = BLAKE3( utf8("kvnc/comms/id") || <32-byte Ed25519 public key> )
  ```
  Output is lowercase hex (64 chars). Must match `kovanica-comms-core` on the Rust
  side exactly — change `COMMS_ID_DOMAIN` only in lockstep with that crate.
- **`src/rpc.ts`** — thin wrapper over `@kovanica/api-client`: build a JSON-RPC
  client, read the chain head (`kovanica_blockNumber`), and re-export the `newHeads`
  WebSocket subscription helper.
- **`src/index.ts`** — re-exports identity + rpc.

Nothing here is consensus-critical; comms identity is **client-only**.

## Dependencies

- `@kovanica/api-client` (`file:../api-client`)
- `@kovanica/signer` (`file:../signer`) — wallet keys / addresses / hex helpers
- `@noble/hashes` — BLAKE3 (real BLAKE3, not `blakejs`)

## Scripts

```sh
npm test      # vitest run
npm run build # tsc --noEmit (typecheck only)
```

## Build & test (verified)

```sh
npm install
npm run build   # tsc --noEmit — clean
npm test        # vitest run — 7 tests, incl. a cross-language KAT with kovanica-comms-core
```

Requires Node.js >= 18 and npm. The sibling `@kovanica/*` packages are `file:` deps
consumed as TypeScript source via path aliases, so install them too
(`npm install` in `../signer` and `../api-client`) before typechecking here.
