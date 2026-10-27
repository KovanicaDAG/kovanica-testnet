/**
 * Synchronous-mode elevation for this package's `@noble/ed25519`.
 *
 * `@noble/ed25519` v2 asks the caller for SHA-512; without this hook every
 * `*Sync` / sync key-derivation call throws `hashes.sha512Sync not set`.
 *
 * `packages/comms` resolves its *own* copy of `@noble/ed25519` (see
 * `node_modules/@noble/ed25519`), distinct from the copy resolved inside
 * `@kovanica/signer`, so the hook installed by `packages/signer/src/ed25519.ts`
 * does not cover us. Importing this module for its side effect is therefore
 * required before any sync Ed25519 call site runs.
 *
 * Same hook pattern as `packages/signer/src/ed25519.ts`.
 */

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";

ed.etc.sha512Sync = (...messages: Uint8Array[]) => sha512(ed.etc.concatBytes(...messages));
