# Kovanica Console

Desktop app for Linux, Windows, and macOS. Version 0.1.0 shows whether a node
is reachable and what chain it sealed.

`apps/desktop` is the Comms client. This app lives beside it and does not
replace it.

```
apps/console-desktop/
├── src/                  connection screen (plain TypeScript)
└── src-tauri/            Tauri v2 shell
```

## Connection

The endpoint comes from a setting saved in the app data directory, then from
`KOVANICA_RPC_URL`, then from `https://rpc-testnet.kovanica.online/rpc`.

The screen shows chain id, committed height, leader round, epoch, and peers.
Chain id is proven only when commit seals verify through `kovanica-light-ffi`
for one registered id and the committee matches a pinned genesis checkpoint
for that id. This build pins none, so a seal that matches the node's own
committee is labelled consistent but not proven. A node that cannot be reached
shows that error and clears the previous status. The shell has no shell plugin
and no filesystem plugin. RPC calls stay in the Rust process.

## Wallet

Creating or importing a key uses the same keystore the Android wallet stores.
The JSON is version 2: Argon2id (64 MiB, 3 iterations, parallelism 4) and
XChaCha20-Poly1305. Android keeps that JSON under the `keystore` preference
in `apps/android-wallet/app/src/main/java/io/kovanica/wallet/MainActivity.kt`
(`onCreateWallet` and `onImportWallet`). The format is defined in
`crates/kovanica-keystore/src/lib.rs`. This app writes those same bytes to
`wallet.keystore.json` in the app data directory, mode `0600`, and refuses a
symlink or a file that is already there.

The recovery phrase is shown after a key is created. A lock removes that copy
from the screen. The keystore still holds the phrase, and Show recovery phrase
again asks for the password and shows it. It is not written to the log, the
keystore, or `localStorage`. The screen does not copy it. The Android wallet
does not either. A Rust timer clears the session after 5 minutes without activity,
even when the screen is not polling. Only the explicit activity call moves
that deadline. Status, quote, and send do not. Addresses, signing,
and KUNA amounts stay in Rust (`kovanica-types`, `kovanica-crypto`, and
`kovanica-light-ffi`), so a later address encoding arrives with the crates.

A transfer shows the recipient, the amount, the fee, the chain id, and the
nonce before it is signed. Chain 1 asks for an extra confirmation, and that check happens
before the keystore is decrypted. The chain id in the transaction is the one
the connection screen proved. This build pins no genesis committee, so the
screen does not prove a chain id and the wallet will not sign.

Balance and transfer history come from the node. Both are labelled
"reported by node". The light client does not prove them. The wallet screen
creates or imports a key, shows the recovery phrase, can show it again after
the password, and reviews a transfer before sending. The screen does not copy
the phrase. A Rust timer
clears the session after 5 minutes without activity.

## Run

```sh
cd apps/console-desktop
npm install
npm test
npm run tauri dev
```

A Linux bundle:

```sh
npm run tauri build
```

## Checks

```sh
npm run lint
npm test
cd src-tauri && cargo fmt --all --check && cargo clippy --all-targets -- -D warnings && cargo test
```
