# kovanica-faucet

Rate-limited testnet faucet (`POST /faucet`, `GET /health`).

```
kovanica-faucet --chain-id 2 --keystore faucet.keystore --rpc-url http://127.0.0.1:8545 --listen 0.0.0.0:8080 \
            [--dispense-kovanica 10] [--rate-limit-window 3600] [--max-requests 3]
```

`--chain-id` is **required** (no default): 1 mainnet, 2 testnet, 3 devnet, 4 testnet v2, 1337 local. Any other value is rejected at startup.

## Mainnet guard

`--chain-id 1` (mainnet) is **refused by default**: the faucet would dispense real KUNA. To run it on
mainnet anyway you must pass the explicit, loudly-named `--allow-mainnet` flag or set
`KOVANICA_FAUCET_ALLOW_MAINNET=1`. Both print a startup warning; without one the process exits with a
clear error before loading the keystore.

## Rate limiting behind a reverse proxy

The per-IP rate limiter keys on the client IP. `X-Forwarded-For` is **only** trusted when the socket
peer is a configured trusted proxy:

```
kovanica-faucet --chain-id 2 --trusted-proxies 10.0.0.0/8,127.0.0.1 ...
# or: KOVANICA_FAUCET_TRUSTED_PROXIES=10.0.0.0/8,127.0.0.1
```

When the flag/env is unset — or the peer is not in the list — the socket peer IP is used and any
client-supplied `X-Forwarded-For` is ignored. In a trusted chain the header is walked right-to-left,
skipping trusted hops; the first untrusted address is the real client. A malformed list fails startup.

## Low-balance guard (optional)

`--min-balance-ku <n>` makes the faucet return HTTP 503 instead of attempting a transfer when its own
balance drops below `n` KUNA. The default `0` disables the check.

## Keystore passphrase

There is **no `--passphrase` flag**. Command-line arguments are visible in `ps` and shell history.
For an encrypted keystore, the passphrase is taken from the first of these that is available:

1. `--passphrase-file <path>`: the file's contents, with trailing `\n`/`\r\n` trimmed. On unix the file
   must be mode `0600` or `0400`; otherwise the faucet refuses to start.
2. env `KOVANICA_FAUCET_PASSPHRASE` (non-empty).
3. an interactive no-echo prompt, but only when stdin is a TTY.

If none is available, the faucet exits with an error. The passphrase is never logged. It is kept in
zeroizing memory and wiped right after the keystore is decrypted.

Docker/compose: mount a secret file (e.g. `/run/secrets/faucet_passphrase`, mode 0400) and pass
`--passphrase-file /run/secrets/faucet_passphrase`.
