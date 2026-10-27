# Genesis Ceremony ([DRAFT - needs human review])

Status: the wrapper script `ops/genesis/ceremony.sh` **exists** and is described
below; the underlying `kovanica-node genesis` tool and the startup genesis
guard are still being finished (see **Known gaps**).
Consensus impact: ledger-safe / client-only — the genesis file only defines
initial state, once, before the chain starts.

Purpose: coordinate a multi-validator genesis so that all genesis
validators (testnet: 5 recommended, at most 20; mainnet: 15–20 enforced) agree on the validator set, staking allocations, treasury address,
and chain id.

## Inputs

- **`validators.json`** — a JSON array; each entry is
  `{ "address": <32-byte hex>, "public_key": <hex?>, "stake": <atoms?> }`
  (`address` required, `public_key` / `stake` optional at this layer).
- **Treasury address** and **founder address** — both 32-byte hex. The founder
  receives the 200,000 KUNA premine.
- **Chain id** — `1` mainnet, `2` testnet, `3` devnet, `4` testnet v2, `1337` local. A
  `genesis_validators.toml` that declares `chain_id` must match the node's
  configured chain id.

## Procedure (`ops/genesis/ceremony.sh`)

Usage:

```sh
./ops/genesis/ceremony.sh --network testnet --validators validators.json \
    [--output ./genesis] [--force]
```

Flags: `--network` (default `testnet`), `--validators` (required, JSON file),
`--output` (default `./genesis`), `--force` (overwrite existing outputs). The
script is `set -euo pipefail` and fails early if `--validators` is missing.

Steps it runs:

1. **[1/4] Generate genesis** — `cargo run --release -p kovanica-node --
   genesis --validators <file> --output <output>/genesis.json [--force]`.
2. **[2/4] Generate validator keys** — the same `genesis` subcommand with
   `--validator-keys-out <output>/keys`.
3. **[3/4] Create `genesis_validators.toml`** — writes the file header and
   lists the validator addresses/stakes it read out of `genesis.json`.
4. **[4/4] Create `bootnodes.toml`** — a single `bootnodes = [...]` entry:
   `testnet.kovanica.online:8000` for `--network testnet`, otherwise
   `mainnet.kovanica.online:8000`.

Outputs, in `--output`: `genesis.json`, `genesis_validators.toml`,
`bootnodes.toml`, and `keys/` (validator key files).

Next steps the script prints: distribute `genesis.json` to all validators,
each validator places it in its data directory (`KOVANICA_DATA_DIR`), configures
the bootnodes, and all validators start simultaneously.

The files that actually enter the network tag, and the `sha256sum -c` check
every node runs before the first start, are described in
[`docs/TESTNET-RESET.md`](TESTNET-RESET.md). A node whose bundle, chain id,
treasury or binary differs from the others never joins the mesh.

## `genesis_validators.toml` format

```
chain_id = 2            # optional; mandatory for mainnet (1) / testnet (2)

[[validator]]
address = "<32-byte hex>"
stake = 50000000000000
public_key = "<32-byte hex>"      # optional
vrf_public_key = "<hex>"          # optional
```

`stake` is required per entry; the minimum is the validator min stake. On
startup the node also looks for `validators.json`, `funded_accounts.toml`, and
`founder_premine.hex` in the data directory.

### Mainnet genesis needs 15–20 validators

Mainnet genesis is refused unless the declared validator set (deduplicated by
address, across `genesis_validators.toml` and `validators.json`) has at least
`MIN_ACTIVE_VALIDATORS` (15) members. The upper bound is **20**, not the
protocol's 21: the genesis allocation is 1 M KUNA and every genesis validator
locks the 50 000 KUNA minimum stake, so 21 cannot be funded at genesis — 21 is
reachable later through staking. `kovanica-node --check-config` reports the
same error when a ceremony file is present; it does not require the files to
exist, because an already-initialised mainnet data directory legitimately has
none. Testnets, devnet and local chains are exempt (1–4 nodes is normal there).

### `funded_accounts.toml` is refused on mainnet

```
[[account]]
address = "<32-byte hex>"
balance = 1000000000000          # base units (9 decimals)
```

Pre-funding accounts from a file is a testnet, devnet and local convenience.
On **chain 1 (mainnet)** the file must not exist at all: every KUNA there has to
come from the published allocation (founder premine, treasury vesting, genesis
validator allocation), never from a loose file in the data directory. The node
fails at startup — and `kovanica-node --check-config` reports it — if
`funded_accounts.toml` is present on mainnet, rather than ignoring it, because
silently skipping it would boot a genesis the operator believes they
configured. The mainnet `sha256sum` list therefore omits it (see
[`docs/TESTNET-RESET.md`](TESTNET-RESET.md)). All other chain ids (2, 3, 4, 1337)
accept the file.

## Genesis digest guard (startup behaviour)

On first start the node persists a digest of its genesis configuration in the
data directory. On every later start it recomputes the digest and compares it
against the persisted value:

- **match** — startup proceeds;
- **mismatch** — startup **refuses** with an error naming the genesis mismatch,
  because the data directory was created for a different genesis;
- an **override environment variable** forces startup past the mismatch for a
  deliberate single-node migration. Never set it on a live mesh;
- **no persisted digest but chain state present** — startup **refuses**, even
  with the override: the data directory predates the chain-4 format change and
  must be wiped, not migrated.

## Data preservation

After the first genesis write, set `KOVANICA_DATA_DIR` and **never delete** the
data directory or its `consensus.redb` / `state.redb`. Rebuild only by wiping
every node together (see `docs/TESTNET-RESET.md`).

## Safety rules

- No reset switch on a public node; the reset path is the manual wipe in
  `docs/TESTNET-RESET.md`.
- `FAUCET=0`; seed nodes must **not** expose a faucet.
- Keep the seed DNS records grey-cloud.
- P2P is plaintext TCP on port **8000**; set bootnodes via
  `KOVANICA_BOOTNODES` (or the config), never hard-code peers into binaries.

## Known gaps (not done)

- `ceremony.sh` does not pass `--treasury-address` / `--founder-address`, which
  the `genesis` subcommand currently requires; the script must be updated (or
  the addresses added to the ceremony flow) before it runs end-to-end.
- `ceremony.sh` step 3 writes only a header to `genesis_validators.toml`; it
  does not yet emit the `[[validator]]` entries the node parses.
- `ceremony.sh` drives the tool with `cargo run --release`, not a released,
  checksummed binary.
- No dedicated multi-party `validators.json` build helper (entries are
  collected by hand and hashed out-of-band).
