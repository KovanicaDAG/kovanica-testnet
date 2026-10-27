# Testnet reset procedure

> This codebase has **no `reset` subcommand and no `KOVANICA_ALLOW_RESET`
> switch**. A reset is performed by stopping the node, wiping its data
> directory, and starting a build again. There is nothing to "apply": a fresh
> `KOVANICA_DATA_DIR` starts a fresh chain under whatever rules the running
> binary enforces.

## What a reset does and does not do

A reset changes the live mesh only when **every** seed/validator in the mesh is
rebuilt from the same commit and started again together. Restarting a single
node on a rebuilt binary while the others keep running splits that node from
the mesh.

- Chain height, balances, and the mempool are gone — the new chain starts at
  genesis.
- Consensus follows the running binary's rules. Under MysticGhost, commit
  colouring is scoped GHOSTDAG, and each committed leader mints the block
  reward. If no light nodes are bonded, the light escrow share returns to the
  contributing leaders.

## Procedure

1. **Agree and freeze.** Pick the commit that the whole mesh will run. Note
   the chain id and genesis inputs; a reset with mismatched genesis inputs
   will not converge.
2. **Stop every node in the mesh.** The running process keeps
   `consensus.redb` / `state.redb` open even if you delete them on disk, so
   the process must be stopped before the wipe.
3. **Wipe the data directory on every node.** The data directory is whatever
   `data_dir` in the config points at (`./data` by default), overridable with
   the `KOVANICA_DATA_DIR` environment variable. Delete that directory (it
   holds `consensus.redb` and `state.redb`). Some older scripts still spell the
   variable `KOVANICA_DATA`; the node reads **`KOVANICA_DATA_DIR`**.
4. **Deploy the frozen build to every node** (same binary, same commit).
5. **Start them together**, with matching bootnodes
   (`KOVANICA_BOOTNODES`, or `bootnodes` in the config; default P2P listen is
   `0.0.0.0:8000`).
6. **Verify convergence** — compare the `network_tag` startup line (see
   below) and then head height / digest across all nodes before re-opening
   the mesh to public traffic.

## Chain 4: one byte-identical genesis bundle for every node

Since #87, every libp2p protocol id and gossip topic carries the node's
**network tag**: `<chain_id>-<first 16 hex chars of the genesis config
digest>`. Examples are `/kovanica/<tag>/block-sync/1.1.0` and
`kovanica/<tag>/votes`. A peer that advertises another tag is disconnected at
identify. Two nodes whose genesis inputs differ in a single byte therefore
**never talk to each other**. The node logs no error for this; it simply has
no peers on the right tag.

The digest (`genesis_config_digest`) covers:

- the canonical genesis block digest, which comes from the binary, so every
  node must run the **same binary** (same commit, same `sha256sum` of
  `kovanica-node`) — a different build can change the tag with the files
  untouched;
- `chain_id` — every node must be configured with the same value;
- the treasury address;
- these files in the data directory, where present: `validators.json`,
  `founder_premine.hex`, `funded_accounts.toml`, and
  `genesis_validators.toml`.

The treasury address is `treasury_address` in the config file, or
`KOVANICA_TREASURY_ADDRESS` when that variable is set (the variable wins).
If neither is set, the **all-zero address** is what enters the digest. Two
nodes that disagree about the treasury, including one of them leaving it
unset, get different tags.

**Every** chain-4 node needs the **same chain id, the same binary and the
same file set**, byte for byte: validators, seeds, RPC nodes, the explorer
backend and the faucet. A file that is missing on one node and present on
another changes the tag, even when the operator treats that file as optional.
Do not let each operator re-type or regenerate files.

### Check the bundle before the first start

Coordinators publish two things with the bundle: a `SHA256SUMS` file and the
expected network tag. **Where those are published is not fixed in this
repository** — the person who cuts the bundle names the place and announces
it with the bundle. Do not invent a host for it.

From the directory that holds the bundle files.

Off mainnet, `funded_accounts.toml` may be part of the bundle (every chain
except chain 1 allows it):

```sh
# off mainnet
sha256sum validators.json founder_premine.hex funded_accounts.toml genesis_validators.toml > SHA256SUMS
```

On mainnet (chain 1) that file is forbidden. It must not be in the data
directory, and the checksum list must not name it:

```sh
# chain 1 (mainnet)
sha256sum validators.json founder_premine.hex genesis_validators.toml > SHA256SUMS
```

On each node, after the files are copied into the data directory and before
the first start:

```sh
sha256sum -c SHA256SUMS
```

`sha256sum -c` exits non-zero if a listed file differs or is missing. Then
print the tag without starting the node (this does not open the database or
the network):

```sh
kovanica-node network-tag --config kovanica.toml
```

That command reads the same config, the same `KOVANICA_CHAIN_ID` /
`KOVANICA_TREASURY_ADDRESS` / `KOVANICA_DATA_DIR` overrides, and the same
files the node will hash. The printed line must equal the published tag.

A running node also returns the tag on the read-only `kovanica_syncStatus`
method as `networkTag`, and logs it at `info` on startup:

```
network identity: peers must share this tag  chain_id=4 network_tag=4-<16 hex>
```

Before opening the mesh, compare that line (or `networkTag`, or
`network-tag`) on every node. A node with a different tag has a different
bundle, chain id, treasury or binary. Fix the inputs, wipe the data
directory, and restart. Do not use the genesis-mismatch override.

## Genesis digest guard (startup behaviour)

The node persists a digest of its genesis configuration in the data directory
on first start. On later starts it recomputes that digest and compares it with
the persisted value:

- **match** — startup proceeds normally;
- **mismatch** — startup **refuses** with a clear error naming the genesis
  mismatch, because it means the data directory was created for a different
  genesis than the one now configured (a silent start would fork);
- an **override environment variable** exists to force startup past the
  mismatch. Do not set it on a live mesh: it defeats exactly the guard that
  stops two nodes from running diverged genesis state. It is only for a
  deliberate single-node migration;
- **no persisted digest but chain state present** — startup **refuses**, with
  or without the override. Genesis writes the digest together with the state,
  so such a data directory predates the chain-4 format change (#81) and cannot
  be migrated. Wipe it (step 3).

If you see the mismatch error after a legitimate reset, the fix is the wipe in
step 3 — not the override.

## Historical note (2026-10-14)

The note this document replaced described a live mesh where the running
process was still an older `/usr/local/bin/kovanica-node` while
`consensus.redb` and `state.redb` had already been deleted from disk, and
where `seed2` / `seed3` were still on the older build. It correctly observed
that `KOVANICA_ALLOW_RESET=0` does nothing — there is no such switch in this
codebase. The correct remedy was, and remains, the manual procedure above:
stop all nodes, wipe the data directories, deploy one build everywhere, start
together.
