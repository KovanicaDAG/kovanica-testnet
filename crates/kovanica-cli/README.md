# kovanica console

`kovanica` is the Kovanica terminal wallet and node console. One binary
covers Linux (`kovanica`) and Windows (`kovanica.exe`). The crate version
is **0.1.0**, still before 1.0. Version 1.0.0 is reserved for testnet launch.

The native coin is **KUNA** (9 decimals). 1 KUNA = 1_000_000_000 atoms.
Addresses are parsed and printed by `kovanica_types::Address`. Pass a
Kovanica address; this console does not define its own address spelling.

## Build

From the workspace root. `CARGO_TARGET_DIR` can point at a worktree-local
`target` directory when several checkouts share a machine.

### Linux

```bash
rustup target add x86_64-unknown-linux-gnu
cargo build --release -p kovanica-cli --target x86_64-unknown-linux-gnu
```

Binary: `target/x86_64-unknown-linux-gnu/release/kovanica`

### Windows (cross-compile from Linux)

Install mingw-w64 so `x86_64-w64-mingw32-gcc` is on `PATH`. Cargo uses that
compiler as the linker for `x86_64-pc-windows-gnu`.

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release -p kovanica-cli --target x86_64-pc-windows-gnu
```

If Cargo does not find the linker:

```bash
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
```

Binary: `target/x86_64-pc-windows-gnu/release/kovanica.exe`

On Windows, a new keystore or seed file gets an owner-only DACL
(`D:P(A;;FA;;;OW)`) before the secret bytes are written. On Unix the file
mode is `0600`. `kovanica address` refuses a symlink or a file that other
users can read. Platforms without those controls only check that the path
is a regular file.

The release profile enables LTO, so a release build is slow.

## Global options

| Flag | Role |
|------|------|
| `--rpc-url` | Node JSON-RPC URL. Default `http://127.0.0.1:8545`. |
| `--chain-id` | Signing chain id. Falls back to `KOVANICA_CHAIN_ID`. Required for commands that sign. When the node reports `networkTag` or `chainId`, a different local value is refused. |
| `--json` | Machine-readable JSON. |

`kovanica --help` lists every command.

## Amounts

Native amounts must name a unit. A decimal point or a trailing `KUNA`
(any case, optional space) selects KUNA. An `atoms` or `atom` suffix
selects atoms. A bare integer such as `5` is rejected, so it is neither
five KUNA nor five atoms.

```text
--amount 1.5       # 1.500000000 KUNA
--amount 1.5KUNA   # same
--amount 1 KUNA    # same
--amount 5atoms    # 5 atoms
--amount 5         # rejected
```

Parsing is integer arithmetic. More than 9 fractional digits, a sign, an
exponent, or a value that does not fit in `u64` is rejected. Fees stay
whole atoms (`--fee 1`). Token `--amount` is a whole number of that token's
base units.

`balance` and `staking` print KUNA with 9 decimal places. JSON keeps the
atom count and adds a decimal string (`balanceKuna`, `totalKuna`, …).

## Usage

Placeholder `<kovanica-address>` stands for an address produced by
`kovanica-types`. Do not paste a real seed, keystore, or mnemonic into a
shell history you share.

```bash
kovanica status --chain-id <chain-id>
kovanica balance <kovanica-address>
kovanica staking <kovanica-address>
kovanica history <kovanica-address>
kovanica --chain-id <chain-id> transfer \
  --to <kovanica-address> \
  --amount 1.5 \
  --keystore keystore.json
kovanica tui --keystore keystore.json
```

`status` prints the local signing chain id, committed height, DAG round,
committee epoch, sync state, peer count, and the current committee when the
node returns them. Sync comes from `kovanica_syncStatus`. When that object
includes `networkTag` (the `<chain_id>-<digest>` prefix) or `chainId`, and
`--chain-id` names a different chain, `status`, `transfer`, `stake`, and the
other signing commands refuse. If the node reports neither, the signing chain
stays the local flag. Epoch comes from `kovanica_getCommitteeInfo`. Peer count
falls back to `/health` when sync status is absent. A dead RPC still fails the
command.

`staking <address>` reads `kovanica_getStake`, `kovanica_getRewards`, and
`kovanica_getValidators`. Own stake is the sum of validator rows for that
address. Delegated stake is the remainder of the `getStake` total. The node
returns one total, so the command cannot list each delegation. `stake`,
`unstake`, `delegate`, and `claim-rewards` still submit signed transactions.

`register-light-node --stake` uses the same amount parser. The minimum bond
is 100 KUNA, written `100KUNA` or `100.0`.

## Transaction history

`history <address>` reads `kovanica_getTransactionHistory` and lists committed
transactions that touch the given address, newest first.

```bash
kovanica history <kovanica-address>
kovanica history <kovanica-address> --limit 50
kovanica history <kovanica-address> --cursor <cursor>
kovanica history <kovanica-address> --sent
kovanica history <kovanica-address> --received
kovanica history <kovanica-address> --json
```

Columns: `HEIGHT`, `TIMESTAMP`, `KIND`, `STATUS`, `FROM`, `TO`, `AMOUNT`, `FEE`, `HASH`.
`--limit` controls page size (default 20, max 100). `--cursor` accepts the `next_cursor`
value from a previous page to paginate backwards in history. Direction can be
filtered with `--sent` or `--received` (default is all).

