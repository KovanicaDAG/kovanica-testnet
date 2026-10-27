# Kovanica Contract Examples

Worked end-to-end flows for the contract crates. All amounts are in
**atoms** (base units): `1 KUNA = 1_000_000_000 atoms` (9 decimals). Addresses use the canonical PRO-21 64-character base32 format (`kvnc...dag`).

> **CLI status.** `kovanica-cli` provides native contract subcommands (`htlc`,
> `vault`, `multisig`, `token`) implemented in `crates/kovanica-cli/src/contracts.rs`
> that map 1:1 onto the contract entry points in [`docs/CONTRACTS.md`](CONTRACTS.md)
> and JSON-RPC methods. Flows can be executed via the CLI or directly via JSON-RPC.

---

## HTLC atomic swap (KVP-104)

Alice locks KUNA for Bob; Bob claims with the preimage before expiry, or
Alice refunds after expiry.

```bash
# 1. Alice locks 100 KUNA for Bob.
#    hash-lock = BLAKE3-256(preimage) as hex; expiry = unix timestamp.
kovanica htlc create \
  --claimer <Bob-address> \
  --amount 100000000000 \
  --hash-lock <64-hex-chars> \
  --expiry <unix-seconds>

# → returns swap_id (32 bytes, hex)

# 2. Bob claims with the preimage before expiry.
kovanica htlc claim \
  --id <swap_id> \
  --preimage <hex>

# 3. (Alternative) If Bob never claims, Alice refunds after expiry.
kovanica htlc refund --id <swap_id>
```

Notes:

- `create` moves the amount into a per-record escrow address
  (`hash(b"htlc/escrow" || id)`); `claim` pays the designated claimer only.
- `hash-lock` is `kovanica_common::hash(preimage)` (BLAKE3-256).
- `refund` may be triggered by anyone once `expiry` has passed.

## Time-lock vault (KVP-105)

```bash
# Create: beneficiary can claim after an absolute unlock time.
kovanica vault create \
  --beneficiary <address> \
  --amount 50000000000 \
  --unlock-at <unix-seconds>

# Beneficiary claims the vested amount (repeat as vesting progresses).
kovanica vault claim --id <vault_id>

# Creator cancels and reclaims everything not yet claimed.
kovanica vault cancel --id <vault_id>
```

`--unlock-at` selects the `Absolute` schedule; a `--start/--end/--cliff`
form selects `Linear` vesting (see `VestingSchedule` in
[`docs/CONTRACTS.md`](CONTRACTS.md) §3).

## Multisig (KVP-101)

```bash
# Create a 2-of-3 wallet.
kovanica multisig create \
  --owners <addr1,addr2,addr3> \
  --threshold 2

# Any owner proposes (proposer auto-confirms) → returns tx_id.
kovanica multisig propose \
  --id <multisig_id> \
  --to <address> \
  --amount 1000000000

# Another owner confirms.
kovanica multisig confirm --id <multisig_id> --tx-id <tx_id>

# Anyone executes once the threshold is met; funds leave the multisig
# contract's own account.
kovanica multisig execute --id <multisig_id> --tx-id <tx_id>
```

## Token (KVP-102)

```bash
# Deploy a token; caller becomes owner + minter and receives the supply.
kovanica token create --name "My Token" --symbol MTK --decimals 9 \
  --initial-supply 1000000000000000

# Standard ERC-20-style flows.
kovanica token transfer --to <address> --amount 5000000000
kovanica token approve --spender <address> --amount 5000000000
kovanica token mint --to <address> --amount 1000000000   # minter only
kovanica token burn --amount 1000000000
```

---

## Indexer hooks

Every flow above emits events with the canonical topics defined in
`kovanica_common::events` (see [`docs/CONTRACTS.md`](CONTRACTS.md) §9). Match on
the topic bytes and decode the data payload — e.g. `htlc_created` carries the
32-byte swap id, `multisig_proposed` carries the 8-byte tx id (little-endian),
and the token topics carry empty data.
