# JSON-RPC reference

Machine-readable request and response schemas are generated from
`crates/kovanica-rpc/src/openapi.rs` (`generate_openapi_spec`). The
`kovanica_*` methods the node registers are the list in
`KNOWN_RPC_METHODS` (`crates/kovanica-rpc/src/lib.rs`).

This page documents `kovanica_getTransactionHistory`. Integer quantities
follow the same rule as the other chain methods: a JSON number or a
`0x`-prefixed hex string. A decimal string is parsed as hex.

## `kovanica_getTransactionHistory`

Newest-first committed transactions that touch an address. The call is
read-only. It is not a write method and does not require an auth token.

The handler reads only that address's rows in the local `address_tx_index`
table. It stops after one page of matching or scanned rows (plus one extra
peek, to decide whether another page exists). It does not scan the chain.
Block rewards are not transactions and are not in the history.

### Parameters

One object, or a one-element array containing that object.

| Field | Required | Meaning |
| --- | --- | --- |
| `address` | yes | Canonical `kvnc…dag` (checksum checked) or raw 32-byte hex. Parsed by the same `parse_address` helper as the other account methods. |
| `limit` | no | Page size. Default 20. Values above 100 are clamped to 100. `0` returns an empty page and no cursor. |
| `cursor` | no | Opaque cursor from a previous `next_cursor`. A malformed cursor is JSON-RPC `-32602`. |
| `direction` | no | `sent`, `received`, or `all` (the default). Any other value is `-32602`. |

`sent` matches rows where the address is the sender. `received` matches
rows where the address is the counterparty. A transaction whose sender and
counterparty are the same address is one row and appears in both filters.

### Result

```json
{
  "entries": [
    {
      "hash": "0x…",
      "height": "0x1",
      "timestamp": null,
      "from": "kvnc…dag",
      "to": "kvnc…dag",
      "amount": "0xa",
      "fee": "0x1",
      "kind": "transfer",
      "status": "success"
    }
  ],
  "next_cursor": null
}
```

| Field | Meaning |
| --- | --- |
| `hash` | Transaction hash, `0x` + 32-byte hex. |
| `height` | Committed-leader height, hex quantity. |
| `timestamp` | Leader-header producer time, hex quantity, when that header exists and its timestamp is non-zero. `null` when the header is missing or the timestamp is still the consensus placeholder `0`. |
| `from` | Sender, canonical address. |
| `to` | Counterparty, canonical address, or `null` when the kind names none. |
| `amount` | Atoms moved by the kind, hex quantity. `0x0` when the kind has no KUNA amount. `SetCommission`'s basis points are not an amount. |
| `fee` | Fee in atoms, hex quantity. |
| `kind` | `transfer`, `stake`, `unstake`, `delegate`, `claim_rewards`, `deploy`, `call`, `register_light_node`, `exit_light_node`, `submit_light_witness`, `set_commission`, `claim_treasury`, or `evidence`. |
| `status` | `success` or `failed`. Failed receipts are indexed. |
| `next_cursor` | Opaque string for the next page, or `null` when this page is the last. |

Pass `next_cursor` back as `cursor` with the same `address` and
`direction`. The cursor is 16 bytes (`kvh1`, then height and tx index,
big-endian) encoded as hex. It does not contain the address.

### Where the rows come from

There was no address index. Existing tables map a transaction hash to a
block hash, list executed hashes per height, and store receipts per height
and per hash. None of them can answer "transactions for this account"
without scanning every height.

`address_tx_index` is written in the same redb write transaction as commit
application, after receipts are stored and before the account sparse
Merkle root. It is not an input to that root, to snapshot export, or to
any consensus hash.

Each row's key is 44 bytes: address, committed-leader height, transaction
index inside that commit. The value is 117 bytes (version, role, kind,
success, hash, sender, counterparty, amount, fee). Logical payload is
161 bytes per row, plus redb B-tree overhead. A transaction writes a
second row when its counterparty is a different address (322 bytes). A
self-counterparty is a single row. Counterparties are `Transfer.to`,
`Delegate.validator`, `Call.contract`, `SetCommission.validator`, and
`ClaimRewards.validator` when it is set. Other kinds are sender-only.
The contract address created by `Deploy` is not indexed, and block rewards
are not in the history.

The table is not created at startup. A database from before this index
opens normally. A history query before the first commit that contains a
transaction returns an empty page. There is no backfill and no migration.
After a chain-4 reset the table starts empty with the new chain. An
in-place upgrade records history from the first commit after the upgrade.

Rows are not removed when DAG blocks are pruned.

Leader headers are saved in a later write, and `leader_header()` currently
stores timestamp `0`. Clients should treat `timestamp: null` as "no
producer time", not as an error.
