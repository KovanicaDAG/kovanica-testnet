# Committee epoch and light-client header verification

Status: fixed in the working tree (uncommitted). Scope: a client-side defect plus an
additive node RPC surface — no consensus, execution, or storage change.

## Symptom

```
leader header committee hash does not match
```

This is `LightError::Committee` (`crates/kovanica-light/src/lib.rs:24`). It is raised by
**client-side verification only** — it does not indicate a faulty chain or node. Funds are
never at risk.

## Mechanism

`verify_sealed_header(chain_id, committee, header, seals, parent)`
(`crates/kovanica-light/src/lib.rs:52-78`) rejects a sealed leader header when

```
header.committee_hash != committee_seal_hash(committee.epoch, &members)
```

`committee_seal_hash(epoch, members)` (`crates/kovanica-types/src/light_client.rs:170-188`)
sorts the members by authority index and hashes

```
epoch.to_le_bytes() ‖ u32_le(count) ‖ for each member { index.to_le_bytes() ‖ 32-byte public key ‖ stake.to_le_bytes() }
```

keyed as `Hash::new_keyed(DOMAIN_COMMITTEE = b"KUNA-COMMITTEE-v1", &data)`
(`crates/kovanica-types/src/hash.rs:20,46`).

Two consequences follow directly from the input:

1. **The epoch is part of the hash.** A verifier that uses a different epoch than the one
   the header was sealed under will always fail.
2. **The member set is part of the hash.** Network addresses and VRF keys are deliberately
   excluded, so only `(index, public key, stake)` matters; member ordering does not.

The hash function itself is correct. It was checked against the live testnet: the sealed
header's `committeeHash` (`0x04741e61…860a`, `epoch = 0`) is reproduced exactly from the
committee returned by that node, and reversing the member order yields the same digest.

## The two ways this fires

### 1. The client supplies the wrong epoch

The light client cannot learn the node's committee epoch over RPC — it was never reported.
The Android app therefore verified against a user-editable "Committee epoch" preference
instead of the epoch the header itself declares. Any stale or hand-edited value produces
this error even though the node is perfectly healthy.

The leader-header JSON *does* carry the epoch the header was sealed with (the RPC emits
`"epoch": quantity(header.epoch)`), so the client can and should use it.

### 2. The committee was re-derived after the header was sealed

The node rebuilds its committee from live staking state at startup
(`crates/kovanica-node/src/main.rs:1885-1967`). On a fresh chain with no active validators
it falls back to a **single local authority** (index 0, the node's own public key,
`MIN_VALIDATOR_STAKE`, epoch 0). Any later change to the validator set, its stakes, its
index assignment, or the public-key source changes the seal hash — while headers that were
already sealed keep the hash they were sealed with.

Because the committee query returned only the *current* committee and ignored its
parameters, a client could not tell that it was comparing a historical header against a
newer committee. It simply got a mismatch.

**Residual limitation:** the node retains no committee history. A header sealed under an
older committee remains unverifiable until committee history is stored. This is documented
rather than papered over; a query for a non-current epoch now fails explicitly instead of
silently returning the current committee.

## Reproduction

Not reproduced end-to-end locally; the mechanism above is established by reading the
verification path and by the epoch probe against live testnet data. To reproduce:

1. Run a node and point the Kovanica Lightnode app at it (Local or a custom RPC URL).
2. Set the app's **Committee epoch** to any value other than the one the header was sealed
   under — the simplest failing case is a non-zero value against a node whose committee
   epoch is 0.
3. Sync the light client: verification fails with `leader header committee hash does not
   match`.

The second failure mode needs a validator-set change between sealing and verification:
let the node seal headers under one committee, then restart it with a different active
validator set and re-verify an older header.

## Fixes applied

- **App (Kovanica Light, and the Wallet app's matching `sync()`)**: verify against the
  **header's own `epoch`**, parsed from the fetched leader-header JSON, falling back to the
  configured preference only when the header omits it. The failure message now names the
  epoch that was used and explains the likely cause.
- **Node RPC**: new **`kovanica_getCommitteeInfo`** returning
  `{ "epoch": <hex quantity>, "members": [ … ] }` with member rows identical to
  `kovanica_getCommittee`. The existing `kovanica_getCommittee` response shape is
  unchanged (still a bare array) so existing clients keep working.
- **Node RPC**: `kovanica_getCommittee` accepts an optional epoch as its first parameter.
  When it is present and does not match the live committee epoch the call now returns
  `-32602 InvalidParams` ("committee history is not retained; only the current epoch (N) is
  available") instead of silently answering with the current committee.

## See also

- `crates/kovanica-rpc/src/chain_methods.rs` — `handle_get_committee`,
  `handle_get_committee_info`, `committee_members_json`
- `crates/kovanica-light/src/lib.rs` — `verify_sealed_header`, `LightError`
- `crates/kovanica-types/src/light_client.rs` — `committee_seal_hash`
