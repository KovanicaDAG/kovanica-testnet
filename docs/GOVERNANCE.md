# Governance Spec (Phase 25 — Draft / Stage-3)

Summary: Parameter-change, treasury-spend, upgrade-signaling, and stake-weighted voting specification for Kovanica (KUNA), derived from `crates/kovanica-staking/src/lib.rs`, `crates/kovanica-types/src/committee.rs`, `kovanica-cli/src/main.rs`, and the existing 38-line `docs/GOVERNANCE.md` skeleton; all on-chain proposal/voting mechanics are planned (Phase 25 `[ ]` NOT DONE), not implemented.

Status: **Draft / Stage-3** (Phase 25 — not shipped; do not mark Shipped).
Consensus impact: **client-only / ledger-safe** for proposal format and treasury flow; **consensus-safe** only once quorum thresholds and epoch-boundary execution rules are adopted by the committee (currently not active). No consensus rule changed by this document.

Cross-links: `docs/archive/B-TREASURY-PROPOSAL.md` (treasury proposal skeleton), `docs/A8.2-DELEGATION-SKELETON.md` (Phase 18 deferred, delegation required for stake-weighted voting), `TASKLIST.md` Phase 25 (`[ ]` governance hooks; `kovanica-cli propose/vote → not_implemented` at `main.rs:366-374`), `crates/kovanica-staking/src/lib.rs` (`MIN_VALIDATOR_STAKE=50_000 KUNA`, `SLASH_PCT_BPS=500`, `EPOCH_ROUNDS=7_200`, `UNBONDING_ROUNDS=100_000`, `TREASURY_TOTAL=8_000_000 KUNA`), `crates/kovanica-types/src/committee.rs` (quorum `2f+1`, validity `f+1`), `crates/kovanica-cli/src/main.rs` (`ProposeArgs` / `VoteArgs` stubs).

---

## 1. Existing skeleton (38 lines — referenced only, not reproduced)

`docs/GOVERNANCE.md` (Tasklist line 386) exists as a 38-line skeleton. This spec replaces it with a full document. The skeleton contained only: status line (draft), references to Phase 25, and pointers to `kovanica-staking` and `B-TREASURY-PROPOSAL.md`. It did not define proposal formats, vote thresholds, or lifecycle stages. Those are added below.

---

## 2. Parameter-change proposal format (planned — not on-chain yet)

A parameter-change proposal is a client-submitted record (intended RPC `kovanica_propose`) that targets a consensus-parameter key. The format below is the planned wire shape; no `kovanica-types/src/` struct exists for it yet (only `Vote` for consensus leader votes exists).

### 2.1 Proposed fields (`ProposeArgs` — `kovanica-cli/src/main.rs:263-268`)

| Field | Type (planned) | Source / note |
|---|---|---|
| `proposal_id` | `String` (e.g. `prop-{epoch}-{counter}`) | From `B-TREASURY-PROPOSAL.md` §5 |
| `title` | `String` | `ProposeArgs::title` (`main.rs:265`) — stub only |
| `target_key` | `String` | Planned; not in stub (e.g. `SUBSIDY_ERA_BLOCKS`, `DECAY_NUM`, `MIN_VALIDATOR_STAKE`, `EPOCH_ROUNDS`) |
| `new_value` | `String` or `u64` | Planned; must pass validation against canonical ranges |
| `justification_hash` | `[u8; 32]` | `B-TREASURY-PROPOSAL.md` — BLAKE3 over description text |
| `proposal_deadline` | `u64` (epoch) | `B-TREASURY-PROPOSAL.md`; execution at epoch boundary only |
| `proposer` | `Address` | Derived from keystore (`--keystore`) |

Status: `ProposeArgs` defines only `title`; `propose` command calls `node::not_implemented("propose","kovanica_propose",...)` at `main.rs:366-369`. The full parameter-change struct is planned, not in `kovanica-types` and not in `kovanica-staking`.

### 2.2 Lifecycle stages (planned)

1. **Draft** — client builds `Proposal` struct, signs with Ed25519 (64-byte sig / 128 hex, per `docs/SIGNATURE_FORMAT.md`).
2. **Submit** — `POST /api/propose` (intended RPC `kovanica_propose`; not implemented). Stored in mempool / proposal index (client-only).
3. **Voting** — stake-weighted vote opens at submit height; closes at `proposal_deadline` (`B-TREASURY-PROPOSAL.md`).
4. **Quorum check** — `2f+1` of active validator stake (see §3.3). If not met, status → `Rejected`.
5. **Approval check** — >50% of voted stake must be `approve` (`B-TREASURY-PROPOSAL.md`).
6. **Execution** — at next `EPOCH_ROUNDS` boundary (`EPOCH_ROUNDS = 7_200`, `kovanica-staking/src/lib.rs:119`); parameter updated in `StakingState` or execution layer. Only then does the change become consensus-effective.
7. **Executed / Rejected / Open** — `ProposalStatus` enum (`B-TREASURY-PROPOSAL.md` lines 19-25).

---

## 3. On-chain stake-weighted voting mechanism (planned — Phase 18 delegation required)

Voting requires stable delegation (`A8.2-DELEGATION-SKELETON.md` deferred). The mechanism uses the active validator committee (`committee_order()` in `kovanica-staking/src/lib.rs:497`) and their delegated stakes.

### 3.1 Vote command interface (`VoteArgs` — `main.rs:271-278`)

| Field | Type (planned / stub) | Note |
|---|---|---|
| `proposal_id` | `u64` | `VoteArgs::proposal_id` (`main.rs:273`); intended `kovanica_vote` |
| `approve` | `bool` (optional, omit for against) | `VoteArgs::approve` (`main.rs:275`) |

Status: mapped to `node::not_implemented("vote","kovanica_vote",...)` at `main.rs:372-375`. No vote persistence, no stake-weight aggregation, no `ProposalStatus` transition exists in `kovanica-staking/src/lib.rs` (only `TreasuryProposal` is sketched in `B-TREASURY-PROPOSAL.md`).

### 3.2 Weight calculation (planned — uses `StakingState`)

Weight = validator's self-stake (after unbonding / delegation) + delegated amounts from `Delegation` entries (`kovanica-staking/src/lib.rs:349-353`). The committee is ordered by total stake (`committee_order()`), truncated to `MAX_ACTIVE_VALIDATORS = 21`, with tie-break by address (`lib.rs:497-511`).

### 3.3 Quorum and validity thresholds (from `kovanica-types/src/committee.rs`)

- **Quorum (approval)**: `floor(2/3 * total_stake) + 1` = `total_stake * 2 / 3 + 1` (`Committee::new`, `committee.rs`). For the planned 15–21 validator range (`MIN_ACTIVE_VALIDATORS=15`, `MAX_ACTIVE_VALIDATORS=21`, `lib.rs:104-107`), this yields ~67% of total staked.
- **Validity (minimum turnout)**: `floor(total_stake / 3) + 1` (`committee.rs`). No proposal can execute unless at least ~33% of stake participates.
- **Vote threshold for approval**: >50% of *voted* stakes must be `approve` (`B-TREASURY-PROPOSAL.md`). This is separate from quorum; both must pass.

Canonical numbers preserved: `MIN_ACTIVE_VALIDATORS=15`, `MAX_ACTIVE_VALIDATORS=21`, `MIN_VALIDATOR_STAKE=50_000 KUNA`, `UNBONDING_ROUNDS=100_000`, `EPOCH_ROUNDS=7_200`, `SLASH_PCT_BPS=500`. Do not restate differently.

---

## 4. Treasury spend proposal flow (planned — `B-TREASURY-PROPOSAL.md` skeleton)

Treasury is 8 × 1 M KUNA = `TREASURY_TOTAL = 8_000_000 KUNA`, linear over `TREASURY_YEARS = 8`, `TREASURY_ANNUAL = 1_000_000 KUNA` (`kovanica-staking/src/lib.rs:58-60`, `BLOCKS_PER_YEAR = 2_628_000` at `lib.rs:72`). Vesting driven by `committed_leader_height`; claim via `TreasuryState::claim()` (`lib.rs:262-270`); address fixed at genesis (`lib.rs:778`).

### 4.1 Treasury proposal struct (`B-TREASURY-PROPOSAL.md` lines 7-17)

```rust
pub struct TreasuryProposal {
    pub proposal_id: String,          // "prop-{epoch}-{counter}"
    pub target_vault_index: u8,       // 0..7 (8 vaults)
    pub amount_atoms: u64,
    pub recipient: Address,
    pub justification_hash: [u8; 32],
    pub proposal_deadline: u64,        // epoch
    pub stake_voted_for: u64,
    pub stake_voted_against: u64,
    pub status: ProposalStatus,       // Open / Voting / Approved / Rejected / Executed
}
```

Status: this struct exists only in `B-TREASURY-PROPOSAL.md`; no matching `kovanica-types/src/` definition. `StakingState::claim_treasury()` exists (`lib.rs:665-672`) for treasury withdrawal, but no proposal-to-release linkage.

### 4.2 Flow (planned — not executed in code)

1. Submit `TreasuryProposal` (client-only; intended RPC `kovanica_propose` with proposal-type = treasury).
2. Vote via `VoteArgs` (`main.rs:271-278`) — weight = validator stake (§3.2).
3. Quorum check (§3.3): `2/3` active validator stake (`B-TREASURY-PROPOSAL.md` line 31).
4. Approval check: >50% voted must be for (`B-TREASURY-PROPOSAL.md`).
5. Execution: only at epoch boundary (`EPOCH_ROUNDS = 7_200`); release from vault index 0..7 (`B-TREASURY-PROPOSAL.md`).
6. `StakingState::claim()` releases from `TreasuryState` (`lib.rs:262`) to the treasury address or recipient; the proposal mechanism determines whether release is permitted.

---

## 5. Upgrade signaling mechanism (planned — Phase 25 / post-RFC-006)

Upgrade signaling is client-only / ledger-safe until adopted as a consensus rule (hard gate: RFC-006 must be solid first, per `AGENTS.md`; `TASKLIST.md` Phase 25 deferred).

### 5.1 Signal format (planned)

A validator broadcasts an upgrade-intent record (into `StatementBlock::statements`, placeholder `Vec<u8>` at `kovanica-types/src/block.rs:48-49`; VRF payload format `b"KUNA-VRF1"` already reserved at `block.rs` for wire-upgrade statements). Planned fields:

- `upgrade_epoch`: `u64` — epoch at which upgrade activates
- `target_version`: `String` — e.g. `v2.1.0`
- `change_digest`: `Hash` — BLAKE3 of the patch / binary hash
- `signature`: `Ed25519` (64 bytes) — validator's signing key over the above

Status: `StatementBlock::statements` is an empty placeholder; `compute_digest_statements()` only includes statements when `s.len() >= 137 && s[..9] == b"KUNA-VRF1"` (`block.rs`). No upgrade-intent parsing exists.

### 5.2 Activation rule (planned — consensus-safe only post-adoption)

- Signal is valid if signed by at least `validity_threshold = total_stake/3 + 1` (`committee.rs`) of the *current* committee.
- Activation requires `quorum_threshold = 2*total_stake/3 + 1` over a window of at least one epoch (epoch = 8 h = 7200 DAG rounds = 2400 leader heights; `EPOCH_ROUNDS` / `EPOCH_LEADER_HEIGHTS`).
- Once activated, the upgrade applies at the first `committed_leader_height` that is a multiple of `EPOCH_LEADER_HEIGHTS` (2400 leader heights) after the activation epoch.

Status: not implemented; no `node::not_implemented` stub for upgrade, but no `StatementBlock` parsing is present either.

---

## 6. CLI mapping — what exists vs stub

From `crates/kovanica-cli/src/main.rs` (command match at `main.rs` ~340-380):

| CLI command | Args struct | Implementation status | Key lines |
|---|---|---|---|
| `stake` | `StakeArgs` | **Implemented** (`cmd_stake` → `StakingState::bond_validator`) | `main.rs` ~347 |
| `unstake` | `UnstakeArgs` | **Implemented** (`cmd_unstake` → `unbond_validator`) | `main.rs` ~348 |
| `delegate` | `DelegateArgs` | **Implemented** (`cmd_delegate` → `StakingState::delegate`) | `main.rs` ~349 |
| `claim-rewards` | `ClaimRewardsArgs` | **Implemented** (`cmd_claim_rewards`) | `main.rs` ~350 |
| `propose` | `ProposeArgs` (`title`) | **Stub — `not_implemented`** (`"propose"` / `"kovanica_propose"`) | `main.rs:366-369` |
| `vote` | `VoteArgs` (`proposal_id` `u64`, `approve` `bool`) | **Stub — `not_implemented`** (`"vote"` / `"kovanica_vote"`) | `main.rs:372-375` |

`ProposeArgs` and `VoteArgs` are fully defined structurally but have no backing RPC or state mutation. `kovanica-staking/src/lib.rs` has no `submit_treasury_proposal` / `vote_for` methods (only `TreasuryProposal` sketched in docs; no `StakingState` fields for proposal tracking). `kovanica-types/src/` has `Vote` (consensus leader vote), not governance proposal vote.

---

## 7. Consensus / ledger / client classification (per `AGENTS.md` rules)

- **Proposal format (§2)**: client-only (format definition; does not change consensus).
- **Vote mechanism (§3)**: ledger-safe (uses existing `StakingState` / `Committee`; changes state only when executed at epoch boundary); becomes consensus-safe only after formal adoption by committee rules.
- **Treasury flow (§4)**: ledger-safe (`TreasuryState` existing; proposal-to-release linkage is planned).
- **Upgrade signaling (§5)**: client-only / ledger-safe (signal in `StatementBlock::statements`; no consensus rule change until adopted).
- **Thresholds (§3.3)**: consensus-safe because they reuse `Committee::new` arithmetic (`2f+1`, `f+1`) already used for leader commitment; proposal adoption of the same thresholds is safe.

---

## 8. Canonical constants (byte-identical to sources)

Reproduced from `kovanica-staking/src/lib.rs`, `kovanica-types/src/committee.rs`, `AGENTS.md` / RFC-006 equivalents (adapted to KUNA / kovanica naming):

- `TOTAL_SUPPLY = 90_200_000 * ONE_KUNA` (90.2 M KUNA; `lib.rs:44`)
- `MIN_VALIDATOR_STAKE = 50_000 * ONE_KUNA` (50 000 KUNA; `lib.rs:98`)
- `MIN_ACTIVE_VALIDATORS = 15`, `MAX_ACTIVE_VALIDATORS = 21` (`lib.rs:104-107`)
- `SUBSIDY_ERA_BLOCKS = 8_100_000`, `DECAY_NUM = 3`, `DECAY_DEN = 4`, `INITIAL_BLOCK_REWARD = 2.5 KUNA = 5*ONE_KUNA/2` (`lib.rs:82-91`)
- `UNBONDING_ROUNDS = 100_000` (`lib.rs:112`)
- `EPOCH_ROUNDS = 7_200` (`lib.rs:119`); `LEADER_INTERVAL_SECS = 12` (`lib.rs:66`); `BLOCKS_PER_YEAR = 2_628_000` (`lib.rs:72`)
- `TREASURY_TOTAL = 8_000_000 * ONE_KUNA`; `TREASURY_ANNUAL = 1_000_000 * ONE_KUNA`; `TREASURY_YEARS = 8` (`lib.rs:58-60`)
- `SLASH_PCT_BPS = 500` (5%; `lib.rs:356`)
- Quorum: `total_stake * 2 / 3 + 1`; Validity: `total_stake / 3 + 1` (`committee.rs`)

No rounding, no restatement differences.

---

## 9. Open gaps (listed explicitly — no invented fixes)

- `kovanica-types/src/`: no `Proposal`, `TreasuryProposal`, or governance `Vote` types (only consensus `Vote` at `vote.rs`).
- `kovanica-staking/src/lib.rs`: no `submit_treasury_proposal`, `vote_for`, `vote_against`, or proposal-state fields in `StakingState` (`lib.rs:418-433`).
- `kovanica-cli/src/`: `propose` / `vote` are `not_implemented`; argument structs lack proposal-type selector.
- `docs/GOVERNANCE.md` (this file): replaces 38-line skeleton; all sections marked [DRAFT — needs human review] because Phase 25 is `[ ]` NOT DONE.
- Upgrade-signaling `StatementBlock::statements` parsing not implemented (`block.rs:48`).
- Treasury-spend proposal-to-release linkage not implemented (`B-TREASURY-PROPOSAL.md` only).

---

*Written for docs.kovanica.online / RFC/KVP corpus. Matches RFC-authoring format (summary line, Status, Consensus impact, cross-links, draft marking). Commit reference: `a2ec2db` (work tree `kovanica` / `crates/kovanica-cli`, `crates/kovanica-staking`). Phase 25 status: not done (`TASKLIST.md` line 342, 414). Do not mark Shipped — that requires governance / human decision.*
