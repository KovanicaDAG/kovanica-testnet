# KUNA Tokenomics Specification

**Version:** 0.2.0  
**Status:** Locked for implementation (revised 2026-10-13)

---

## 1. Supply Overview

| Allocation                  | Amount (KUNA)   | % of Total | Notes                                      |
|-----------------------------|-----------------|------------|--------------------------------------------|
| Mining subsidy              | 81 000 000      | 89.80 %    | Emitted via block rewards                  |
| Treasury                    | 8 000 000       | 8.87 %     | 1 M / year × 8 years, linear vesting       |
| Genesis validator allocation| 1 000 000       | 1.11 %     | Split evenly across genesis validators     |
| Founder premine             | 200 000         | 0.22 %     | Unlocked at genesis                        |
| **Total supply**            | **90 200 000**  | 100 %      | Hard cap                                   |

Decimals: **9** (1 KUNA = 1 000 000 000 base units).

The genesis validator allocation is minted **once** at genesis: 1 000 000 KUNA are
split evenly across the genesis validator set. Each validator's share backs its
`MIN_VALIDATOR_STAKE` (50 000 KUNA) self-stake; the remainder is liquid balance.
See §7.2 for the deterministic split rule.

---

## 2. Block Reward Schedule

- **Initial reward:** 2.5 KUNA  
- **Decay:** × ¾ every **8 100 000** committed leader blocks (one era)  
- Reward is paid **only** to the author of a **committed leader block** in the DAG.
- Round length is **4 s**; with a wave of 3, one leader commits every **12 s**
  (`LEADER_INTERVAL_SECS = 12`). One era is therefore ≈ **3.08 years**.

### Approximate issuance per era

| Era | Reward       | Era issuance | Cumulative mining |
|-----|--------------|--------------|-------------------|
| 0   | 2.5 KUNA     | 20.25 M      | 20.25 M           |
| 1   | 1.875 KUNA   | 15.1875 M    | 35.4375 M         |
| 2   | 1.40625 KUNA | 11.390625 M  | 46.828125 M       |
| 3   | 1.0546875    | 8.54296875 M | 55.37109375 M     |
| …   | …            | …            | → 81 M            |

The geometric series sums exactly to `s₀ × era × 1/(1 − ¾) = 2.5 × 8 100 000 × 4 = 81 M`.
After ~40 eras the remaining emission becomes negligible and the mining subsidy
is effectively exhausted (≈ 12.3 years for ~99 %).

---

## 3. Reward Distribution (DAG binding)

In the Mysticeti-style DAG:

1. Consensus produces a `CommittedSubDag` containing a **leader block**.
2. The execution layer calls `StakingState::on_leader_committed(leader_author)`.
3. The current `committed_leader_height` is used to look up `block_reward(height)`.
4. The reward is credited to the **payout address** of the validator that authored the leader.
5. `committed_leader_height` is incremented and treasury vesting is advanced.

This guarantees that only **finalized, ordered leader blocks** mint new tokens.

Light-node share (`LIGHT_REWARD_BPS = 2 000`, 20 %): it is escrowed per
**light-set epoch** and settled once per epoch, i.e. every **2 400 committed
leaders ≈ 8 h** (`EPOCH_LEADER_HEIGHTS`, `epoch_for_height`; Toni 2026-10-23).
The beacon for an epoch is taken at its first height. A light node that
registers becomes active in the next light-set epoch (at most ≈ 8 h later).

---

## 4. Treasury Vesting

- Total: **8 000 000 KUNA**
- Schedule: **1 000 000 KUNA per year** for 8 years
- Conversion: `BLOCKS_PER_YEAR = 2 628 000` (≈ 1 committed leader / 12 s)
- Vesting is advanced automatically on every committed leader.
- The treasury address can `claim()` only the already-vested portion.

```text
year 0          year 1          year 2          …          year 8
|---------------|---------------|---------------|-----------|
0 KUNA          1 M             2 M             …          8 M (capped)
```

---

## 5. Staking Parameters

| Parameter                | Value                  |
|--------------------------|------------------------|
| Active validators        | 15 – 21                |
| Min stake to join        | 50 000 KUNA            |
| Unbonding period         | 100 000 committed leader blocks (~13.9 days at 12 s/leader) |
| Commission               | set by validator (bps) |
| Commission change cooldown | 7 200 committed leader blocks (≈ 1 day = 3 epochs of 8 h) |
| Slash jail               | 7 200 committed leader blocks (≈ 1 day = 3 epochs of 8 h, nominal) |

Rewards go to the validator’s configured `payout_address` (defaults to the staking address). Future versions may support auto-compounding or commission splits with delegators.

---

## 6. Circulating Supply Formula

```
circulating ≈ FOUNDER_PREMINE
            + GENESIS_VALIDATOR_ALLOCATION
            + total_mining_issued
            + treasury.vested
```

Capped at `TOTAL_SUPPLY`. The genesis set circulating supply is therefore
1 200 000 KUNA (premine + genesis allocation); treasury vests over time.

---

## 7. Implementation Locations

| Component                    | Crate / Module                          |
|-----------------------------|-----------------------------------------|
| Constants & emission math   | `kovanica-staking`                          |
| TreasuryState               | `kovanica-staking`                          |
| `on_leader_committed`       | `kovanica-staking`                          |
| Reward application on commit| `kovanica-execution::ExecutionContext`      |
| CommittedSubDag             | `kovanica-consensus`                        |

### 7.1 Canonical constants (`crates/kovanica-staking/src/lib.rs`)

| Constant | Canonical value |
|----------|-----------------|
| `DECIMALS` / `ONE_KUNA` | 9 decimals, 1 KUNA = 1 000 000 000 base units |
| `TOTAL_SUPPLY` | 90 200 000 KUNA (hard cap) |
| `FOUNDER_PREMINE` | 200 000 KUNA |
| `GENESIS_VALIDATOR_ALLOCATION` | 1 000 000 KUNA |
| `TREASURY_TOTAL` / `TREASURY_ANNUAL` / `TREASURY_YEARS` | 8 000 000 KUNA / 1 000 000 KUNA per year / 8 years (linear) |
| `MINING_SUBSIDY_BUDGET` | 81 000 000 KUNA |
| `INITIAL_BLOCK_REWARD` (s₀) | 2.5 KUNA per committed leader |
| `SUBSIDY_ERA_BLOCKS` | 8 100 000 committed leaders per era |
| `DECAY_NUM` / `DECAY_DEN` | × ¾ per era |
| `LEADER_INTERVAL_SECS` | 12 (4 s round × wave 3) |
| `BLOCKS_PER_YEAR` | 2 628 000 (treasury vesting conversion only) |
| `EPOCH_ROUNDS` | epoch = 8 h = 7200 DAG rounds = 2400 leader heights (validator rotation, decoupled from the era) |
| `MIN_VALIDATOR_STAKE` | 50 000 KUNA |
| `MIN_ACTIVE_VALIDATORS` / `MAX_ACTIVE_VALIDATORS` | 15 / 21 |
| `UNBONDING_ROUNDS` | 100 000 committed leader blocks (~13.9 days at 12 s/leader) |

`MINING_SUBSIDY_BUDGET` is derived, not hard-coded:

```
MINING_SUBSIDY_BUDGET = TOTAL_SUPPLY − FOUNDER_PREMINE − TREASURY_TOTAL
                        − GENESIS_VALIDATOR_ALLOCATION
                      = 90 200 000 − 200 000 − 8 000 000 − 1 000 000 = 81 000 000
```

### 7.2 Genesis validator allocation split

`genesis_validator_shares(n)` splits `GENESIS_VALIDATOR_ALLOCATION` across `n`
genesis validators as evenly as integer atoms allow:

- `base = ALLOCATION / n`, `remainder = ALLOCATION % n`
- the first `remainder` validators (sorted ascending by address) receive `base + 1`
- the shares sum to **exactly** `GENESIS_VALIDATOR_ALLOCATION`

Because each share must back a `MIN_VALIDATOR_STAKE` (50 000 KUNA) self-stake,
an even 1 000 000 KUNA split supports **at most 20 genesis validators**.
The minimum viable set is **5 validators** (each receives 200 000 KUNA, leaving
150 000 KUNA liquid after the 50 000 KUNA self-stake).

**Genesis validator count.** Testnet: **5 recommended**; the code enforces
only the maximum of 20 (a larger set cannot be funded from
`GENESIS_VALIDATOR_ALLOCATION` at `MIN_VALIDATOR_STAKE`, so `init_genesis`
bails), and smaller sets are accepted (local and test clusters use 1–4 nodes).
Mainnet (chain 1): **15–20 enforced** by `ensure_mainnet_genesis_validator_count`
in `init_genesis` and `--check-config`; the lower bound is
`MIN_ACTIVE_VALIDATORS` (15). The 5-validator genesis is for the chain 4
testnet (Toni, 2026-10-23). Raise `GENESIS_VALIDATOR_ALLOCATION` to support
more than 20.

These values are cross-checked by the unit tests in `kovanica-staking`
(`canonical_values_match_skeleton`, `genesis_validator_shares_sum_exactly_and_are_even`).

---

## 8. Future Governance Hooks

- Change `BLOCKS_PER_YEAR` (affects vesting speed)
- Adjust min stake / max validators
- Activate residual fee-burn or fee-to-stakers mechanisms once mining subsidy is low
