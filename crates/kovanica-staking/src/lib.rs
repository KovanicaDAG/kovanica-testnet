//! Staking, delegation, validator set management, token emission and treasury for Kovanica (KUNA).
//!
//! Tokenomics (locked):
//! - Total supply: 90_200_000 KUNA
//! - Founder premine: 200_000 KUNA
//! - Genesis validator allocation: 1_000_000 KUNA (split evenly, minted once)
//! - Treasury: 8_000_000 KUNA (1M/year × 8 years) with linear vesting
//! - Mining subsidy: 81_000_000 KUNA
//! - Initial block reward: 2.5 KUNA (paid to the author of a committed leader block)
//! - Decay: × 3/4 every 8_100_000 committed leaders
//! - Active validators: 15–21
//!
//! All canonical numbers above are shared with the tokenomics skeleton
//! (`kovanica-skeleton/staking/src/lib.rs`); this crate keeps them as `u64`
//! (the storage wire format). Cross-checked by the unit tests in this file.

#![deny(unsafe_code)]

pub mod light;
pub use light::{
    distribute_escrow, split_block_reward, LightNode, LightSet, LightSetError, LightWitness,
    SettleOutcome, LIGHT_REWARD_BPS, LIGHT_WITNESS_SLOTS, MAX_LIGHT_NODES, MIN_LIGHT_BOND,
};

use bincode::{DefaultOptions, Options};
use kovanica_types::{
    decode_with_version, encode_with_version, Address, Hash, PublicKey,
    SealCommitteeSnapshotMember, Stake, STAKING_STATE_VERSION, STAKING_STATE_VERSION_PREVIOUS,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap as HashMap;
use thiserror::Error;
use tracing::info;

// ============================================================
// Tokenomics constants (9 decimals)
// ============================================================

/// Ticker / display symbol of the native currency (display only; not
/// persisted, not part of any hash or signature domain).
pub const TICKER: &str = "KUNA";

/// Number of base units in 1 KUNA.
pub const DECIMALS: u32 = 9;
pub const ONE_KUNA: u64 = 1_000_000_000; // 10^9

/// Total maximum supply: 90.2 million KUNA.
pub const TOTAL_SUPPLY: u64 = 90_200_000 * ONE_KUNA;

/// Founder premine: 200_000 KUNA.
pub const FOUNDER_PREMINE: u64 = 200_000 * ONE_KUNA;

/// Genesis validator allocation: 1_000_000 KUNA.
///
/// Split evenly across the genesis validator set (see
/// [`genesis_validator_shares`]) and minted exactly once, at genesis. Each
/// validator locks `MIN_VALIDATOR_STAKE` from its share; the remainder stays
/// liquid in its account.
pub const GENESIS_VALIDATOR_ALLOCATION: u64 = 1_000_000 * ONE_KUNA;

/// Treasury allocation: 8 × 1_000_000 KUNA over 8 years.
pub const TREASURY_TOTAL: u64 = 8_000_000 * ONE_KUNA;
pub const TREASURY_ANNUAL: u64 = 1_000_000 * ONE_KUNA;
pub const TREASURY_YEARS: u32 = 8;

/// Seconds between consecutive **committed leader** blocks.
///
/// One leader is committed per wave; a wave is `WAVE_LENGTH = 3` rounds and a
/// round is targeted at 4 s, hence 12 s per committed leader.
pub const LEADER_INTERVAL_SECS: u64 = 12;

/// Number of committed-leader blocks that correspond to one year.
///
/// Used only for the treasury vesting schedule (tunable later via governance).
/// `31_536_000 / 12 = 2_628_000`.
pub const BLOCKS_PER_YEAR: u64 = 31_536_000 / LEADER_INTERVAL_SECS;

/// Mining subsidy budget: everything that is not premine, genesis validator
/// allocation or treasury.
pub const MINING_SUBSIDY_BUDGET: u64 =
    TOTAL_SUPPLY - FOUNDER_PREMINE - TREASURY_TOTAL - GENESIS_VALIDATOR_ALLOCATION; // 81M

/// Initial block reward: 2.5 KUNA.
///
/// (Skeleton name: `INITIAL_REWARD` — same value.)
pub const INITIAL_BLOCK_REWARD: u64 = 5 * ONE_KUNA / 2;

/// Subsidy era length in committed leaders (chosen so cumulative issuance ≈ 81M).
///
/// (Skeleton name: `ERA_LENGTH` — same value: 8_100_000.)
pub const SUBSIDY_ERA_BLOCKS: u64 = 8_100_000;

/// Decay factor numerator / denominator = 3/4.
pub const DECAY_NUM: u64 = 3;
pub const DECAY_DEN: u64 = 4;

// ============================================================
// Staking constants
// ============================================================

/// Minimum stake required to become a validator (in base units).
pub const MIN_VALIDATOR_STAKE: Stake = 50_000 * ONE_KUNA; // 50 000 KUNA

/// Minimum number of active validators (target range 15–21).
///
/// The set is considered under-provisioned below this size; new validators
/// should be admitted while active count < `MAX_ACTIVE_VALIDATORS`.
pub const MIN_ACTIVE_VALIDATORS: u32 = 15;

/// Maximum number of active validators (target range 15-21).
pub const MAX_ACTIVE_VALIDATORS: usize = 21;

/// Unbonding period, counted in **committed leader blocks** (≈ 13.9 days at
/// 12 s per committed leader: `1_200_000 s / 86_400`).
///
/// The historical name says "rounds", but the value is added to
/// `committed_leader_height`, which advances once per committed leader — not
/// once per DAG round. One committed leader is produced every `WAVE_LENGTH`
/// (3) rounds, so 100 000 committed leaders is 300 000 DAG rounds.
///
/// (Skeleton name: `UNBONDING_PERIOD` — same value: 100_000.)
pub const UNBONDING_ROUNDS: u64 = 100_000;

/// Jail length for a slashed validator, in committed leader heights (PRO-19).
///
/// A slashed validator is deactivated immediately and may not re-enter until
/// `committed_leader_height >= jailed_until_height`. `7_200` committed leaders
/// is about 1 day at 12 s/leader (`86_400 / 12`), which is Toni's 2026-10-23
/// decision ("jail about 1 day, `JAIL_ROUNDS = 7200`"), replacing the earlier
/// `21_600` (about 3 days). With the 8 h epoch (Toni 2026-10-23) that is
/// **3 epochs** (`3 * EPOCH_LEADER_HEIGHTS`), matching the original
/// "3 epochs / about 1 day" wording. Same unit and value as
/// [`COMMISSION_CHANGE_COOLDOWN`].
///
/// After the jail the validator returns only through an explicit stake
/// transaction (`reactivate_validator`); nothing re-activates it automatically.
///
/// The field is compared against `committed_leader_height` (heights), not DAG
/// rounds — see the note on `UNBONDING_ROUNDS` about the historical name.
pub const JAIL_ROUNDS: u64 = 7_200;

/// Epoch length in **DAG rounds** (7 200 × 4 s ≈ 8 h; Toni 2026-10-23).
/// Staking state is keyed by committed height, so it uses
/// [`EPOCH_LEADER_HEIGHTS`] (2 400 heights, the same 8 h) through
/// `kovanica_types::epoch_for_height`.
///
/// Deliberately decoupled from `SUBSIDY_ERA_BLOCKS` so the active validator set
/// keeps rotating frequently even though the subsidy era is long.
///
/// Canonical definition lives in `kovanica_types::EPOCH_ROUNDS`; re-exported
/// here so existing `kovanica_staking::EPOCH_ROUNDS` paths keep working and the
/// `EPOCH_ROUNDS` crate-value equality test in this crate guards drift.
pub use kovanica_types::{EPOCH_LEADER_HEIGHTS, EPOCH_ROUNDS};

/// Maximum consecutive missed leader rounds before a validator is marked offline.
///
/// At 12 s/leader, 100 missed leaders = 20 minutes of missed blocks.
/// This threshold balances liveness against transient network issues.
pub const MAX_MISSED_LEADERS_BEFORE_OFFLINE: u64 = 100;

/// Commission change cooldown in committed leader blocks.
///
/// At 12 s/leader, 7 200 blocks = 24 hours = 3 epochs of 8 h. A validator can
/// only change commission once per day to prevent gaming the system. The value
/// is unchanged by the 8 h epoch decision (it used to be written as
/// `EPOCH_ROUNDS`, which only coincided with one day while the epoch was
/// thought to be 7 200 leaders).
pub const COMMISSION_CHANGE_COOLDOWN: u64 = 3 * EPOCH_LEADER_HEIGHTS; // 7_200 blocks ≈ 24h

// ============================================================
// Emission schedule (mining rewards)
// ============================================================

/// Returns the block reward (in base units) for a given **committed leader height**.
///
/// In the DAG model the “height” is the sequential number of committed leader
/// blocks (not the raw round number). Reward starts at 2.5 KUNA and is
/// multiplied by 3/4 every SUBSIDY_ERA_BLOCKS committed leaders.
pub fn block_reward(committed_leader_height: u64) -> u64 {
    let era = committed_leader_height / SUBSIDY_ERA_BLOCKS;
    let mut reward = INITIAL_BLOCK_REWARD;

    for _ in 0..era {
        reward = reward.saturating_mul(DECAY_NUM) / DECAY_DEN;
        if reward == 0 {
            break;
        }
    }
    reward
}

/// Approximate cumulative mining issuance up to (but not including) `height`.
pub fn cumulative_mining_issuance(committed_leader_height: u64) -> u64 {
    let mut total = 0u64;
    let mut reward = INITIAL_BLOCK_REWARD;
    let mut remaining = committed_leader_height;

    while remaining > 0 && reward > 0 {
        let blocks_in_this_era = remaining.min(SUBSIDY_ERA_BLOCKS);
        total = total.saturating_add(reward.saturating_mul(blocks_in_this_era));
        remaining -= blocks_in_this_era;
        reward = reward.saturating_mul(DECAY_NUM) / DECAY_DEN;
    }
    total.min(MINING_SUBSIDY_BUDGET)
}

/// Deterministically split [`GENESIS_VALIDATOR_ALLOCATION`] across `n` genesis
/// validators.
///
/// Shares are equal except for the integer remainder, which is handed out one
/// atom at a time to the first entries. The returned shares therefore sum to
/// exactly `GENESIS_VALIDATOR_ALLOCATION`, which keeps the supply invariant
/// exact even though `1_000_000 KUNA` is not divisible by `n` in atoms.
/// Returns an empty vector when `n == 0`.
pub fn genesis_validator_shares(n: usize) -> Vec<u64> {
    if n == 0 {
        return Vec::new();
    }
    let n = n as u64;
    let base = GENESIS_VALIDATOR_ALLOCATION / n;
    let mut remainder = GENESIS_VALIDATOR_ALLOCATION % n;
    (0..n)
        .map(|_| {
            if remainder > 0 {
                remainder -= 1;
                base + 1
            } else {
                base
            }
        })
        .collect()
}

// ============================================================
// Treasury vesting
// ============================================================

/// Treasury vesting state.
///
/// 8 000 000 KUNA are released linearly over 8 years (1 000 000 KUNA per year).
/// Vesting is driven by committed-leader height (using BLOCKS_PER_YEAR as the
/// conversion factor). The treasury address is fixed at genesis.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TreasuryState {
    /// Fixed treasury address (set at genesis).
    pub treasury_address: Address,
    /// Total amount already vested and available to the treasury.
    pub vested: u64,
    /// Total amount already claimed / transferred out of the treasury.
    pub claimed: u64,
    /// Genesis committed-leader height (usually 0).
    pub start_height: u64,
}

impl TreasuryState {
    pub fn new(treasury_address: Address, start_height: u64) -> Self {
        Self {
            treasury_address,
            vested: 0,
            claimed: 0,
            start_height,
        }
    }

    /// How many full years have elapsed since start_height.
    fn years_elapsed(&self, current_height: u64) -> u32 {
        if current_height <= self.start_height {
            return 0;
        }
        let blocks = current_height - self.start_height;
        let years = (blocks / BLOCKS_PER_YEAR) as u32;
        years.min(TREASURY_YEARS)
    }

    /// Total amount that should be vested at the given committed-leader height.
    pub fn expected_vested(&self, current_height: u64) -> u64 {
        let years = self.years_elapsed(current_height);
        (years as u64)
            .saturating_mul(TREASURY_ANNUAL)
            .min(TREASURY_TOTAL)
    }

    /// Advance vesting to the given height. Returns the newly vested amount
    /// (which is added to `self.vested`).
    pub fn advance(&mut self, current_height: u64) -> u64 {
        let expected = self.expected_vested(current_height);
        let newly_vested = expected.saturating_sub(self.vested);
        self.vested = expected;
        newly_vested
    }

    /// Amount currently available to be claimed by the treasury.
    pub fn available(&self) -> u64 {
        self.vested.saturating_sub(self.claimed)
    }

    /// Claim (transfer out) up to `amount` from the available treasury balance.
    /// Returns the actual amount claimed.
    pub fn claim(&mut self, amount: u64) -> Result<u64, StakingError> {
        let avail = self.available();
        if amount == 0 || avail == 0 {
            return Ok(0);
        }
        let claimed = amount.min(avail);
        self.claimed = self.claimed.saturating_add(claimed);
        Ok(claimed)
    }

    /// Check how much is currently claimable from the treasury.
    pub fn claimable(&self) -> u64 {
        self.available()
    }
}

// ============================================================
// Reward distribution (tied to committed leader blocks)
// ============================================================

/// Result of applying a block reward for a committed leader.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RewardOutcome {
    /// Authority index that proposed the leader block.
    pub leader_author: u16,
    /// Address that receives the reward (validator payout address).
    pub recipient: Address,
    /// Amount paid (in base units).
    pub amount: u64,
    /// Committed-leader height that was used for the reward calculation.
    pub height: u64,
}

/// Applies the mining reward for a newly committed leader block.
///
/// Called by the execution layer every time a `CommittedSubDag` is finalized.
/// The reward goes to the validator that authored the leader block.
///
/// `committed_leader_height` is a monotonically increasing counter of how many
/// leader blocks have been committed so far (starts at 0).
pub fn apply_leader_reward(
    committed_leader_height: u64,
    leader_author: u16,
    recipient: Address,
) -> RewardOutcome {
    let amount = block_reward(committed_leader_height);
    RewardOutcome {
        leader_author,
        recipient,
        amount,
        height: committed_leader_height,
    }
}

// ============================================================
// Staking types
// ============================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub address: Address,
    pub stake: Stake,
    pub commission_bps: u16, // basis points (100 = 1%)
    pub active: bool,
    /// Address that receives block rewards (defaults to `address`).
    pub payout_address: Address,
    /// Public key for consensus voting (optional for backward compatibility;
    /// required for active validators in the committee).
    #[serde(default)]
    pub public_key: Option<PublicKey>,
    /// VRF public key for verifiable leader selection (optional).
    #[serde(default)]
    pub vrf_public_key: Option<VrfPublicKey>,
    /// Consecutive missed leader rounds (for offline detection).
    /// Reset to 0 when the validator produces a committed leader block.
    #[serde(default)]
    pub missed_leader_count: u64,
    /// Last committed-leader height when this validator produced a leader block.
    #[serde(default)]
    pub last_online_height: u64,
    /// Committed-leader height when commission was last changed.
    /// Used to enforce a cooldown period before the next change.
    #[serde(default)]
    pub last_commission_change_height: u64,
    /// Set once this validator has been slashed for provable misbehaviour.
    #[serde(default)]
    pub slashed: bool,
    /// Committed-leader height at which the slash jail ends (PRO-19).
    ///
    /// * `0` on a slashed record means "no jail" — the legacy F7 semantics:
    ///   the validator stays out **forever**. This is what pre-jail rows
    ///   (untagged legacy, or StakingState v1) decode to, so the F7 guarantee
    ///   is preserved for records slashed before the jail existed.
    /// * `> 0` on a slashed record is the jail end. Before it, a stake or a
    ///   reactivation is rejected; at/after it, an explicit stake transaction
    ///   with `stake >= MIN_VALIDATOR_STAKE` clears `slashed` and the jail.
    ///
    /// Nothing ever re-activates automatically.
    #[serde(default)]
    pub jailed_until_height: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Delegation {
    pub delegator: Address,
    pub validator: Address,
    pub amount: Stake,
}

/// Fixed slash percentage (basis points); 500 bps = 5%.
pub const SLASH_PCT_BPS: u16 = 500;

/// VRF public key for verifiable leader selection (optional).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct VrfPublicKey(pub [u8; 32]);

impl VrfPublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Unbonding queue entry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UnbondingEntry {
    pub delegator: Address,
    pub validator: Address,
    pub amount: Stake,
    /// Committed-leader height at which the unbond becomes withdrawable.
    pub release_height: u64,
}

/// Double-sign evidence (skeleton — fixed % slash applied).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DoubleSignEvidence {
    pub validator: Address,
    pub height: u64,
}

#[derive(Error, Debug)]
pub enum StakingError {
    #[error("Insufficient stake")]
    InsufficientStake,
    #[error("Validator set full")]
    ValidatorSetFull,
    #[error("Not a validator")]
    NotValidator,
    #[error("Still unbonding")]
    StillUnbonding,
    #[error("No delegation found")]
    NoDelegation,
    #[error("Unbonding not complete")]
    UnbondNotComplete,
    #[error("Evidence already processed")]
    EvidenceProcessed,
    #[error("Treasury has insufficient available balance")]
    TreasuryInsufficient,
    #[error("Validator already registered")]
    ValidatorExists,
    #[error("Commission must be <= 10000 bps")]
    InvalidCommission,
    #[error("Remaining self-stake would be below MIN_VALIDATOR_STAKE")]
    BelowMinimumStake,
    #[error("Commission change is on cooldown; try again later")]
    CommissionCooldown,
    #[error("Validator was slashed and cannot re-enter the active set")]
    ValidatorSlashed,
}

/// Combined staking + emission + treasury state.
#[derive(Default, Serialize, Deserialize)]
pub struct StakingState {
    pub validators: Vec<ValidatorInfo>,
    pub delegations: Vec<Delegation>,
    pub total_staked: Stake,
    /// Monotonically increasing counter of committed leader blocks.
    pub committed_leader_height: u64,
    /// Total mining rewards issued so far.
    pub total_mining_issued: u64,
    /// Cumulative mining rewards credited per recipient address.
    #[serde(default)]
    pub reward_totals: HashMap<Address, u64>,
    /// Unbonding queue: delegations being withdrawn.
    pub unbonding_queue: Vec<UnbondingEntry>,
    /// Treasury vesting state (None until genesis configures it).
    pub treasury: Option<TreasuryState>,
}

/// Historical `ValidatorInfo` shape written before the PRO-19 jail
/// (`c8800ac` untagged rows and StakingState v1): 11 fields, `slashed` present.
#[derive(Deserialize)]
struct ValidatorInfoV1 {
    address: Address,
    stake: Stake,
    commission_bps: u16,
    active: bool,
    payout_address: Address,
    public_key: Option<PublicKey>,
    vrf_public_key: Option<VrfPublicKey>,
    missed_leader_count: u64,
    last_online_height: u64,
    last_commission_change_height: u64,
    slashed: bool,
}

/// Oldest `ValidatorInfo` shape (pre-`c8800ac`): 10 fields, no `slashed`.
#[derive(Deserialize)]
struct ValidatorInfoV0 {
    address: Address,
    stake: Stake,
    commission_bps: u16,
    active: bool,
    payout_address: Address,
    public_key: Option<PublicKey>,
    vrf_public_key: Option<VrfPublicKey>,
    missed_leader_count: u64,
    last_online_height: u64,
    last_commission_change_height: u64,
}

/// A `StakingState` whose validator payload uses a historical `ValidatorInfo`.
///
/// Field order, names, and `serde` defaults mirror `StakingState` exactly, so
/// the only difference from the current layout is `V`.
#[derive(Deserialize)]
struct StakingStateLegacy<V> {
    validators: Vec<V>,
    delegations: Vec<Delegation>,
    total_staked: Stake,
    committed_leader_height: u64,
    total_mining_issued: u64,
    #[serde(default)]
    reward_totals: HashMap<Address, u64>,
    unbonding_queue: Vec<UnbondingEntry>,
    treasury: Option<TreasuryState>,
}

trait LegacyValidator {
    /// Lift a pre-jail record, defaulting the jail to 0 (permanent for any
    /// record that was already slashed — the F7 guarantee).
    fn lift(self) -> ValidatorInfo;
}

impl LegacyValidator for ValidatorInfoV1 {
    fn lift(self) -> ValidatorInfo {
        ValidatorInfo {
            address: self.address,
            stake: self.stake,
            commission_bps: self.commission_bps,
            active: self.active,
            payout_address: self.payout_address,
            public_key: self.public_key,
            vrf_public_key: self.vrf_public_key,
            missed_leader_count: self.missed_leader_count,
            last_online_height: self.last_online_height,
            last_commission_change_height: self.last_commission_change_height,
            slashed: self.slashed,
            jailed_until_height: 0,
        }
    }
}

impl LegacyValidator for ValidatorInfoV0 {
    fn lift(self) -> ValidatorInfo {
        ValidatorInfo {
            address: self.address,
            stake: self.stake,
            commission_bps: self.commission_bps,
            active: self.active,
            payout_address: self.payout_address,
            public_key: self.public_key,
            vrf_public_key: self.vrf_public_key,
            missed_leader_count: self.missed_leader_count,
            last_online_height: self.last_online_height,
            last_commission_change_height: self.last_commission_change_height,
            slashed: false,
            jailed_until_height: 0,
        }
    }
}

impl<V: LegacyValidator> StakingStateLegacy<V> {
    fn lift(self) -> StakingState {
        StakingState {
            validators: self
                .validators
                .into_iter()
                .map(LegacyValidator::lift)
                .collect(),
            delegations: self.delegations,
            total_staked: self.total_staked,
            committed_leader_height: self.committed_leader_height,
            total_mining_issued: self.total_mining_issued,
            reward_totals: self.reward_totals,
            unbonding_queue: self.unbonding_queue,
            treasury: self.treasury,
        }
    }
}

impl StakingState {
    pub fn new() -> Self {
        Self {
            validators: Vec::new(),
            delegations: Vec::new(),
            total_staked: 0,
            committed_leader_height: 0,
            total_mining_issued: 0,
            reward_totals: HashMap::new(),
            unbonding_queue: Vec::new(),
            treasury: None,
        }
    }

    /// Serialize StakingState with versioned encoding.
    ///
    /// Format: magic byte (0x4B) + version ([`STAKING_STATE_VERSION`], currently
    /// 2) + bincode payload.
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        let payload = bincode::serialize(self)?;
        Ok(encode_with_version(STAKING_STATE_VERSION, &payload))
    }

    /// Load staking state from bytes with backward compatibility.
    ///
    /// Handles:
    /// - Current versioned format (v2): `ValidatorInfo` with `jailed_until_height`
    /// - Previous versioned format (v1): `ValidatorInfo` with `slashed`, no jail
    ///   (lifted with `jailed_until_height = 0`, preserving F7)
    /// - Old untagged formats: 11-field `ValidatorInfo` (`slashed`) or 10-field
    ///   (no `slashed`), tried newest-first with `reject_trailing_bytes`
    /// - Unknown version: clear error
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        // Use bincode's default options with fixint encoding (same as serialize).
        // Reject trailing bytes (do NOT allow_trailing_bytes) to detect corruption.
        let options = DefaultOptions::new()
            .with_fixint_encoding()
            .with_no_limit()
            .reject_trailing_bytes();

        // Check for versioned encoding
        match decode_with_version(bytes) {
            Ok((STAKING_STATE_VERSION, payload)) => {
                // Current versioned format.
                options.deserialize::<StakingState>(payload)
            }
            Ok((STAKING_STATE_VERSION_PREVIOUS, payload)) => {
                // Previous StakingState layout: ValidatorInfo had `slashed` but
                // no `jailed_until_height`. Lift every record with a jail height
                // of 0, which keeps a pre-jail slashed record permanently out
                // (F7) while leaving un-slashed records untouched.
                StakingState::deserialize_legacy_validators(payload, options, true)
            }
            Ok((v, _)) => {
                // Known magic but unknown version
                Err(Box::new(bincode::ErrorKind::Custom(format!(
                    "staking state decode error: unknown version {}",
                    v
                ))))
            }
            Err("no version prefix") => {
                // Untagged rows written before the version prefix existed. Try
                // each historical layout in newest-first order; the first that
                // consumes the whole buffer (reject_trailing_bytes) wins.
                //   1. c8800ac/f3675d3: 11-field ValidatorInfo (`slashed`, no jail)
                //   2. pre-c8800ac: 10-field ValidatorInfo (no `slashed`)
                if let Ok(state) = options.deserialize::<StakingState>(bytes) {
                    return Ok(state);
                }
                for has_slashed in [true, false] {
                    match StakingState::deserialize_legacy_validators(bytes, options, has_slashed) {
                        Ok(state) => return Ok(state),
                        Err(_) => continue,
                    }
                }
                Err(Box::new(bincode::ErrorKind::Custom(
                    "staking state decode error: untagged bytes match no known layout".to_string(),
                )))
            }
            Err(e) => {
                // Truncated or other error
                Err(Box::new(bincode::ErrorKind::Custom(format!(
                    "staking state decode error: {}",
                    e
                ))))
            }
        }
    }

    /// Decode a pre-jail row with an exact historical `ValidatorInfo` layout.
    ///
    /// `has_slashed` selects the `ValidatorInfo` shape that was written:
    /// `false` for the oldest untagged rows (10 fields, no `slashed`) and
    /// `true` for the `c8800ac` untagged rows and StakingState version 1
    /// (11 fields, `slashed` present but no jail height). Both predate the
    /// PRO-19 jail, so every record lifts with `jailed_until_height: 0`,
    /// which keeps a previously slashed record permanently barred (F7).
    ///
    /// Decoding goes through bincode's `Options::deserialize`, so
    /// `reject_trailing_bytes` is enforced exactly as for the current format.
    fn deserialize_legacy_validators<O: Options>(
        bytes: &[u8],
        options: O,
        has_slashed: bool,
    ) -> Result<Self, bincode::Error> {
        if has_slashed {
            let raw: StakingStateLegacy<ValidatorInfoV1> = options.deserialize(bytes)?;
            Ok(raw.lift())
        } else {
            let raw: StakingStateLegacy<ValidatorInfoV0> = options.deserialize(bytes)?;
            Ok(raw.lift())
        }
    }

    /// Configure treasury at genesis.
    pub fn init_treasury(&mut self, treasury_address: Address) {
        self.treasury = Some(TreasuryState::new(treasury_address, 0));
    }

    /// Try to activate a new validator.
    pub fn join_validator(
        &mut self,
        address: Address,
        stake: Stake,
        commission_bps: u16,
        payout_address: Option<Address>,
        public_key: Option<PublicKey>,
        vrf_public_key: Option<VrfPublicKey>,
    ) -> Result<(), StakingError> {
        if stake < MIN_VALIDATOR_STAKE {
            return Err(StakingError::InsufficientStake);
        }
        if commission_bps > 10_000 {
            return Err(StakingError::InvalidCommission);
        }
        if self.validators.iter().any(|v| v.address == address) {
            return Err(StakingError::ValidatorExists);
        }
        if self.validators.iter().filter(|v| v.active).count() >= MAX_ACTIVE_VALIDATORS {
            return Err(StakingError::ValidatorSetFull);
        }

        self.validators.push(ValidatorInfo {
            address,
            stake,
            commission_bps,
            active: true,
            payout_address: payout_address.unwrap_or(address),
            public_key,
            vrf_public_key,
            missed_leader_count: 0,
            last_online_height: self.committed_leader_height,
            last_commission_change_height: self.committed_leader_height,
            slashed: false,
            jailed_until_height: 0,
        });
        self.total_staked += stake;
        Ok(())
    }

    /// Reactivate an existing, currently-inactive validator with an explicit
    /// self-stake of `amount`.
    ///
    /// F7 (Toni's decision): there is NO automatic return to the active set —
    /// an evicted/offline or fully-unbonded validator returns ONLY when it
    /// explicitly submits a new stake transaction. This is that path.
    ///
    /// Rules:
    /// * The address MUST already have a validator record; otherwise
    ///   [`StakingError::NotValidator`] and the caller uses [`Self::join_validator`].
    /// * A currently-`active` record is not re-activated here; that is a
    ///   [`Self::bond_validator`] (top-up) call — returns
    ///   [`StakingError::ValidatorExists`] to keep the two paths disjoint.
    /// * The post-stake stake (`existing + amount`, the same quantity
    ///   [`Self::committee_order`] checks) MUST reach [`MIN_VALIDATOR_STAKE`]; a
    ///   slashed record (whose stake fell below the minimum) therefore stays out
    ///   until it is topped back up to the minimum, and is never silently
    ///   reactivated with too little at stake.
    /// * Reactivation counts toward [`MAX_ACTIVE_VALIDATORS`]; a full set
    ///   returns [`StakingError::ValidatorSetFull`].
    /// * `missed_leader_count` is reset so the reactivated validator starts a
    ///   clean liveness window.
    pub fn reactivate_validator(
        &mut self,
        address: Address,
        amount: Stake,
    ) -> Result<(), StakingError> {
        if amount == 0 {
            return Err(StakingError::InsufficientStake);
        }
        let v_idx = self
            .validators
            .iter()
            .position(|v| v.address == address)
            .ok_or(StakingError::NotValidator)?;
        if self.validators[v_idx].active {
            return Err(StakingError::ValidatorExists);
        }
        // Slashed records are barred while the jail runs. A *legacy* slashed
        // record (decoded with `jailed_until_height == 0`) stays out forever:
        // F7's "never re-enter" guarantee is preserved for anything slashed
        // before the jail existed. A jailed record (height > 0) may return,
        // but only through this explicit stake transaction and only once the
        // jail has elapsed at the current committed-leader height. Nothing
        // reactivates on its own — see `slash_validator`.
        if self.validators[v_idx].slashed {
            let jail_end = self.validators[v_idx].jailed_until_height;
            if jail_end == 0 || self.committed_leader_height < jail_end {
                return Err(StakingError::ValidatorSlashed);
            }
        }
        let topped_up = self.validators[v_idx].stake.saturating_add(amount);
        if topped_up < MIN_VALIDATOR_STAKE {
            return Err(StakingError::InsufficientStake);
        }
        if self.validators.iter().filter(|v| v.active).count() >= MAX_ACTIVE_VALIDATORS {
            return Err(StakingError::ValidatorSetFull);
        }
        let committed_height = self.committed_leader_height;
        let v = &mut self.validators[v_idx];
        v.stake = topped_up;
        v.active = true;
        v.missed_leader_count = 0;
        v.last_online_height = committed_height;
        // Serving the jail clears both flags; the record rejoins as un-slashed.
        v.slashed = false;
        v.jailed_until_height = 0;
        self.total_staked = self.total_staked.saturating_add(amount);
        Ok(())
    }

    /// Validators in consensus committee order: active with
    /// `stake >= MIN_VALIDATOR_STAKE`, top [`MAX_ACTIVE_VALIDATORS`] by stake
    /// (ties by address), then sorted by address. The position in this list
    /// is the authority index. Mirrors `kovanica-node::build_committee` exactly.
    pub fn committee_order(&self) -> Vec<&ValidatorInfo> {
        let mut active: Vec<&ValidatorInfo> = self
            .validators
            .iter()
            .filter(|v| v.active && v.stake >= MIN_VALIDATOR_STAKE)
            .collect();
        active.sort_by(|a, b| {
            b.stake
                .cmp(&a.stake)
                .then_with(|| a.address.0.cmp(&b.address.0))
        });
        active.truncate(MAX_ACTIVE_VALIDATORS);
        active.sort_by_key(|v| v.address.0);
        active
    }

    /// Validator behind a consensus authority index (identity-based: the
    /// committee is ordered by validator address/key, not by insertion
    /// position in `validators`).
    pub fn authority_validator(&self, authority_index: u16) -> Option<&ValidatorInfo> {
        self.committee_order()
            .get(authority_index as usize)
            .copied()
    }

    /// Look up payout address for a given authority index.
    pub fn payout_address_for(&self, authority_index: u16) -> Option<Address> {
        self.authority_validator(authority_index)
            .map(|v| v.payout_address)
    }

    /// Validator record by identity address (regardless of `active`).
    pub fn validator(&self, address: Address) -> Option<&ValidatorInfo> {
        self.validators.iter().find(|v| v.address == address)
    }

    /// Committee member by identity address: active and above
    /// [`MIN_VALIDATOR_STAKE`], i.e. exactly the set [`Self::committee_order`]
    /// would include.
    ///
    /// Leader rewards must be resolved through this predicate, never through a
    /// positional authority index, because the live committee order can change
    /// mid-epoch (unbond, slash, liveness eviction).
    pub fn active_validator(&self, address: Address) -> Option<&ValidatorInfo> {
        self.validators
            .iter()
            .find(|v| v.address == address && v.active && v.stake >= MIN_VALIDATOR_STAKE)
    }

    /// Snapshot of the current committee in authority-index order, in the
    /// shape persisted in the `EPOCH_COMMITTEE` table.
    ///
    /// `committee_order()` is the single source of the ordering (stake desc,
    /// ties by address, top [`MAX_ACTIVE_VALIDATORS`], re-sorted by address);
    /// the enumerate position is the authority index. Returns `None` when the
    /// committee is empty or a member has no consensus public key — such a
    /// committee cannot be frozen, so callers must fall back rather than store
    /// a snapshot with holes in the index sequence.
    pub fn epoch_committee_snapshot(&self) -> Option<Vec<SealCommitteeSnapshotMember>> {
        let committee = self.committee_order();
        if committee.is_empty() {
            return None;
        }
        let mut members = Vec::with_capacity(committee.len());
        for (index, validator) in committee.iter().enumerate() {
            members.push(SealCommitteeSnapshotMember {
                index: index as u16,
                public_key: validator.public_key?,
                stake: validator.stake,
                vrf_public_key: validator
                    .vrf_public_key
                    .as_ref()
                    .map(|key| PublicKey(key.0)),
            });
        }
        Some(members)
    }

    /// Cumulative mining rewards credited to `address` so far (accounting only;
    /// spendable balance updates are applied by the execution layer).
    pub fn reward_total(&self, address: &Address) -> u64 {
        self.reward_totals.get(address).copied().unwrap_or(0)
    }

    /// Total amount delegated to `validator` by delegators.
    pub fn delegated_to(&self, validator: Address) -> Stake {
        self.delegations
            .iter()
            .filter(|d| d.validator == validator)
            .map(|d| d.amount)
            .fold(0, Stake::saturating_add)
    }

    /// Validator's own bonded stake (`stake` minus delegations).
    pub fn self_stake(&self, validator: Address) -> Stake {
        self.validators
            .iter()
            .find(|v| v.address == validator)
            .map(|v| v.stake.saturating_sub(self.delegated_to(validator)))
            .unwrap_or(0)
    }

    /// Add `amount` of self-stake to an existing active validator.
    pub fn bond_validator(&mut self, address: Address, amount: Stake) -> Result<(), StakingError> {
        if amount == 0 {
            return Err(StakingError::InsufficientStake);
        }
        let v = self
            .validators
            .iter_mut()
            .find(|v| v.address == address && v.active)
            .ok_or(StakingError::NotValidator)?;
        v.stake = v.stake.saturating_add(amount);
        self.total_staked = self.total_staked.saturating_add(amount);
        Ok(())
    }

    /// Start unbonding `amount` of a validator's own stake. The remaining
    /// self-stake must be 0 (validator deactivated) or `>= MIN_VALIDATOR_STAKE`.
    /// Funds go to the unbonding queue (`UNBONDING_ROUNDS`).
    pub fn unbond_validator(
        &mut self,
        address: Address,
        amount: Stake,
    ) -> Result<(), StakingError> {
        if amount == 0 {
            return Err(StakingError::InsufficientStake);
        }
        let own = self.self_stake(address);
        let v_idx = self
            .validators
            .iter()
            .position(|v| v.address == address)
            .ok_or(StakingError::NotValidator)?;
        if amount > own {
            return Err(StakingError::InsufficientStake);
        }
        let remaining = own - amount;
        if remaining != 0 && remaining < MIN_VALIDATOR_STAKE {
            return Err(StakingError::BelowMinimumStake);
        }
        let v = &mut self.validators[v_idx];
        v.stake -= amount;
        let deactivated = remaining == 0 && v.active;
        if remaining == 0 {
            v.active = false;
        }
        self.total_staked = self.total_staked.saturating_sub(amount);
        self.unbonding_queue.push(UnbondingEntry {
            delegator: address,
            validator: address,
            amount,
            release_height: self
                .committed_leader_height
                .saturating_add(UNBONDING_ROUNDS),
        });
        // A full unbond deactivates the validator unconditionally. There is no
        // automatic refill: re-entry into the active set happens ONLY via a new
        // stake transaction (`join_validator`). This keeps the departure
        // deterministic and avoids resurrecting an evicted/unbonded validator.
        let _ = deactivated;
        Ok(())
    }

    /// Called by the execution layer when a leader block is committed,
    /// resolving the leader from its **live** authority index.
    ///
    /// Prefer [`Self::on_leader_committed_resolved`] on the execution path:
    /// authority indices are pinned by the epoch committee snapshot, while the
    /// live order shifts whenever a validator joins, unbonds, is slashed or is
    /// evicted mid-epoch. This index-based entry point remains for callers
    /// that already hold a live-index identity (tests, genesis bootstrap).
    ///
    /// 1. Calculates the reward for the current `committed_leader_height`
    /// 2. Advances the height counter
    /// 3. Advances treasury vesting
    /// 4. Updates validator liveness (online/offline detection)
    /// 5. Returns the RewardOutcome so the caller can credit the balance
    pub fn on_leader_committed(
        &mut self,
        leader_author: u16,
    ) -> Result<RewardOutcome, StakingError> {
        let leader = self
            .authority_validator(leader_author)
            .map(|v| v.address)
            .ok_or(StakingError::NotValidator)?;
        self.on_leader_committed_resolved(leader_author, leader)
    }

    /// Commit a leader whose identity (`leader`) was resolved by the caller —
    /// on the execution path, from the epoch committee snapshot that assigned
    /// `leader_author`.
    ///
    /// Fails with [`StakingError::NotValidator`] when `leader` is no longer an
    /// active, sufficiently staked committee member (e.g. it was slashed or
    /// unbonded inside this very sub-DAG). Callers that must not halt the chain
    /// then use [`Self::on_leader_committed_forfeited_resolved`].
    pub fn on_leader_committed_resolved(
        &mut self,
        leader_author: u16,
        leader: Address,
    ) -> Result<RewardOutcome, StakingError> {
        let recipient = self
            .active_validator(leader)
            .map(|v| v.payout_address)
            .ok_or(StakingError::NotValidator)?;
        let amount = block_reward(self.committed_leader_height);
        Ok(self.commit_leader(leader_author, Some(leader), recipient, amount))
    }

    /// Commit a leader that is no longer resolvable in the active committee —
    /// e.g. it equivocated and was slashed in the very sub-DAG it led (PRO-19).
    ///
    /// The reward is forfeited (no mint, no payout) but all consensus
    /// bookkeeping still advances: `committed_leader_height`, liveness counters,
    /// and treasury vesting. This makes a misbehaving leader unable to halt the
    /// chain simply by being slashed mid-round.
    pub fn on_leader_committed_forfeited(&mut self, leader_author: u16) -> RewardOutcome {
        let leader = self.authority_validator(leader_author).map(|v| v.address);
        self.on_leader_committed_forfeited_resolved(leader_author, leader)
    }

    /// Forfeit a leader whose identity was resolved from the epoch committee.
    ///
    /// `leader = None` means the authority index is not a member of that
    /// committee; the height/liveness/treasury transitions still run and no
    /// balance is credited. Liveness skips the resolved leader **by address**,
    /// so a shifted live order cannot charge the wrong validator with a miss.
    pub fn on_leader_committed_forfeited_resolved(
        &mut self,
        leader_author: u16,
        leader: Option<Address>,
    ) -> RewardOutcome {
        let recipient = leader
            .and_then(|address| self.validator(address))
            .map(|v| v.payout_address)
            .unwrap_or(Address([0u8; 32]));
        self.commit_leader(leader_author, leader, recipient, 0)
    }

    /// Shared leader-commit bookkeeping for both the paid and the forfeited
    /// case. `amount == 0` performs no mint and records no reward total, but the
    /// height and liveness transitions are identical.
    fn commit_leader(
        &mut self,
        leader_author: u16,
        leader: Option<Address>,
        recipient: Address,
        amount: u64,
    ) -> RewardOutcome {
        let height = self.committed_leader_height;
        let outcome = RewardOutcome {
            leader_author,
            recipient,
            amount,
            height,
        };

        // Update global counters
        self.committed_leader_height = height.saturating_add(1);
        self.total_mining_issued = self
            .total_mining_issued
            .saturating_add(outcome.amount)
            .min(MINING_SUBSIDY_BUDGET);

        // Per-recipient reward accounting (nothing to record for a forfeit)
        if outcome.amount > 0 {
            *self.reward_totals.entry(recipient).or_insert(0) = self
                .reward_totals
                .get(&recipient)
                .copied()
                .unwrap_or(0)
                .saturating_add(outcome.amount);
        }
        // Advance treasury vesting
        if let Some(ref mut treasury) = self.treasury {
            treasury.advance(self.committed_leader_height);
        }

        // Validator liveness: reset missed count for the leader, increment for
        // others. Identity-based, so a shifted live index cannot credit one
        // validator with another's leadership.
        self.validator_online_by_address(leader);
        self.advance_validator_liveness_by_address(leader);

        outcome
    }

    /// Current circulating supply approximation (premine + genesis validator
    /// allocation + mining issued + vested treasury).
    pub fn circulating_supply(&self) -> u64 {
        let treasury_vested = self.treasury.as_ref().map(|t| t.vested).unwrap_or(0);
        FOUNDER_PREMINE
            .saturating_add(GENESIS_VALIDATOR_ALLOCATION)
            .saturating_add(self.total_mining_issued)
            .saturating_add(treasury_vested)
            .min(TOTAL_SUPPLY)
    }

    /// Claim available treasury funds.
    /// Returns the amount actually claimed (may be less than requested if not enough vested).
    pub fn claim_treasury(&mut self, amount: u64) -> Result<u64, StakingError> {
        let treasury = self
            .treasury
            .as_mut()
            .ok_or(StakingError::TreasuryInsufficient)?;
        let claimed = treasury.claim(amount)?;
        Ok(claimed)
    }

    /// Current staking epoch derived from committed-leader height (starts at
    /// 0, increments every [`EPOCH_LEADER_HEIGHTS`] = 2 400 heights ≈ 8 h).
    ///
    /// Epoch is a pure function of committed height, so every node derives the
    /// same value at the same height — no extra persisted counter needed.
    pub fn current_epoch(&self) -> u64 {
        kovanica_types::epoch_for_height(self.committed_leader_height)
    }

    /// Rotate epoch at the [`EPOCH_LEADER_HEIGHTS`] boundary. Returns `(new_epoch,
    /// rotated)` where `rotated` is true iff this call crossed a boundary
    /// (i.e. the previous height was in a lower epoch).
    ///
    /// Rotation is idempotent within an epoch and does not mutate the
    /// validator set, unbonding queue, or treasury. Callers use `rotated` to
    /// trigger a committee rebuild at the boundary.
    pub fn rotate_epoch(&mut self) -> (u64, bool) {
        let epoch = self.current_epoch();
        let rotated =
            epoch > 0 && kovanica_types::is_epoch_start_height(self.committed_leader_height);
        (epoch, rotated)
    }

    /// Called when a validator produces a committed leader block.
    /// Resets their missed leader count and updates last_online_height.
    ///
    /// Resolves the identity from the **live** authority order; the execution
    /// path uses [`Self::validator_online_by_address`] with the epoch
    /// committee's identity instead.
    pub fn validator_online(&mut self, leader_author: u16) {
        let leader = self.authority_validator(leader_author).map(|v| v.address);
        self.validator_online_by_address(leader);
    }

    /// Reset the missed-leader counter for the leader's identity address.
    ///
    /// The record is matched by address regardless of `active`, so a leader
    /// deactivated inside its own sub-DAG is still recorded as online for the
    /// height it led (the commit bookkeeping runs for forfeits too).
    pub fn validator_online_by_address(&mut self, leader: Option<Address>) {
        let Some(address) = leader else {
            return;
        };
        if let Some(v_mut) = self.validators.iter_mut().find(|v| v.address == address) {
            v_mut.missed_leader_count = 0;
            v_mut.last_online_height = self.committed_leader_height;
        }
    }

    /// Increment missed leader count for validators that didn't produce a block
    /// at the given height. Returns the list of validators that went offline
    /// (exceeded MAX_MISSED_LEADERS_BEFORE_OFFLINE).
    ///
    /// Should be called at each committed leader height after the leader reward
    /// is applied. The `leader_author` is the one that succeeded; all other
    /// active validators in the committee get their missed count incremented.
    pub fn advance_validator_liveness(&mut self, leader_author: u16) -> Vec<Address> {
        let leader = self.authority_validator(leader_author).map(|v| v.address);
        self.advance_validator_liveness_by_address(leader)
    }

    /// Address-resolved variant of [`Self::advance_validator_liveness`].
    ///
    /// The leader is excluded **by address**, which is what makes liveness
    /// deterministic: the execution path passes the identity from the epoch
    /// committee snapshot, so a mid-epoch reshuffle of the live authority order
    /// cannot turn the successful leader into a "missed" one (or vice versa).
    pub fn advance_validator_liveness_by_address(
        &mut self,
        leader_address: Option<Address>,
    ) -> Vec<Address> {
        let committee: Vec<_> = self.committee_order().into_iter().cloned().collect();
        let mut went_offline = Vec::new();

        for v in committee {
            if leader_address == Some(v.address) {
                continue; // Leader succeeded, already handled by validator_online
            }
            if let Some(v_mut) = self
                .validators
                .iter_mut()
                .find(|validator| validator.address == v.address && validator.active)
            {
                v_mut.missed_leader_count = v_mut.missed_leader_count.saturating_add(1);
                if v_mut.missed_leader_count >= MAX_MISSED_LEADERS_BEFORE_OFFLINE {
                    v_mut.active = false;
                    went_offline.push(v.address);
                    info!(
                        validator = %v.address,
                        missed = v_mut.missed_leader_count,
                        "validator marked offline after excessive missed leaders"
                    );
                }
            }
        }

        // Offline evictions are final until the validator re-enters the active
        // set with a NEW stake transaction (`join_validator`). No automatic
        // refill from inactive candidates, so an evicted validator is never
        // silently resurrected.
        went_offline
    }

    /// Check if a commission change is allowed (cooldown period has passed).
    /// Allows the first change from the initial commission (0) without cooldown.
    pub fn can_change_commission(&self, validator: Address) -> bool {
        let Some(v) = self.validators.iter().find(|v| v.address == validator) else {
            return false;
        };
        // First change from initial commission (0) is always allowed
        if v.commission_bps == 0 {
            return true;
        }
        let elapsed = self
            .committed_leader_height
            .saturating_sub(v.last_commission_change_height);
        elapsed >= COMMISSION_CHANGE_COOLDOWN
    }

    /// Set a validator's commission (basis points, `<= 10_000`).
    /// Enforces a cooldown period between changes.
    pub fn set_commission(
        &mut self,
        address: Address,
        commission_bps: u16,
    ) -> Result<(), StakingError> {
        if commission_bps > 10_000 {
            return Err(StakingError::InvalidCommission);
        }
        if !self.can_change_commission(address) {
            return Err(StakingError::CommissionCooldown);
        }
        let v = self
            .validators
            .iter_mut()
            .find(|v| v.address == address)
            .ok_or(StakingError::NotValidator)?;
        v.commission_bps = commission_bps;
        v.last_commission_change_height = self.committed_leader_height;
        Ok(())
    }

    /// Minimal genesis staking state (Phase 24.1): `min_validators` active
    /// validators at `MIN_VALIDATOR_STAKE`, treasury configured, height 0.
    /// Used by genesis / testnet initialization.
    ///
    /// This only sets up *staking* state; the matching account balances come
    /// from [`genesis_validator_shares`], which the node applies at first run.
    pub fn genesis(min_validators: u32) -> Self {
        let mut state = Self::new();
        let treasury_addr = Address([0xFF; 32]); // fixed genesis treasury
        state.init_treasury(treasury_addr);
        // Admit minimum active validators deterministically (sorted by address byte)
        for i in 0..min_validators {
            let byte = (i as u8 + 1) % 255; // avoid zero address collision
            let validator = Address([byte; 32]);
            state
                .join_validator(validator, MIN_VALIDATOR_STAKE, 0, None, None, None)
                .expect("genesis validator admission");
        }
        state
    }

    /// Check how much treasury is currently claimable.
    pub fn treasury_claimable(&self) -> u64 {
        self.treasury.as_ref().map(|t| t.claimable()).unwrap_or(0)
    }

    /// Get the treasury address if configured.
    pub fn treasury_address(&self) -> Option<Address> {
        self.treasury.as_ref().map(|t| t.treasury_address)
    }

    // ============================================================
    // Delegation + unbonding (Phase 8.2)
    // ============================================================

    /// Delegate `amount` from `delegator` to `validator`.
    pub fn delegate(
        &mut self,
        delegator: Address,
        validator: Address,
        amount: Stake,
    ) -> Result<(), StakingError> {
        if amount == 0 {
            return Ok(());
        }
        let v_idx = self
            .validators
            .iter()
            .position(|v| v.address == validator && v.active)
            .ok_or(StakingError::NotValidator)?;
        self.validators[v_idx].stake = self.validators[v_idx].stake.saturating_add(amount);
        self.delegations.push(Delegation {
            delegator,
            validator,
            amount,
        });
        self.total_staked = self.total_staked.saturating_add(amount);
        Ok(())
    }

    /// Start unbonding `amount` for `delegator` from `validator`.
    pub fn unbond(
        &mut self,
        delegator: Address,
        validator: Address,
        amount: Stake,
    ) -> Result<(), StakingError> {
        if amount == 0 {
            return Ok(());
        }
        let mut remaining = amount;
        let mut updates: Vec<(usize, u64, bool)> = Vec::new(); // (idx, take, full_consumed)
        for (i, d) in self.delegations.iter().enumerate() {
            if d.delegator == delegator && d.validator == validator && remaining > 0 {
                let take = remaining.min(d.amount);
                remaining -= take;
                updates.push((i, take, take == d.amount));
                if remaining == 0 {
                    break;
                }
            }
        }
        // Apply validator stake reduction and delegation adjustments.
        for (idx, take, full) in &updates {
            if let Some(v_idx) = self.validators.iter().position(|v| v.address == validator) {
                self.validators[v_idx].stake = self.validators[v_idx].stake.saturating_sub(*take);
            }
            self.total_staked = self.total_staked.saturating_sub(*take);
            if !full {
                self.delegations[*idx].amount -= *take;
            }
        }
        if remaining > 0 {
            // Undo validator stake changes (simplified skeleton: assume match)
            for (idx, take, full) in &updates {
                if let Some(v_idx) = self.validators.iter().position(|v| v.address == validator) {
                    self.validators[v_idx].stake =
                        self.validators[v_idx].stake.saturating_add(*take);
                }
                self.total_staked = self.total_staked.saturating_add(*take);
                if !full {
                    self.delegations[*idx].amount += *take;
                }
            }
            return Err(StakingError::NoDelegation);
        }
        // Remove fully consumed delegations (highest index first).
        let to_remove: Vec<usize> = updates
            .iter()
            .filter(|(_, _, f)| *f)
            .map(|(i, _, _)| *i)
            .collect();
        let mut sorted = to_remove;
        sorted.sort_by(|a, b| b.cmp(a));
        sorted.dedup();
        for idx in sorted {
            self.delegations.remove(idx);
        }
        let release_height = self
            .committed_leader_height
            .saturating_add(UNBONDING_ROUNDS);
        self.unbonding_queue.push(UnbondingEntry {
            delegator,
            validator,
            amount,
            release_height,
        });
        Ok(())
    }

    /// Return unbonding entries ready for withdrawal at current `committed_leader_height`.
    /// Deterministic: sorted by (delegator, validator, release_height).
    pub fn unbonding_ready(&self) -> Vec<&UnbondingEntry> {
        let current = self.committed_leader_height;
        let mut ready: Vec<&UnbondingEntry> = self
            .unbonding_queue
            .iter()
            .filter(|e| e.release_height <= current)
            .collect();
        ready.sort_by(|a, b| {
            a.delegator
                .0
                .cmp(&b.delegator.0)
                .then(a.validator.0.cmp(&b.validator.0))
                .then(a.release_height.cmp(&b.release_height))
        });
        ready
    }

    /// Withdraw from unbonding queue once `release_height` passed.
    pub fn withdraw_unbonded(
        &mut self,
        delegator: Address,
        validator: Address,
    ) -> Result<u64, StakingError> {
        let current = self.committed_leader_height;
        let mut withdrawn = 0u64;
        let mut to_remove = Vec::new();
        for (i, entry) in self.unbonding_queue.iter().enumerate() {
            if entry.delegator == delegator
                && entry.validator == validator
                && entry.release_height <= current
            {
                withdrawn = withdrawn.saturating_add(entry.amount);
                to_remove.push(i);
            }
        }
        if withdrawn == 0 {
            return Err(StakingError::UnbondNotComplete);
        }
        to_remove.sort_by(|a, b| b.cmp(a));
        for idx in to_remove {
            self.unbonding_queue.remove(idx);
        }
        Ok(withdrawn)
    }

    /// Reward sharing (commission-based, deterministic, exact).
    ///
    /// The validator takes `commission_bps` of `reward_amount`; the rest is
    /// split pro-rata over the validator's self-stake and every delegation.
    /// Integer-division dust goes to the validator, so the shares always sum
    /// to exactly `reward_amount`. Output is sorted by address and merged
    /// (one entry per address). Unknown validator → empty.
    pub fn reward_share(
        &self,
        validator_address: Address,
        reward_amount: u64,
        commission_bps: u16,
    ) -> Vec<(Address, u64)> {
        if !self
            .validators
            .iter()
            .any(|v| v.address == validator_address)
        {
            return Vec::new();
        }
        let commission_bps = u128::from(commission_bps.min(10_000));
        let reward = u128::from(reward_amount);
        let validator_cut = reward * commission_bps / 10_000;
        let pool = reward - validator_cut;
        let own = u128::from(self.self_stake(validator_address));
        let mut stakes: Vec<(Address, u128)> = self
            .delegations
            .iter()
            .filter(|d| d.validator == validator_address && d.amount > 0)
            .map(|d| (d.delegator, u128::from(d.amount)))
            .collect();
        let total: u128 = own + stakes.iter().map(|(_, a)| a).sum::<u128>();
        let mut merged: std::collections::BTreeMap<[u8; 32], u128> = Default::default();
        let mut distributed = 0u128;
        if total > 0 {
            stakes.sort_by_key(|(a, _)| a.0);
            for (addr, stake) in stakes {
                let share = (pool * stake).checked_div(total).unwrap_or(0);
                distributed += share;
                *merged.entry(addr.0).or_default() += share;
            }
        }
        // Commission + own pro-rata share + rounding dust.
        *merged.entry(validator_address.0).or_default() += reward - distributed;
        merged
            .into_iter()
            .map(|(a, v)| (Address(a), v as u64))
            .collect()
    }

    /// Process double-sign evidence: slash the validator by
    /// `SLASH_PCT_BPS`.
    ///
    /// Kept as the legacy entry point; the round in `evidence` is not used
    /// for accounting (deduplication is the caller's job). New code should
    /// call [`Self::slash_validator`].
    pub fn slash(&mut self, evidence: DoubleSignEvidence) -> Result<u64, StakingError> {
        self.slash_validator(evidence.validator)
    }

    /// Apply a fixed-percentage slash to a validator.
    ///
    /// Security audit (20.1): slash is deterministic — fixed 500 bps, sum is
    /// commutative, so delegation processing order does not affect the total
    /// slashed amount.
    ///
    /// The cut applies to three pools:
    ///
    /// 1. the validator's self-stake;
    /// 2. every delegation to it;
    /// 3. **every still-pending unbonding entry for it (H2)**. Without this a
    ///    validator could start an unbond and keep the queued funds out of
    ///    reach of the slash, even though the entry was created from stake
    ///    that was live when the offence happened. Pending entries have
    ///    already been removed from `total_staked` and from the delegator's
    ///    self-stake at unbond time, so their cut must **not** be subtracted
    ///    from either; it is redirected away from the queued withdrawal.
    ///
    /// Entries cut to zero are dropped from the queue: `withdraw_unbonded`
    /// treats a zero-sum withdrawal as `UnbondNotComplete`, so leaving them
    /// would wedge both the payout loop and the queue forever.
    ///
    /// `validator.stake` already includes delegated stake, so the cut is
    /// computed once on the self-stake and once per delegation (never twice
    /// on delegated stake). Returns the **total** amount removed from the
    /// three pools (staked and queued alike); the caller decides its
    /// destination — execution credits it to the treasury account. Duplicate
    /// evidence must be rejected by the caller (`EvidenceProcessed`), as the
    /// processed-evidence set is persisted outside `StakingState`.
    pub fn slash_validator(&mut self, validator: Address) -> Result<u64, StakingError> {
        let v_idx = self
            .validators
            .iter()
            .position(|v| v.address == validator)
            .ok_or(StakingError::NotValidator)?;
        let cut = |x: u64| (u128::from(x) * u128::from(SLASH_PCT_BPS) / 10_000) as u64;
        let own_slash = cut(self.self_stake(validator));
        let mut delegated_slash = 0u64;
        for d in self.delegations.iter_mut() {
            if d.validator == validator && d.amount > 0 {
                let d_slash = cut(d.amount);
                d.amount -= d_slash;
                delegated_slash = delegated_slash.saturating_add(d_slash);
            }
        }
        // H2: pending unbonding entries are still slashable.
        let mut unbonding_slash = 0u64;
        for entry in self
            .unbonding_queue
            .iter_mut()
            .filter(|e| e.validator == validator)
        {
            let entry_slash = cut(entry.amount);
            entry.amount = entry.amount.saturating_sub(entry_slash);
            unbonding_slash = unbonding_slash.saturating_add(entry_slash);
        }
        self.unbonding_queue.retain(|e| e.amount > 0);

        let staked_slash = own_slash.saturating_add(delegated_slash);
        self.validators[v_idx].stake = self.validators[v_idx].stake.saturating_sub(staked_slash);
        // PRO-19: a slashed validator leaves the active set immediately and is
        // jailed. `saturating_add` keeps the arithmetic total on absurd inputs;
        // in practice heights are far below `u64::MAX`.
        //
        // A record that was already slashed with a jail height of 0 is a legacy
        // row under the F7 rule: it is permanently excluded. Never turn that
        // marker into a finite jail (which would make the record reactivatable
        // later) and never shorten an existing jail on a repeat slash.
        let permanently_excluded =
            self.validators[v_idx].slashed && self.validators[v_idx].jailed_until_height == 0;
        self.validators[v_idx].slashed = true;
        self.validators[v_idx].active = false;
        if !permanently_excluded {
            self.validators[v_idx].jailed_until_height = self.validators[v_idx]
                .jailed_until_height
                .max(self.committed_leader_height.saturating_add(JAIL_ROUNDS));
        }
        self.total_staked = self.total_staked.saturating_sub(staked_slash);
        Ok(staked_slash.saturating_add(unbonding_slash))
    }

    /// Deterministic id of a piece of double-sign evidence
    /// (`blake3(author || round_le)`, domain-separated).
    ///
    /// Legacy evidence carries a committed height rather than a round; it is
    /// hashed the same way so there is one id format. Both are 32 bytes, so
    /// the `PROCESSED_EVIDENCE` table has a single key width.
    pub fn evidence_id(evidence: &DoubleSignEvidence) -> [u8; 32] {
        let mut data = [0u8; 40];
        data[..32].copy_from_slice(&evidence.validator.0);
        data[32..].copy_from_slice(&evidence.height.to_le_bytes());
        Hash::new_keyed(Hash::DOMAIN_EVIDENCE, data).0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn ticker_is_kuna() {
        assert_eq!(TICKER, "KUNA");
        assert_eq!(DECIMALS, 9);
        assert_eq!(ONE_KUNA, 1_000_000_000);
    }

    #[test]
    fn initial_reward_is_2_5_kuna() {
        assert_eq!(block_reward(0), 5 * ONE_KUNA / 2);
        assert_eq!(block_reward(SUBSIDY_ERA_BLOCKS - 1), 5 * ONE_KUNA / 2);
    }

    #[test]
    fn first_decay() {
        let r = block_reward(SUBSIDY_ERA_BLOCKS);
        assert_eq!(r, 1_875_000_000); // 1.875 KUNA = 2.5 × 3/4
    }

    #[test]
    fn cumulative_approaches_budget() {
        let high = SUBSIDY_ERA_BLOCKS * 40;
        let issued = cumulative_mining_issuance(high);
        assert!(issued <= MINING_SUBSIDY_BUDGET);
        assert!(issued > MINING_SUBSIDY_BUDGET * 99 / 100);
    }

    #[test]
    fn treasury_vests_linearly() {
        let addr = Address::default();
        let mut treasury = TreasuryState::new(addr, 0);

        // Before first year → nothing vested
        assert_eq!(treasury.advance(BLOCKS_PER_YEAR - 1), 0);
        assert_eq!(treasury.vested, 0);

        // After exactly 1 year → 1M vested
        let newly = treasury.advance(BLOCKS_PER_YEAR);
        assert_eq!(newly, TREASURY_ANNUAL);
        assert_eq!(treasury.vested, TREASURY_ANNUAL);

        // After 8 years → full amount
        treasury.advance(BLOCKS_PER_YEAR * 8);
        assert_eq!(treasury.vested, TREASURY_TOTAL);

        // After 10 years → still capped
        treasury.advance(BLOCKS_PER_YEAR * 10);
        assert_eq!(treasury.vested, TREASURY_TOTAL);
    }

    #[test]
    fn treasury_claim() {
        let addr = Address::default();
        let mut treasury = TreasuryState::new(addr, 0);
        treasury.advance(BLOCKS_PER_YEAR * 2); // 2M vested

        assert_eq!(treasury.available(), 2 * TREASURY_ANNUAL);
        let claimed = treasury.claim(TREASURY_ANNUAL).unwrap();
        assert_eq!(claimed, TREASURY_ANNUAL);
        assert_eq!(treasury.available(), TREASURY_ANNUAL);
    }

    // ------------------------------------------------------------
    // Skeleton parity (`kovanica-skeleton/staking/src/lib.rs`)
    // ------------------------------------------------------------

    /// Reference copy of the skeleton's `block_reward`, computed in `u128`.
    /// The canonical `block_reward` above is `u64`; they must agree.
    fn skeleton_block_reward(committed_leader_height: u64) -> u64 {
        let era = committed_leader_height / SUBSIDY_ERA_BLOCKS;
        let mut reward: u128 = 2_500_000_000; // 2.5 KUNA
        for _ in 0..era {
            reward = reward.saturating_mul(3) / 4;
            if reward == 0 {
                break;
            }
        }
        reward as u64
    }

    /// Reference copy of the skeleton's `treasury_vested(h)`:
    /// linear 1M KUNA/year over 8 years, measured from height 0.
    fn skeleton_treasury_vested(committed_leader_height: u64) -> u64 {
        let years = committed_leader_height / BLOCKS_PER_YEAR;
        let vested = years.saturating_mul(TREASURY_ANNUAL);
        vested.min(TREASURY_TOTAL)
    }

    /// Independent schedule oracle: each era applies the rational decay to the
    /// preceding integer reward and rounds down to whole atoms at that era.
    /// The property bounds the era count, so this u128 calculation cannot
    /// overflow and does not rely on the production constants or function.
    fn reference_block_reward(era: u64) -> u64 {
        let mut reward = 2_500_000_000u128;
        for _ in 0..era {
            reward = reward * 3 / 4;
        }
        reward as u64
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn block_reward_matches_independent_geometric_schedule(
            era in 0u64..=100,
            offset in 0u64..SUBSIDY_ERA_BLOCKS,
        ) {
            let height = era * SUBSIDY_ERA_BLOCKS + offset;

            prop_assert_eq!(block_reward(height), reference_block_reward(era));
        }

        #[test]
        fn cumulative_issuance_is_bounded_for_every_u64_height(height in any::<u64>()) {
            prop_assert!(
                cumulative_mining_issuance(height) <= MINING_SUBSIDY_BUDGET,
                "height {height}"
            );
        }

        #[test]
        fn committed_leader_rewards_keep_circulating_supply_under_cap(
            start_height in prop_oneof![
                Just(0u64),
                Just(SUBSIDY_ERA_BLOCKS - 1),
                Just(8 * BLOCKS_PER_YEAR),
                Just(100 * SUBSIDY_ERA_BLOCKS),
                0u64..=(100 * SUBSIDY_ERA_BLOCKS),
            ],
            validator_count in 1usize..=4,
            payout_seed in any::<u8>(),
            authors in prop::collection::vec(any::<u8>(), 1..64),
        ) {
            let mut state = StakingState::new();
            state.init_treasury(Address([payout_seed; 32]));

            for index in 0..validator_count {
                let address_byte = payout_seed.wrapping_add(index as u8);
                let validator = Address([address_byte; 32]);
                let payout = Address([address_byte.wrapping_add(128); 32]);
                state
                    .join_validator(validator, MIN_VALIDATOR_STAKE, 0, Some(payout), None, None)
                    .expect("generated validator setup is valid");
            }

            // Seed a schedule-consistent state at an arbitrary height. The
            // exact 100-era case exercises supply close to the cap after the
            // treasury has fully vested.
            state.committed_leader_height = start_height;
            state.total_mining_issued = cumulative_mining_issuance(start_height);
            state
                .treasury
                .as_mut()
                .expect("treasury was initialized")
                .advance(start_height);
            prop_assert!(state.circulating_supply() <= TOTAL_SUPPLY);

            for author in authors {
                let authority_index = (author as usize % validator_count) as u16;
                state
                    .on_leader_committed(authority_index)
                    .expect("generated authority index exists");
                prop_assert!(
                    state.circulating_supply() <= TOTAL_SUPPLY,
                    "height {}",
                    state.committed_leader_height
                );
            }
        }
    }

    #[test]
    fn canonical_values_match_skeleton() {
        assert_eq!(DECIMALS, 9);
        assert_eq!(ONE_KUNA, 1_000_000_000);
        assert_eq!(TOTAL_SUPPLY, 90_200_000 * ONE_KUNA);
        assert_eq!(FOUNDER_PREMINE, 200_000 * ONE_KUNA);
        assert_eq!(GENESIS_VALIDATOR_ALLOCATION, 1_000_000 * ONE_KUNA);
        assert_eq!(TREASURY_TOTAL, 8_000_000 * ONE_KUNA);
        assert_eq!(TREASURY_ANNUAL, 1_000_000 * ONE_KUNA);
        assert_eq!(MINING_SUBSIDY_BUDGET, 81_000_000 * ONE_KUNA);
        assert_eq!(INITIAL_BLOCK_REWARD, 5 * ONE_KUNA / 2); // skeleton INITIAL_REWARD
        assert_eq!(SUBSIDY_ERA_BLOCKS, 8_100_000); // skeleton ERA_LENGTH
        assert_eq!((DECAY_NUM, DECAY_DEN), (3, 4));
        assert_eq!(BLOCKS_PER_YEAR, 2_628_000);
        assert_eq!(LEADER_INTERVAL_SECS, 12);
        assert_eq!(EPOCH_ROUNDS, 7_200);
        assert_eq!(MIN_VALIDATOR_STAKE, 50_000 * ONE_KUNA);
        assert_eq!(MIN_ACTIVE_VALIDATORS, 15);
        assert_eq!(MAX_ACTIVE_VALIDATORS, 21);
        assert_eq!(UNBONDING_ROUNDS, 100_000); // skeleton UNBONDING_PERIOD
                                               // Supply book must close exactly.
        assert_eq!(
            FOUNDER_PREMINE + GENESIS_VALIDATOR_ALLOCATION + TREASURY_TOTAL + MINING_SUBSIDY_BUDGET,
            TOTAL_SUPPLY
        );
    }

    #[test]
    fn reward_schedule_matches_skeleton() {
        // Era 0 → 2.5 KUNA, boundary of era 0 → 2.5 KUNA,
        // era 1 → 1.875 KUNA after the 3/4 decay, plus later eras.
        let heights = [
            0u64,
            SUBSIDY_ERA_BLOCKS - 1,
            SUBSIDY_ERA_BLOCKS,
            2 * SUBSIDY_ERA_BLOCKS,
            3 * SUBSIDY_ERA_BLOCKS + 12_345,
        ];
        for h in heights {
            assert_eq!(block_reward(h), skeleton_block_reward(h), "height {h}");
        }
        assert_eq!(block_reward(0), 5 * ONE_KUNA / 2);
        assert_eq!(block_reward(SUBSIDY_ERA_BLOCKS), 1_875_000_000); // 1.875 KUNA
    }

    #[test]
    fn treasury_vesting_matches_skeleton() {
        let treasury = TreasuryState::new(Address::default(), 0);
        let heights = [
            0u64,
            BLOCKS_PER_YEAR - 1,
            BLOCKS_PER_YEAR,
            BLOCKS_PER_YEAR + 1,
            7 * BLOCKS_PER_YEAR + BLOCKS_PER_YEAR / 2,
            8 * BLOCKS_PER_YEAR,
            9 * BLOCKS_PER_YEAR,
            100 * BLOCKS_PER_YEAR,
        ];
        for h in heights {
            assert_eq!(
                treasury.expected_vested(h),
                skeleton_treasury_vested(h),
                "height {h}"
            );
        }
    }

    #[test]
    fn cumulative_issuance_never_exceeds_budget() {
        // Naive per-height sum of block_reward over the first 3 full eras
        // must agree with cumulative_mining_issuance and stay in budget.
        let three_eras = 3 * SUBSIDY_ERA_BLOCKS;
        let naive: u64 = (0..three_eras).map(block_reward).sum();
        assert_eq!(naive, cumulative_mining_issuance(three_eras));
        assert!(naive <= MINING_SUBSIDY_BUDGET);

        // Full schedule: sum each era's reward until it decays to zero.
        // The geometric series 2.5 KUNA × 8_100_000 × 1/(1 − 3/4) equals
        // exactly 81M KUNA; floor-truncation keeps the real sum just below.
        let mut naive_full = 0u64;
        let mut era = 0u64;
        loop {
            let reward = block_reward(era * SUBSIDY_ERA_BLOCKS);
            if reward == 0 {
                break;
            }
            naive_full = naive_full.saturating_add(reward.saturating_mul(SUBSIDY_ERA_BLOCKS));
            era += 1;
        }
        assert!(naive_full <= MINING_SUBSIDY_BUDGET);
        assert!(naive_full > MINING_SUBSIDY_BUDGET * 99 / 100);

        // Spot checks at various heights, including a pathological one.
        for h in [
            0u64,
            SUBSIDY_ERA_BLOCKS,
            40 * SUBSIDY_ERA_BLOCKS,
            200 * SUBSIDY_ERA_BLOCKS,
            u64::MAX,
        ] {
            assert!(
                cumulative_mining_issuance(h) <= MINING_SUBSIDY_BUDGET,
                "height {h}"
            );
        }
    }

    #[test]
    fn leader_reward_goes_to_payout_address() {
        let mut state = StakingState::new();
        let validator = Address([1u8; 32]);
        let payout = Address([2u8; 32]);
        state
            .join_validator(validator, MIN_VALIDATOR_STAKE, 0, Some(payout), None, None)
            .unwrap();

        let outcome = state.on_leader_committed(0).unwrap();
        assert_eq!(outcome.recipient, payout);
        assert_ne!(outcome.recipient, validator);
        assert_eq!(outcome.amount, block_reward(0));
        assert_eq!(outcome.height, 0);
        assert_eq!(state.total_mining_issued, outcome.amount);
        assert_eq!(state.committed_leader_height, 1);

        // Unknown authority index must not mint.
        assert!(matches!(
            state.on_leader_committed(9),
            Err(StakingError::NotValidator)
        ));
    }

    #[test]
    fn resolved_leader_payment_ignores_a_mid_epoch_joiner_at_index_zero() {
        let mut state = StakingState::new();
        for i in 1..=3u8 {
            state
                .join_validator(a(i), MIN_VALIDATOR_STAKE, 0, Some(a(i + 10)), None, None)
                .unwrap();
        }

        // a(0) joining mid-epoch sorts to live index 0, so the live order no
        // longer maps index 0 to the epoch's leader. The snapshot-resolved
        // identity must still win: a(1) led, not the newcomer.
        state
            .join_validator(a(0), MIN_VALIDATOR_STAKE, 0, Some(a(10)), None, None)
            .unwrap();
        assert_eq!(state.committee_order()[0].address, a(0));

        let outcome = state.on_leader_committed_resolved(0, a(1)).unwrap();
        assert_eq!(
            outcome.recipient,
            a(11),
            "pays the identity that held index 0, not the shifted live index"
        );
        assert_eq!(outcome.amount, block_reward(0));

        let missed = |addr: Address| state.validator(addr).unwrap().missed_leader_count;
        assert_eq!(missed(a(1)), 0, "the real leader is online");
        assert_eq!(missed(a(2)), 1);
        assert_eq!(missed(a(3)), 1);
    }

    #[test]
    fn resolved_leader_deactivated_in_its_own_subdag_forfeits_without_paying_the_shifted_index() {
        let mut state = StakingState::new();
        for i in 1..=3u8 {
            state
                .join_validator(a(i), MIN_VALIDATOR_STAKE, 0, Some(a(i + 10)), None, None)
                .unwrap();
        }
        // a(1) held index 0 at epoch start. The sub-DAG it led slashed it, so
        // it left the live committee: index 0 now resolves to a(2).
        state.validators[0].missed_leader_count = 5;
        state.validators[0].active = false;
        assert_eq!(state.committee_order()[0].address, a(2));

        let outcome = state.on_leader_committed_forfeited_resolved(0, Some(a(1)));
        assert_eq!(outcome.amount, 0, "a leader that left must not be paid");
        assert_eq!(
            outcome.recipient,
            a(11),
            "outcome still names the real leader"
        );
        assert_eq!(
            state.committed_leader_height, 1,
            "height advances on forfeit"
        );

        let missed = |addr: Address| state.validator(addr).unwrap().missed_leader_count;
        assert_eq!(missed(a(1)), 0, "the leader's own miss counter is reset");
        assert_eq!(
            missed(a(2)),
            1,
            "the shifted index-0 validator takes a miss"
        );
        assert_eq!(missed(a(3)), 1);
    }

    #[test]
    fn epoch_committee_snapshot_is_committee_order_in_index_order() {
        let mut state = StakingState::new();
        for i in 1..=3u8 {
            state
                .join_validator(
                    a(i),
                    MIN_VALIDATOR_STAKE,
                    0,
                    Some(a(i + 10)),
                    Some(PublicKey(a(i).0)),
                    None,
                )
                .unwrap();
        }

        let snapshot = state
            .epoch_committee_snapshot()
            .expect("freezable committee");
        let order = state.committee_order();
        assert_eq!(snapshot.len(), order.len());
        for (index, (member, validator)) in snapshot.iter().zip(order.iter()).enumerate() {
            assert_eq!(member.index, index as u16);
            assert_eq!(
                Address::from_public_key(&member.public_key),
                validator.address
            );
            assert_eq!(member.stake, validator.stake);
        }

        // One member without a consensus key would leave a hole in the index
        // sequence, so the snapshot is refused rather than stored sparse.
        state.validators[1].public_key = None;
        assert!(state.epoch_committee_snapshot().is_none());
    }

    #[test]
    fn delegate_unbond_wait_withdraw_and_slash_reduces_stake() {
        let mut state = StakingState::new();
        let validator = Address([1u8; 32]);
        let delegator = Address([2u8; 32]);
        state
            .join_validator(validator, MIN_VALIDATOR_STAKE, 0, None, None, None)
            .unwrap();
        let delegate_amount = 10_000 * ONE_KUNA;
        state
            .delegate(delegator, validator, delegate_amount)
            .unwrap();
        assert_eq!(state.delegations.len(), 1);

        state.unbond(delegator, validator, delegate_amount).unwrap();
        assert_eq!(state.delegations.len(), 0);
        assert_eq!(state.unbonding_queue.len(), 1);

        assert!(matches!(
            state.withdraw_unbonded(delegator, validator),
            Err(StakingError::UnbondNotComplete)
        ));

        let entry = state.unbonding_queue[0].clone();
        state.committed_leader_height = entry.release_height;
        let withdrawn = state.withdraw_unbonded(delegator, validator).unwrap();
        assert_eq!(withdrawn, delegate_amount);
        assert!(state.unbonding_queue.is_empty());

        // Slash reduces validator stake (fixed %) — fresh state for isolation
        let mut slash_state = StakingState::new();
        slash_state
            .join_validator(validator, MIN_VALIDATOR_STAKE, 0, None, None, None)
            .unwrap();
        slash_state
            .delegate(delegator, validator, delegate_amount)
            .unwrap();
        let evidence = DoubleSignEvidence {
            validator,
            height: 1,
        };
        let slashed = slash_state.slash(evidence).unwrap();
        assert!(slashed > 0);
        assert!(slash_state.total_staked < MIN_VALIDATOR_STAKE.saturating_add(delegate_amount));
    }

    /// H2: a validator cannot dodge the slash by unbonding first.
    #[test]
    fn slash_cuts_pending_unbonding_entries() {
        let mut state = StakingState::new();
        let validator = Address([1u8; 32]);
        let delegator = Address([2u8; 32]);
        let self_stake = 60_000 * ONE_KUNA;
        state
            .join_validator(validator, self_stake, 0, None, None, None)
            .unwrap();
        state
            .delegate(delegator, validator, 10_000 * ONE_KUNA)
            .unwrap();
        // 60k self + 10k delegated staked; move 10k self into the queue while
        // staying above MIN_VALIDATOR_STAKE (so the validator is still active).
        state
            .unbond_validator(validator, 10_000 * ONE_KUNA)
            .unwrap();
        assert!(state.validators[0].active);
        assert_eq!(state.unbonding_queue.len(), 1);
        let staked_before = state.total_staked;
        let queued_before = state.unbonding_queue[0].amount;

        let slashed = state.slash_validator(validator).unwrap();

        // 5% of 50k self + 5% of 10k delegation + 5% of the 10k queued entry.
        assert_eq!(slashed, 3_500 * ONE_KUNA);
        // The queued cut was never part of `total_staked`, so only the staked
        // part reduces it (57k = 60k - 3k).
        assert_eq!(state.total_staked, staked_before - 3_000 * ONE_KUNA);
        assert_eq!(
            state.unbonding_queue[0].amount,
            queued_before - queued_before / 20
        );
        assert!(state.validators[0].slashed);
        // The queued funds stay withdrawable, just reduced.
        state.committed_leader_height = state.unbonding_queue[0].release_height;
        assert_eq!(
            state.withdraw_unbonded(validator, validator).unwrap(),
            queued_before - queued_before / 20
        );
        assert!(state.unbonding_queue.is_empty());
    }

    /// The legacy entry point keeps the same accounting and now shares H2.
    #[test]
    fn legacy_slash_delegates_to_slash_validator() {
        let mut a = StakingState::new();
        let mut b = StakingState::new();
        for st in [&mut a, &mut b] {
            st.join_validator(Address([1u8; 32]), MIN_VALIDATOR_STAKE, 0, None, None, None)
                .unwrap();
            st.unbond_validator(Address([1u8; 32]), 0)
                .expect_err("zero unbond is rejected");
            st.unbonding_queue.push(UnbondingEntry {
                delegator: Address([2u8; 32]),
                validator: Address([1u8; 32]),
                amount: 1_000 * ONE_KUNA,
                release_height: 10,
            });
        }
        let legacy = a
            .slash(DoubleSignEvidence {
                validator: Address([1u8; 32]),
                height: 1,
            })
            .unwrap();
        let direct = b.slash_validator(Address([1u8; 32])).unwrap();
        assert_eq!(legacy, direct);
        assert_eq!(a.unbonding_queue[0].amount, b.unbonding_queue[0].amount);
    }

    #[test]
    fn evidence_id_is_32_bytes_and_domain_separated() {
        let ev = DoubleSignEvidence {
            validator: Address([1u8; 32]),
            height: 7,
        };
        let id = StakingState::evidence_id(&ev);
        assert_eq!(id.len(), 32);
        assert_eq!(id, StakingState::evidence_id(&ev));
        assert_ne!(
            id,
            StakingState::evidence_id(&DoubleSignEvidence {
                validator: Address([1u8; 32]),
                height: 8,
            })
        );
    }

    #[test]
    fn epoch_rotation_at_epoch_boundary() {
        let mut state = StakingState::new();
        assert_eq!(state.rotate_epoch(), (0, false));

        state.committed_leader_height = EPOCH_LEADER_HEIGHTS - 1;
        assert_eq!(state.rotate_epoch(), (0, false));

        state.committed_leader_height = EPOCH_LEADER_HEIGHTS;
        assert_eq!(state.rotate_epoch(), (1, true));

        // Idempotent mid-epoch: same epoch, no further rotation.
        state.committed_leader_height = EPOCH_LEADER_HEIGHTS + 1;
        assert_eq!(state.rotate_epoch(), (1, false));

        state.committed_leader_height = 2 * EPOCH_LEADER_HEIGHTS;
        assert_eq!(state.rotate_epoch(), (2, true));
    }

    #[test]
    fn unbonding_ready_sorted_deterministic() {
        let mut state = StakingState::new();
        state
            .join_validator(Address([1u8; 32]), MIN_VALIDATOR_STAKE, 0, None, None, None)
            .unwrap();
        state
            .delegate(Address([2u8; 32]), Address([1u8; 32]), 5_000 * ONE_KUNA)
            .unwrap();
        state
            .unbond(Address([2u8; 32]), Address([1u8; 32]), 5_000 * ONE_KUNA)
            .unwrap();

        // Before release → none ready.
        assert!(state.unbonding_ready().is_empty());

        state.committed_leader_height = UNBONDING_ROUNDS;
        let ready = state.unbonding_ready();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].amount, 5_000 * ONE_KUNA);
    }

    #[test]
    fn slash_is_deterministic_fixed_500bps() {
        let mut state = StakingState::new();
        let validator = Address([3u8; 32]);
        state
            .join_validator(validator, MIN_VALIDATOR_STAKE, 0, None, None, None)
            .unwrap();
        let evidence = DoubleSignEvidence {
            validator,
            height: 1,
        };
        let total_first = state.slash(evidence.clone()).unwrap();
        // Re-apply to fresh validator with same stake (simulated second occurrence)
        let mut state2 = StakingState::new();
        state2
            .join_validator(validator, MIN_VALIDATOR_STAKE, 0, None, None, None)
            .unwrap();
        let total_second = state2.slash(evidence.clone()).unwrap();
        assert_eq!(
            total_first, total_second,
            "slash amount must be deterministic for same evidence"
        );
        assert_eq!(total_first, MIN_VALIDATOR_STAKE / 20); // 500 bps = 5%
    }

    #[test]
    fn genesis_state_has_15_validators_and_treasury() {
        let state = StakingState::genesis(MIN_ACTIVE_VALIDATORS);
        assert_eq!(state.validators.len(), MIN_ACTIVE_VALIDATORS as usize);
        assert!(state
            .validators
            .iter()
            .all(|v| v.active && v.stake == MIN_VALIDATOR_STAKE));
        assert!(state.treasury.is_some());
        assert_eq!(state.committed_leader_height, 0);
        assert_eq!(
            state.total_staked,
            MIN_VALIDATOR_STAKE * MIN_ACTIVE_VALIDATORS as u64
        );
    }

    #[test]
    fn genesis_validator_shares_sum_exactly_and_are_even() {
        // 1 KUNA = 10^9 atoms, so 1M KUNA almost never divides evenly by n;
        // the splitter must still conserve every atom.
        for n in [1usize, 2, 3, 15, 21, 100] {
            let shares = genesis_validator_shares(n);
            assert_eq!(shares.len(), n);
            let sum: u64 = shares.iter().sum();
            assert_eq!(sum, GENESIS_VALIDATOR_ALLOCATION, "n={n}");
            let max = *shares.iter().max().unwrap();
            let min = *shares.iter().min().unwrap();
            assert!(max - min <= 1, "shares differ by <= 1 atom (n={n})");
        }
        assert!(genesis_validator_shares(0).is_empty());
    }

    #[test]
    fn staking_state_bincode_roundtrip() {
        let mut state = StakingState::new();
        state.init_treasury(Address([42u8; 32]));

        for i in 0..3u8 {
            let addr = Address([i + 1; 32]);
            let payout = Address([i + 11; 32]);
            state
                .join_validator(addr, MIN_VALIDATOR_STAKE, 0, Some(payout), None, None)
                .unwrap();
        }

        let bytes = state.to_bytes().expect("serialize");
        let decoded = StakingState::from_bytes(&bytes).expect("deserialize");

        assert_eq!(state.validators.len(), decoded.validators.len());
        for (a, b) in state.validators.iter().zip(decoded.validators.iter()) {
            assert_eq!(a.address, b.address);
            assert_eq!(a.stake, b.stake);
            assert_eq!(a.public_key, b.public_key);
        }
        assert_eq!(
            state.committed_leader_height,
            decoded.committed_leader_height
        );
        assert_eq!(state.total_mining_issued, decoded.total_mining_issued);
    }
    // ---- staking wiring -------------------------------------------------

    fn a(b: u8) -> Address {
        Address([b; 32])
    }

    #[test]
    fn join_validator_rejects_duplicates() {
        let mut st = StakingState::new();
        st.join_validator(a(1), MIN_VALIDATOR_STAKE, 0, None, None, None)
            .unwrap();
        let err = st.join_validator(a(1), MIN_VALIDATOR_STAKE, 0, None, None, None);
        assert!(matches!(err, Err(StakingError::ValidatorExists)));
        assert_eq!(st.validators.len(), 1);
        assert_eq!(st.total_staked, MIN_VALIDATOR_STAKE);
    }

    #[test]
    fn bond_unbond_validator_uses_queue_and_unbonding_rounds() {
        let mut st = StakingState::new();
        st.join_validator(a(1), MIN_VALIDATOR_STAKE, 0, None, None, None)
            .unwrap();
        st.bond_validator(a(1), 10 * ONE_KUNA).unwrap();
        assert_eq!(st.self_stake(a(1)), MIN_VALIDATOR_STAKE + 10 * ONE_KUNA);
        // Leaving 1..MIN-1 of self-stake is rejected.
        assert!(matches!(
            st.unbond_validator(a(1), 20 * ONE_KUNA),
            Err(StakingError::BelowMinimumStake)
        ));
        st.unbond_validator(a(1), 10 * ONE_KUNA).unwrap();
        assert_eq!(st.unbonding_queue[0].release_height, UNBONDING_ROUNDS);
        assert!(matches!(
            st.withdraw_unbonded(a(1), a(1)),
            Err(StakingError::UnbondNotComplete)
        ));
        st.committed_leader_height = UNBONDING_ROUNDS;
        assert_eq!(st.withdraw_unbonded(a(1), a(1)).unwrap(), 10 * ONE_KUNA);
        // Full exit deactivates.
        st.unbond_validator(a(1), MIN_VALIDATOR_STAKE).unwrap();
        assert!(!st.validators[0].active);
        assert_eq!(st.total_staked, 0);
    }

    #[test]
    fn full_unbond_never_refills_from_inactive_spares() {
        // 16 validators: 15 active at MIN + one inactive-but-qualified spare.
        // Reactivation was deleted: a full unbond leaves the spare inactive.
        let mut st = StakingState::new();
        for i in 1..=16u8 {
            st.join_validator(a(i), MIN_VALIDATOR_STAKE, 0, None, None, None)
                .unwrap();
        }
        // Deactivate one (spare) manually, leaving 15 active.
        st.validators[15].active = false;

        // Full unbond of an active validator deactivates it and the spare is
        // NEVER reactivated — re-entry only via a new stake transaction.
        st.unbond_validator(a(1), MIN_VALIDATOR_STAKE).unwrap();
        assert!(!st.validators[0].active);
        assert!(
            !st.validators[15].active,
            "spare must NOT be reactivated: no automatic refill exists"
        );
    }

    #[test]
    fn full_unbond_needs_an_explicit_reactivation_to_return() {
        // Re-entry into the active set is NOT automatic: a full unbond
        // deactivates the validator and `join_validator` refuses to re-add an
        // address that already has a (now-inactive) record. The explicit
        // operator action is `reactivate_validator`, driven by a new stake tx.
        let mut st = StakingState::new();
        for i in 1..=15u8 {
            st.join_validator(a(i), MIN_VALIDATOR_STAKE, 0, None, None, None)
                .unwrap();
        }
        st.unbond_validator(a(1), MIN_VALIDATOR_STAKE).unwrap();
        assert!(!st.validators[0].active, "full unbond deactivates");
        assert_eq!(
            st.committee_order().len(),
            14,
            "unbonded validator leaves the set"
        );

        // A plain re-join of the same address is refused: the record persists.
        assert!(
            matches!(
                st.join_validator(a(1), MIN_VALIDATOR_STAKE, 0, None, None, None),
                Err(StakingError::ValidatorExists)
            ),
            "an existing (inactive) record blocks a silent re-join"
        );
        assert!(
            !st.validators[0].active,
            "validator stays inactive until an explicit reactivation"
        );

        // The explicit reactivation brings it back.
        st.reactivate_validator(a(1), MIN_VALIDATOR_STAKE).unwrap();
        assert!(
            st.validators[0].active,
            "explicit reactivation returns the validator"
        );
        assert_eq!(
            st.committee_order().len(),
            15,
            "an explicit re-stake restores the full set"
        );
    }

    #[test]
    fn offline_eviction_never_refills_from_inactive_spares() {
        // 15 active + 1 offline spare. Evicting one active via the missed-leader
        // threshold must NOT refill from the spare.
        let mut st = StakingState::new();
        for i in 1..=16u8 {
            st.join_validator(a(i), MIN_VALIDATOR_STAKE, 0, None, None, None)
                .unwrap();
        }
        st.validators[15].active = false; // spare

        // Drive validator a(1) (authority index 0) over the offline threshold.
        // Leader is a(2) (index 1); every other active validator is incremented.
        st.validators[0].missed_leader_count = MAX_MISSED_LEADERS_BEFORE_OFFLINE - 1;
        let went_offline = st.advance_validator_liveness(1);
        assert!(went_offline.contains(&a(1)));

        assert!(
            !st.validators[15].active,
            "spare must NOT be reactivated after an offline eviction"
        );
        assert!(!st.validators[0].active, "evicted validator stays offline");
    }

    #[test]
    fn offline_eviction_is_terminal_until_an_explicit_reactivation() {
        // An evicted validator is never resurrected silently: the inactive
        // record persists, a duplicate join is refused, and only the explicit
        // `reactivate_validator` (a new stake tx) brings it back.
        let mut st = StakingState::new();
        for i in 1..=15u8 {
            st.join_validator(a(i), MIN_VALIDATOR_STAKE, 0, None, None, None)
                .unwrap();
        }
        st.validators[0].missed_leader_count = MAX_MISSED_LEADERS_BEFORE_OFFLINE - 1;
        let went_offline = st.advance_validator_liveness(1);
        assert!(went_offline.contains(&a(1)));
        assert!(!st.validators[0].active);
        let missed = st.validators[0].missed_leader_count;

        // Advancing liveness again must not reactivate the evicted validator.
        st.advance_validator_liveness(1);
        assert!(!st.validators[0].active, "evicted validator stays offline");
        assert_eq!(
            st.validators[0].missed_leader_count, missed,
            "no automatic refill means missed count is untouched"
        );

        // No silent re-entry: a duplicate join is refused while the record
        // remains, so reactivation needs an explicit operator action.
        assert!(matches!(
            st.join_validator(a(1), MIN_VALIDATOR_STAKE, 0, None, None, None),
            Err(StakingError::ValidatorExists)
        ));
        assert!(!st.validators[0].active);

        // The explicit re-stake returns it and clears the missed counter.
        st.reactivate_validator(a(1), MIN_VALIDATOR_STAKE).unwrap();
        assert!(
            st.validators[0].active,
            "explicit re-stake returns the validator"
        );
        assert_eq!(
            st.validators[0].missed_leader_count, 0,
            "reactivation resets the missed-leader counter"
        );
    }

    #[test]
    fn f7_jarvis_evicted_validator_can_restake_explicitly() {
        // An evicted validator must return ONLY via an explicit re-stake, and
        // that reactivation must survive a restart and an epoch rotation.
        let mut st = StakingState::new();
        for i in 1..=15u8 {
            st.join_validator(a(i), MIN_VALIDATOR_STAKE, 0, None, None, None)
                .unwrap();
        }

        // Evict a(1) via the missed-leader threshold.
        st.validators[0].missed_leader_count = MAX_MISSED_LEADERS_BEFORE_OFFLINE - 1;
        let went_offline = st.advance_validator_liveness(1);
        assert!(went_offline.contains(&a(1)));
        assert!(!st.validators[0].active);
        assert_eq!(st.committee_order().len(), 14);

        // Explicit re-stake at MIN brings it back.
        st.reactivate_validator(a(1), MIN_VALIDATOR_STAKE).unwrap();
        assert!(st.validators[0].active, "explicit re-stake reactivates");
        assert_eq!(st.committee_order().len(), 15);
        assert_eq!(st.validators[0].missed_leader_count, 0);

        // Survives a restart (bincode roundtrip with versioned encoding, the persisted form).
        let bytes = st.to_bytes().expect("serialize");
        let mut restarted = StakingState::from_bytes(&bytes).expect("deserialize");
        assert!(
            restarted.validators[0].active,
            "reactivation survives a restart"
        );
        assert_eq!(restarted.committee_order().len(), 15);

        // Survives an epoch rotation (which does not mutate the set).
        restarted.committed_leader_height = EPOCH_LEADER_HEIGHTS;
        let (epoch, rotated) = restarted.rotate_epoch();
        assert_eq!(epoch, 1);
        assert!(rotated);
        assert!(
            restarted.validators[0].active,
            "reactivation survives an epoch rotation"
        );
        assert_eq!(restarted.committee_order().len(), 15);
    }

    #[test]
    fn f7_jarvis_evicted_validator_stays_inactive_without_restake() {
        // Without a re-stake an evicted validator must stay out across a
        // restart and an epoch rotation: nothing auto-refills it.
        let mut st = StakingState::new();
        for i in 1..=15u8 {
            st.join_validator(a(i), MIN_VALIDATOR_STAKE, 0, None, None, None)
                .unwrap();
        }
        st.validators[0].missed_leader_count = MAX_MISSED_LEADERS_BEFORE_OFFLINE - 1;
        st.advance_validator_liveness(1);
        assert!(!st.validators[0].active);

        // Across a restart.
        let bytes = st.to_bytes().expect("serialize");
        let mut restarted = StakingState::from_bytes(&bytes).expect("deserialize");
        assert!(
            !restarted.validators[0].active,
            "no re-stake: still inactive after restart"
        );
        assert_eq!(restarted.committee_order().len(), 14);

        // Across an epoch rotation.
        restarted.committed_leader_height = EPOCH_LEADER_HEIGHTS;
        let (_epoch, rotated) = restarted.rotate_epoch();
        assert!(rotated);
        assert!(
            !restarted.validators[0].active,
            "no re-stake: still inactive after an epoch rotation"
        );
        assert_eq!(restarted.committee_order().len(), 14);
    }

    #[test]
    fn f7_jarvis_slashed_validator_cannot_restake() {
        // A slashed validator stays OUT. Topping its stake back up to MIN via
        // an explicit stake tx must NOT reinstate it: reactivate_validator
        // refuses a slashed record.
        let mut st = StakingState::new();
        for i in 1..=15u8 {
            st.join_validator(a(i), MIN_VALIDATOR_STAKE, 0, None, None, None)
                .unwrap();
        }

        // Slash a(1). The 5% cut drops it below MIN, and the record is flagged
        // slashed.
        let evidence = DoubleSignEvidence {
            validator: a(1),
            height: 42,
        };
        let slashed_amount = st.slash(evidence).unwrap();
        assert!(slashed_amount > 0, "slash must cut stake");
        assert!(
            st.validators[0].slashed,
            "slashing must flag the validator record"
        );
        // Deactivate it (evicted / below minimum in the committee sense).
        st.validators[0].active = false;

        // An explicit re-stake that tops it back above MIN is still refused.
        let err = st
            .reactivate_validator(a(1), MIN_VALIDATOR_STAKE * 10)
            .unwrap_err();
        assert!(
            matches!(err, StakingError::ValidatorSlashed),
            "slashed validator must be refused, got {err:?}"
        );
        assert!(!st.validators[0].active, "slashed validator stays inactive");
        assert!(
            !st.committee_order().iter().any(|v| v.address == a(1)),
            "slashed validator must not re-enter the committee"
        );

        // The slashed flag survives a bincode restart, so a restarted node
        // enforces the same rule.
        let bytes = st.to_bytes().expect("serialize");
        let mut restarted = StakingState::from_bytes(&bytes).expect("deserialize");
        assert!(
            restarted.validators[0].slashed,
            "slashed flag must survive a restart"
        );
        assert!(matches!(
            restarted.reactivate_validator(a(1), MIN_VALIDATOR_STAKE * 10),
            Err(StakingError::ValidatorSlashed)
        ));
        assert!(!restarted.validators[0].active);
    }

    #[test]
    fn f7_jarvis_unslashed_evicted_validator_still_restakes() {
        // Control: a merely evicted (never slashed) validator still returns via
        // an explicit stake tx — the slashed guard must not block it.
        let mut st = StakingState::new();
        for i in 1..=15u8 {
            st.join_validator(a(i), MIN_VALIDATOR_STAKE, 0, None, None, None)
                .unwrap();
        }
        assert!(
            !st.validators[0].slashed,
            "a fresh validator is not slashed"
        );

        // Evict a(1) via the missed-leader threshold (not a slash).
        st.validators[0].missed_leader_count = MAX_MISSED_LEADERS_BEFORE_OFFLINE - 1;
        let went_offline = st.advance_validator_liveness(1);
        assert!(went_offline.contains(&a(1)));
        assert!(!st.validators[0].active);
        assert!(!st.validators[0].slashed, "offline eviction is not a slash");

        // Explicit re-stake returns it.
        st.reactivate_validator(a(1), MIN_VALIDATOR_STAKE).unwrap();
        assert!(
            st.validators[0].active,
            "unslashed evicted validator returns"
        );
        assert_eq!(st.committee_order().len(), 15);
    }

    #[test]
    fn rotate_epoch_reports_boundary_truthfully() {
        let mut st = StakingState::new();
        assert_eq!(st.current_epoch(), 0);
        let (e, rotated) = st.rotate_epoch();
        assert_eq!(e, 0);
        assert!(!rotated);

        st.committed_leader_height = EPOCH_LEADER_HEIGHTS;
        let (e, rotated) = st.rotate_epoch();
        assert_eq!(e, 1);
        assert!(rotated, "boundary crossing must be reported");

        st.committed_leader_height = EPOCH_LEADER_HEIGHTS + 5;
        let (e, rotated) = st.rotate_epoch();
        assert_eq!(e, 1);
        assert!(!rotated, "mid-epoch call is not a boundary");
    }

    #[test]
    fn set_commission_validates() {
        let mut st = StakingState::new();
        st.join_validator(a(1), MIN_VALIDATOR_STAKE, 0, None, None, None)
            .unwrap();
        assert!(st.set_commission(a(1), 10_001).is_err());
        st.set_commission(a(1), 1_000).unwrap();
        assert_eq!(st.validators[0].commission_bps, 1_000);
        // Advance height past cooldown to allow another change
        st.committed_leader_height = COMMISSION_CHANGE_COOLDOWN;
        st.set_commission(a(1), 2_000).unwrap();
        assert_eq!(st.validators[0].commission_bps, 2_000);
    }

    // Old behaviour: authority index was the insertion position.
    #[test]
    fn authority_index_maps_by_identity_not_position() {
        let mut st = StakingState::new();
        for b in [3u8, 1, 2] {
            st.join_validator(a(b), MIN_VALIDATOR_STAKE, 0, Some(a(b + 10)), None, None)
                .unwrap();
        }
        assert_eq!(st.payout_address_for(0), Some(a(11)));
        assert_eq!(st.payout_address_for(1), Some(a(12)));
        assert_eq!(st.payout_address_for(2), Some(a(13)));
        assert_eq!(st.payout_address_for(3), None);
    }

    // Old behaviour: self-stake earned nothing and the shares did not sum to
    // the reward.
    #[test]
    fn reward_share_is_exact_and_pays_commission_and_delegators() {
        let mut st = StakingState::new();
        st.join_validator(a(1), MIN_VALIDATOR_STAKE, 1_000, None, None, None)
            .unwrap();
        let alone = st.reward_share(a(1), 10 * ONE_KUNA, 1_000);
        assert_eq!(alone, vec![(a(1), 10 * ONE_KUNA)]);
        st.delegate(a(5), a(1), MIN_VALIDATOR_STAKE).unwrap();
        let shares = st.reward_share(a(1), 10 * ONE_KUNA, 1_000);
        let sum: u64 = shares.iter().map(|(_, x)| x).sum();
        assert_eq!(sum, 10 * ONE_KUNA);
        // 10% commission, rest split 50/50.
        assert_eq!(shares, vec![(a(1), 5_500_000_000), (a(5), 4_500_000_000)]);
    }

    // Old behaviour: delegated stake was cut twice (inside validator.stake
    // and again per delegation), desynchronising total_staked.
    #[test]
    fn slash_cuts_delegated_stake_once() {
        let mut st = StakingState::new();
        st.join_validator(a(1), MIN_VALIDATOR_STAKE, 0, None, None, None)
            .unwrap();
        st.delegate(a(5), a(1), 10_000 * ONE_KUNA).unwrap();
        let slashed = st
            .slash(DoubleSignEvidence {
                validator: a(1),
                height: 7,
            })
            .unwrap();
        assert_eq!(slashed, 3_000 * ONE_KUNA); // 5% of 60k
        assert_eq!(st.validators[0].stake, 57_000 * ONE_KUNA);
        assert_eq!(st.total_staked, 57_000 * ONE_KUNA);
        assert_eq!(st.self_stake(a(1)), 47_500 * ONE_KUNA);
        assert_eq!(st.delegations[0].amount, 9_500 * ONE_KUNA);
    }

    #[derive(Debug, Clone)]
    enum Op {
        Join(u8),
        Delegate(u8, u8, u64),
        Unbond(u8, u8, u64),
        Leader(u16),
        Slash(u8),
        Advance,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0u8..4).prop_map(Op::Join),
            (10u8..13, 0u8..4, 1u64..20_000).prop_map(|(d, v, x)| Op::Delegate(d, v, x)),
            (10u8..13, 0u8..4, 1u64..20_000).prop_map(|(d, v, x)| Op::Unbond(d, v, x)),
            (0u16..4).prop_map(Op::Leader),
            (0u8..4).prop_map(Op::Slash),
            Just(Op::Advance),
        ]
    }

    proptest! {
        // Conservation: liquid + staked + unbonding + treasury (slashed stake)
        // == premine + mining issued, and everything stays <= the cap.
        #[test]
        fn supply_never_exceeds_cap(ops in proptest::collection::vec(op(), 1..60)) {
            let mut st = StakingState::new();
            st.init_treasury(a(0xFF));
            let mut liquid: u128 = u128::from(FOUNDER_PREMINE);
            let mut treasury: u128 = 0;
            let mut slashed_evidence = std::collections::BTreeSet::new();
            for o in ops {
                match o {
                    Op::Join(v) => {
                        if liquid >= u128::from(MIN_VALIDATOR_STAKE)
                            && st.join_validator(a(v + 1), MIN_VALIDATOR_STAKE, 500, None, None, None).is_ok() {
                            liquid -= u128::from(MIN_VALIDATOR_STAKE);
                        }
                    }
                    Op::Delegate(d, v, x) => {
                        let x = x * ONE_KUNA;
                        if liquid >= u128::from(x) && st.delegate(a(d), a(v + 1), x).is_ok() {
                            liquid -= u128::from(x);
                        }
                    }
                    Op::Unbond(d, v, x) => { let _ = st.unbond(a(d), a(v + 1), x * ONE_KUNA); }
                    Op::Leader(i) => {
                        if let Some(v) = st.authority_validator(i).cloned() {
                            let before = st.total_mining_issued;
                            let out = st.on_leader_committed(i).unwrap();
                            let shares = st.reward_share(v.address, out.amount, v.commission_bps);
                            let paid: u64 = shares.iter().map(|(_, x)| x).sum();
                            prop_assert_eq!(paid, out.amount);
                            prop_assert_eq!(st.total_mining_issued - before, out.amount);
                            liquid += u128::from(paid);
                        }
                    }
                    Op::Slash(v) => {
                        let ev = DoubleSignEvidence { validator: a(v + 1), height: st.committed_leader_height };
                        if slashed_evidence.insert(StakingState::evidence_id(&ev)) {
                            if let Ok(x) = st.slash(ev) { treasury += u128::from(x); }
                        }
                    }
                    Op::Advance => {
                        st.committed_leader_height += UNBONDING_ROUNDS;
                        let pairs: Vec<_> = st.unbonding_ready().iter().map(|e| (e.delegator, e.validator)).collect();
                        for (d, v) in pairs {
                            if let Ok(x) = st.withdraw_unbonded(d, v) { liquid += u128::from(x); }
                        }
                    }
                }
                let queued: u128 = st.unbonding_queue.iter().map(|e| u128::from(e.amount)).sum();
                let stakes: u128 = st.validators.iter().map(|v| u128::from(v.stake)).sum();
                prop_assert_eq!(stakes, u128::from(st.total_staked));
                for v in &st.validators {
                    prop_assert!(v.stake >= st.delegated_to(v.address));
                }
                let accounted = liquid + u128::from(st.total_staked) + queued + treasury;
                prop_assert_eq!(accounted, u128::from(FOUNDER_PREMINE) + u128::from(st.total_mining_issued));
                // Every bucket of the supply book must fit under the cap:
                // premine + mining + treasury + genesis allocation.
                prop_assert!(
                    accounted
                        + u128::from(TREASURY_TOTAL)
                        + u128::from(GENESIS_VALIDATOR_ALLOCATION)
                        <= u128::from(TOTAL_SUPPLY)
                );
            }
        }
    }

    // A StakingState persisted by a pre-c8800ac binary (ValidatorInfo without `slashed`)
    // must still load, as the commit message claims ("bincode stays backward compatible").
    // Test from Jarvis review (c8800ac).
    #[test]
    fn f7_jarvis_pre_slashed_field_state_still_loads() {
        let mut st = StakingState::new();
        for i in 1..=3u8 {
            st.join_validator(a(i), MIN_VALIDATOR_STAKE, 0, None, None, None)
                .unwrap();
        }
        let full = bincode::serialize(&st).unwrap();
        // validators is the first field: u64 len + each ValidatorInfo. The two
        // trailing fields are `slashed` (1 byte) and `jailed_until_height`
        // (u64, 8 bytes); drop all 9 per validator to reconstruct the oldest
        // pre-`slashed` (10-field) layout.
        let vec_bytes = bincode::serialize(&st.validators).unwrap();
        assert_eq!(&full[..vec_bytes.len()], &vec_bytes[..]);
        let mut old = vec_bytes[..8].to_vec();
        for v in &st.validators {
            let b = bincode::serialize(v).unwrap();
            assert!(
                b[b.len() - 9..].iter().all(|byte| *byte == 0),
                "slashed + jail height are zero in a fresh record"
            );
            old.extend_from_slice(&b[..b.len() - 9]);
        }
        old.extend_from_slice(&full[vec_bytes.len()..]);
        let decoded = StakingState::from_bytes(&old);
        assert!(
            decoded.is_ok(),
            "pre-c8800ac staking bytes must load: {:?}",
            decoded.err()
        );
        assert_eq!(decoded.unwrap().validators.len(), 3);
    }

    // Old StakingState bytes (pre-c8800ac, no slashed field) decode to identical
    // in-memory state. Test from Jarvis review.
    #[test]
    fn jarvis_old_bytes_decode_to_identical_state() {
        let mut st = StakingState::new();
        for i in 1..=3u8 {
            st.join_validator(a(i), MIN_VALIDATOR_STAKE, 0, None, None, None)
                .unwrap();
        }
        let full = bincode::serialize(&st).unwrap();
        // Strip the two trailing fields (`slashed` 1 byte + `jailed_until_height`
        // 8 bytes) from each ValidatorInfo to reach the pre-`slashed` layout.
        let vec_bytes = bincode::serialize(&st.validators).unwrap();
        assert_eq!(&full[..vec_bytes.len()], &vec_bytes[..]);
        let mut old = vec_bytes[..8].to_vec();
        for v in &st.validators {
            let b = bincode::serialize(v).unwrap();
            assert!(b[b.len() - 9..].iter().all(|byte| *byte == 0));
            old.extend_from_slice(&b[..b.len() - 9]);
        }
        old.extend_from_slice(&full[vec_bytes.len()..]);
        let decoded = StakingState::from_bytes(&old).unwrap();
        assert_eq!(decoded.validators.len(), 3);
        // Validate each field round-trips identically.
        for (orig, dec) in st.validators.iter().zip(decoded.validators.iter()) {
            assert_eq!(orig.address, dec.address);
            assert_eq!(orig.stake, dec.stake);
            assert_eq!(orig.commission_bps, dec.commission_bps);
            assert_eq!(orig.active, dec.active);
            assert_eq!(orig.payout_address, dec.payout_address);
            assert_eq!(orig.public_key, dec.public_key);
            assert_eq!(orig.vrf_public_key, dec.vrf_public_key);
            assert_eq!(orig.missed_leader_count, dec.missed_leader_count);
            assert_eq!(orig.last_online_height, dec.last_online_height);
            assert_eq!(
                orig.last_commission_change_height,
                dec.last_commission_change_height
            );
            assert!(!dec.slashed); // defaulted to false
        }
        assert_eq!(decoded.delegations, st.delegations);
        assert_eq!(decoded.total_staked, st.total_staked);
        assert_eq!(decoded.committed_leader_height, st.committed_leader_height);
        assert_eq!(decoded.total_mining_issued, st.total_mining_issued);
        assert_eq!(decoded.reward_totals, st.reward_totals);
        assert_eq!(decoded.unbonding_queue, st.unbonding_queue);
        assert_eq!(decoded.treasury, st.treasury);
    }

    // Single validator, no delegations: old bytes decode identically.
    // Test from Jarvis review.
    #[test]
    fn jarvis_single_validator_no_delegations_old_bytes() {
        let mut st = StakingState::new();
        st.join_validator(a(1), MIN_VALIDATOR_STAKE, 0, None, None, None)
            .unwrap();
        let full = bincode::serialize(&st).unwrap();
        let vec_bytes = bincode::serialize(&st.validators).unwrap();
        let mut old = vec_bytes[..8].to_vec();
        for v in &st.validators {
            let b = bincode::serialize(v).unwrap();
            assert!(b[b.len() - 9..].iter().all(|byte| *byte == 0));
            old.extend_from_slice(&b[..b.len() - 9]);
        }
        old.extend_from_slice(&full[vec_bytes.len()..]);
        let decoded = StakingState::from_bytes(&old).unwrap();
        assert_eq!(decoded.validators.len(), 1);
        assert_eq!(decoded.delegations.len(), 0);
    }

    // Corrupted new-format row (version prefix present, payload corrupted) must
    // NOT be silently accepted as old format. Test from Jarvis review.
    #[test]
    fn jarvis_corrupt_new_row_is_not_silently_accepted() {
        let mut st = StakingState::new();
        st.join_validator(a(1), MIN_VALIDATOR_STAKE, 0, None, None, None)
            .unwrap();
        let new_bytes = StakingState::to_bytes(&st).unwrap();
        // Corrupt the payload (flip a byte after the version header).
        let mut bad = new_bytes.clone();
        if bad.len() > 3 {
            bad[3] ^= 0xFF;
        }
        let result = StakingState::from_bytes(&bad);
        assert!(result.is_err(), "corrupted new-format must fail to decode");
    }

    // Huge validator count in old format must not cause OOM / panic.
    // Test from Jarvis review.
    #[test]
    fn jarvis_huge_validator_len_does_not_panic() {
        // Build a fake old-format payload with a massive validator count.
        // The old format is: validators_len (u64) + validators...
        // We only need the length field to trigger the capacity check.
        let fake_len: u64 = 10_000_000;
        let mut fake = Vec::new();
        fake.extend_from_slice(&fake_len.to_le_bytes());
        // No actual validator data - deserializer will fail on missing bytes.
        let result = StakingState::from_bytes(&fake);
        // Must not panic, must not OOM. Should fail cleanly on missing data.
        assert!(result.is_err());
    }

    // ---- Jarvis review tests (PR #68, commit 8105a8d) ----
    struct JRng(u64);
    impl JRng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn addr(&mut self) -> Address {
            let mut b = [0u8; 32];
            for x in b.iter_mut() {
                *x = self.next() as u8;
            }
            Address(b)
        }
    }
    /// Strip the two trailing per-validator fields (`slashed` 1 byte +
    /// `jailed_until_height` 8 bytes) to reach the oldest (10-field) layout.
    fn j_old_bytes(st: &StakingState) -> Vec<u8> {
        strip_validator_trailer(st, 9, None)
    }

    /// Strip only the `jailed_until_height` (8 bytes) to reach the layout that
    /// `c8800ac`/`f3675d3` wrote untagged (11 fields, `slashed` present).
    fn j_c8800ac_bytes(st: &StakingState) -> Vec<u8> {
        strip_validator_trailer(st, 8, None)
    }

    /// The same 11-field layout, but tagged as StakingState version 1.
    fn j_v1_bytes(st: &StakingState) -> Vec<u8> {
        strip_validator_trailer(st, 8, Some(kovanica_types::STAKING_STATE_VERSION_PREVIOUS))
    }

    fn strip_validator_trailer(st: &StakingState, drop: usize, version: Option<u8>) -> Vec<u8> {
        let full = bincode::serialize(st).unwrap();
        let vec_bytes = bincode::serialize(&st.validators).unwrap();
        let mut out = Vec::new();
        let head;
        if let Some(v) = version {
            out.extend_from_slice(&[kovanica_types::SNAPSHOT_MAGIC, v]);
            head = 0;
        } else {
            head = 0;
        }
        out.extend_from_slice(&vec_bytes[head..8]);
        for v in &st.validators {
            let b = bincode::serialize(v).unwrap();
            out.extend_from_slice(&b[..b.len() - drop]);
        }
        out.extend_from_slice(&full[vec_bytes.len()..]);
        out
    }
    fn j_state(r: &mut JRng, n: usize, dels: usize, treasury: bool) -> StakingState {
        let mut st = StakingState::new();
        if treasury {
            st.init_treasury(r.addr());
        }
        let mut vals = vec![];
        for _ in 0..n {
            let a = r.addr();
            vals.push(a);
            st.join_validator(
                a,
                MIN_VALIDATOR_STAKE + (r.next() % 1000) * ONE_KUNA,
                (r.next() % 2000) as u16,
                Some(a),
                Some(PublicKey(a.0)),
                Some(VrfPublicKey(r.addr().0)),
            )
            .unwrap();
        }
        for _ in 0..dels {
            let v = vals[(r.next() as usize) % n];
            st.delegations.push(Delegation {
                delegator: r.addr(),
                validator: v,
                amount: r.next() % (1u64 << 50),
            });
        }
        st.committed_leader_height = r.next() % 100_000;
        st.total_mining_issued = r.next() % (1u64 << 55);
        st
    }
    #[test]
    fn jj_fuzz_old_new_corrupt() {
        let mut r = JRng(0x9e3779b97f4a7c15);
        let (mut total, mut wrong_old, mut wrong_unv, mut wrong_v1, mut corrupt_ok) =
            (0, 0, 0, 0, 0);
        for n in 1..=5usize {
            for dels in [0usize, 1, 3] {
                for t in [false, true] {
                    for _ in 0..400 {
                        let st = j_state(&mut r, n, dels, t);
                        let want = bincode::serialize(&st).unwrap();
                        total += 1;
                        // legacy pre-c8800ac
                        match StakingState::from_bytes(&j_old_bytes(&st)) {
                            Ok(g) if bincode::serialize(&g).unwrap() == want => {}
                            _ => wrong_old += 1,
                        }
                        // unversioned c8800ac/f3675d3 rows (11 fields, slashed,
                        // no jail height)
                        match StakingState::from_bytes(&j_c8800ac_bytes(&st)) {
                            Ok(g) if bincode::serialize(&g).unwrap() == want => {}
                            _ => wrong_unv += 1,
                        }
                        // StakingState version 1 rows (same 11-field layout, tagged)
                        let v1 = j_v1_bytes(&st);
                        match StakingState::from_bytes(&v1) {
                            Ok(g) if bincode::serialize(&g).unwrap() == want => {}
                            _ => wrong_v1 += 1,
                        }
                        // corruptions of a v1 row: truncate 3; append 1 byte;
                        // unknown version byte; oversized validators length.
                        if StakingState::from_bytes(&v1[..v1.len() - 3]).is_ok() {
                            corrupt_ok += 1;
                        }
                        let mut c = v1.clone();
                        c.push(0);
                        if StakingState::from_bytes(&c).is_ok() {
                            corrupt_ok += 1;
                        }
                        let mut c = v1.clone();
                        c[1] = 99; // no such version
                        if StakingState::from_bytes(&c).is_ok() {
                            corrupt_ok += 1;
                        }
                        let mut c = v1.clone();
                        c[2..10].copy_from_slice(&(u64::MAX).to_le_bytes());
                        if StakingState::from_bytes(&c).is_ok() {
                            corrupt_ok += 1;
                        }
                    }
                }
            }
        }
        println!(
            "JARVIS fuzz total={total} wrong_old={wrong_old} wrong_unversioned={wrong_unv} wrong_v1={wrong_v1} corrupt_accepted={corrupt_ok}"
        );
        assert_eq!((wrong_old, wrong_unv, wrong_v1, corrupt_ok), (0, 0, 0, 0));
    }
    #[test]
    fn jj_huge_len_no_abort() {
        for len in [1u64 << 40, u64::MAX, 1u64 << 20] {
            let mut bytes = bincode::serialize(&StakingState::new()).unwrap();
            bytes[..8].copy_from_slice(&len.to_le_bytes());
            assert!(StakingState::from_bytes(&bytes).is_err());
        }
        println!("JARVIS huge len: Err, no abort");
    }
    #[test]
    fn jj_legacy_first_byte_collision() {
        // Legacy/unversioned staking row starts with validators.len() as u64 LE.
        // 75 validators => first byte 0x4B == SNAPSHOT_MAGIC.
        let mut r = JRng(7);
        let mut st = StakingState::new();
        for _ in 0..75 {
            let a = r.addr();
            st.validators.push(ValidatorInfo {
                address: a,
                stake: MIN_VALIDATOR_STAKE,
                commission_bps: 0,
                active: false,
                payout_address: a,
                public_key: None,
                vrf_public_key: None,
                missed_leader_count: 0,
                last_online_height: 0,
                last_commission_change_height: 0,
                slashed: false,
                jailed_until_height: 0,
            });
        }
        let unv = bincode::serialize(&st).unwrap();
        println!(
            "JARVIS collision: first byte {:#x}, second {:#x}; from_bytes(unversioned 75) = {:?}",
            unv[0],
            unv[1],
            StakingState::from_bytes(&unv)
                .map(|s| s.validators.len())
                .map_err(|e| e.to_string())
        );
        println!(
            "JARVIS collision: from_bytes(legacy 75) = {:?}",
            StakingState::from_bytes(&j_old_bytes(&st))
                .map(|s| s.validators.len())
                .map_err(|e| e.to_string())
        );
    }
    // --- PRO-19 part 2: slash jail (explicit re-entry only) ---

    /// Toni's 2026-10-23 decisions: the jail lasts about one day, and an
    /// epoch is 8 h. At 12 s per committed leader the jail is 7_200 heights,
    /// which is 3 epochs (same wall-clock time as 3 × 7 200 DAG rounds of
    /// 4 s) and one commission cooldown.
    #[test]
    fn jail_lasts_one_day_of_committed_leaders() {
        const ROUND_SECS: u64 = 4;
        assert_eq!(JAIL_ROUNDS, 7_200);
        assert_eq!(JAIL_ROUNDS, 3 * EPOCH_LEADER_HEIGHTS, "jail = 3 epochs");
        assert_eq!(
            JAIL_ROUNDS * LEADER_INTERVAL_SECS,
            3 * EPOCH_ROUNDS * ROUND_SECS,
            "jail = 3 epochs of nominal wall-clock time (no skipped slots)"
        );
        assert_eq!(JAIL_ROUNDS, COMMISSION_CHANGE_COOLDOWN);
        assert_eq!(JAIL_ROUNDS * LEADER_INTERVAL_SECS, 86_400);
    }

    /// A slashed validator leaves the active set at once and is jailed until
    /// `committed_leader_height + JAIL_ROUNDS`. Nothing re-activates it by
    /// itself, not even after the jail elapses.
    #[test]
    fn slash_deactivates_and_jails_until_explicit_restake() {
        let mut st = StakingState::new();
        st.committed_leader_height = 1_000;
        st.join_validator(a(1), MIN_VALIDATOR_STAKE, 0, None, None, None)
            .unwrap();
        assert!(st.validators[0].active);

        st.slash_validator(a(1)).unwrap();
        let v = &st.validators[0];
        assert!(v.slashed, "slash marks the record");
        assert!(
            !v.active,
            "slash removes it from the active set immediately"
        );
        assert_eq!(
            v.jailed_until_height,
            1_000 + JAIL_ROUNDS,
            "jail ends JAIL_ROUNDS after the current committed-leader height"
        );

        // Time passing alone must not restart it.
        st.committed_leader_height = 1_000 + JAIL_ROUNDS + 5;
        assert!(!st.validators[0].active, "time alone never reactivates");
        assert!(st.validators[0].slashed, "time alone never clears the flag");
    }

    /// A stake transaction during the jail (and while the record is jailed at
    /// all) is rejected; the record cannot be topped up back into the set.
    #[test]
    fn stake_during_jail_is_rejected() {
        let mut st = StakingState::new();
        st.committed_leader_height = 0;
        st.join_validator(a(1), MIN_VALIDATOR_STAKE, 0, None, None, None)
            .unwrap();
        st.slash_validator(a(1)).unwrap();
        let v = &st.validators[0];
        assert_eq!(v.jailed_until_height, JAIL_ROUNDS);

        // Mid-jail stake is refused.
        st.committed_leader_height = JAIL_ROUNDS - 1;
        assert!(matches!(
            st.reactivate_validator(a(1), MIN_VALIDATOR_STAKE),
            Err(StakingError::ValidatorSlashed)
        ));

        // Exactly at the jail boundary the record may return, but only with an
        // explicit stake of at least MIN_VALIDATOR_STAKE.
        st.committed_leader_height = JAIL_ROUNDS;
        assert!(matches!(
            st.reactivate_validator(a(1), 1),
            Err(StakingError::InsufficientStake)
        ));
        assert!(matches!(
            st.reactivate_validator(a(1), MIN_VALIDATOR_STAKE),
            Ok(())
        ));
        let v = &st.validators[0];
        assert!(v.active, "an explicit restake returns the validator");
        assert!(!v.slashed, "a served jail clears the slashed flag");
        assert_eq!(v.jailed_until_height, 0, "and clears the jail");
    }

    /// Jarvis #80 review P2: a jail that starts at a non-zero height ends
    /// exactly `JAIL_ROUNDS` later. Slashed at height 1 → still jailed at
    /// 7 200, re-stakeable at 7 201.
    #[test]
    fn jail_from_height_one_ends_at_7201() {
        let mut st = StakingState::new();
        st.committed_leader_height = 1;
        st.join_validator(a(1), MIN_VALIDATOR_STAKE, 0, None, None, None)
            .unwrap();
        st.slash_validator(a(1)).unwrap();
        assert_eq!(st.validators[0].jailed_until_height, 7_201);

        st.committed_leader_height = 7_200;
        assert!(matches!(
            st.reactivate_validator(a(1), MIN_VALIDATOR_STAKE),
            Err(StakingError::ValidatorSlashed)
        ));
        st.committed_leader_height = 7_201;
        assert!(matches!(
            st.reactivate_validator(a(1), MIN_VALIDATOR_STAKE),
            Ok(())
        ));
        assert!(st.validators[0].active);
    }

    /// Rows slashed before the jail existed decode with `jailed_until_height == 0`
    /// and stay barred forever — the F7 guarantee is preserved for them.
    #[test]
    fn legacy_slashed_row_without_a_jail_height_stays_out() {
        let mut st = StakingState::new();
        st.committed_leader_height = 10;
        st.join_validator(a(1), MIN_VALIDATOR_STAKE, 0, None, None, None)
            .unwrap();
        // Model a pre-jail slashed record: slashed, inactive, no jail height.
        st.validators[0].slashed = true;
        st.validators[0].active = false;
        st.validators[0].jailed_until_height = 0;

        // Even long after, and even at any height, a stake cannot revive it.
        st.committed_leader_height = 10_000_000;
        assert!(matches!(
            st.reactivate_validator(a(1), MIN_VALIDATOR_STAKE),
            Err(StakingError::ValidatorSlashed)
        ));

        // A repeat slash must not convert the permanent marker into a finite
        // jail (which would become reactivatable once the jail elapses).
        st.slash_validator(a(1)).unwrap();
        assert_eq!(
            st.validators[0].jailed_until_height, 0,
            "re-slashing a permanently excluded record keeps jail height 0"
        );
        assert!(matches!(
            st.reactivate_validator(a(1), MIN_VALIDATOR_STAKE),
            Err(StakingError::ValidatorSlashed)
        ));
    }

    /// StakingState v1 rows (11-field ValidatorInfo, no jail) lift to a jail of
    /// 0 and keep a pre-existing `slashed` flag, so a slashed v1 row stays out.
    #[test]
    fn version_1_staking_row_decodes_without_a_jail() {
        let mut st = StakingState::new();
        st.join_validator(a(1), MIN_VALIDATOR_STAKE, 0, None, None, None)
            .unwrap();
        st.join_validator(a(2), MIN_VALIDATOR_STAKE, 0, None, None, None)
            .unwrap();
        // One record slashed pre-jail: slashed, inactive, no jail height.
        st.validators[0].slashed = true;
        st.validators[0].active = false;

        let mut decoded = StakingState::from_bytes(&j_v1_bytes(&st)).unwrap();
        assert_eq!(decoded.validators.len(), 2);
        assert_eq!(decoded.validators[0].jailed_until_height, 0);
        assert!(decoded.validators[0].slashed, "v1 slashed flag survives");
        assert_eq!(decoded.validators[1].jailed_until_height, 0);
        assert!(!decoded.validators[1].slashed);

        // And that lifted record is permanently barred.
        assert!(matches!(
            decoded.reactivate_validator(a(1), MIN_VALIDATOR_STAKE),
            Err(StakingError::ValidatorSlashed)
        ));
    }

    /// A round-trip through the current (v2) encoding preserves a jail.
    #[test]
    fn jail_round_trips_through_version_2_encoding() {
        let mut st = StakingState::new();
        st.committed_leader_height = 500;
        st.join_validator(a(1), MIN_VALIDATOR_STAKE, 0, None, None, None)
            .unwrap();
        st.slash_validator(a(1)).unwrap();
        let decoded = StakingState::from_bytes(&st.to_bytes().unwrap()).unwrap();
        assert!(decoded.validators[0].slashed);
        assert!(!decoded.validators[0].active);
        assert_eq!(decoded.validators[0].jailed_until_height, 500 + JAIL_ROUNDS);
    }
}
