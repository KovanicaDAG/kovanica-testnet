//! Light-node registration, VRF witness set, and reward escrow.
//!
//! This state is not a field of [`crate::StakingState`]. Callers persist it
//! in its own table. Light stake does not enter the validator committee.
//!
//! [`LIGHT_REWARD_BPS`] is 2_000 (20% of `block_reward`). The escrow is paid
//! to light-node witnesses at epoch close. Unclaimed atoms return to the
//! leaders who contributed them, so the atoms minted at a height still equal
//! `block_reward`. Tests may pass 0 into [`split_block_reward`] to check the
//! no-escrow path.

use kovanica_types::{Address, Hash, PublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ONE_KUNA, UNBONDING_ROUNDS};

/// Fraction of `block_reward` escrowed for light nodes, in basis points.
///
/// 2_000 is 20%. The leader side is the rest. The two sides sum to the
/// scheduled reward, and dust from the division stays with the leader.
pub const LIGHT_REWARD_BPS: u16 = 2_000;

/// Minimum light-node bond: 100 KUNA.
pub const MIN_LIGHT_BOND: u64 = 100 * ONE_KUNA;

/// Cap on light identities stored by a full node.
pub const MAX_LIGHT_NODES: usize = 4_096;

/// Winning witness slots in one epoch.
pub const LIGHT_WITNESS_SLOTS: usize = 32;

/// One registered light node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightNode {
    /// Account that bonded the stake.
    pub address: Address,
    /// ECVRF public key for the lottery.
    pub vrf_public_key: PublicKey,
    /// Bond in atoms.
    pub stake: u64,
    /// First epoch in which this node may submit a witness.
    pub effective_epoch: u64,
    /// Last epoch (inclusive) the node may witness, once it has exited.
    pub exit_epoch: Option<u64>,
}

/// One stored VRF witness. The execution layer checks the proof first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightWitness {
    /// Registered light-node address.
    pub address: Address,
    /// VRF hash (32 bytes).
    pub vrf_hash: [u8; 32],
    /// VRF proof (96 bytes).
    #[serde(with = "kovanica_types::crypto::vrf_proof_bytes")]
    pub vrf_proof: [u8; 96],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LightEpoch {
    epoch: u64,
    beacon: Option<Hash>,
    /// Leader payout address and atoms contributed during this epoch.
    escrow: Vec<(Address, u64)>,
    witnesses: Vec<LightWitness>,
    settled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LightUnbond {
    address: Address,
    amount: u64,
    release_height: u64,
}

/// Light-node set. Persist this blob in the `light_set` table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LightSet {
    nodes: Vec<LightNode>,
    epochs: Vec<LightEpoch>,
    unbonding: Vec<LightUnbond>,
}

/// Why a light-node transition was rejected.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LightSetError {
    /// The bond is below [`MIN_LIGHT_BOND`].
    #[error("light bond is below the minimum")]
    BondTooSmall,
    /// This address already has a light-node identity.
    #[error("light node is already registered")]
    AlreadyRegistered,
    /// [`MAX_LIGHT_NODES`] identities are already stored.
    #[error("light node set is full")]
    CapReached,
    /// The address has no light-node identity.
    #[error("light node is not registered")]
    NotRegistered,
    /// The node is not active in the requested epoch.
    #[error("light node is not active in this epoch")]
    NotActive,
    /// A witness for this address is already stored.
    #[error("light witness is already stored")]
    DuplicateWitness,
    /// The epoch has no beacon yet, or it is already settled.
    #[error("light epoch is not open for witnesses")]
    EpochClosed,
}

/// Where an epoch's escrow went.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SettleOutcome {
    /// Atoms paid to winning witnesses.
    pub winner_payouts: Vec<(Address, u64)>,
    /// Atoms returned to leaders who contributed escrow.
    pub leader_refunds: Vec<(Address, u64)>,
}

impl SettleOutcome {
    /// Sum of winner payouts and leader refunds.
    pub fn total(&self) -> u64 {
        let winners: u64 = self.winner_payouts.iter().map(|(_, amount)| *amount).sum();
        let refunds: u64 = self.leader_refunds.iter().map(|(_, amount)| *amount).sum();
        winners.saturating_add(refunds)
    }
}

/// Split `full` into `(leader_side, escrow)`.
///
/// `bps` is clamped to 10_000. The truncated remainder stays on the leader
/// side, and the two parts sum to `full`. The live call uses
/// [`LIGHT_REWARD_BPS`] (20%).
pub fn split_block_reward(full: u64, bps: u16) -> (u64, u64) {
    let bps = u128::from(bps.min(10_000));
    let escrow = (u128::from(full) * bps / 10_000) as u64;
    (full - escrow, escrow)
}

/// Divide an epoch escrow across submitted winners and contributing leaders.
///
/// There are [`LIGHT_WITNESS_SLOTS`] equal slots. Each submitted winner
/// takes one slot. Integer dust on that division goes to the lowest winner
/// address. Unfilled slots are returned to contributing leaders in proportion
/// to what they paid in, with that dust given one atom at a time starting at
/// the lowest leader address. No winners means the whole escrow is returned.
/// The two vectors sum to `escrow_total`.
pub fn distribute_escrow(
    escrow_total: u64,
    winners: &[Address],
    contributors: &[(Address, u64)],
) -> SettleOutcome {
    if escrow_total == 0 {
        return SettleOutcome::default();
    }
    let mut winners = winners.to_vec();
    winners.sort_by_key(|address| address.0);
    winners.dedup();
    if winners.is_empty() {
        return SettleOutcome {
            winner_payouts: Vec::new(),
            leader_refunds: pro_rata(escrow_total, contributors),
        };
    }
    let slots = LIGHT_WITNESS_SLOTS as u64;
    let n = winners.len() as u64;
    let per_slot = escrow_total / slots;
    let dust = escrow_total % slots;
    let unfilled = per_slot.saturating_mul(slots.saturating_sub(n));
    let mut winner_payouts = Vec::with_capacity(winners.len());
    for (index, address) in winners.iter().enumerate() {
        let mut amount = per_slot;
        if index == 0 {
            amount = amount.saturating_add(dust);
        }
        if amount > 0 {
            winner_payouts.push((*address, amount));
        }
    }
    SettleOutcome {
        winner_payouts,
        leader_refunds: pro_rata(unfilled, contributors),
    }
}

fn pro_rata(amount: u64, parts: &[(Address, u64)]) -> Vec<(Address, u64)> {
    let mut ranked: Vec<(Address, u64)> = parts
        .iter()
        .copied()
        .filter(|(_, contrib)| *contrib > 0)
        .collect();
    ranked.sort_by_key(|(address, _)| address.0);
    let mut merged: Vec<(Address, u64)> = Vec::new();
    for (address, contrib) in ranked {
        if let Some(slot) = merged.iter_mut().find(|(existing, _)| *existing == address) {
            slot.1 = slot.1.saturating_add(contrib);
        } else {
            merged.push((address, contrib));
        }
    }
    let total: u128 = merged.iter().map(|(_, contrib)| u128::from(*contrib)).sum();
    if amount == 0 || total == 0 || merged.is_empty() {
        return Vec::new();
    }
    let mut given = 0u64;
    let mut out: Vec<(Address, u64)> = Vec::new();
    for (address, contrib) in &merged {
        let share = (u128::from(amount) * u128::from(*contrib) / total) as u64;
        given = given.saturating_add(share);
        if share > 0 {
            out.push((*address, share));
        }
    }
    let mut dust = amount.saturating_sub(given);
    let mut index = 0usize;
    while dust > 0 {
        let address = merged[index % merged.len()].0;
        if let Some(slot) = out.iter_mut().find(|(existing, _)| *existing == address) {
            slot.1 = slot.1.saturating_add(1);
        } else {
            out.push((address, 1));
        }
        dust -= 1;
        index += 1;
    }
    out.sort_by_key(|(address, _)| address.0);
    out
}

impl LightSet {
    /// Registered nodes, in address order.
    pub fn nodes(&self) -> &[LightNode] {
        &self.nodes
    }

    /// Beacon recorded for `epoch`, if the opening leader has been committed.
    pub fn beacon(&self, epoch: u64) -> Option<Hash> {
        self.epochs
            .iter()
            .find(|record| record.epoch == epoch)
            .and_then(|record| record.beacon)
    }

    /// Witnesses stored for `epoch`.
    pub fn witnesses(&self, epoch: u64) -> &[LightWitness] {
        self.epochs
            .iter()
            .find(|record| record.epoch == epoch)
            .map(|record| record.witnesses.as_slice())
            .unwrap_or(&[])
    }

    /// Escrow contributions for `epoch` (empty once the epoch is settled).
    pub fn escrow(&self, epoch: u64) -> &[(Address, u64)] {
        self.epochs
            .iter()
            .find(|record| record.epoch == epoch)
            .map(|record| record.escrow.as_slice())
            .unwrap_or(&[])
    }

    /// Nodes that may witness `epoch`.
    pub fn active_nodes(&self, epoch: u64) -> Vec<&LightNode> {
        self.nodes
            .iter()
            .filter(|node| node_is_active(node, epoch))
            .collect()
    }

    /// Bond `stake` at `height`. The node becomes active at the next epoch.
    ///
    /// `height` is a committed leader height; the light-set epoch is
    /// `kovanica_types::epoch_for_height(height)`, 2 400 heights ≈ 8 h, the same height-based unit execution uses to
    /// index the beacon (deliberately distinct from the round-based committee
    /// epoch).
    pub fn register(
        &mut self,
        address: Address,
        vrf_public_key: PublicKey,
        stake: u64,
        height: u64,
    ) -> Result<(), LightSetError> {
        if stake < MIN_LIGHT_BOND {
            return Err(LightSetError::BondTooSmall);
        }
        if self.nodes.iter().any(|node| node.address == address) {
            return Err(LightSetError::AlreadyRegistered);
        }
        if self.nodes.len() >= MAX_LIGHT_NODES {
            return Err(LightSetError::CapReached);
        }
        let epoch = kovanica_types::epoch_for_height(height);
        self.nodes.push(LightNode {
            address,
            vrf_public_key,
            stake,
            effective_epoch: epoch.saturating_add(1),
            exit_epoch: None,
        });
        self.nodes.sort_by_key(|node| node.address.0);
        Ok(())
    }

    /// Exit. A node that is not active yet is refunded immediately.
    ///
    /// An active node stays in the current epoch and unbonds after
    /// [`UNBONDING_ROUNDS`] committed leaders. Returns `(refund_now, unbond_height)`.
    /// The epoch here is the same height-based light-set epoch as
    /// [`Self::register`] (`kovanica_types::epoch_for_height(height)`, 2 400 heights ≈ 8 h), not the round-based
    /// committee epoch.
    pub fn exit(
        &mut self,
        address: Address,
        height: u64,
    ) -> Result<(u64, Option<u64>), LightSetError> {
        let epoch = kovanica_types::epoch_for_height(height);
        let index = self
            .nodes
            .iter()
            .position(|node| node.address == address)
            .ok_or(LightSetError::NotRegistered)?;
        if self.nodes[index].exit_epoch.is_some() {
            return Err(LightSetError::AlreadyRegistered);
        }
        if self.nodes[index].effective_epoch > epoch {
            let stake = self.nodes[index].stake;
            self.nodes.remove(index);
            return Ok((stake, None));
        }
        let stake = self.nodes[index].stake;
        self.nodes[index].exit_epoch = Some(epoch);
        let release_height = height.saturating_add(UNBONDING_ROUNDS);
        self.unbonding.push(LightUnbond {
            address,
            amount: stake,
            release_height,
        });
        self.unbonding
            .sort_by_key(|entry| (entry.address.0, entry.release_height));
        Ok((0, Some(release_height)))
    }

    /// Record the epoch-opening leader digest. A later call does not replace it.
    pub fn note_beacon(&mut self, epoch: u64, beacon: Hash) {
        let record = self.epoch_mut(epoch);
        if record.beacon.is_none() {
            record.beacon = Some(beacon);
        }
    }

    /// Add `amount` of escrow attributed to `leader` in `epoch`.
    pub fn add_escrow(&mut self, epoch: u64, leader: Address, amount: u64) {
        if amount == 0 {
            return;
        }
        let record = self.epoch_mut(epoch);
        if record.settled {
            return;
        }
        if let Some(slot) = record.escrow.iter_mut().find(|(addr, _)| *addr == leader) {
            slot.1 = slot.1.saturating_add(amount);
        } else {
            record.escrow.push((leader, amount));
            record.escrow.sort_by_key(|(addr, _)| addr.0);
        }
    }

    /// Store a witness. The caller has already checked the VRF proof.
    pub fn submit_witness(
        &mut self,
        epoch: u64,
        address: Address,
        vrf_hash: [u8; 32],
        vrf_proof: [u8; 96],
    ) -> Result<(), LightSetError> {
        if !self
            .active_nodes(epoch)
            .iter()
            .any(|node| node.address == address)
        {
            return Err(LightSetError::NotActive);
        }
        let record = self.epoch_mut(epoch);
        if record.settled || record.beacon.is_none() {
            return Err(LightSetError::EpochClosed);
        }
        if record
            .witnesses
            .iter()
            .any(|witness| witness.address == address)
        {
            return Err(LightSetError::DuplicateWitness);
        }
        record.witnesses.push(LightWitness {
            address,
            vrf_hash,
            vrf_proof,
        });
        record.witnesses.sort_by_key(|witness| witness.address.0);
        Ok(())
    }

    /// Winning addresses for `epoch`, lowest priority first, at most 32.
    ///
    /// The same witnesses always produce the same order. Priorities are
    /// compared exactly by [`kovanica_types::vrf_priority_cmp`] (lower
    /// `hash / stake` wins) rather than through a `u128` scalar that saturated
    /// and left every witness tied on the same value. Addresses break ties.
    pub fn winners(&self, epoch: u64) -> Vec<Address> {
        let active = self.active_nodes(epoch);
        let Some(record) = self.epochs.iter().find(|record| record.epoch == epoch) else {
            return Vec::new();
        };
        let mut ranked: Vec<(&LightWitness, u64)> = Vec::new();
        for witness in &record.witnesses {
            let Some(node) = active.iter().find(|node| node.address == witness.address) else {
                continue;
            };
            ranked.push((witness, node.stake));
        }
        ranked.sort_by(|left, right| {
            kovanica_types::vrf_priority_cmp(&left.0.vrf_hash, left.1, &right.0.vrf_hash, right.1)
                .then(left.0.address.0.cmp(&right.0.address.0))
        });
        ranked.truncate(LIGHT_WITNESS_SLOTS);
        ranked
            .into_iter()
            .map(|(witness, _)| witness.address)
            .collect()
    }

    /// Pay the epoch escrow and mark it settled. A second call pays nothing.
    pub fn settle(&mut self, epoch: u64) -> SettleOutcome {
        let winners = self.winners(epoch);
        let Some(record) = self.epochs.iter_mut().find(|record| record.epoch == epoch) else {
            return SettleOutcome::default();
        };
        if record.settled {
            return SettleOutcome::default();
        }
        let escrow_total: u64 = record.escrow.iter().map(|(_, amount)| *amount).sum();
        let contributors = record.escrow.clone();
        let outcome = distribute_escrow(escrow_total, &winners, &contributors);
        record.escrow.clear();
        record.witnesses.clear();
        record.settled = true;
        outcome
    }

    /// Bonds whose unbonding height has been reached. Removes those identities.
    pub fn release_unbonded(&mut self, height: u64) -> Vec<(Address, u64)> {
        let mut ready = Vec::new();
        self.unbonding.retain(|entry| {
            if entry.release_height <= height {
                ready.push((entry.address, entry.amount));
                false
            } else {
                true
            }
        });
        ready.sort_by_key(|(address, _)| address.0);
        let mut merged: Vec<(Address, u64)> = Vec::new();
        for (address, amount) in ready {
            if let Some(slot) = merged.iter_mut().find(|(existing, _)| *existing == address) {
                slot.1 = slot.1.saturating_add(amount);
            } else {
                merged.push((address, amount));
            }
        }
        for (address, _) in &merged {
            let still = self.unbonding.iter().any(|entry| entry.address == *address);
            if !still {
                self.nodes
                    .retain(|node| node.address != *address || node.exit_epoch.is_none());
            }
        }
        merged
    }

    fn epoch_mut(&mut self, epoch: u64) -> &mut LightEpoch {
        if let Some(index) = self.epochs.iter().position(|record| record.epoch == epoch) {
            return &mut self.epochs[index];
        }
        self.epochs.push(LightEpoch {
            epoch,
            beacon: None,
            escrow: Vec::new(),
            witnesses: Vec::new(),
            settled: false,
        });
        self.epochs.sort_by_key(|record| record.epoch);
        let index = self
            .epochs
            .iter()
            .position(|record| record.epoch == epoch)
            .expect("epoch pushed above");
        &mut self.epochs[index]
    }
}

fn node_is_active(node: &LightNode, epoch: u64) -> bool {
    if node.effective_epoch > epoch {
        return false;
    }
    match node.exit_epoch {
        Some(end) => epoch <= end,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{block_reward, EPOCH_LEADER_HEIGHTS};

    fn addr(byte: u8) -> Address {
        Address([byte; 32])
    }

    fn key(byte: u8) -> PublicKey {
        PublicKey([byte; 32])
    }

    #[test]
    fn registration_activates_on_the_next_epoch() {
        let mut set = LightSet::default();
        set.register(addr(1), key(1), MIN_LIGHT_BOND, 10).unwrap();
        assert!(set.active_nodes(0).is_empty());
        assert_eq!(set.active_nodes(1).len(), 1);
        assert_eq!(set.nodes()[0].effective_epoch, 1);
        let (refund, unbond) = set.exit(addr(1), 10).unwrap();
        assert_eq!(refund, MIN_LIGHT_BOND);
        assert!(unbond.is_none());
        assert!(set.nodes().is_empty());
    }

    /// The light-set epoch is 8 h of committed leaders (2 400 heights), not
    /// 7 200: a registration at the last height of epoch 0 is active in
    /// epoch 1, one at height 2 400 only in epoch 2.
    #[test]
    fn light_set_epoch_boundary_is_2400_heights() {
        assert_eq!(EPOCH_LEADER_HEIGHTS, 2_400);
        let mut set = LightSet::default();
        set.register(addr(1), key(1), MIN_LIGHT_BOND, EPOCH_LEADER_HEIGHTS - 1)
            .unwrap();
        set.register(addr(2), key(2), MIN_LIGHT_BOND, EPOCH_LEADER_HEIGHTS)
            .unwrap();
        assert_eq!(set.nodes()[0].effective_epoch, 1);
        assert_eq!(set.nodes()[1].effective_epoch, 2);
        assert_eq!(set.active_nodes(1).len(), 1);
        assert_eq!(set.active_nodes(2).len(), 2);
    }

    #[test]
    fn an_active_exit_unbonds_and_can_still_witness_this_epoch() {
        let mut set = LightSet::default();
        set.register(addr(1), key(1), MIN_LIGHT_BOND, 0).unwrap();
        let (refund, release) = set.exit(addr(1), EPOCH_LEADER_HEIGHTS).unwrap();
        assert_eq!(refund, 0);
        assert_eq!(release, Some(EPOCH_LEADER_HEIGHTS + UNBONDING_ROUNDS));
        assert_eq!(set.active_nodes(1).len(), 1);
        assert!(set.active_nodes(2).is_empty());
        assert!(set
            .release_unbonded(EPOCH_LEADER_HEIGHTS + UNBONDING_ROUNDS - 1)
            .is_empty());
        let paid = set.release_unbonded(EPOCH_LEADER_HEIGHTS + UNBONDING_ROUNDS);
        assert_eq!(paid, vec![(addr(1), MIN_LIGHT_BOND)]);
        assert!(set.nodes().is_empty());
    }

    #[test]
    fn the_winner_set_is_deterministic_and_a_witness_is_stored() {
        let mut set = LightSet::default();
        set.register(addr(1), key(1), MIN_LIGHT_BOND, 0).unwrap();
        set.register(addr(2), key(2), MIN_LIGHT_BOND * 3, 0)
            .unwrap();
        set.note_beacon(1, Hash::new([9u8]));
        set.submit_witness(1, addr(1), [2u8; 32], [0u8; 96])
            .unwrap();
        set.submit_witness(1, addr(2), [1u8; 32], [0u8; 96])
            .unwrap();
        assert_eq!(set.witnesses(1).len(), 2);
        assert!(set
            .submit_witness(1, addr(1), [3u8; 32], [0u8; 96])
            .is_err());
        let first = set.winners(1);
        let second = set.winners(1);
        assert_eq!(first, second);
        assert_eq!(first.len(), 2);
        // addr(2) posted a smaller hash with a larger bond, so it has the
        // lower hash/stake priority and must rank first. Before the overflow
        // fix both witnesses saturated to the same scalar and the order fell
        // back to the address bytes.
        assert_eq!(
            kovanica_types::vrf_priority_cmp(
                &[1u8; 32],
                MIN_LIGHT_BOND * 3,
                &[2u8; 32],
                MIN_LIGHT_BOND,
            ),
            std::cmp::Ordering::Less
        );
        assert_eq!(first[0], addr(2));
        assert_eq!(first[1], addr(1));
    }

    #[test]
    fn zero_bps_leaves_the_whole_reward_on_the_leader_side() {
        let full = block_reward(0);
        let (leader_side, escrow) = split_block_reward(full, 0);
        assert_eq!(escrow, 0);
        assert_eq!(leader_side, full);
        let mut staking = crate::StakingState::new();
        staking
            .join_validator(addr(1), crate::MIN_VALIDATOR_STAKE, 1_000, None, None, None)
            .unwrap();
        staking
            .delegate(addr(5), addr(1), crate::MIN_VALIDATOR_STAKE)
            .unwrap();
        let shares = staking.reward_share(addr(1), leader_side, 1_000);
        let sum: u64 = shares.iter().map(|(_, amount)| *amount).sum();
        assert_eq!(sum, full);
    }

    #[test]
    fn live_light_reward_bps_is_twenty_percent() {
        assert_eq!(LIGHT_REWARD_BPS, 2_000);
        let full = block_reward(0);
        let (leader_side, escrow) = split_block_reward(full, LIGHT_REWARD_BPS);
        assert_eq!(leader_side + escrow, full);
        assert_eq!(escrow, full / 5);
        assert_eq!(leader_side, full - escrow);
    }

    #[test]
    fn escrow_plus_unclaimed_refund_conserves_block_rewards() {
        let bps = 2_000u16;
        let mut leader_sum = 0u64;
        let mut escrow_sum = 0u64;
        let mut by_leader: Vec<(Address, u64)> = Vec::new();
        for height in 0..8u64 {
            let full = block_reward(height);
            let (leader_side, escrow) = split_block_reward(full, bps);
            assert_eq!(leader_side + escrow, full);
            leader_sum += leader_side;
            escrow_sum += escrow;
            let leader = if height % 2 == 0 { addr(1) } else { addr(2) };
            if let Some(slot) = by_leader.iter_mut().find(|(who, _)| *who == leader) {
                slot.1 += escrow;
            } else {
                by_leader.push((leader, escrow));
            }
        }
        let scheduled: u64 = (0..8u64).map(block_reward).sum();
        assert_eq!(leader_sum + escrow_sum, scheduled);

        let winners = vec![addr(9), addr(4)];
        let partial = distribute_escrow(escrow_sum, &winners, &by_leader);
        assert_eq!(partial.total(), escrow_sum);
        assert_eq!(leader_sum + partial.total(), scheduled);
        assert!(!partial.leader_refunds.is_empty());

        let nobody = distribute_escrow(escrow_sum, &[], &by_leader);
        assert!(nobody.winner_payouts.is_empty());
        assert_eq!(nobody.total(), escrow_sum);
        assert_eq!(leader_sum + nobody.total(), scheduled);

        let mut set = LightSet::default();
        for (leader, amount) in &by_leader {
            set.add_escrow(3, *leader, *amount);
        }
        set.note_beacon(3, Hash::zero());
        let settled = set.settle(3);
        assert_eq!(settled.total(), escrow_sum);
        assert!(set.settle(3).total() == 0);
    }
}
