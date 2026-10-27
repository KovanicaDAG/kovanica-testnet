//! Light-client types for Kovanica.
//!
//! A light client follows sealed committed-leader headers. It does not
//! replay the DAG. When a header says MysticGhost coloured the wave, the
//! client can re-run [`crate::colouring::colour_mergeset`] on the mergeset
//! headers and check the blue and non-blue roots.
//!
//! [`StateProof::verify`] checks an account path in the balance-and-nonce
//! sparse tree. A sibling list of any other length is rejected.

use crate::account_tree::{self, AccountProof};
use crate::colouring::{self, ColourBlock, ColourError, GhostCommitment};
use crate::commit::CommittedSubDag;
use crate::committee::Committee;
use crate::crypto::{PublicKey, Signature};
use crate::hash::Hash;
use crate::merkle;
use crate::signing::COMMIT_DOMAIN_TAG;
use crate::{Address, AuthorityIndex, Round, Stake};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;

/// A committed-leader header.
///
/// The hash covers every field below. It is not mixed into the block
/// digest or the vote preimage. `parent_leader_digest` is the previous
/// committed leader's block digest (zero at the first sealed height).
///
/// `mysticghost` is false on the linearizer path. Then `blue_root` and
/// `non_blue_root` are the zero hash. When it is true, those roots are
/// [`crate::colouring::mysticghost_commitment`] outputs and a light client
/// with the mergeset headers can re-check them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaderHeader {
    /// Committed-leader height (the reward height).
    pub committed_height: u64,
    /// Round of the committed leader block.
    pub leader_round: Round,
    /// Digest of the committed leader block.
    pub leader_digest: Hash,
    /// Authority index of the leader author.
    pub leader_author: AuthorityIndex,
    /// Previous committed leader block digest. Zero for the first header.
    pub parent_leader_digest: Hash,
    /// Transaction Merkle root stored on the leader block.
    pub tx_merkle_root: Hash,
    /// Merkle root of the transaction hashes execution applied, in order.
    pub executed_tx_root: Hash,
    /// Merkle root of red block digests. Zero when MysticGhost is off or none are red.
    pub non_blue_root: Hash,
    /// Merkle root of the pure blue order. Zero when MysticGhost is off.
    pub blue_root: Hash,
    /// Whether this commit used scoped GHOSTDAG colouring.
    pub mysticghost: bool,
    /// Account state root after executing this commit.
    pub state_root: Hash,
    /// Committee epoch. Zero until epoch rotation is live.
    pub epoch: u64,
    /// Hash of the committee that signed the seals.
    pub committee_hash: Hash,
    /// Producer timestamp, in milliseconds.
    ///
    /// Statement blocks carry no clock. The node writes `0` so every
    /// validator hashes the same header.
    pub timestamp: u64,
}

impl LeaderHeader {
    /// Canonical header bytes. Field order is fixed; this is not bincode.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(8 + 8 + 32 * 8 + 2 + 1 + 8 + 8);
        data.extend_from_slice(&self.committed_height.to_le_bytes());
        data.extend_from_slice(&self.leader_round.to_le_bytes());
        data.extend_from_slice(&self.leader_digest.0);
        data.extend_from_slice(&self.leader_author.to_le_bytes());
        data.extend_from_slice(&self.parent_leader_digest.0);
        data.extend_from_slice(&self.tx_merkle_root.0);
        data.extend_from_slice(&self.executed_tx_root.0);
        data.extend_from_slice(&self.non_blue_root.0);
        data.extend_from_slice(&self.blue_root.0);
        data.push(u8::from(self.mysticghost));
        data.extend_from_slice(&self.state_root.0);
        data.extend_from_slice(&self.epoch.to_le_bytes());
        data.extend_from_slice(&self.committee_hash.0);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data
    }

    /// Domain-separated hash of [`Self::canonical_bytes`].
    pub fn hash(&self) -> Hash {
        Hash::new_keyed(Hash::DOMAIN_HEADER, self.canonical_bytes())
    }

    /// Bytes a validator signs for this header on `chain_id`.
    ///
    /// Layout: `KUNA/commit/v1` (16 bytes) || `chain_id` u64 LE || header hash.
    /// The epoch is inside the header hash. `chain_id` is outside it so a
    /// seal cannot move to another network. Vote bytes are not used.
    pub fn seal_message(&self, chain_id: u64) -> Vec<u8> {
        let mut data = Vec::with_capacity(16 + 8 + 32);
        data.extend_from_slice(&COMMIT_DOMAIN_TAG);
        data.extend_from_slice(&chain_id.to_le_bytes());
        data.extend_from_slice(&self.hash().0);
        data
    }

    /// Linearizer headers keep the colouring roots at zero.
    pub fn colouring_roots_match_flag(&self) -> bool {
        if self.mysticghost {
            true
        } else {
            self.blue_root == Hash::zero() && self.non_blue_root == Hash::zero()
        }
    }
}

/// Transaction hashes execution applied, in sub-DAG block order.
pub fn executed_tx_hashes(subdag: &CommittedSubDag) -> Vec<Hash> {
    subdag
        .blocks
        .iter()
        .flat_map(|block| block.transactions.iter().map(|tx| tx.hash))
        .collect()
}

/// Build the header a validator seals after execution.
///
/// `timestamp` is always 0. When `mysticghost` is false, both colouring
/// roots are zero. When it is true, `blue_root` is the Merkle root of
/// `subdag.blocks` digests in that order and `non_blue_root` is the Merkle
/// root of `subdag.non_blue` digests. That matches the committer's blue
/// order when the leader was already blue. A light client that still has
/// the mergeset and the previous tips re-checks those roots with
/// [`verify_colouring`].
pub fn leader_header(
    subdag: &CommittedSubDag,
    committed_height: u64,
    parent_leader_digest: Hash,
    state_root: Hash,
    epoch: u64,
    committee_hash: Hash,
    mysticghost: bool,
) -> LeaderHeader {
    let executed = executed_tx_hashes(subdag);
    let (blue_root, non_blue_root) = if mysticghost {
        let blue: Vec<Hash> = subdag.blocks.iter().map(|block| block.digest).collect();
        let red: Vec<Hash> = subdag.non_blue.iter().map(|block| block.digest).collect();
        (merkle::root(&blue), merkle::root(&red))
    } else {
        (Hash::zero(), Hash::zero())
    };
    LeaderHeader {
        committed_height,
        leader_round: subdag.leader_round,
        leader_digest: subdag.leader.digest,
        leader_author: subdag.leader_author,
        parent_leader_digest,
        tx_merkle_root: subdag.leader.merkle_root,
        executed_tx_root: merkle::root(&executed),
        non_blue_root,
        blue_root,
        mysticghost,
        state_root,
        epoch,
        committee_hash,
        timestamp: 0,
    }
}

/// One row of a sealed committee: `(authority index, public key, stake)`.
///
/// Network addresses and VRF keys are deliberately absent — they are not part
/// of [`committee_seal_hash`]. This alias is the canonical shape of the
/// per-epoch committee snapshot (`EPOCH_COMMITTEE`) that `publish_local_seal`
/// freezes and the RPC committee is rebuilt from, so both hash the same rows.
pub type SealCommitteeMember = (AuthorityIndex, PublicKey, Stake);

/// One row of the persisted `EPOCH_COMMITTEE` snapshot.
///
/// This is a strict superset of [`SealCommitteeMember`]: the extra
/// `vrf_public_key` is stored so a restarted node can rebuild the boot
/// committee WITH its VRF keys, instead of dropping to `None` and diverging on
/// leader selection (B3). It is *not* hashed — [`Self::seal_member`] projects
/// the exact `(index, public_key, stake)` triple that
/// [`committee_seal_hash`] covers, so the sealed hash is unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealCommitteeSnapshotMember {
    /// Authority index assigned by the committee builder (stable per epoch).
    pub index: AuthorityIndex,
    /// Consensus (Ed25519) public key of the authority.
    pub public_key: PublicKey,
    /// Staked amount at snapshot time.
    pub stake: Stake,
    /// VRF public key for leader selection, if the authority has one.
    ///
    /// `#[serde(default)]` keeps bincode/serde backward compatible with
    /// snapshots written before the VRF key was stored (they deserialize to
    /// `None`; the reader backfills from the staking record).
    #[serde(default)]
    pub vrf_public_key: Option<PublicKey>,
}

impl SealCommitteeSnapshotMember {
    /// The hashed projection: exactly the fields [`committee_seal_hash`] covers.
    ///
    /// The persisted snapshot gained a `vrf_public_key` field, but the seal
    /// hash must remain bit-identical, so the hash always goes through this
    /// `(index, public_key, stake)` view.
    pub fn seal_member(&self) -> SealCommitteeMember {
        (self.index, self.public_key, self.stake)
    }
}

/// Versioned encoding for on-disk persisted structures.
///
/// The format is: `magic_byte (0x4B) || version (u8) || payload`.
/// - Version 1: new format with SealCommitteeSnapshotMember (with optional vrf_public_key)
/// - No prefix (or unknown magic): old untagged format (Vec<SealCommitteeMember> tuples)
///
/// Unknown/future versions return a clear error rather than silently falling back.
pub const SNAPSHOT_MAGIC: u8 = 0x4B; // 'K' for Kovanica

/// Current version for EPOCH_COMMITTEE snapshots.
pub const EPOCH_COMMITTEE_VERSION: u8 = 1;

/// Current version for StakingState snapshots.
///
/// Bumped to 2 when `ValidatorInfo` gained `jailed_until_height` (the PRO-19
/// slash/jail rule). Version 1 rows are still decoded and lifted: the jail
/// height defaults to 0, which means "permanent exclusion" — the pre-jail
/// F7 semantics — so an already-slashed v1 row can never come back.
pub const STAKING_STATE_VERSION: u8 = 2;

/// Previous StakingState layout that is still accepted on decode.
pub const STAKING_STATE_VERSION_PREVIOUS: u8 = 1;

/// Encode a snapshot with version prefix.
pub fn encode_with_version<B: AsRef<[u8]>>(version: u8, payload: B) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + payload.as_ref().len());
    out.push(SNAPSHOT_MAGIC);
    out.push(version);
    out.extend_from_slice(payload.as_ref());
    out
}

/// Decode a snapshot with version prefix.
///
/// Returns:
/// - `Ok((version, payload))` if the magic byte matches and version is known
/// - `Err("unknown version")` if magic matches but version is unknown
/// - `Err("no version prefix")` if magic byte doesn't match (old format)
pub fn decode_with_version(bytes: &[u8]) -> Result<(u8, &[u8]), &'static str> {
    if bytes.len() < 2 {
        return Err("truncated: too short for version header");
    }
    if bytes[0] != SNAPSHOT_MAGIC {
        return Err("no version prefix");
    }
    let version = bytes[1];
    // Accept the current EPOCH_COMMITTEE version, the current StakingState
    // version, and the previous StakingState version. Values are matched
    // explicitly (no ranges) so an unknown/future version is still an error
    // rather than a silent fallback.
    if version == EPOCH_COMMITTEE_VERSION
        || version == STAKING_STATE_VERSION
        || version == STAKING_STATE_VERSION_PREVIOUS
    {
        Ok((version, &bytes[2..]))
    } else {
        Err("unknown version")
    }
}

/// The hashed projection of a whole snapshot, in snapshot order.
pub fn snapshot_seal_members(members: &[SealCommitteeSnapshotMember]) -> Vec<SealCommitteeMember> {
    members.iter().map(|m| m.seal_member()).collect()
}

/// Hash of the committee a commit seal is bound to.
///
/// Members are `(index, public key, stake)`. Network addresses and VRF
/// keys are left out: they are not part of the seal. Input order does not
/// matter; the hash sorts by authority index.
pub fn committee_seal_hash(epoch: u64, members: &[SealCommitteeMember]) -> Hash {
    let mut members = members.to_vec();
    members.sort_by_key(|member| member.0);
    let mut data = Vec::with_capacity(8 + 4 + members.len() * (2 + 32 + 8));
    data.extend_from_slice(&epoch.to_le_bytes());
    let count = u32::try_from(members.len()).unwrap_or(u32::MAX);
    data.extend_from_slice(&count.to_le_bytes());
    for (index, key, stake) in members {
        data.extend_from_slice(&index.to_le_bytes());
        data.extend_from_slice(&key.0);
        data.extend_from_slice(&stake.to_le_bytes());
    }
    Hash::new_keyed(Hash::DOMAIN_COMMITTEE, &data)
}

/// A locally produced header plus the producer's own seal.
///
/// This is the gossip payload. The signature bytes travel with the seal.
/// Votes do not persist their signatures; seals do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealAnnouncement {
    /// Header the seal signs.
    pub header: LeaderHeader,
    /// One validator's signature over [`LeaderHeader::seal_message`].
    pub seal: CommitSeal,
}

/// One validator's signature over [`LeaderHeader::seal_message`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitSeal {
    /// Signer, as an index in the epoch committee.
    pub authority_index: AuthorityIndex,
    /// Ed25519 signature over the seal message.
    pub signature: Signature,
}

/// Why a seal set was rejected. Signature bytes are checked in `kovanica-crypto`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealError {
    /// `mysticghost` is false but a colouring root is not zero.
    ColouringFlag,
    /// Header epoch does not match the committee epoch.
    EpochMismatch,
    /// The same authority signed twice.
    DuplicateSigner,
    /// `authority_index` is not in the committee.
    UnknownAuthority,
    /// Signed stake is below `floor(2T/3)+1`, or total stake is zero.
    Quorum,
}

/// Stake quorum for a seal set: `floor(2T/3)+1`, computed in `u128`.
///
/// Returns `None` when `total` is zero. Matches `CommitteeInfo::quorum_threshold`.
pub fn quorum_threshold(total: u64) -> Option<u64> {
    if total == 0 {
        return None;
    }
    Some((u128::from(total) * 2 / 3 + 1) as u64)
}

/// Check seal-set structure and stake weight.
///
/// Does not check signatures. Callers verify each signature over
/// [`LeaderHeader::seal_message`] before calling this, and pass only the
/// indexes that verified.
pub fn seal_quorum(
    header: &LeaderHeader,
    signer_indexes: &[AuthorityIndex],
    committee: &Committee,
) -> Result<(), SealError> {
    if !header.colouring_roots_match_flag() {
        return Err(SealError::ColouringFlag);
    }
    if header.epoch != committee.epoch {
        return Err(SealError::EpochMismatch);
    }
    let mut signed = 0u128;
    let mut seen = BTreeMap::new();
    for &index in signer_indexes {
        if seen.insert(index, ()).is_some() {
            return Err(SealError::DuplicateSigner);
        }
        let Some(authority) = committee.get_by_index(index) else {
            return Err(SealError::UnknownAuthority);
        };
        signed += u128::from(authority.stake);
    }
    let Some(need) = quorum_threshold(committee.total_stake) else {
        return Err(SealError::Quorum);
    };
    if signed < u128::from(need) {
        return Err(SealError::Quorum);
    }
    Ok(())
}

/// Mergeset headers a light client re-colours.
///
/// Verification recomputes the MysticGhost commitment and requires the
/// header's blue root, non-blue root, and leader digest to match. It does
/// not replace the commit seal: the seal is what binds those roots to the
/// state root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColouringCertificate {
    /// Mergeset headers. Digests must be unique and must include the leader.
    pub blocks: Vec<ColourBlock>,
    /// Tips seeded as already blue. Not part of `blocks`.
    pub previous_tips: Vec<Hash>,
    /// Leader block digest. Must equal the header's `leader_digest`.
    pub leader: Hash,
}

/// Re-run MysticGhost and compare the roots to a sealed header.
pub fn verify_colouring(
    header: &LeaderHeader,
    certificate: &ColouringCertificate,
) -> Result<GhostCommitment, ColourError> {
    if !header.mysticghost {
        return Err(ColourError::NotGhost);
    }
    if certificate.leader != header.leader_digest {
        return Err(ColourError::LeaderMismatch);
    }
    let commitment = colouring::mysticghost_commitment(
        &certificate.blocks,
        &certificate.previous_tips,
        certificate.leader,
    )?;
    if commitment.blue_root != header.blue_root || commitment.non_blue_root != header.non_blue_root
    {
        return Err(ColourError::RootMismatch);
    }
    Ok(commitment)
}

/// Legacy vote-set certificate.
///
/// Votes sign the leader hash only, and the node does not store the
/// signature bytes. New light clients use [`CommitSeal`] on a
/// [`LeaderHeader`]. This type does not cover `state_root` or the
/// MysticGhost roots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaveCommitCertificate {
    /// The committed leader block hash.
    pub leader_hash: Hash,
    /// The round of the committed leader.
    pub leader_round: Round,
    /// The height of the committed leader in the committed DAG.
    pub committed_height: u64,
    /// Validator signatures for this wave commit (authority_index -> signature).
    /// Must represent > 2/3 of committee stake.
    pub signatures: BTreeMap<AuthorityIndex, Signature>,
    /// The committee hash this certificate was created under.
    pub committee_hash: Hash,
}

impl WaveCommitCertificate {
    /// Create a new wave commit certificate.
    pub fn new(
        leader_hash: Hash,
        leader_round: Round,
        committed_height: u64,
        signatures: BTreeMap<AuthorityIndex, Signature>,
        committee_hash: Hash,
    ) -> Self {
        Self {
            leader_hash,
            leader_round,
            committed_height,
            signatures,
            committee_hash,
        }
    }

    /// Whether the listed indexes have stake of at least `floor(2T/3)+1`.
    ///
    /// Does not verify the signature bytes.
    pub fn verify_quorum(&self, committee: &Committee) -> bool {
        let signed: u128 = self
            .signatures
            .keys()
            .filter_map(|&idx| committee.get_by_index(idx))
            .map(|a| u128::from(a.stake))
            .sum();
        quorum_threshold(committee.total_stake).is_some_and(|need| signed >= u128::from(need))
    }
}

/// Account balance and nonce against an account-tree root.
///
/// `siblings` has one hash per tree level, index 0 under the root.
/// [`Self::verify`] recomputes the root. A short or long sibling list fails.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateProof {
    /// The state root this proof is against.
    pub state_root: Hash,
    /// The address being proved.
    pub address: Address,
    /// Balance in atoms. Zero when [`Self::present`] is false.
    pub balance: u64,
    /// Account nonce. Zero when [`Self::present`] is false.
    pub nonce: u64,
    /// Whether the account is present. Absence is a real proof.
    pub present: bool,
    /// Sibling hashes, length 256.
    pub siblings: Vec<Hash>,
}

impl StateProof {
    /// Check this proof against [`Self::state_root`].
    pub fn verify(&self) -> bool {
        let mut siblings = [Hash::zero(); 256];
        if self.siblings.len() != siblings.len() {
            return false;
        }
        siblings.copy_from_slice(&self.siblings);
        account_tree::verify_account_proof(
            &self.state_root,
            &AccountProof {
                address: self.address,
                balance: self.balance,
                nonce: self.nonce,
                present: self.present,
                siblings,
            },
        )
    }
}

/// Domain for the light-node lottery. Not a vote tag and not a transaction tag.
pub const LIGHT_VRF_DOMAIN: &[u8] = b"KUNA/light-vrf/v1";

/// VRF input for one light-node epoch.
///
/// Layout: `KUNA/light-vrf/v1` || `chain_id` u64 LE || `epoch` u64 LE || beacon.
/// `beacon` is the epoch-opening committed leader block digest.
pub fn light_vrf_input(chain_id: u64, epoch: u64, beacon: &Hash) -> Vec<u8> {
    let mut data = Vec::with_capacity(LIGHT_VRF_DOMAIN.len() + 8 + 8 + 32);
    data.extend_from_slice(LIGHT_VRF_DOMAIN);
    data.extend_from_slice(&chain_id.to_le_bytes());
    data.extend_from_slice(&epoch.to_le_bytes());
    data.extend_from_slice(&beacon.0);
    data
}

/// Stake-weighted lottery priority. Lower wins.
///
/// This is the same formula as validator VRF leader selection:
/// `hash / stake`, using the first 16 bytes of the VRF hash.
///
/// `total_stake` is accepted for backwards compatibility. It was previously
/// multiplied into the numerator, but that saturated: a VRF hash prefix is a
/// full 128-bit value and `total_stake` is ~2^47, so `hash * total_stake`
/// overflowed `u128` and every authority got the identical saturated priority.
/// The factor is a common scale and does not affect the ordering, so it is no
/// longer applied. Callers that need exact ordering between two priorities
/// must use [`vrf_priority_cmp`], which compares without any floor division.
pub fn light_vrf_priority(vrf_hash: &[u8; 32], stake: u64, _total_stake: u64) -> u128 {
    vrf_hash_prefix(vrf_hash) / u128::from(stake.max(1))
}

/// The first 16 bytes of a VRF hash as a little-endian `u128`.
///
/// This is the canonical prefix used by both validator leader election and the
/// light-node lottery.
pub fn vrf_hash_prefix(vrf_hash: &[u8; 32]) -> u128 {
    let mut prefix = [0u8; 16];
    prefix.copy_from_slice(&vrf_hash[..16]);
    u128::from_le_bytes(prefix)
}

/// 128-bit × 64-bit product as a 192-bit big-endian limb array.
///
/// The product cannot be held in `u128`: a hash prefix uses all 128 bits and a
/// stake reaches ~2^47 atoms, so the result needs 175 bits. Splitting into
/// 64-bit limbs keeps every intermediate inside `u128`.
#[inline]
fn mul_u128_u64(n: u128, d: u64) -> [u64; 3] {
    let lo = u128::from(n as u64) * u128::from(d);
    let hi = (n >> 64) * u128::from(d);
    let mid = hi + (lo >> 64);
    [(mid >> 64) as u64, mid as u64, lo as u64]
}

/// Compare two stake-weighted VRF priorities exactly. Lower `hash / stake` wins.
///
/// `hash_a / stake_a` against `hash_b / stake_b` is decided by cross-multiplying
/// into 192-bit products (`hash_a * stake_b` against `hash_b * stake_a`). No
/// intermediate saturates, so the order is exact and deterministic — unlike a
/// `u128` priority that overflows and collapses every authority to one value.
///
/// Returns [`Ordering::Less`] when `a` has the higher priority (smaller
/// `hash / stake`), [`Ordering::Greater`] when `b` does, and
/// [`Ordering::Equal`] when the two ratios are identical.
pub fn vrf_priority_cmp(
    hash_a: &[u8; 32],
    stake_a: u64,
    hash_b: &[u8; 32],
    stake_b: u64,
) -> Ordering {
    let left = mul_u128_u64(vrf_hash_prefix(hash_a), stake_b.max(1));
    let right = mul_u128_u64(vrf_hash_prefix(hash_b), stake_a.max(1));
    left.cmp(&right)
}

/// Light client sync checkpoint.
///
/// `header` is the sealed committed-leader header. `seals` are the quorum
/// signatures over it. `wave_certificate` remains for older callers and is
/// not sufficient on its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightClientCheckpoint {
    /// The committed leader height this checkpoint represents.
    pub height: u64,
    /// The committed leader block hash.
    pub leader_hash: Hash,
    /// The state root at this height.
    pub state_root: Hash,
    /// The committee hash at this height.
    pub committee_hash: Hash,
    /// Wave commit certificate for this height.
    pub wave_certificate: WaveCommitCertificate,
    /// Sealed header. Absent on checkpoints written before seals existed.
    #[serde(default)]
    pub header: Option<LeaderHeader>,
    /// Quorum seals for `header`.
    #[serde(default)]
    pub seals: Vec<CommitSeal>,
    /// Timestamp of the checkpoint (block timestamp).
    pub timestamp: u64,
}

impl LightClientCheckpoint {
    /// Create a checkpoint without seals.
    pub fn new(
        height: u64,
        leader_hash: Hash,
        state_root: Hash,
        committee_hash: Hash,
        wave_certificate: WaveCommitCertificate,
        timestamp: u64,
    ) -> Self {
        Self {
            height,
            leader_hash,
            state_root,
            committee_hash,
            wave_certificate,
            header: None,
            seals: Vec::new(),
            timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::colouring::ColourBlock;
    use crate::committee::{Authority, Committee};
    use crate::crypto::PublicKey;

    fn authority(index: u16, stake: u64) -> Authority {
        Authority {
            index,
            public_key: PublicKey([index as u8; 32]),
            vrf_public_key: None,
            address: Address([index as u8; 32]),
            stake,
            network_address: String::new(),
        }
    }

    fn header(mysticghost: bool, blue: Hash, non_blue: Hash) -> LeaderHeader {
        LeaderHeader {
            committed_height: 1,
            leader_round: 3,
            leader_digest: Hash::new([9u8]),
            leader_author: 0,
            parent_leader_digest: Hash::zero(),
            tx_merkle_root: Hash::zero(),
            executed_tx_root: Hash::zero(),
            non_blue_root: non_blue,
            blue_root: blue,
            mysticghost,
            state_root: Hash::new([4u8]),
            epoch: 0,
            committee_hash: Hash::zero(),
            timestamp: 1,
        }
    }

    fn empty_block(author: u16, round: u64) -> crate::block::StatementBlock {
        let digest = crate::block::StatementBlock::compute_digest(author, round, &[], &[]);
        crate::block::StatementBlock {
            author,
            round,
            parents: vec![],
            transactions: vec![],
            statements: vec![],
            signature: Signature([0; 64]),
            digest,
            merkle_root: Hash::zero(),
        }
    }

    #[test]
    fn leader_header_is_deterministic_and_linearizer_roots_are_zero() {
        let leader = empty_block(0, 3);
        let subdag = crate::commit::CommittedSubDag {
            blocks: vec![leader.clone()],
            leader: leader.clone(),
            leader_round: 3,
            leader_author: 0,
            non_blue: vec![],
        };
        let parent = Hash::new([7u8]);
        let state = Hash::new([8u8]);
        let committee = committee_seal_hash(
            0,
            &[(1, PublicKey([2; 32]), 50), (0, PublicKey([1; 32]), 50)],
        );
        let again = committee_seal_hash(
            0,
            &[(0, PublicKey([1; 32]), 50), (1, PublicKey([2; 32]), 50)],
        );
        assert_eq!(committee, again);
        let header = leader_header(&subdag, 4, parent, state, 0, committee, false);
        let same = leader_header(&subdag, 4, parent, state, 0, committee, false);
        assert_eq!(header.hash(), same.hash());
        assert_eq!(header.timestamp, 0);
        assert_eq!(header.parent_leader_digest, parent);
        assert_eq!(header.blue_root, Hash::zero());
        assert_eq!(header.non_blue_root, Hash::zero());
        assert!(header.colouring_roots_match_flag());
        assert_eq!(header.executed_tx_root, Hash::zero());
    }

    #[test]
    fn mysticghost_header_commits_block_and_red_digests() {
        let leader = empty_block(0, 3);
        let red = empty_block(1, 2);
        let subdag = crate::commit::CommittedSubDag {
            blocks: vec![leader.clone()],
            leader: leader.clone(),
            leader_round: 3,
            leader_author: 0,
            non_blue: vec![crate::block::BlockReference {
                author: red.author,
                round: red.round,
                digest: red.digest,
            }],
        };
        let header = leader_header(
            &subdag,
            1,
            Hash::zero(),
            Hash::zero(),
            0,
            Hash::zero(),
            true,
        );
        assert!(header.mysticghost);
        assert_eq!(header.blue_root, leader.digest);
        assert_eq!(header.non_blue_root, red.digest);
        assert_eq!(header.timestamp, 0);
    }

    #[test]
    fn seal_message_covers_chain_id_and_header() {
        let header = header(false, Hash::zero(), Hash::zero());
        let a = header.seal_message(1);
        let b = header.seal_message(2);
        assert_ne!(a, b);
        assert_eq!(&a[..16], &COMMIT_DOMAIN_TAG);
        let mut changed = header.clone();
        changed.state_root = Hash::new([5u8]);
        assert_ne!(header.seal_message(1), changed.seal_message(1));
    }

    #[test]
    fn linearizer_header_rejects_a_colouring_root() {
        let committee = Committee::new(0, vec![authority(0, 1), authority(1, 1), authority(2, 1)]);
        let header = header(false, Hash::new([1u8]), Hash::zero());
        assert_eq!(
            seal_quorum(&header, &[0, 1, 2], &committee),
            Err(SealError::ColouringFlag)
        );
    }

    #[test]
    fn quorum_matches_floor_two_thirds_plus_one() {
        let committee = Committee::new(0, (0..4).map(|i| authority(i, 1)).collect());
        let header = header(false, Hash::zero(), Hash::zero());
        assert_eq!(
            seal_quorum(&header, &[0, 1], &committee),
            Err(SealError::Quorum)
        );
        assert!(seal_quorum(&header, &[0, 1, 2], &committee).is_ok());
    }

    #[test]
    fn colouring_certificate_accepts_a_recomputed_root() {
        let genesis = ColourBlock {
            digest: Hash::new([1u8]),
            round: 0,
            parents: vec![],
        };
        let leader = ColourBlock {
            digest: Hash::new([2u8]),
            round: 1,
            parents: vec![genesis.digest],
        };
        let blocks = vec![genesis, leader.clone()];
        let commitment = colouring::mysticghost_commitment(&blocks, &[], leader.digest).unwrap();
        let header = header(true, commitment.blue_root, commitment.non_blue_root);
        let mut header = header;
        header.leader_digest = leader.digest;
        let certificate = ColouringCertificate {
            blocks,
            previous_tips: vec![],
            leader: leader.digest,
        };
        assert!(verify_colouring(&header, &certificate).is_ok());

        header.blue_root = Hash::new([9u8]);
        assert_eq!(
            verify_colouring(&header, &certificate).unwrap_err(),
            ColourError::RootMismatch
        );
    }

    #[test]
    fn wave_commit_certificate_creation() {
        let sigs = BTreeMap::new();
        let cert = WaveCommitCertificate::new(Hash::zero(), 42, 100, sigs, Hash::zero());
        assert_eq!(cert.leader_round, 42);
        assert_eq!(cert.committed_height, 100);
    }

    #[test]
    fn state_proof_rejects_a_short_sibling_list() {
        let proof = StateProof {
            state_root: Hash::zero(),
            address: Address([0; 32]),
            balance: 1,
            nonce: 0,
            present: true,
            siblings: vec![Hash::zero()],
        };
        assert!(!proof.verify());
    }

    #[test]
    fn light_client_checkpoint_creation() {
        let sigs = BTreeMap::new();
        let wave_cert = WaveCommitCertificate::new(Hash::zero(), 42, 100, sigs, Hash::zero());
        let checkpoint = LightClientCheckpoint::new(
            100,
            Hash::zero(),
            Hash::zero(),
            Hash::zero(),
            wave_cert,
            1234567890,
        );
        assert_eq!(checkpoint.height, 100);
        assert!(checkpoint.seals.is_empty());
        assert_eq!(checkpoint.timestamp, 1234567890);
    }
}

#[cfg(test)]
mod vrf_priority_tests {
    use super::*;
    use crate::committee::{Authority, Committee};
    use crate::crypto::PublicKey;
    use std::collections::HashMap;

    /// The priority formula as it was computed before the overflow fix. Kept
    /// only to document the regression: `hash * total_stake` saturated to
    /// `u128::MAX`, so distinct hashes produced an identical priority.
    fn saturating_priority(vrf_hash: &[u8; 32], stake: u64, total_stake: u64) -> u128 {
        vrf_hash_prefix(vrf_hash)
            .saturating_mul(u128::from(total_stake))
            .saturating_div(u128::from(stake.max(1)))
    }

    #[test]
    fn old_saturating_priority_collapsed_distinct_hashes() {
        let a = [0x7fu8; 32];
        let b = [0x11u8; 32];
        let c = [0xe3u8; 32];
        let stake = 50_000_000_000_000u64;
        let total = 3 * stake;

        let pa = saturating_priority(&a, stake, total);
        let pb = saturating_priority(&b, stake, total);
        let pc = saturating_priority(&c, stake, total);
        assert_eq!(pa, pb, "old formula tied two distinct hashes");
        assert_eq!(pb, pc, "old formula tied two distinct hashes");

        // The exact comparator keeps them strictly ordered (b < a < c).
        assert_eq!(vrf_priority_cmp(&b, stake, &a, stake), Ordering::Less);
        assert_eq!(vrf_priority_cmp(&a, stake, &c, stake), Ordering::Less);
        assert_eq!(vrf_priority_cmp(&a, stake, &b, stake), Ordering::Greater);
    }

    #[test]
    fn priority_is_exact_beyond_u128() {
        // [0xff; 32] has the largest possible 128-bit prefix. Cross-multiplying
        // it by a stake needs 175 bits, which u128 cannot hold.
        let max = [0xffu8; 32];
        let tiny = [0x00u8; 32];
        let huge_stake = 50_000_000_000_000u64;
        assert_eq!(
            vrf_priority_cmp(&tiny, huge_stake, &max, huge_stake),
            Ordering::Less
        );
        assert_eq!(
            vrf_priority_cmp(&max, 1, &tiny, u64::MAX),
            Ordering::Greater,
            "a max hash at stake 1 loses to a zero hash at any stake"
        );
    }

    #[test]
    fn priority_weights_by_stake() {
        let hash = [0x40u8; 32];
        // Equal hash, larger stake wins (lower hash/stake).
        assert_eq!(vrf_priority_cmp(&hash, 200, &hash, 100), Ordering::Less);
        assert_eq!(vrf_priority_cmp(&hash, 100, &hash, 200), Ordering::Greater);
        assert_eq!(vrf_priority_cmp(&hash, 100, &hash, 100), Ordering::Equal);
    }

    #[test]
    fn light_vrf_priority_keeps_ordering_without_total_stake() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let stake = 50_000_000_000_000u64;
        // The `total_stake` argument no longer matters; only `hash / stake`.
        assert_eq!(
            light_vrf_priority(&a, stake, 1),
            light_vrf_priority(&a, stake, 3 * stake)
        );
        assert!(light_vrf_priority(&a, stake, 0) < light_vrf_priority(&b, stake, 0));
    }

    #[test]
    fn committee_leader_with_vrf_rotates_for_equal_stakes() {
        let authority = |index: u16| Authority {
            index,
            public_key: PublicKey([index as u8; 32]),
            vrf_public_key: Some(PublicKey([index as u8; 32])),
            address: crate::Address([index as u8; 32]),
            stake: 50_000_000_000_000,
            network_address: format!("/ip4/127.0.0.1/tcp/90{index:02}"),
        };
        let committee = Committee::new(0, (0..3).map(authority).collect());

        // Hashes ordered so the winner is 1, then 2, then 0. Before the fix
        // every priority saturated to the same value and index 0 always won.
        let rounds: [(u64, [[u8; 32]; 3], u16); 3] = [
            (3, [[0x30u8; 32], [0x10u8; 32], [0x20u8; 32]], 1),
            (6, [[0x30u8; 32], [0x20u8; 32], [0x10u8; 32]], 2),
            (9, [[0x10u8; 32], [0x20u8; 32], [0x30u8; 32]], 0),
        ];
        for (round, hashes, expected) in rounds {
            let mut outputs = HashMap::new();
            outputs.insert(0, hashes[0]);
            outputs.insert(1, hashes[1]);
            outputs.insert(2, hashes[2]);
            assert_eq!(
                committee.leader_with_vrf(round, &outputs),
                expected,
                "round {round}"
            );
        }
    }
}
