//! Stateless admission checks applied at the network edge.
//!
//! Every gossip message is validated here before gossipsub is allowed to
//! forward it to the rest of the mesh (`validate_messages` is on, see
//! [`crate::behaviour`]). The checks are deliberately *stateless*: they only
//! answer "is this message authentic and internally consistent?". Whether a
//! vote counts or a block is acceptable for the DAG is still decided by the
//! consensus engine / block manager. Nothing here changes a consensus rule.
//!
//! * Votes: the voter must be a committee member and the Ed25519 signature
//!   must verify over [`Vote::signature_data`] under that member's key.
//! * Blocks: the digest is recomputed from the content, the merkle root must
//!   match the transactions, the author must be a committee member and the
//!   signature must verify over the digest under the author's key.

use kovanica_types::{
    block::StatementBlock, epoch_for_round, transaction::TransactionKind, Address, AuthorityIndex,
    Hash, PublicKey, SealAnnouncement, SigningContext, SkipCert, Timeout, Transaction, Vote,
};
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, RwLock},
};

/// Committee public keys indexed by authority index.
pub type AuthorityKeys = HashMap<AuthorityIndex, PublicKey>;

/// Why a gossip message failed edge validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    /// The voter / block author is not in the configured committee.
    UnknownAuthority(AuthorityIndex),
    /// The signature does not verify under the authority's committee key.
    BadSignature(AuthorityIndex),
    /// The block digest does not match its recomputed content digest.
    DigestMismatch,
    /// The block merkle root does not match its transactions.
    MerkleMismatch,
    /// Transaction fee is zero but a fee is required.
    ZeroFee,
    /// Transaction signature verification failed.
    TxBadSignature(Address),
    /// Transaction sender is not a known authority.
    UnknownSender(Address),
    /// A linearizer header carried a colouring root.
    ColouringFlag,
    /// The seal's header epoch is not the verifier's epoch.
    EpochMismatch,
    /// A skip certificate is empty, oversized, mixes rounds or repeats a
    /// signer.
    MalformedCertificate,
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rejection::UnknownAuthority(index) => write!(f, "unknown authority {index}"),
            Rejection::BadSignature(index) => write!(f, "bad signature from authority {index}"),
            Rejection::DigestMismatch => write!(f, "block digest does not match its content"),
            Rejection::MerkleMismatch => {
                write!(f, "block merkle root does not match its transactions")
            }
            Rejection::ZeroFee => write!(f, "transaction fee is zero but a fee is required"),
            Rejection::TxBadSignature(addr) => {
                write!(f, "transaction signature verification failed for {addr}")
            }
            Rejection::UnknownSender(addr) => {
                write!(f, "transaction sender {addr} is not a known authority")
            }
            Rejection::ColouringFlag => write!(f, "linearizer header has a colouring root"),
            Rejection::EpochMismatch => {
                write!(f, "commit seal epoch does not match the local epoch")
            }
            Rejection::MalformedCertificate => write!(f, "malformed skip certificate"),
        }
    }
}

/// What the gossip edge should do with one commit seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealAdmission {
    /// Signature is valid and the header hash matches local execution. Forward it.
    Accept,
    /// Signature is valid, but this node has no matching header yet. Do not
    /// forward and do not penalise the peer.
    Ignore,
    /// The seal is not authentic.
    Reject(Rejection),
}

/// Local executed-header lookup used before a seal is forwarded.
///
/// A node that has not executed the height returns `None`. The edge then
/// ignores the seal instead of accepting a header it cannot check.
pub trait LocalHeaderHash: Send + Sync {
    /// Hash of the leader header this node stored at `committed_height`.
    fn local_header_hash(&self, committed_height: u64) -> Option<Hash>;
}

/// Admit one seal at the gossip edge.
///
/// Invalid signatures are rejected. A valid seal is forwarded only when
/// `local_header_hash` is `Some` and equal to `announcement.header.hash()`.
/// Anything else is ignored so a seal cannot stick before local execution.
pub fn admit_seal(
    keys: &AuthorityKeys,
    chain_id: u64,
    announcement: &SealAnnouncement,
    local_header_hash: Option<Hash>,
) -> SealAdmission {
    let header = &announcement.header;
    if !header.colouring_roots_match_flag() {
        return SealAdmission::Reject(Rejection::ColouringFlag);
    }
    // Epoch MUST derive from leader_round (same as vote signing ctx)
    // to avoid restart mismatch: `epoch_for_round` is the canonical,
    // round-based epoch unit shared with consensus and staking.
    let expected_epoch = epoch_for_round(header.leader_round);
    if header.epoch != expected_epoch {
        return SealAdmission::Reject(Rejection::EpochMismatch);
    }
    let Some(key) = keys.get(&announcement.seal.authority_index) else {
        return SealAdmission::Reject(Rejection::UnknownAuthority(
            announcement.seal.authority_index,
        ));
    };
    if kovanica_crypto::verify_commit_seal(chain_id, header, &announcement.seal, key).is_err() {
        return SealAdmission::Reject(Rejection::BadSignature(announcement.seal.authority_index));
    }
    match local_header_hash {
        Some(hash) if hash == header.hash() => SealAdmission::Accept,
        _ => SealAdmission::Ignore,
    }
}

/// Errors returned by a [`VoteVerifier`]: Foundation's v1 vote signature
/// error type (`kovanica_crypto::SigError`), re-exported unchanged.
pub use kovanica_crypto::SigError;

/// Vote signature verification used at the gossip edge.
///
/// The node injects the implementation via
/// [`NetworkService::set_vote_verifier`](crate::NetworkService::set_vote_verifier).
/// Mapping `vote.voter` to the right committee `pubkey` is the caller's job
/// (done by [`verify_vote_with`]); the verifier only checks the signature.
pub trait VoteVerifier: Send + Sync {
    /// Verify `vote.signature` over the v1 bytes
    /// [`Vote::signature_data(ctx)`](Vote::signature_data) under `pubkey`.
    ///
    /// `ctx` is the verifier's own configured chain id + committee epoch,
    /// never taken from the network message. Argument order mirrors
    /// `kovanica_crypto::verify_vote_signature(ctx, vote, pubkey)`.
    fn verify_vote_signature(
        &self,
        ctx: &SigningContext,
        vote: &Vote,
        pubkey: &PublicKey,
    ) -> Result<(), SigError>;
}

/// Default verifier: Foundation's v1 `kovanica_crypto::verify_vote_signature`
/// (domain tag `KUNA/vote/v1`, chain id, epoch, voter; Ed25519 strict).
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519VoteVerifier;

impl VoteVerifier for Ed25519VoteVerifier {
    fn verify_vote_signature(
        &self,
        ctx: &SigningContext,
        vote: &Vote,
        pubkey: &PublicKey,
    ) -> Result<(), SigError> {
        kovanica_crypto::verify_vote_signature(ctx, vote, pubkey)
    }
}

/// Verify that `vote` is signed by its claimed voter under `keys`, using
/// `verifier` for the signature check.
pub fn verify_vote_with(
    verifier: &dyn VoteVerifier,
    keys: &AuthorityKeys,
    vote: &Vote,
    ctx: &SigningContext,
) -> Result<(), Rejection> {
    let key = keys
        .get(&vote.voter)
        .ok_or(Rejection::UnknownAuthority(vote.voter))?;
    verifier
        .verify_vote_signature(ctx, vote, key)
        .map_err(|_| Rejection::BadSignature(vote.voter))
}

/// Verify that `vote` is signed by its claimed voter under `keys`
/// (default [`Ed25519VoteVerifier`]).
pub fn verify_vote(
    keys: &AuthorityKeys,
    vote: &Vote,
    ctx: &SigningContext,
) -> Result<(), Rejection> {
    verify_vote_with(&Ed25519VoteVerifier, keys, vote, ctx)
}

/// Verify a block's digest, merkle root and author signature under `keys`.
///
/// The digest is recomputed first, so a valid signature cannot be replayed
/// over modified transactions or parents.
pub fn verify_block(keys: &AuthorityKeys, block: &StatementBlock) -> Result<(), Rejection> {
    let digest = StatementBlock::compute_digest_statements(
        block.author,
        block.round,
        &block.parents,
        &block.transactions,
        if kovanica_types::block::is_vrf_statement(&block.statements) {
            Some(&block.statements)
        } else {
            None
        },
    );
    if digest != block.digest {
        return Err(Rejection::DigestMismatch);
    }
    if StatementBlock::compute_merkle_root(&block.transactions) != block.merkle_root {
        return Err(Rejection::MerkleMismatch);
    }
    let key = keys
        .get(&block.author)
        .ok_or(Rejection::UnknownAuthority(block.author))?;
    kovanica_crypto::verify_block_signature(key, &block.digest, &block.signature)
        .map_err(|_| Rejection::BadSignature(block.author))
}

/// Holder for the committee keys used by the edge checks.
///
/// Until keys are configured nothing can be authenticated, so votes and
/// blocks are neither delivered nor forwarded (fail closed).
/// Verify a leader-slot timeout under `keys` (PRO-40 (b)): committee member
/// and a signature over `KUNA/timeout/v1 ‖ chain_id ‖ genesis_hash ‖
/// epoch(R) ‖ voter ‖ R`.
pub fn verify_timeout(
    keys: &AuthorityKeys,
    timeout: &Timeout,
    chain_id: u64,
    genesis_hash: &Hash,
) -> Result<(), Rejection> {
    let key = keys
        .get(&timeout.voter)
        .ok_or(Rejection::UnknownAuthority(timeout.voter))?;
    kovanica_crypto::verify(
        key,
        &timeout.signature_data(chain_id, genesis_hash),
        &timeout.signature,
    )
    .map_err(|_| Rejection::BadSignature(timeout.voter))
}

/// Edge check of a skip certificate: at most one timeout per committee
/// member, all for the certificate's round, every signature valid. Whether
/// the signers hold a stake quorum is decided by consensus, which knows the
/// stakes.
pub fn verify_skip_cert(
    keys: &AuthorityKeys,
    cert: &SkipCert,
    chain_id: u64,
    genesis_hash: &Hash,
) -> Result<(), Rejection> {
    if cert.timeouts.is_empty() || cert.timeouts.len() > keys.len() {
        return Err(Rejection::MalformedCertificate);
    }
    let mut seen = std::collections::HashSet::new();
    for timeout in &cert.timeouts {
        if timeout.round != cert.round || !seen.insert(timeout.voter) {
            return Err(Rejection::MalformedCertificate);
        }
        verify_timeout(keys, timeout, chain_id, genesis_hash)?;
    }
    Ok(())
}

pub(crate) struct GossipValidator {
    /// Keys indexed by authority index (for votes and blocks).
    authority_keys: RwLock<AuthorityKeys>,
    /// Keys indexed by address (for transactions).
    address_keys: RwLock<HashMap<Address, PublicKey>>,
    vote_verifier: RwLock<Arc<dyn VoteVerifier>>,
}

impl Default for GossipValidator {
    fn default() -> Self {
        Self {
            authority_keys: RwLock::new(AuthorityKeys::new()),
            address_keys: RwLock::new(HashMap::new()),
            vote_verifier: RwLock::new(Arc::new(Ed25519VoteVerifier)),
        }
    }
}

/// Stake, delegate and evidence are fee-free by design; everything else pays
/// a fee.
///
/// Evidence is free because reporting a valid equivocation is a public good
/// and the proof itself is the payload. This is safe at the gossip edge
/// because [`GossipValidator::verify_transaction`] only accepts transactions
/// whose sender key belongs to the current committee — the same restriction
/// the mempool applies through its staking check.
fn requires_fee(kind: &TransactionKind) -> bool {
    !matches!(
        kind,
        TransactionKind::Stake { .. }
            | TransactionKind::Delegate { .. }
            | TransactionKind::Evidence { .. }
    )
}

impl GossipValidator {
    /// Replace the vote signature verifier.
    pub(crate) fn set_vote_verifier(&self, verifier: Arc<dyn VoteVerifier>) {
        *self
            .vote_verifier
            .write()
            .unwrap_or_else(|e| e.into_inner()) = verifier;
    }

    /// Replace the committee keys.
    ///
    /// Populates both the authority-indexed map (for votes/blocks) and the
    /// address-indexed map (for transactions).
    pub(crate) fn set_keys(&self, keys: AuthorityKeys) {
        let mut auth_keys = self
            .authority_keys
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *auth_keys = keys.clone();

        // Also populate the address-indexed map for transaction validation.
        let mut addr_keys = self.address_keys.write().unwrap_or_else(|e| e.into_inner());
        addr_keys.clear();
        for pk in keys.values() {
            // We need the address for this authority index.
            // The address is derived from the public key.
            let addr = Address::from_public_key(pk);
            addr_keys.insert(addr, *pk);
        }
    }

    /// `true` once at least one committee key is configured.
    pub(crate) fn is_configured(&self) -> bool {
        !self
            .authority_keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }

    /// Copy of the committee keys. The set is at most a few dozen entries.
    pub(crate) fn authority_keys_snapshot(&self) -> AuthorityKeys {
        self.authority_keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub(crate) fn verify_vote(&self, vote: &Vote, ctx: &SigningContext) -> Result<(), Rejection> {
        let verifier = self
            .vote_verifier
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        verify_vote_with(
            verifier.as_ref(),
            &self
                .authority_keys
                .read()
                .unwrap_or_else(|e| e.into_inner()),
            vote,
            ctx,
        )
    }

    pub(crate) fn verify_timeout(
        &self,
        timeout: &Timeout,
        chain_id: u64,
        genesis_hash: &Hash,
    ) -> Result<(), Rejection> {
        verify_timeout(
            &self
                .authority_keys
                .read()
                .unwrap_or_else(|e| e.into_inner()),
            timeout,
            chain_id,
            genesis_hash,
        )
    }

    pub(crate) fn verify_skip_cert(
        &self,
        cert: &SkipCert,
        chain_id: u64,
        genesis_hash: &Hash,
    ) -> Result<(), Rejection> {
        verify_skip_cert(
            &self
                .authority_keys
                .read()
                .unwrap_or_else(|e| e.into_inner()),
            cert,
            chain_id,
            genesis_hash,
        )
    }

    pub(crate) fn verify_block(&self, block: &StatementBlock) -> Result<(), Rejection> {
        verify_block(
            &self
                .authority_keys
                .read()
                .unwrap_or_else(|e| e.into_inner()),
            block,
        )
    }

    /// Stateless transaction validation for gossip edge checks.
    ///
    /// Verifies the transaction is well-formed, has a valid signature,
    /// correct hash binding, and (optionally) a non-zero fee. This is
    /// intentionally stateless: it does not check nonce, balance, or
    /// mempool state — those are enforced at `on_transaction_message`
    /// after the message passes the gossip edge.
    #[allow(dead_code)]
    pub(crate) fn verify_transaction(
        &self,
        tx: &Transaction,
        signing_ctx: &SigningContext,
    ) -> Result<(), Rejection> {
        // Verify hash binding
        let expected_hash = tx.signing_hash(signing_ctx);
        if tx.hash != expected_hash {
            return Err(Rejection::DigestMismatch);
        }

        // Verify signature
        let addr_keys = self.address_keys.read().unwrap_or_else(|e| e.into_inner());
        let key = addr_keys
            .get(&tx.sender)
            .ok_or(Rejection::UnknownSender(tx.sender))?;
        kovanica_crypto::verify_transaction_signature(key, tx, signing_ctx)
            .map_err(|_| Rejection::TxBadSignature(tx.sender))?;

        // Verify fee is non-zero for fee-paying transaction kinds
        if requires_fee(&tx.kind) && tx.fee == 0 {
            return Err(Rejection::ZeroFee);
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    /// Signing context used by the network tests (local chain, epoch 0).
    pub(crate) const TEST_CTX: SigningContext =
        SigningContext::new(kovanica_types::signing::chain_id::LOCAL);
    use kovanica_types::{Hash, Signature};

    /// Deterministic committee of `n` keys (seed byte = index + 1).
    pub(crate) fn committee(n: u16) -> (Vec<kovanica_types::SigningKey>, AuthorityKeys) {
        let mut signers = Vec::new();
        let mut keys = AuthorityKeys::new();
        for index in 0..n {
            let signer = kovanica_types::SigningKey::from_bytes(&[index as u8 + 1; 32]);
            keys.insert(index, PublicKey::from(signer.verifying_key()));
            signers.push(signer);
        }
        (signers, keys)
    }

    pub(crate) fn signed_vote(signer: &kovanica_types::SigningKey, voter: u16) -> Vote {
        let mut vote = Vote {
            leader_round: 3,
            leader_hash: Hash::new(b"leader"),
            voter,
            signature: Signature([0; 64]),
        };
        vote.signature = kovanica_crypto::sign(signer, &vote.signature_data(&TEST_CTX));
        vote
    }

    pub(crate) fn signed_block(signer: &kovanica_types::SigningKey, author: u16) -> StatementBlock {
        let digest = StatementBlock::compute_digest(author, 1, &[], &[]);
        StatementBlock {
            author,
            round: 1,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: kovanica_crypto::sign(signer, digest.as_ref()),
            digest,
            merkle_root: StatementBlock::compute_merkle_root(&[]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use kovanica_types::{Hash, Signature};

    #[test]
    fn valid_vote_is_accepted() {
        let (signers, keys) = committee(4);
        assert_eq!(
            verify_vote(&keys, &signed_vote(&signers[2], 2), &TEST_CTX),
            Ok(())
        );
    }

    #[test]
    fn forged_vote_signature_is_rejected() {
        let (signers, keys) = committee(4);
        let mut vote = signed_vote(&signers[1], 1);
        vote.signature = Signature([7; 64]);
        assert_eq!(
            verify_vote(&keys, &vote, &TEST_CTX),
            Err(Rejection::BadSignature(1))
        );
    }

    #[test]
    fn vote_signed_by_another_validator_is_rejected() {
        let (signers, keys) = committee(4);
        // Validator 0 signs but claims to be validator 3.
        let mut vote = signed_vote(&signers[0], 3);
        vote.signature = kovanica_crypto::sign(&signers[0], &vote.signature_data(&TEST_CTX));
        assert_eq!(
            verify_vote(&keys, &vote, &TEST_CTX),
            Err(Rejection::BadSignature(3))
        );
    }

    #[test]
    fn tampered_vote_payload_is_rejected() {
        let (signers, keys) = committee(4);
        let mut vote = signed_vote(&signers[1], 1);
        vote.leader_hash = Hash::new(b"other leader");
        assert_eq!(
            verify_vote(&keys, &vote, &TEST_CTX),
            Err(Rejection::BadSignature(1))
        );
        let mut vote = signed_vote(&signers[1], 1);
        vote.leader_round += 1;
        assert_eq!(
            verify_vote(&keys, &vote, &TEST_CTX),
            Err(Rejection::BadSignature(1))
        );
    }

    #[test]
    fn vote_from_non_member_is_rejected() {
        let (signers, keys) = committee(4);
        let vote = signed_vote(&signers[0], 9);
        assert_eq!(
            verify_vote(&keys, &vote, &TEST_CTX),
            Err(Rejection::UnknownAuthority(9))
        );
    }

    #[test]
    fn valid_block_is_accepted() {
        let (signers, keys) = committee(4);
        assert_eq!(verify_block(&keys, &signed_block(&signers[1], 1)), Ok(()));
    }

    #[test]
    fn block_with_replayed_signature_over_new_content_is_rejected() {
        let (signers, keys) = committee(4);
        let original = signed_block(&signers[1], 1);
        // Keep digest + signature, change the content.
        let mut tampered = original.clone();
        tampered.round = 2;
        assert_eq!(
            verify_block(&keys, &tampered),
            Err(Rejection::DigestMismatch)
        );
    }

    #[test]
    fn block_with_wrong_merkle_root_is_rejected() {
        let (signers, keys) = committee(4);
        let mut block = signed_block(&signers[1], 1);
        block.merkle_root = Hash::new(b"bogus");
        assert_eq!(verify_block(&keys, &block), Err(Rejection::MerkleMismatch));
    }

    #[test]
    fn block_with_bad_signature_or_unknown_author_is_rejected() {
        let (signers, keys) = committee(4);
        let mut block = signed_block(&signers[1], 1);
        block.signature = Signature([0; 64]);
        assert_eq!(verify_block(&keys, &block), Err(Rejection::BadSignature(1)));

        let block = signed_block(&signers[0], 7);
        assert_eq!(
            verify_block(&keys, &block),
            Err(Rejection::UnknownAuthority(7))
        );
    }

    #[test]
    fn unconfigured_validator_rejects_everything() {
        let (signers, _) = committee(1);
        let validator = GossipValidator::default();
        assert!(!validator.is_configured());
        assert!(validator
            .verify_vote(&signed_vote(&signers[0], 0), &TEST_CTX)
            .is_err());
        assert!(validator
            .verify_block(&signed_block(&signers[0], 0))
            .is_err());
    }

    // --- VoteVerifier trait ---

    #[test]
    fn trait_accepts_valid_signature() {
        let (signers, keys) = committee(4);
        let vote = signed_vote(&signers[2], 2);
        assert_eq!(
            Ed25519VoteVerifier.verify_vote_signature(&TEST_CTX, &vote, &keys[&2]),
            Ok(())
        );
        assert_eq!(
            verify_vote_with(&Ed25519VoteVerifier, &keys, &vote, &TEST_CTX),
            Ok(())
        );
    }

    #[test]
    fn trait_rejects_bad_signature() {
        let (signers, keys) = committee(4);
        let mut vote = signed_vote(&signers[1], 1);
        vote.signature = Signature([7; 64]);
        assert_eq!(
            Ed25519VoteVerifier.verify_vote_signature(&TEST_CTX, &vote, &keys[&1]),
            Err(SigError::VerificationFailed)
        );
        assert_eq!(
            verify_vote_with(&Ed25519VoteVerifier, &keys, &vote, &TEST_CTX),
            Err(Rejection::BadSignature(1))
        );
    }

    #[test]
    fn trait_path_rejects_unknown_voter_without_calling_verifier() {
        struct Panicking;
        impl VoteVerifier for Panicking {
            fn verify_vote_signature(
                &self,
                _: &SigningContext,
                _: &Vote,
                _: &PublicKey,
            ) -> Result<(), SigError> {
                panic!("verifier must not be called for unknown voters");
            }
        }
        let (signers, keys) = committee(4);
        let vote = signed_vote(&signers[0], 9);
        assert_eq!(
            verify_vote_with(&Panicking, &keys, &vote, &TEST_CTX),
            Err(Rejection::UnknownAuthority(9))
        );
    }

    #[test]
    fn gossip_validator_uses_injected_verifier() {
        struct RejectAll;
        impl VoteVerifier for RejectAll {
            fn verify_vote_signature(
                &self,
                _: &SigningContext,
                _: &Vote,
                _: &PublicKey,
            ) -> Result<(), SigError> {
                Err(SigError::VerificationFailed)
            }
        }
        let (signers, keys) = committee(4);
        let validator = GossipValidator::default();
        validator.set_keys(keys);
        let vote = signed_vote(&signers[0], 0);
        assert_eq!(validator.verify_vote(&vote, &TEST_CTX), Ok(()));
        validator.set_vote_verifier(Arc::new(RejectAll));
        assert_eq!(
            validator.verify_vote(&vote, &TEST_CTX),
            Err(Rejection::BadSignature(0))
        );
    }

    fn sample_header() -> kovanica_types::LeaderHeader {
        kovanica_types::LeaderHeader {
            committed_height: 4,
            leader_round: 3,
            leader_digest: Hash::new([9u8]),
            leader_author: 0,
            parent_leader_digest: Hash::zero(),
            tx_merkle_root: Hash::zero(),
            executed_tx_root: Hash::zero(),
            non_blue_root: Hash::zero(),
            blue_root: Hash::zero(),
            mysticghost: false,
            state_root: Hash::new([4u8]),
            epoch: 0,
            committee_hash: Hash::zero(),
            timestamp: 0,
        }
    }

    #[test]
    fn valid_seal_is_forwarded_only_when_the_local_header_matches() {
        let (signers, keys) = committee(1);
        let header = sample_header();
        let signature = kovanica_crypto::sign(&signers[0], &header.seal_message(TEST_CTX.chain_id));
        let announcement = kovanica_types::SealAnnouncement {
            header: header.clone(),
            seal: kovanica_types::CommitSeal {
                authority_index: 0,
                signature,
            },
        };
        assert_eq!(
            admit_seal(&keys, TEST_CTX.chain_id, &announcement, None),
            SealAdmission::Ignore
        );
        assert_eq!(
            admit_seal(
                &keys,
                TEST_CTX.chain_id,
                &announcement,
                Some(Hash::new([1u8]))
            ),
            SealAdmission::Ignore
        );
        assert_eq!(
            admit_seal(&keys, TEST_CTX.chain_id, &announcement, Some(header.hash())),
            SealAdmission::Accept
        );
        let mut forged = announcement.clone();
        forged.seal.signature = Signature([7; 64]);
        assert_eq!(
            admit_seal(&keys, TEST_CTX.chain_id, &forged, Some(header.hash())),
            SealAdmission::Reject(Rejection::BadSignature(0))
        );
    }

    // B1c: a seal for a header after the first epoch boundary is admitted;
    // a header whose epoch does not match leader_round / EPOCH_ROUNDS is rejected.
    // Test from Jarvis review (2026-10-20).
    #[test]
    fn b1c_jarvis_seal_after_epoch_boundary_is_admitted() {
        let (signers, keys) = committee(1);
        let mut header = sample_header();
        header.leader_round = kovanica_types::EPOCH_ROUNDS + 1;
        header.epoch = 1;
        let signature = kovanica_crypto::sign(&signers[0], &header.seal_message(TEST_CTX.chain_id));
        let ann = kovanica_types::SealAnnouncement {
            header: header.clone(),
            seal: kovanica_types::CommitSeal {
                authority_index: 0,
                signature,
            },
        };
        assert_eq!(
            admit_seal(&keys, TEST_CTX.chain_id, &ann, Some(header.hash())),
            SealAdmission::Accept
        );
        let mut bad = header.clone();
        bad.epoch = 0;
        let signature = kovanica_crypto::sign(&signers[0], &bad.seal_message(TEST_CTX.chain_id));
        let ann = kovanica_types::SealAnnouncement {
            header: bad.clone(),
            seal: kovanica_types::CommitSeal {
                authority_index: 0,
                signature,
            },
        };
        assert_eq!(
            admit_seal(&keys, TEST_CTX.chain_id, &ann, Some(bad.hash())),
            SealAdmission::Reject(Rejection::EpochMismatch)
        );
    }

    fn signed_transaction(
        signer: &kovanica_types::SigningKey,
        kind: TransactionKind,
        fee: u64,
    ) -> Transaction {
        let mut tx = Transaction {
            sender: Address::from_public_key(&PublicKey::from(signer.verifying_key())),
            nonce: 0,
            kind,
            fee,
            signature: Signature([0; 64]),
            hash: Hash::zero(),
        };
        tx.hash = tx.signing_hash(&TEST_CTX);
        tx.signature = kovanica_crypto::sign(signer, tx.hash.as_ref());
        tx
    }

    #[test]
    fn zero_fee_transfer_from_a_committee_member_is_rejected() {
        let (signers, keys) = committee(4);
        let validator = GossipValidator::default();
        validator.set_keys(keys);
        let tx = signed_transaction(
            &signers[0],
            TransactionKind::Transfer {
                to: Address([9u8; 32]),
                amount: 1,
            },
            0,
        );
        assert_eq!(
            validator.verify_transaction(&tx, &TEST_CTX),
            Err(Rejection::ZeroFee)
        );
    }

    #[test]
    fn zero_fee_evidence_from_a_committee_member_is_accepted() {
        let (signers, keys) = committee(4);
        let offender = &signers[0];
        let author = Address::from_public_key(&PublicKey::from(offender.verifying_key()));
        let header = |seed: &[u8]| {
            let digest = Hash::new(seed);
            kovanica_types::SignedBlockHeader {
                author,
                round: 1,
                digest,
                signature: kovanica_crypto::sign(offender, digest.as_ref()),
            }
        };
        let evidence = kovanica_types::EquivocationEvidence {
            header_a: header(b"a"),
            header_b: header(b"b"),
        };
        let validator = GossipValidator::default();
        validator.set_keys(keys);
        // The reporter is a different committee member than the offender.
        let tx = signed_transaction(&signers[1], TransactionKind::Evidence { evidence }, 0);
        assert_eq!(validator.verify_transaction(&tx, &TEST_CTX), Ok(()));
    }

    #[test]
    fn transaction_from_a_non_committee_key_is_rejected() {
        let (_signers, keys) = committee(4);
        let validator = GossipValidator::default();
        validator.set_keys(keys);
        let outsider = kovanica_types::SigningKey::from_bytes(&[42u8; 32]);
        let tx = signed_transaction(&outsider, TransactionKind::Stake { amount: 1 }, 0);
        assert_eq!(
            validator.verify_transaction(&tx, &TEST_CTX),
            Err(Rejection::UnknownSender(Address::from_public_key(
                &PublicKey::from(outsider.verifying_key())
            )))
        );
    }
}
