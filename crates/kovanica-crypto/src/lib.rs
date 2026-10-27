//! Cryptographic operations for Kovanica.
//! Signing, verification, key generation, VRF.

#![deny(unsafe_code)]

mod vrf;
pub use vrf::{
    decode_statements, derive_vrf_secret_from_seed, encode_statements, vrf_hash_to_u64, vrf_prove,
    vrf_verify, VRFError, VRFKeyPair, VRFOutput,
};

use ed25519_dalek::Signature as DalekSignature;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use kovanica_types::crypto::{PublicKey, Signature};
use kovanica_types::hash::Hash;
use kovanica_types::SigningContext;
use rand::rngs::OsRng;
use thiserror::Error;

use std::sync::RwLock;

static VALIDATOR_KEYS: RwLock<Vec<VerifyingKey>> = RwLock::new(Vec::new());

pub fn set_validator_keys(keys: Vec<VerifyingKey>) {
    *VALIDATOR_KEYS.write().unwrap() = keys;
}

/// Set validator keys from `kovanica_types::crypto::PublicKey` (converts to dalek VerifyingKey).
pub fn set_validator_keys_from_public(keys: Vec<PublicKey>) {
    let verifying_keys: Vec<VerifyingKey> = keys
        .into_iter()
        .map(|pk| VerifyingKey::from_bytes(&pk.0).expect("invalid validator public key"))
        .collect();
    *VALIDATOR_KEYS.write().unwrap() = verifying_keys;
}

fn get_validator_key(author: u16) -> Option<VerifyingKey> {
    let keys = VALIDATOR_KEYS.read().unwrap();
    keys.get(author as usize).cloned()
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Signature verification failed")]
    VerificationFailed,
}

/// Generate a new ed25519 keypair.
pub fn generate_keypair() -> (SigningKey, PublicKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key = PublicKey::from(verifying_key);
    (signing_key, public_key)
}

/// Sign a message (usually a block digest or transaction hash).
pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Signature {
    let sig = signing_key.sign(message);
    Signature::from(sig)
}

/// Verify a signature with Ed25519 **strict** verification
/// (`VerifyingKey::verify_strict`): rejects small-order / weak public keys,
/// non-canonical `R`/`A` encodings and non-canonical `S`. Signatures produced
/// by [`sign`] always pass.
pub fn verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(&public_key.0).map_err(|_| CryptoError::InvalidPublicKey)?;
    let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
    vk.verify_strict(message, &sig)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// Convenience: verify block signature.
pub fn verify_block_signature(
    public_key: &PublicKey,
    digest: &Hash,
    signature: &Signature,
) -> Result<(), CryptoError> {
    verify(public_key, digest.as_ref(), signature)
}

/// Convenience: verify transaction signature.
pub fn verify_transaction_signature(
    public_key: &PublicKey,
    tx: &kovanica_types::transaction::Transaction,
    ctx: &kovanica_types::SigningContext,
) -> Result<(), CryptoError> {
    let hash = tx.signing_hash(ctx);
    let message = hash.as_ref();
    verify(public_key, message, &tx.signature)
}

/// Errors returned by the vote signature API ([`verify_vote_signature`]).
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigError {
    /// The public key bytes are not a valid Ed25519 point (or are a weak /
    /// small-order key rejected by strict verification).
    #[error("invalid public key")]
    InvalidPublicKey,
    /// The signature does not verify over the vote's canonical bytes under
    /// the given public key.
    #[error("vote signature verification failed")]
    VerificationFailed,
}

/// Verify one post-execution commit seal.
///
/// The message is [`kovanica_types::LeaderHeader::seal_message`]: domain
/// `KUNA/commit/v1`, the caller's `chain_id`, and the header hash. The
/// header hash covers the state root and the MysticGhost blue / non-blue
/// roots. This does not check stake quorum; [`verify_commit_seals`] does.
pub fn verify_commit_seal(
    chain_id: u64,
    header: &kovanica_types::LeaderHeader,
    seal: &kovanica_types::CommitSeal,
    pubkey: &PublicKey,
) -> Result<(), SigError> {
    let vk = VerifyingKey::from_bytes(&pubkey.0).map_err(|_| SigError::InvalidPublicKey)?;
    let sig = DalekSignature::from_bytes(&seal.signature.0);
    vk.verify_strict(&header.seal_message(chain_id), &sig)
        .map_err(|_| SigError::VerificationFailed)
}

/// Verify a seal set: every signature, then the stake quorum.
///
/// `chain_id` is the verifier's own chain id. A seal signed for another
/// network fails. Duplicate signers, unknown indexes, a linearizer header
/// with a colouring root, and an epoch mismatch fail closed.
pub fn verify_commit_seals(
    chain_id: u64,
    header: &kovanica_types::LeaderHeader,
    seals: &[kovanica_types::CommitSeal],
    committee: &kovanica_types::Committee,
) -> Result<(), CommitSealError> {
    for seal in seals {
        let authority = committee
            .get_by_index(seal.authority_index)
            .ok_or(CommitSealError::UnknownAuthority)?;
        verify_commit_seal(chain_id, header, seal, &authority.public_key).map_err(
            |err| match err {
                SigError::InvalidPublicKey => CommitSealError::InvalidPublicKey,
                SigError::VerificationFailed => CommitSealError::Signature,
            },
        )?;
    }
    let indexes: Vec<kovanica_types::AuthorityIndex> =
        seals.iter().map(|seal| seal.authority_index).collect();
    kovanica_types::light_client::seal_quorum(header, &indexes, committee)
        .map_err(CommitSealError::Structure)
}

/// Failure of [`verify_commit_seals`].
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CommitSealError {
    /// The signature bytes do not match the header on this chain.
    #[error("commit seal signature verification failed")]
    Signature,
    /// The committee key is not a valid Ed25519 point.
    #[error("invalid signer public key")]
    InvalidPublicKey,
    /// The signer index is not in the committee.
    #[error("unknown seal authority")]
    UnknownAuthority,
    /// Stake, epoch, or colouring-flag check failed.
    #[error("commit seal set rejected")]
    Structure(kovanica_types::SealError),
}

/// Verify a consensus vote signature (signature format **v1**).
///
/// API contract (owned by Exec-Foundation, spec `docs/SIGNATURE_FORMAT.md` §1):
/// - The message is exactly [`Vote::signature_data(ctx)`](kovanica_types::Vote::signature_data):
///   the 74-byte v1 encoding with domain tag `KUNA/vote/v1`, `chain_id`,
///   `epoch`, `voter`, `leader_round` and `leader_hash`. The producer passes the
///   same bytes to [`sign`].
/// - `ctx` MUST be built by the verifier from its **own** configured
///   `chain_id` and its current committee epoch, never from a network message.
/// - `pubkey` MUST be `committee[epoch][vote.voter]`; the caller maps the
///   index to the key. `voter` is covered by the signature, so a signature
///   cannot be moved to another committee slot.
/// - `vote.signature` is checked with Ed25519 **strict** verification
///   (`VerifyingKey::verify_strict`): rejects non-canonical `S`, and weak /
///   small-order public keys. Signatures produced by [`sign`] always pass.
pub fn verify_vote_signature(
    ctx: &SigningContext,
    vote: &kovanica_types::Vote,
    pubkey: &PublicKey,
) -> Result<(), SigError> {
    let vk = VerifyingKey::from_bytes(&pubkey.0).map_err(|_| SigError::InvalidPublicKey)?;
    let sig = DalekSignature::from_bytes(&vote.signature.0);
    vk.verify_strict(&vote.signature_data(ctx), &sig)
        .map_err(|_| SigError::VerificationFailed)
}

/// Verify a set of block signatures.
///
/// The only decisive check is per-item Ed25519 `verify_strict` (see
/// `docs/BLOCK_SIGNATURE_V2.md`, "Strogo svugdje"). `ed25519_dalek::verify_batch`
/// uses the cofactored equation and accepts signatures that `verify_strict`
/// rejects (vectors N1, N3), so it is never used to accept. The result is
/// always identical to `all(verify_strict(item))`. Blocks are processed in
/// deterministic round order.
///
/// Returns `Ok(true)` iff every signature is valid; an invalid signature is a
/// hard error (`CryptoError::VerificationFailed`).
pub fn verify_batch(blocks: &[kovanica_types::block::StatementBlock]) -> Result<bool, CryptoError> {
    let mut ordered: Vec<&kovanica_types::block::StatementBlock> = blocks.iter().collect();
    ordered.sort_by_key(|b| b.round);
    for b in ordered {
        let vk = get_validator_key(b.author).ok_or(CryptoError::InvalidPublicKey)?;
        let sig = DalekSignature::from_bytes(&b.signature.0);
        vk.verify_strict(b.digest.as_ref(), &sig)
            .map_err(|_| CryptoError::VerificationFailed)?;
    }
    Ok(true)
}

#[cfg(test)]
mod batch_tests {
    use super::*;
    use kovanica_types::block::StatementBlock;
    use kovanica_types::hash::Hash;
    use rand::rngs::OsRng;

    #[test]
    fn verify_batch_4_signatures() {
        let mut csprng = OsRng;
        let mut keys: Vec<(SigningKey, VerifyingKey)> = Vec::with_capacity(4);
        for _ in 0..4 {
            let sk = SigningKey::generate(&mut csprng);
            keys.push((sk.clone(), sk.verifying_key()));
        }

        set_validator_keys(keys.iter().map(|(_, vk)| *vk).collect());

        let msg = b"batch-test-4";
        let mut blocks: Vec<StatementBlock> = Vec::with_capacity(4);
        for (i, (sk, _vk)) in keys.iter().enumerate() {
            let digest = Hash::new_keyed(Hash::DOMAIN_BLOCK, msg);
            let sig = sk.sign(digest.as_ref());
            blocks.push(StatementBlock {
                author: i as u16,
                round: (i as u64) % 2,
                parents: vec![],
                transactions: vec![],
                statements: vec![],
                signature: Signature::from(sig),
                digest,
                merkle_root: Default::default(),
            });
        }
        assert!(verify_batch(&blocks).unwrap());
    }
}

#[cfg(test)]
mod vote_sig_tests {
    use super::*;
    use kovanica_types::hash::Hash;
    use kovanica_types::Vote;

    const CTX: SigningContext = SigningContext {
        chain_id: 2,
        epoch: 7,
    };

    fn signed_vote(sk: &SigningKey) -> Vote {
        let mut vote = Vote {
            leader_round: 42,
            leader_hash: Hash::new("leader-block"),
            voter: 3,
            signature: Signature([0u8; 64]),
        };
        vote.signature = sign(sk, &vote.signature_data(&CTX));
        vote
    }

    #[test]
    fn valid_vote_signature_ok() {
        let (sk, pk) = generate_keypair();
        let vote = signed_vote(&sk);
        assert_eq!(verify_vote_signature(&CTX, &vote, &pk), Ok(()));
    }

    #[test]
    fn tampered_round_fails() {
        let (sk, pk) = generate_keypair();
        let mut vote = signed_vote(&sk);
        vote.leader_round += 1;
        assert_eq!(
            verify_vote_signature(&CTX, &vote, &pk),
            Err(SigError::VerificationFailed)
        );
    }

    #[test]
    fn tampered_hash_fails() {
        let (sk, pk) = generate_keypair();
        let mut vote = signed_vote(&sk);
        vote.leader_hash.0[0] ^= 0x01;
        assert_eq!(
            verify_vote_signature(&CTX, &vote, &pk),
            Err(SigError::VerificationFailed)
        );
    }

    #[test]
    fn tampered_signature_fails() {
        let (sk, pk) = generate_keypair();
        let mut vote = signed_vote(&sk);
        vote.signature.0[10] ^= 0x01;
        assert_eq!(
            verify_vote_signature(&CTX, &vote, &pk),
            Err(SigError::VerificationFailed)
        );
    }

    #[test]
    fn wrong_key_fails() {
        let (sk, _pk) = generate_keypair();
        let (_other_sk, other_pk) = generate_keypair();
        let vote = signed_vote(&sk);
        assert_eq!(
            verify_vote_signature(&CTX, &vote, &other_pk),
            Err(SigError::VerificationFailed)
        );
    }

    #[test]
    fn invalid_public_key_rejected() {
        let (sk, _pk) = generate_keypair();
        let vote = signed_vote(&sk);
        // y = 2 does not decompress to a curve point.
        let mut bad = [0u8; 32];
        bad[0] = 2;
        let res = verify_vote_signature(&CTX, &vote, &PublicKey(bad));
        assert!(
            matches!(
                res,
                Err(SigError::InvalidPublicKey) | Err(SigError::VerificationFailed)
            ),
            "got {res:?}"
        );
    }

    #[test]
    fn small_order_public_key_rejected() {
        // Identity point (small order): must never verify under strict mode.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let vote = Vote {
            leader_round: 1,
            leader_hash: Hash::new("x"),
            voter: 0,
            signature: Signature([0u8; 64]),
        };
        assert!(verify_vote_signature(&CTX, &vote, &PublicKey(identity)).is_err());
    }

    #[test]
    fn wrong_chain_id_fails() {
        let (sk, pk) = generate_keypair();
        let vote = signed_vote(&sk);
        let other = SigningContext { chain_id: 1, ..CTX };
        assert_eq!(
            verify_vote_signature(&other, &vote, &pk),
            Err(SigError::VerificationFailed)
        );
    }

    #[test]
    fn wrong_epoch_fails() {
        let (sk, pk) = generate_keypair();
        let vote = signed_vote(&sk);
        let other = CTX.with_epoch(8);
        assert_eq!(
            verify_vote_signature(&other, &vote, &pk),
            Err(SigError::VerificationFailed)
        );
    }

    #[test]
    fn reassigned_voter_index_fails() {
        let (sk, pk) = generate_keypair();
        let mut vote = signed_vote(&sk);
        vote.voter = 4;
        assert_eq!(
            verify_vote_signature(&CTX, &vote, &pk),
            Err(SigError::VerificationFailed)
        );
    }

    /// Golden vector V1 from `docs/SIGNATURE_FORMAT.md` §4 (deterministic
    /// Ed25519 signature by the spec key, seed `07` x 32).
    #[test]
    fn spec_vector_v1_verifies_and_reproduces() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = PublicKey(sk.verifying_key().to_bytes());
        let mut vote = Vote {
            leader_round: 42,
            leader_hash: Hash([0x11; 32]),
            voter: 3,
            signature: Signature([0u8; 64]),
        };
        vote.signature = sign(&sk, &vote.signature_data(&CTX));
        assert_eq!(
            hex::encode(vote.signature.0),
            "04edabde7c75345b9c4e12a793b2a4f05948c6edb5cbd197056fd68ef87d2a4c5311ff5df6eb6322c8fc229097079410873af37dceb4b43af66722005415a70b"
        );
        assert_eq!(verify_vote_signature(&CTX, &vote, &pk), Ok(()));
    }

    /// A transaction signature must never verify as a vote signature (and the
    /// vote tag differs from the tx tag, so the reverse also holds).
    #[test]
    fn vote_sig_over_other_domain_fails() {
        let (sk, pk) = generate_keypair();
        let mut vote = signed_vote(&sk);
        let mut tx_like = kovanica_types::signing::TX_DOMAIN_TAG.to_vec();
        tx_like.extend_from_slice(&vote.signature_data(&CTX)[16..]);
        vote.signature = sign(&sk, &tx_like);
        assert!(verify_vote_signature(&CTX, &vote, &pk).is_err());
    }
}

#[cfg(test)]
mod commit_seal_tests {
    use super::*;
    use kovanica_types::committee::{Authority, Committee};
    use kovanica_types::{Address, CommitSeal, LeaderHeader};

    fn authority(index: u16, public_key: PublicKey) -> Authority {
        Authority {
            index,
            public_key,
            vrf_public_key: None,
            address: Address([index as u8; 32]),
            stake: 1,
            network_address: String::new(),
        }
    }

    fn header() -> LeaderHeader {
        LeaderHeader {
            committed_height: 7,
            leader_round: 9,
            leader_digest: Hash::new(b"leader"),
            leader_author: 0,
            parent_leader_digest: Hash::zero(),
            tx_merkle_root: Hash::zero(),
            executed_tx_root: Hash::new(b"executed"),
            non_blue_root: Hash::zero(),
            blue_root: Hash::zero(),
            mysticghost: false,
            state_root: Hash::new(b"state"),
            epoch: 0,
            committee_hash: Hash::zero(),
            timestamp: 11,
        }
    }

    #[test]
    fn three_of_four_seals_verify_and_two_do_not() {
        let header = header();
        let keys: Vec<_> = (0..4).map(|_| generate_keypair()).collect();
        let committee = Committee::new(
            0,
            keys.iter()
                .enumerate()
                .map(|(i, (_, pk))| authority(i as u16, *pk))
                .collect(),
        );
        let seals: Vec<CommitSeal> = keys
            .iter()
            .enumerate()
            .map(|(i, (sk, _))| CommitSeal {
                authority_index: i as u16,
                signature: sign(sk, &header.seal_message(1337)),
            })
            .collect();

        assert!(verify_commit_seals(1337, &header, &seals[..3], &committee).is_ok());
        assert_eq!(
            verify_commit_seals(1337, &header, &seals[..2], &committee),
            Err(CommitSealError::Structure(
                kovanica_types::SealError::Quorum
            ))
        );
        assert_eq!(
            verify_commit_seals(1, &header, &seals[..3], &committee),
            Err(CommitSealError::Signature)
        );
    }

    #[test]
    fn mysticghost_root_is_covered_by_the_seal() {
        let mut header = header();
        header.mysticghost = true;
        header.blue_root = Hash::new(b"blue");
        let (sk, pk) = generate_keypair();
        let committee = Committee::new(0, vec![authority(0, pk)]);
        let seal = CommitSeal {
            authority_index: 0,
            signature: sign(&sk, &header.seal_message(2)),
        };
        assert!(verify_commit_seals(2, &header, std::slice::from_ref(&seal), &committee).is_ok());
        header.non_blue_root = Hash::new(b"red");
        assert_eq!(
            verify_commit_seals(2, &header, &[seal], &committee),
            Err(CommitSealError::Signature)
        );
    }
}
