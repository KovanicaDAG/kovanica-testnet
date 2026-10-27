//! Light-client checks for Kovanica.
//!
//! This crate verifies sealed committed-leader headers, transaction
//! inclusion, and account proofs. It does not replay the DAG or execute
//! WASM. A rewarded light node is not a validator.

#![deny(unsafe_code)]

use kovanica_crypto::CommitSealError;
use kovanica_types::crypto::Signature;
use kovanica_types::{
    committee_seal_hash, merkle, verify_colouring, Address, Authority, AuthorityIndex,
    ColouringCertificate, CommitSeal, Committee, Hash, LeaderHeader, MerkleProof, PublicKey,
    SealAnnouncement, SigningContext, SigningKey, Stake, StateProof, Transaction, TransactionKind,
};

/// Why a light client rejected a header or a proof.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LightError {
    /// The producer timestamp is not zero.
    #[error("leader header timestamp is not zero")]
    Timestamp,
    /// The header's committee hash is not the configured committee.
    #[error("leader header committee hash does not match")]
    Committee,
    /// The header does not follow the previous sealed leader.
    #[error("leader header does not follow the previous sealed leader")]
    Parent,
    /// Commit seals failed signature or quorum checks.
    #[error("commit seals rejected")]
    Seals(CommitSealError),
    /// MysticGhost roots do not match the supplied mergeset.
    #[error("mysticghost colouring does not match the header")]
    Colouring,
    /// The keystore could not be parsed, decrypted, or re-encrypted.
    #[error("keystore error: {0}")]
    Keystore(String),
    /// A sender address string could not be parsed.
    #[error("invalid sender address: {0}")]
    InvalidAddress(String),
}

/// Check one sealed header against the configured committee.
///
/// `parent` is the previous header this client accepted. `None` treats
/// `header` as a checkpoint: the seal quorum is enough, and the parent
/// digest is not compared. A later header must name the previous leader
/// digest and use the next committed height.
///
/// The timestamp must be 0. Statement blocks have no clock, and a non-zero
/// timestamp would make validators disagree.
pub fn verify_sealed_header(
    chain_id: u64,
    committee: &Committee,
    header: &LeaderHeader,
    seals: &[CommitSeal],
    parent: Option<&LeaderHeader>,
) -> Result<(), LightError> {
    if header.timestamp != 0 {
        return Err(LightError::Timestamp);
    }
    let members: Vec<(AuthorityIndex, PublicKey, Stake)> = committee
        .authorities
        .iter()
        .map(|authority| (authority.index, authority.public_key, authority.stake))
        .collect();
    if header.committee_hash != committee_seal_hash(committee.epoch, &members) {
        return Err(LightError::Committee);
    }
    if let Some(parent) = parent {
        if header.parent_leader_digest != parent.leader_digest
            || header.committed_height != parent.committed_height.saturating_add(1)
        {
            return Err(LightError::Parent);
        }
    }
    kovanica_crypto::verify_commit_seals(chain_id, header, seals, committee)
        .map_err(LightError::Seals)
}

/// Re-check MysticGhost roots when the caller has the mergeset.
pub fn verify_header_colouring(
    header: &LeaderHeader,
    certificate: &ColouringCertificate,
) -> Result<(), LightError> {
    verify_colouring(header, certificate)
        .map(|_| ())
        .map_err(|_| LightError::Colouring)
}

/// Transaction inclusion in the executed-transaction root.
pub fn verify_executed_tx(header: &LeaderHeader, tx_hash: &Hash, proof: &MerkleProof) -> bool {
    merkle::verify(tx_hash, proof, &header.executed_tx_root)
}

/// Transaction inclusion in the leader block's own merkle root.
pub fn verify_leader_tx(header: &LeaderHeader, tx_hash: &Hash, proof: &MerkleProof) -> bool {
    merkle::verify(tx_hash, proof, &header.tx_merkle_root)
}

/// Account balance and nonce against the header's state root.
pub fn verify_account(header: &LeaderHeader, proof: &StateProof) -> bool {
    proof.state_root == header.state_root && proof.verify()
}

/// Build a committee from seal-relevant fields.
///
/// Network addresses and VRF keys are not part of the seal hash.
pub fn committee_from_members(
    epoch: u64,
    members: &[(AuthorityIndex, PublicKey, Stake, Address)],
) -> Committee {
    let authorities = members
        .iter()
        .map(|(index, public_key, stake, address)| Authority {
            index: *index,
            public_key: *public_key,
            vrf_public_key: None,
            address: *address,
            stake: *stake,
            network_address: String::new(),
        })
        .collect();
    Committee::new(epoch, authorities)
}

/// Sign a light-node bond. The stake does not enter the validator committee.
pub fn sign_register_light_node(
    chain_id: u64,
    signing_key: &SigningKey,
    sender: Address,
    vrf_public_key: PublicKey,
    stake: u64,
    nonce: u64,
    fee: u64,
) -> Transaction {
    sign_kind(
        chain_id,
        signing_key,
        sender,
        nonce,
        fee,
        TransactionKind::RegisterLightNode {
            vrf_public_key,
            stake,
        },
    )
}

/// Sign a light-node exit. A pending registration refunds in execution.
pub fn sign_exit_light_node(
    chain_id: u64,
    signing_key: &SigningKey,
    sender: Address,
    nonce: u64,
    fee: u64,
) -> Transaction {
    sign_kind(
        chain_id,
        signing_key,
        sender,
        nonce,
        fee,
        TransactionKind::ExitLightNode,
    )
}

/// Sign one ECVRF witness for `epoch`.
#[allow(clippy::too_many_arguments)]
pub fn sign_light_witness(
    chain_id: u64,
    signing_key: &SigningKey,
    sender: Address,
    epoch: u64,
    vrf_hash: [u8; 32],
    vrf_proof: [u8; 96],
    nonce: u64,
    fee: u64,
) -> Transaction {
    sign_kind(
        chain_id,
        signing_key,
        sender,
        nonce,
        fee,
        TransactionKind::SubmitLightWitness {
            epoch,
            vrf_hash,
            vrf_proof,
        },
    )
}

/// Sign a native transfer. `chain_id` is the caller's configured network.
pub fn sign_transfer(
    chain_id: u64,
    signing_key: &SigningKey,
    sender: Address,
    to: Address,
    amount: u64,
    nonce: u64,
    fee: u64,
) -> Transaction {
    sign_kind(
        chain_id,
        signing_key,
        sender,
        nonce,
        fee,
        TransactionKind::Transfer { to, amount },
    )
}

/// Sign a contract call. `chain_id` is the caller's configured network.
///
/// `args` is the caller-encoded (bincode) calldata; `value` is the native
/// KUNA (base units) sent to the contract, `0` when unused.
#[allow(clippy::too_many_arguments)]
pub fn sign_call(
    chain_id: u64,
    signing_key: &SigningKey,
    sender: Address,
    nonce: u64,
    fee: u64,
    contract: Address,
    value: u64,
    method: String,
    args: Vec<u8>,
    gas_limit: u64,
) -> Transaction {
    sign_kind(
        chain_id,
        signing_key,
        sender,
        nonce,
        fee,
        TransactionKind::Call {
            contract,
            value,
            method,
            args,
            gas_limit,
        },
    )
}

/// Sign a contract deploy. `code` is the WASM bytecode.
pub fn sign_deploy(
    chain_id: u64,
    signing_key: &SigningKey,
    sender: Address,
    nonce: u64,
    fee: u64,
    code: Vec<u8>,
) -> Transaction {
    sign_kind(
        chain_id,
        signing_key,
        sender,
        nonce,
        fee,
        TransactionKind::Deploy { code },
    )
}

fn sign_kind(
    chain_id: u64,
    signing_key: &SigningKey,
    sender: Address,
    nonce: u64,
    fee: u64,
    kind: TransactionKind,
) -> Transaction {
    let mut transaction = Transaction {
        sender,
        nonce,
        kind,
        fee,
        signature: Signature([0u8; 64]),
        hash: Hash::zero(),
    };
    let ctx = SigningContext::new(chain_id);
    let hash = transaction.signing_hash(&ctx);
    transaction.signature = kovanica_crypto::sign(signing_key, hash.as_ref());
    transaction.hash = hash;
    transaction
}

/// Decrypt a wallet and return its 24-word BIP-39 seed phrase for backup.
///
/// The caller is responsible for showing the phrase exactly once and never
/// persisting it. A wrong `passphrase` is an error ([`LightError::Keystore`]),
/// never a panic.
pub fn reveal_mnemonic(keystore_json: &str, passphrase: &str) -> Result<String, LightError> {
    let keystore = kovanica_keystore::parse(keystore_json.as_bytes()).map_err(keystore_failure)?;
    let seed =
        kovanica_keystore::secret_seed(&keystore, Some(passphrase)).map_err(keystore_failure)?;
    kovanica_keystore::seed_to_mnemonic(&seed).map_err(keystore_failure)
}

/// Re-encrypt a wallet under `new_passphrase`, returning the new keystore JSON.
///
/// The caller replaces its stored keystore with the returned value. The seed is
/// preserved, so the address does not change. A wrong `old_passphrase` is an
/// error, never a panic.
pub fn change_passphrase(
    keystore_json: &str,
    old_passphrase: &str,
    new_passphrase: &str,
) -> Result<String, LightError> {
    let keystore = kovanica_keystore::parse(keystore_json.as_bytes()).map_err(keystore_failure)?;
    let seed = kovanica_keystore::secret_seed(&keystore, Some(old_passphrase))
        .map_err(keystore_failure)?;
    let updated = kovanica_keystore::from_seed(&seed, new_passphrase).map_err(keystore_failure)?;
    kovanica_keystore::to_json(&updated).map_err(keystore_failure)
}

fn keystore_failure(err: impl std::fmt::Display) -> LightError {
    LightError::Keystore(err.to_string())
}

/// Derive the address a `Deploy` transaction from `sender` will create.
///
/// The node's deploy path (`kovanica-execution::execute_deploy`, and the
/// matching branch of `touched_accounts`) hashes the sender's 32-byte address
/// with the account nonce **after** it has been incremented for the transaction:
///
/// ```text
/// contract = BLAKE3(sender.0 ‖ u64_le(tx.nonce + 1))
/// ```
///
/// The increment runs before the deploy body executes, so the value a client
/// holds while signing (the `tx.nonce`, which must equal the current account
/// nonce) is exactly one less than the nonce baked into the address. Pass that
/// signing-time nonce here; the `+1` is applied internally (via
/// `saturating_add`, mirroring the node).
///
/// `sender` accepts the canonical 64-character base32 form on every chain.
/// Legacy hex (bare, lowercase `0x`, or `kvnc<hex>dag`) is accepted only where
/// [`kovanica_types::address::legacy_address_allowed`] is true for `chain_id`
/// (devnet 3, chain 4, local 1337). Returns the bare 64-hex contract address.
pub fn contract_address_for(sender: &str, nonce: u64, chain_id: u64) -> Result<String, LightError> {
    let sender = Address::parse_for_chain(sender, chain_id)
        .map_err(|e| LightError::InvalidAddress(e.to_string()))?;
    // Mirrors `kovanica-execution::touched_accounts`: sender bytes followed by
    // the post-increment nonce, little-endian, then BLAKE3.
    let mut material = Vec::with_capacity(40);
    material.extend_from_slice(&sender.0);
    material.extend_from_slice(&nonce.saturating_add(1).to_le_bytes());
    Ok(Address(*blake3::hash(&material).as_bytes()).to_hex())
}

/// A seal announcement is only a convenience for tests and gossip decoding.
pub fn announcement_seal(announcement: &SealAnnouncement) -> &CommitSeal {
    &announcement.seal
}

/// Header field used by a light node that stores the last accepted leader.
pub fn header_leader_digest(header: &LeaderHeader) -> Hash {
    header.leader_digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_types::signing::chain_id;
    use kovanica_types::{leader_header, AccountSmt, CommittedSubDag, StatementBlock};

    fn keys(n: u16) -> (Vec<SigningKey>, Committee) {
        let mut signers = Vec::new();
        let mut members = Vec::new();
        for index in 0..n {
            let signer = SigningKey::from_bytes(&[index as u8 + 1; 32]);
            let public_key = PublicKey::from(signer.verifying_key());
            let address = Address::from_public_key(&public_key);
            members.push((index, public_key, 1u64, address));
            signers.push(signer);
        }
        (signers, committee_from_members(0, &members))
    }

    fn header_for(committee: &Committee, height: u64, parent: Hash, state: Hash) -> LeaderHeader {
        let digest = Hash::new([height as u8 + 1]);
        let leader = StatementBlock {
            author: 0,
            round: height.saturating_mul(3),
            parents: vec![],
            transactions: vec![],
            statements: vec![],
            signature: Signature([0; 64]),
            digest,
            merkle_root: Hash::zero(),
        };
        let subdag = CommittedSubDag {
            blocks: vec![leader.clone()],
            leader,
            leader_round: height.saturating_mul(3),
            leader_author: 0,
            non_blue: vec![],
        };
        let members: Vec<_> = committee
            .authorities
            .iter()
            .map(|authority| (authority.index, authority.public_key, authority.stake))
            .collect();
        leader_header(
            &subdag,
            height,
            parent,
            state,
            committee.epoch,
            committee_seal_hash(committee.epoch, &members),
            false,
        )
    }

    fn seals_for(
        signers: &[SigningKey],
        header: &LeaderHeader,
        chain_id: u64,
        n: u16,
    ) -> Vec<CommitSeal> {
        (0..n)
            .map(|index| CommitSeal {
                authority_index: index,
                signature: kovanica_crypto::sign(
                    &signers[index as usize],
                    &header.seal_message(chain_id),
                ),
            })
            .collect()
    }

    #[test]
    fn three_of_four_seals_pass_and_a_bad_seal_fails() {
        let (signers, committee) = keys(4);
        let header = header_for(&committee, 0, Hash::zero(), Hash::new([4u8]));
        let ok = seals_for(&signers, &header, 1337, 3);
        assert!(verify_sealed_header(1337, &committee, &header, &ok, None).is_ok());
        let short = seals_for(&signers, &header, 1337, 2);
        assert!(verify_sealed_header(1337, &committee, &header, &short, None).is_err());
        let mut bad = ok.clone();
        bad[0].signature = Signature([9u8; 64]);
        assert!(matches!(
            verify_sealed_header(1337, &committee, &header, &bad, None),
            Err(LightError::Seals(_))
        ));
        let mut timed = header.clone();
        timed.timestamp = 1;
        assert_eq!(
            verify_sealed_header(1337, &committee, &timed, &ok, None).unwrap_err(),
            LightError::Timestamp
        );
    }

    #[test]
    fn the_next_header_must_name_the_previous_leader() {
        let (signers, committee) = keys(4);
        let first = header_for(&committee, 0, Hash::zero(), Hash::zero());
        let second = header_for(&committee, 1, first.leader_digest, Hash::new([2u8]));
        let seals = seals_for(&signers, &second, 1337, 3);
        assert!(verify_sealed_header(1337, &committee, &second, &seals, Some(&first)).is_ok());
        let broken = header_for(&committee, 1, Hash::new([9u8]), Hash::new([2u8]));
        let broken_seals = seals_for(&signers, &broken, 1337, 3);
        assert_eq!(
            verify_sealed_header(1337, &committee, &broken, &broken_seals, Some(&first))
                .unwrap_err(),
            LightError::Parent
        );
    }

    #[test]
    fn an_account_proof_confirms_the_recipient_balance() {
        let (_signers, committee) = keys(4);
        let address = Address([7u8; 32]);
        let mut tree = AccountSmt::empty();
        tree.insert(address, 25, 2);
        let proof = tree.prove(&address, 25, 2, true);
        let header = header_for(&committee, 3, Hash::zero(), tree.root());
        let state = StateProof {
            state_root: tree.root(),
            address,
            balance: 25,
            nonce: 2,
            present: true,
            siblings: proof.siblings.to_vec(),
        };
        assert!(verify_account(&header, &state));
        let mut lie = state.clone();
        lie.balance = 26;
        assert!(!verify_account(&header, &lie));
    }

    #[test]
    fn a_signed_transfer_verifies_under_the_configured_chain_id() {
        let signer = SigningKey::from_bytes(&[9u8; 32]);
        let sender = Address::from_public_key(&PublicKey::from(signer.verifying_key()));
        let to = Address([3u8; 32]);
        let tx = sign_transfer(1337, &signer, sender, to, 10, 1, 1);
        assert!(tx.verify_signature(&SigningContext::new(1337)));
        assert!(!tx.verify_signature(&SigningContext::new(2)));
        let leaf = tx.hash;
        let proof = merkle::proof(&[leaf], 0).unwrap();
        let mut header = header_for(&keys(4).1, 0, Hash::zero(), Hash::zero());
        header.executed_tx_root = leaf;
        assert!(verify_executed_tx(&header, &leaf, &proof));
    }

    #[test]
    fn a_signed_call_round_trips_and_matches_the_spec_vectors() {
        // Golden vectors T2/T3 from `docs/SIGNATURE_FORMAT.md` §4: key bytes `07`×32,
        // chain_id = 2, nonce = 6, contract `33`×32, method "transfer",
        // args = 010203, gas_limit = 100_000, fee = 10.
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let sender = Address::from_public_key(&PublicKey::from(signer.verifying_key()));
        assert_eq!(
            hex::encode(sender.0),
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
        );
        let ctx = SigningContext::new(2);
        let contract = Address([0x33; 32]);
        let method = "transfer".to_string();
        let args = vec![1u8, 2, 3];

        // T2: value = 0.
        let call = sign_call(
            2,
            &signer,
            sender,
            6,
            10,
            contract,
            0,
            method.clone(),
            args.clone(),
            100_000,
        );
        assert!(call.verify_signature(&ctx));
        assert!(!call.verify_signature(&SigningContext::new(3)));
        assert_eq!(
            call.hash.to_hex(),
            "439e1830573896f46dc642cedb37605c1e478880f417f0cfae5126eaca48026a"
        );
        assert_eq!(
            hex::encode(call.signature.0),
            "0ff9438c1ea9e8a70e3b491d873c712e8e7d0339b637b00def16d42eea4eed3301454ef10f61b958bf37c95351a89f01270fe194ab8fa046b45373ee54e47f07"
        );
        assert!(matches!(
            call.kind,
            TransactionKind::Call { value: 0, ref method, gas_limit: 100_000, .. }
                if method == "transfer"
        ));

        // T3: value = 500 changes the signed bytes.
        let priced = sign_call(
            2, &signer, sender, 6, 10, contract, 500, method, args, 100_000,
        );
        assert!(priced.verify_signature(&ctx));
        assert_eq!(
            priced.hash.to_hex(),
            "9b76e7fc940641c6e11226b537841ace9ceb000a3943f6b3923b3cf2c6f4f794"
        );
        assert_eq!(
            hex::encode(priced.signature.0),
            "ce4e4d5dcc49159d2b6f72faa3210fe4db5b040e93eadbe315a159afe61f32ff66fc0abf9591c902500a1ce4e02d3816dbae80b8f1721725f03ed52b119f6608"
        );
        assert_ne!(call.hash, priced.hash);
    }

    #[test]
    fn a_signed_deploy_round_trips() {
        let signer = SigningKey::from_bytes(&[9u8; 32]);
        let sender = Address::from_public_key(&PublicKey::from(signer.verifying_key()));
        let ctx = SigningContext::new(1337);
        let deploy = sign_deploy(1337, &signer, sender, 3, 1, vec![0u8, 1, 2, 3]);
        assert!(deploy.verify_signature(&ctx));
        assert!(!deploy.verify_signature(&SigningContext::new(2)));
        assert!(matches!(
            deploy.kind,
            TransactionKind::Deploy { ref code } if code == &[0u8, 1, 2, 3]
        ));
    }

    #[test]
    fn light_node_transactions_verify_under_the_configured_chain_id() {
        let signer = SigningKey::from_bytes(&[4u8; 32]);
        let sender = Address::from_public_key(&PublicKey::from(signer.verifying_key()));
        let ctx = SigningContext::new(1337);
        let register =
            sign_register_light_node(1337, &signer, sender, PublicKey([8u8; 32]), 100, 0, 1);
        let exit = sign_exit_light_node(1337, &signer, sender, 1, 1);
        let witness = sign_light_witness(1337, &signer, sender, 3, [2u8; 32], [5u8; 96], 2, 1);
        assert!(register.verify_signature(&ctx));
        assert!(exit.verify_signature(&ctx));
        assert!(witness.verify_signature(&ctx));
        assert!(!witness.verify_signature(&SigningContext::new(2)));
        assert!(matches!(
            register.kind,
            TransactionKind::RegisterLightNode { stake: 100, .. }
        ));
        assert!(matches!(exit.kind, TransactionKind::ExitLightNode));
        assert!(matches!(
            witness.kind,
            TransactionKind::SubmitLightWitness { epoch: 3, .. }
        ));
    }

    #[test]
    fn reveal_and_change_passphrase_round_trip() {
        let seed = [7u8; 32];
        let keystore = kovanica_keystore::from_seed(&seed, "old").unwrap();
        let json = kovanica_keystore::to_json(&keystore).unwrap();

        // Reveal returns exactly the words that encode the seed.
        let revealed = reveal_mnemonic(&json, "old").unwrap();
        assert_eq!(
            revealed,
            kovanica_keystore::seed_to_mnemonic(&seed).unwrap()
        );
        assert_eq!(revealed.split_whitespace().count(), 24);

        // A wrong passphrase is an error, never a panic.
        assert!(matches!(
            reveal_mnemonic(&json, "nope").unwrap_err(),
            LightError::Keystore(_)
        ));

        // Changing the passphrase keeps the seed but swaps the encryption key.
        let updated = change_passphrase(&json, "old", "new").unwrap();
        let reopened = kovanica_keystore::parse(updated.as_bytes()).unwrap();
        assert_eq!(
            &kovanica_keystore::secret_seed(&reopened, Some("new")).unwrap()[..],
            &seed[..]
        );
        assert!(kovanica_keystore::secret_seed(&reopened, Some("old")).is_err());

        // A wrong old passphrase fails cleanly.
        assert!(change_passphrase(&json, "bad", "new").is_err());
    }

    #[test]
    fn contract_address_reproduces_the_node_derivation() {
        // The node derives the address in two places, both using `tx.nonce+1`
        // and `kovanica_common::hash` (BLAKE3): `execute_deploy` (hashes the
        // *post-increment* account nonce) and `touched_accounts` (encodes
        // `tx.nonce.saturating_add(1)`). Reconstruct that byte layout here so the
        // vector is independent of `contract_address_for`'s own body.
        let sender = Address([0x11u8; 32]);

        for nonce in [0u64, 1, 41, u64::MAX] {
            let mut material = Vec::with_capacity(40);
            material.extend_from_slice(&sender.0);
            material.extend_from_slice(&nonce.saturating_add(1).to_le_bytes());
            let expected = Address(*blake3::hash(&material).as_bytes()).to_hex();

            // Bare hex form and canonical kvnc…dag form must both agree.
            // Chain 4 still accepts legacy hex.
            assert_eq!(
                contract_address_for(&sender.to_hex(), nonce, chain_id::TESTNET_V2).unwrap(),
                expected
            );
            assert_eq!(
                contract_address_for(&sender.encode(), nonce, chain_id::TESTNET_V2).unwrap(),
                expected
            );
            // Canonical base32 does not need a lenient chain.
            assert_eq!(
                contract_address_for(&sender.encode(), nonce, chain_id::MAINNET).unwrap(),
                expected
            );
        }

        // 0x-prefixed input is accepted on a lenient chain, not on mainnet.
        assert_eq!(
            contract_address_for(&format!("0x{}", sender.to_hex()), 41, chain_id::TESTNET_V2)
                .unwrap(),
            contract_address_for(&sender.to_hex(), 41, chain_id::TESTNET_V2).unwrap()
        );
        assert!(matches!(
            contract_address_for(&format!("0x{}", sender.to_hex()), 41, chain_id::MAINNET)
                .unwrap_err(),
            LightError::InvalidAddress(_)
        ));
        assert!(matches!(
            contract_address_for(&format!("0X{}", sender.to_hex()), 41, chain_id::TESTNET_V2)
                .unwrap_err(),
            LightError::InvalidAddress(_)
        ));

        // A malformed sender is rejected, never a panic.
        assert!(matches!(
            contract_address_for("not-an-address", 0, chain_id::TESTNET_V2).unwrap_err(),
            LightError::InvalidAddress(_)
        ));

        // Pinned vector: BLAKE3(0x11×32 ‖ u64_le(41 + 1))
        //   = 806eaf0311f32e976df64184802ea7df85afa268c28978964ed1e3f120cc55bc
        // Locks the byte layout so a future change to either the sender encoding,
        // the `+1`, or the endianness is caught.
        assert_eq!(
            contract_address_for(
                "1111111111111111111111111111111111111111111111111111111111111111",
                41,
                chain_id::TESTNET_V2
            )
            .unwrap(),
            "806eaf0311f32e976df64184802ea7df85afa268c28978964ed1e3f120cc55bc"
        );
        // The same legacy payload is refused on chain 1.
        assert!(matches!(
            contract_address_for(
                "1111111111111111111111111111111111111111111111111111111111111111",
                41,
                chain_id::MAINNET
            )
            .unwrap_err(),
            LightError::InvalidAddress(_)
        ));
    }
}
