//! Native transaction types.

use crate::address::Address;
use crate::crypto::{PublicKey, Signature};
use crate::evidence::EquivocationEvidence;
use crate::hash::Hash;
use crate::signing::{SigningContext, TX_DOMAIN_TAG};
use serde::{Deserialize, Serialize};

/// Kind of native transaction.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TransactionKind {
    /// Simple transfer of KUNA.
    Transfer {
        /// Recipient address.
        to: Address,
        /// Amount in base units.
        amount: u64,
    },
    /// Stake tokens (self-stake for validator).
    Stake {
        /// Amount to stake in base units.
        amount: u64,
    },
    /// Unstake tokens (begin unbonding).
    Unstake {
        /// Amount to unstake in base units.
        amount: u64,
    },
    /// Delegate stake to a validator.
    Delegate {
        /// Validator address to delegate to.
        validator: Address,
        /// Amount to delegate in base units.
        amount: u64,
    },
    /// Claim delegation rewards.
    ClaimRewards {
        /// Validator whose rewards to claim (optional, claims all if None).
        validator: Option<Address>,
    },
    /// Deploy a WASM contract.
    Deploy {
        /// WASM bytecode.
        code: Vec<u8>,
        // init args later
    },
    /// Call a WASM contract.
    Call {
        /// Contract address.
        contract: Address,
        /// Native KUNA (base units) transferred to the contract with the call
        /// (`0` when unused). Part of signature format v1.
        value: u64,
        /// Method name to call.
        method: String,
        /// Encoded arguments.
        args: Vec<u8>,
        /// Gas limit for execution.
        gas_limit: u64,
    },
    /// Bond KUNA and register a light-node VRF key.
    ///
    /// This is not validator stake. It does not enter the committee.
    /// The registration becomes active at the next epoch.
    RegisterLightNode {
        /// ECVRF public key used for the light-node lottery.
        vrf_public_key: PublicKey,
        /// Bond in atoms. The execution layer enforces the minimum.
        stake: u64,
    },
    /// Leave the light-node set and start unbonding the bond.
    ExitLightNode,
    /// Submit an ECVRF witness for one light-node epoch.
    SubmitLightWitness {
        /// Epoch the witness is for (`epoch_for_height(committed_height)`, 2 400 heights ≈ 8 h).
        epoch: u64,
        /// 32-byte VRF hash.
        vrf_hash: [u8; 32],
        /// 96-byte VRF proof.
        #[serde(with = "crate::crypto::vrf_proof_bytes")]
        vrf_proof: [u8; 96],
    },
    /// Set validator commission in basis points (10000 = 100%).
    SetCommission {
        /// Validator address.
        validator: Address,
        /// Commission in basis points.
        commission_bps: u16,
    },
    /// Claim vested treasury funds to the treasury address.
    ClaimTreasury {
        /// Amount to claim in base units.
        amount: u64,
    },
    /// Report a validator that signed two different blocks in one round.
    ///
    /// Gated on [`crate::slashing_active_from`]; below the activation round
    /// the transaction fails deterministically. Self-authenticating: the
    /// sender's signature only authorises inclusion, the proof is the pair of
    /// headers inside `evidence`.
    Evidence {
        /// The two conflicting signed headers.
        evidence: EquivocationEvidence,
    },
}

/// Full signed transaction.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Transaction {
    /// Sender address.
    pub sender: Address,
    /// Sender nonce (prevents replay).
    pub nonce: u64,
    /// Transaction kind (transfer, stake, call, etc.).
    pub kind: TransactionKind,
    /// Fee in base units.
    pub fee: u64,
    /// Ed25519 signature over the transaction hash.
    pub signature: Signature,
    /// Cached hash of the transaction.
    pub hash: Hash,
}

impl Transaction {
    /// Return the cached transaction hash.
    pub fn hash(&self) -> Hash {
        self.hash
    }

    /// Compute the signing hash for this transaction (excluding signature),
    /// signature format **v1** (`docs/SIGNATURE_FORMAT.md` §2).
    ///
    /// Preimage: `"KUNA/tx/v1"` 16-byte tag, `ctx.chain_id` u64 LE, sender,
    /// nonce, kind, fee; hashed with BLAKE3 keyed by [`Hash::DOMAIN_TX`].
    /// `ctx.epoch` is not part of transactions.
    pub fn signing_hash(&self, ctx: &SigningContext) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&TX_DOMAIN_TAG);
        data.extend_from_slice(&ctx.chain_id.to_le_bytes());
        data.extend_from_slice(&self.sender.0);
        data.extend_from_slice(&self.nonce.to_le_bytes());
        // Serialize kind
        match &self.kind {
            TransactionKind::Transfer { to, amount } => {
                data.push(0);
                data.extend_from_slice(&to.0);
                data.extend_from_slice(&amount.to_le_bytes());
            }
            TransactionKind::Stake { amount } => {
                data.push(1);
                data.extend_from_slice(&amount.to_le_bytes());
            }
            TransactionKind::Unstake { amount } => {
                data.push(2);
                data.extend_from_slice(&amount.to_le_bytes());
            }
            TransactionKind::Delegate { validator, amount } => {
                data.push(5);
                data.extend_from_slice(&validator.0);
                data.extend_from_slice(&amount.to_le_bytes());
            }
            TransactionKind::ClaimRewards { validator } => {
                data.push(6);
                if let Some(v) = validator {
                    data.push(1);
                    data.extend_from_slice(&v.0);
                } else {
                    data.push(0);
                }
            }
            TransactionKind::Deploy { code } => {
                data.push(3);
                data.extend_from_slice(&(code.len() as u64).to_le_bytes());
                data.extend_from_slice(code);
            }
            TransactionKind::Call {
                contract,
                value,
                method,
                args,
                gas_limit,
            } => {
                data.push(4);
                data.extend_from_slice(&contract.0);
                data.extend_from_slice(&value.to_le_bytes());
                data.extend_from_slice(&(method.len() as u64).to_le_bytes());
                data.extend_from_slice(method.as_bytes());
                data.extend_from_slice(&(args.len() as u64).to_le_bytes());
                data.extend_from_slice(args);
                data.extend_from_slice(&gas_limit.to_le_bytes());
            }
            TransactionKind::RegisterLightNode {
                vrf_public_key,
                stake,
            } => {
                data.push(7);
                data.extend_from_slice(&vrf_public_key.0);
                data.extend_from_slice(&stake.to_le_bytes());
            }
            TransactionKind::ExitLightNode => {
                data.push(8);
            }
            TransactionKind::SubmitLightWitness {
                epoch,
                vrf_hash,
                vrf_proof,
            } => {
                data.push(9);
                data.extend_from_slice(&epoch.to_le_bytes());
                data.extend_from_slice(vrf_hash);
                data.extend_from_slice(vrf_proof);
            }
            TransactionKind::SetCommission {
                validator,
                commission_bps,
            } => {
                data.push(10);
                data.extend_from_slice(&validator.0);
                data.extend_from_slice(&commission_bps.to_le_bytes());
            }
            TransactionKind::ClaimTreasury { amount } => {
                data.push(11);
                data.extend_from_slice(&amount.to_le_bytes());
            }
            TransactionKind::Evidence { evidence } => {
                data.push(12);
                for header in [&evidence.header_a, &evidence.header_b] {
                    data.extend_from_slice(&header.author.0);
                    data.extend_from_slice(&header.round.to_le_bytes());
                    data.extend_from_slice(&header.digest.0);
                    data.extend_from_slice(&header.signature.0);
                }
            }
        }
        data.extend_from_slice(&self.fee.to_le_bytes());
        Hash::new_keyed(Hash::DOMAIN_TX, &data)
    }

    /// Verify the transaction signature against the sender's public key.
    pub fn verify_signature(&self, ctx: &SigningContext) -> bool {
        // The sender address is the public key (32 bytes)
        let public_key = crate::crypto::PublicKey(self.sender.0);
        self.signature
            .verify(&self.signing_hash(ctx).0, &public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;

    const CTX: SigningContext = SigningContext {
        chain_id: 2,
        epoch: 0,
    };

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn sender() -> Address {
        Address(key().verifying_key().to_bytes())
    }

    fn tx(nonce: u64, kind: TransactionKind, fee: u64) -> Transaction {
        Transaction {
            sender: sender(),
            nonce,
            kind,
            fee,
            signature: Signature([0u8; 64]),
            hash: Hash::zero(),
        }
    }

    fn call(value: u64) -> Transaction {
        tx(
            6,
            TransactionKind::Call {
                contract: Address([0x33; 32]),
                value,
                method: "transfer".to_string(),
                args: vec![1, 2, 3],
                gas_limit: 100_000,
            },
            10,
        )
    }

    /// Check hash and the deterministic Ed25519 signature of a spec vector.
    fn check(tx: &Transaction, hash_hex: &str, sig_hex: &str) {
        let hash = tx.signing_hash(&CTX);
        assert_eq!(hash.to_hex(), hash_hex);
        use ed25519_dalek::Signer;
        let sig = key().sign(&hash.0);
        assert_eq!(hex::encode(sig.to_bytes()), sig_hex);
        let mut signed = tx.clone();
        signed.signature = Signature(sig.to_bytes());
        signed.hash = hash;
        assert!(signed.verify_signature(&CTX));
    }

    #[test]
    fn sender_matches_spec_key() {
        assert_eq!(
            hex::encode(sender().0),
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
        );
    }

    /// Golden vector T1 (Transfer) from `docs/SIGNATURE_FORMAT.md` §4.
    #[test]
    fn t1_transfer_golden() {
        let t = tx(
            5,
            TransactionKind::Transfer {
                to: Address([0x22; 32]),
                amount: 1_000_000,
            },
            1000,
        );
        check(
            &t,
            "4acde0e0a120d6c03eaa197c082238fefadaf36f4f40bc1364ae8b3faa067798",
            "2413f8c3a1508e2b1b2809c5cc9cc74982118d47e8a8e9afaab2d2719349724265b8f80d67359b579001b9c4845723edb9530372a79da9f4093d2f7228820d0e",
        );
    }

    /// Golden vector T2 (Call, value = 0).
    #[test]
    fn t2_call_value_zero_golden() {
        check(
            &call(0),
            "439e1830573896f46dc642cedb37605c1e478880f417f0cfae5126eaca48026a",
            "0ff9438c1ea9e8a70e3b491d873c712e8e7d0339b637b00def16d42eea4eed3301454ef10f61b958bf37c95351a89f01270fe194ab8fa046b45373ee54e47f07",
        );
    }

    /// Golden vector T3 (Call, value = 500).
    #[test]
    fn t3_call_value_golden() {
        check(
            &call(500),
            "9b76e7fc940641c6e11226b537841ace9ceb000a3943f6b3923b3cf2c6f4f794",
            "ce4e4d5dcc49159d2b6f72faa3210fe4db5b040e93eadbe315a159afe61f32ff66fc0abf9591c902500a1ce4e02d3816dbae80b8f1721725f03ed52b119f6608",
        );
    }

    #[test]
    fn chain_id_is_committed() {
        let t = call(0);
        let other = SigningContext::new(3);
        assert_ne!(t.signing_hash(&CTX), t.signing_hash(&other));
        let mut signed = t.clone();
        signed.signature =
            Signature(ed25519_dalek::Signer::sign(&key(), &t.signing_hash(&CTX).0).to_bytes());
        assert!(signed.verify_signature(&CTX));
        assert!(!signed.verify_signature(&other));
    }

    #[test]
    fn epoch_is_not_part_of_tx_hash() {
        let t = call(1);
        assert_eq!(t.signing_hash(&CTX), t.signing_hash(&CTX.with_epoch(9)));
    }

    #[test]
    fn call_value_is_committed() {
        assert_ne!(call(0).signing_hash(&CTX), call(1).signing_hash(&CTX));
    }

    #[test]
    fn light_node_kinds_use_signing_tags_7_8_and_9() {
        let vrf = crate::PublicKey([0x44; 32]);
        let register = tx(
            1,
            TransactionKind::RegisterLightNode {
                vrf_public_key: vrf,
                stake: 100,
            },
            2,
        );
        let exit = tx(1, TransactionKind::ExitLightNode, 2);
        let witness = tx(
            1,
            TransactionKind::SubmitLightWitness {
                epoch: 4,
                vrf_hash: [5u8; 32],
                vrf_proof: [6u8; 96],
            },
            2,
        );
        assert_eq!(
            register.signing_hash(&CTX),
            preimage(1, 7, &register_body())
        );
        assert_eq!(exit.signing_hash(&CTX), preimage(1, 8, &[]));
        assert_eq!(witness.signing_hash(&CTX), preimage(1, 9, &witness_body()));
        assert_ne!(register.signing_hash(&CTX), exit.signing_hash(&CTX));

        fn register_body() -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(&[0x44; 32]);
            body.extend_from_slice(&100u64.to_le_bytes());
            body
        }
        fn witness_body() -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(&4u64.to_le_bytes());
            body.extend_from_slice(&[5u8; 32]);
            body.extend_from_slice(&[6u8; 96]);
            body
        }
        fn preimage(nonce: u64, tag: u8, body: &[u8]) -> Hash {
            let mut data = Vec::new();
            data.extend_from_slice(&TX_DOMAIN_TAG);
            data.extend_from_slice(&CTX.chain_id.to_le_bytes());
            data.extend_from_slice(&sender().0);
            data.extend_from_slice(&nonce.to_le_bytes());
            data.push(tag);
            data.extend_from_slice(body);
            data.extend_from_slice(&2u64.to_le_bytes());
            Hash::new_keyed(Hash::DOMAIN_TX, &data)
        }
    }

    #[test]
    fn tx_and_vote_domains_are_disjoint() {
        assert_ne!(
            crate::signing::TX_DOMAIN_TAG,
            crate::signing::VOTE_DOMAIN_TAG
        );
    }
}
