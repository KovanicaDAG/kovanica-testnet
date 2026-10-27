//! Offline transaction construction and encoding.
//!
//! A Kovanica [`Transaction`] carries a cached `hash` and an Ed25519 `signature`
//! over that hash. The CLI uses `Transaction::signing_hash` (signature format v1,
//! see `docs/SIGNATURE_FORMAT.md`; commits to the `chain_id`) and signs it offline — private keys never
//! leave the machine.

use anyhow::{anyhow, bail, Context, Result};

use kovanica_types::crypto::Signature;
use kovanica_types::signing::{self, SigningContext};
use kovanica_types::transaction::{Transaction, TransactionKind};
use kovanica_types::{Address, Hash, SigningKey};

/// Build the network signing context for transaction signing from the
/// `--chain-id` / `KOVANICA_CHAIN_ID` setting.
///
/// There is no default: signing without knowing the network would either fail
/// verification or, worse, produce a signature for the wrong network. The
/// `chain_id` must be in the registry of `docs/SIGNATURE_FORMAT.md`
/// (1 mainnet, 2 testnet, 3 devnet, 4 testnet v2, 1337 local).
pub fn signing_context(chain_id: Option<u64>) -> Result<SigningContext> {
    let chain_id = chain_id.ok_or_else(|| {
        anyhow!("--chain-id (or KOVANICA_CHAIN_ID) is required to sign transactions: 1 mainnet, 2 testnet, 3 devnet, 4 testnet v2, 1337 local")
    })?;
    if !signing::chain_id::is_registered(chain_id) {
        bail!("unknown chain id {chain_id}: expected 1 (mainnet), 2 (testnet), 3 (devnet), 4 (testnet v2) or 1337 (local)");
    }
    Ok(SigningContext::new(chain_id))
}

/// Build and sign a transaction (signature format v1), returning it ready for
/// submission. The hash is [`Transaction::signing_hash`], the same one the
/// node recomputes and verifies.
pub fn build_signed(
    ctx: &SigningContext,
    sender: Address,
    nonce: u64,
    kind: TransactionKind,
    fee: u64,
    signing_key: &SigningKey,
) -> Result<Transaction> {
    let mut transaction = Transaction {
        sender,
        nonce,
        kind,
        fee,
        signature: Signature([0u8; 64]),
        hash: Hash::zero(),
    };
    let hash = transaction.signing_hash(ctx);
    transaction.signature = kovanica_crypto::sign(signing_key, hash.as_ref());
    transaction.hash = hash;
    Ok(transaction)
}

/// Bincode-encode a signed transaction as a hex string for
/// `kovanica_sendRawTransaction`.
pub fn encode_raw(transaction: &Transaction) -> Result<String> {
    let bytes = bincode::serialize(transaction).context("encoding signed transaction")?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_types::transaction::TransactionKind;

    const CTX: SigningContext = SigningContext {
        chain_id: 2,
        epoch: 0,
    };

    #[test]
    fn signed_transaction_roundtrips_through_bincode() {
        let (signing_key, public_key) = kovanica_crypto::generate_keypair();
        let sender = Address::from_public_key(&public_key);
        let to = Address([9u8; 32]);
        let kind = TransactionKind::Transfer { to, amount: 42 };
        let tx = build_signed(&CTX, sender, 7, kind, 1, &signing_key).unwrap();

        let raw = encode_raw(&tx).unwrap();
        let decoded: Transaction = bincode::deserialize(&hex::decode(raw).unwrap()).unwrap();

        assert_eq!(decoded.sender, tx.sender);
        assert_eq!(decoded.nonce, 7);
        assert_eq!(decoded.fee, 1);
        assert_eq!(decoded.hash, tx.hash);
        assert_eq!(decoded.signature, tx.signature);
        kovanica_crypto::verify(&public_key, tx.hash.as_ref(), &tx.signature).unwrap();
    }

    /// The CLI must produce exactly what the node verifies: hash equals
    /// `signing_hash(ctx)` and `verify_signature(ctx)` holds, but only for the
    /// signing network.
    #[test]
    fn cli_transaction_verifies_like_the_node_does() {
        let (signing_key, public_key) = kovanica_crypto::generate_keypair();
        let sender = Address::from_public_key(&public_key);
        let kind = TransactionKind::Transfer {
            to: Address([2u8; 32]),
            amount: 5,
        };
        let tx = build_signed(&CTX, sender, 1, kind, 1, &signing_key).unwrap();
        assert_eq!(tx.hash, tx.signing_hash(&CTX));
        assert!(tx.verify_signature(&CTX));
        assert!(!tx.verify_signature(&SigningContext::new(1)));
    }

    #[test]
    fn hash_is_deterministic_nonce_and_chain_sensitive() {
        let (signing_key, public_key) = kovanica_crypto::generate_keypair();
        let sender = Address::from_public_key(&public_key);
        let kind = TransactionKind::Transfer {
            to: Address([2u8; 32]),
            amount: 5,
        };
        let a = build_signed(&CTX, sender, 1, kind.clone(), 1, &signing_key).unwrap();
        let b = build_signed(&CTX, sender, 1, kind.clone(), 1, &signing_key).unwrap();
        let c = build_signed(&CTX, sender, 2, kind.clone(), 1, &signing_key).unwrap();
        let d = build_signed(&SigningContext::new(3), sender, 1, kind, 1, &signing_key).unwrap();
        assert_eq!(a.hash, b.hash);
        assert_ne!(a.hash, c.hash);
        assert_ne!(a.hash, d.hash);
    }

    #[test]
    fn chain_id_is_required_and_must_be_registered() {
        assert!(signing_context(None).is_err());
        assert!(signing_context(Some(0)).is_err());
        for id in [1, 2, 3, 4, 1337] {
            assert_eq!(signing_context(Some(id)).unwrap().chain_id, id);
        }
    }

    /// Wire bytes the browser signer must reproduce. The spec key is
    /// seed `07` × 32 (`docs/SIGNATURE_FORMAT.md` §4). Transfer is vector T1.
    ///
    /// `Signature` is serde `serialize_bytes`, so bincode prefixes it with a
    /// u64 length. The other fixed arrays are raw bytes. Signing tags and
    /// bincode variant indexes are not the same numbers.
    #[test]
    fn console_signer_wire_fixtures_match_the_node() {
        use kovanica_types::SigningKey;

        let seed = [0x07u8; 32];
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../packages/signer/fixtures/wire.json"))
                .expect("wire fixture");
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = kovanica_types::PublicKey::from(signing_key.verifying_key());
        let sender = Address::from_public_key(&public_key);
        assert_eq!(
            hex::encode(public_key.0),
            fixture["publicKeyHex"].as_str().unwrap()
        );
        assert_eq!(sender.encode(), fixture["senderAddress"].as_str().unwrap());
        assert_eq!(
            Address([0x22; 32]).encode(),
            fixture["recipientAddress"].as_str().unwrap()
        );
        assert_eq!(
            sender.encode_legacy_hex(),
            fixture["senderAddressLegacy"].as_str().unwrap()
        );
        assert_eq!(
            Address([0x22; 32]).encode_legacy_hex(),
            fixture["recipientAddressLegacy"].as_str().unwrap()
        );
        assert_eq!(
            crate::wallet::seed_to_mnemonic(&seed).unwrap(),
            fixture["mnemonic"].as_str().unwrap()
        );

        let to = Address([0x22; 32]);
        let cases = [
            (
                "transfer",
                TransactionKind::Transfer {
                    to,
                    amount: 1_000_000,
                },
                5u64,
                1000u64,
            ),
            ("stake", TransactionKind::Stake { amount: 77 }, 8, 9),
            ("unstake", TransactionKind::Unstake { amount: 78 }, 9, 9),
            (
                "delegate",
                TransactionKind::Delegate {
                    validator: to,
                    amount: 79,
                },
                10,
                9,
            ),
            (
                "claimNone",
                TransactionKind::ClaimRewards { validator: None },
                11,
                9,
            ),
            (
                "claimSome",
                TransactionKind::ClaimRewards {
                    validator: Some(to),
                },
                12,
                9,
            ),
            // Call vectors T2/T3: contract `33`×32, method "transfer",
            // args 010203, gas_limit 100000, nonce 6, fee 10; only `value`
            // differs (0 vs 500). See `docs/SIGNATURE_FORMAT.md` §4.
            (
                "call-value-zero",
                TransactionKind::Call {
                    contract: Address([0x33; 32]),
                    value: 0,
                    method: "transfer".to_string(),
                    args: vec![1, 2, 3],
                    gas_limit: 100_000,
                },
                6,
                10,
            ),
            (
                "call-value-500",
                TransactionKind::Call {
                    contract: Address([0x33; 32]),
                    value: 500,
                    method: "transfer".to_string(),
                    args: vec![1, 2, 3],
                    gas_limit: 100_000,
                },
                6,
                10,
            ),
        ];

        for entry in fixture["transactions"].as_array().unwrap() {
            let name = entry["name"].as_str().unwrap();
            let (label, kind, nonce, fee) = cases
                .iter()
                .find(|(label, ..)| *label == name)
                .unwrap_or_else(|| panic!("unexpected fixture {name}"));
            assert_eq!(entry["nonce"].as_u64().unwrap(), *nonce, "{name}");
            assert_eq!(entry["fee"].as_u64().unwrap(), *fee, "{name}");
            let tx = build_signed(&CTX, sender, *nonce, kind.clone(), *fee, &signing_key).unwrap();
            assert_eq!(
                tx.hash.to_hex(),
                entry["signingHash"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                hex::encode(tx.signature.0),
                entry["signature"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                encode_raw(&tx).unwrap(),
                entry["rawHex"].as_str().unwrap(),
                "{label}"
            );
            let decoded: Transaction =
                bincode::deserialize(&hex::decode(entry["rawHex"].as_str().unwrap()).unwrap())
                    .unwrap();
            assert_eq!(decoded, tx, "{name}");
            assert!(tx.verify_signature(&CTX), "{name}");
        }
        assert_eq!(
            fixture["transactions"].as_array().unwrap().len(),
            cases.len()
        );
    }

    #[test]
    fn register_light_node_roundtrips_through_bincode() {
        use kovanica_types::crypto::PublicKey;
        use kovanica_types::transaction::TransactionKind;

        let (signing_key, public_key) = kovanica_crypto::generate_keypair();
        let sender = Address::from_public_key(&public_key);
        let vrf_pk = PublicKey([1u8; 32]);
        let kind = TransactionKind::RegisterLightNode {
            vrf_public_key: vrf_pk,
            stake: 100_000_000_000,
        };
        let tx = build_signed(&CTX, sender, 0, kind, 1_000_000, &signing_key).unwrap();

        let raw = encode_raw(&tx).unwrap();
        let decoded: Transaction = bincode::deserialize(&hex::decode(raw).unwrap()).unwrap();

        assert_eq!(decoded.sender, tx.sender);
        assert_eq!(decoded.nonce, 0);
        assert_eq!(decoded.fee, 1_000_000);
        assert_eq!(decoded.hash, tx.hash);
        assert_eq!(decoded.signature, tx.signature);

        match decoded.kind {
            TransactionKind::RegisterLightNode {
                vrf_public_key,
                stake,
            } => {
                assert_eq!(vrf_public_key, vrf_pk);
                assert_eq!(stake, 100_000_000_000);
            }
            _ => panic!("wrong kind"),
        }
    }
}
