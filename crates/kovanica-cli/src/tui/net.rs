//! Node and keystore operations for the interactive wallet.
//!
//! Decryption runs on a blocking thread because Argon2id is deliberate work.
//! Signing uses [`crate::tx::build_signed`]. The node receives only the
//! encoded signed transaction.

use std::fs;
use std::io;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use kovanica_types::transaction::TransactionKind;
use kovanica_types::{Address, PublicKey, SigningKey};
use serde_json::{json, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::rpc::{self, RpcClient};
use crate::tui::app::Review;
use crate::tx;
use crate::wallet;

/// Account figures shown on the home screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Snapshot {
    /// Latest committed block reported by `kovanica_blockNumber`.
    pub height: u64,
    /// Entries in `kovanica_getCommittee`.
    pub committee_size: usize,
    /// Peers from `/health`, when that request succeeds.
    pub peers: Option<usize>,
    /// Spendable native balance, in atoms.
    pub balance: u64,
    /// Next unused account nonce.
    pub nonce: u64,
    /// Own stake plus delegations, in atoms, from `kovanica_getStake`.
    pub stake: u64,
    /// Cumulative rewards from `kovanica_getRewards`.
    pub rewards: u64,
}

/// One row of `kovanica_getValidators`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatorRow {
    /// Validator account, as the node encoded it.
    pub address: String,
    /// Validator stake, in atoms.
    pub stake: u64,
    /// Commission in basis points.
    pub commission_bps: u64,
    /// Whether the validator is active.
    pub active: bool,
}

/// Unlocked account. The signing key lives only in this process.
pub(crate) struct Unlocked {
    pub address: Address,
    pub signing_key: SigningKey,
}

/// A newly written keystore plus the one-time recovery phrase.
pub(crate) struct Created {
    pub unlocked: Unlocked,
    /// 24 English words encoding the same seed. Shown once by the TUI.
    pub phrase: Zeroizing<String>,
}

/// Decrypt `path` with `passphrase`.
pub(crate) async fn unlock(
    path: std::path::PathBuf,
    passphrase: Zeroizing<String>,
) -> Result<Unlocked> {
    spawn_keystore(move || {
        let keystore = wallet::load(&path)?;
        let signing_key = wallet::signing_key(&keystore, Some(passphrase.as_str()))?;
        let address = wallet::address(&keystore)?;
        Ok(Unlocked {
            address,
            signing_key,
        })
    })
    .await
}

/// Create a new encrypted keystore. Refuses to replace an existing path.
pub(crate) async fn create_keystore(
    path: std::path::PathBuf,
    passphrase: Zeroizing<String>,
) -> Result<Created> {
    spawn_keystore(move || {
        ensure_new_file(&path)?;
        let (signing_key, public_key) = kovanica_crypto::generate_keypair();
        let mut seed = signing_key.to_bytes();
        let phrase = Zeroizing::new(wallet::seed_to_mnemonic(&seed)?);
        let keystore = wallet::from_seed(&seed, passphrase.as_str())?;
        seed.zeroize();
        let address = Address::from_public_key(&public_key);
        if wallet::address(&keystore)? != address || wallet::public_key(&keystore)? != public_key {
            bail!("new keystore identity does not match the generated key");
        }
        wallet::save(&path, &keystore)?;
        Ok(Created {
            unlocked: Unlocked {
                address,
                signing_key,
            },
            phrase,
        })
    })
    .await
}

/// Import a 24-word seed phrase into a new encrypted keystore.
pub(crate) async fn import_mnemonic(
    path: std::path::PathBuf,
    mnemonic: Zeroizing<String>,
    passphrase: Zeroizing<String>,
) -> Result<Unlocked> {
    spawn_keystore(move || {
        ensure_new_file(&path)?;
        let seed = wallet::seed_from_mnemonic(mnemonic.as_str())?;
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = PublicKey::from_bytes(signing_key.verifying_key().to_bytes());
        let address = Address::from_public_key(&public_key);
        let keystore = wallet::from_seed(&seed, passphrase.as_str())?;
        if wallet::address(&keystore)? != address || wallet::public_key(&keystore)? != public_key {
            bail!("imported keystore identity does not match the phrase");
        }
        wallet::save(&path, &keystore)?;
        Ok(Unlocked {
            address,
            signing_key,
        })
    })
    .await
}

/// Load the home-screen figures for `address`.
pub(crate) async fn fetch_snapshot(client: &RpcClient, address: &Address) -> Result<Snapshot> {
    let encoded = address.to_string();
    let height = rpc::parse_quantity(&client.call("kovanica_blockNumber", json!([])).await?)?;
    let committee = client.call("kovanica_getCommittee", json!([])).await?;
    let balance = rpc::parse_quantity(
        &client
            .call("kovanica_getBalance", json!([encoded.clone()]))
            .await?,
    )?;
    let nonce = rpc::parse_quantity(
        &client
            .call("kovanica_getNonce", json!([encoded.clone()]))
            .await?,
    )?;
    let stake = rpc::parse_quantity(
        &client
            .call("kovanica_getStake", json!([encoded.clone()]))
            .await?,
    )?;
    let rewards =
        rpc::parse_quantity(&client.call("kovanica_getRewards", json!([encoded])).await?)?;
    Ok(Snapshot {
        height,
        committee_size: committee.as_array().map(Vec::len).unwrap_or(0),
        peers: client.health_peer_count().await,
        balance,
        nonce,
        stake,
        rewards,
    })
}

/// The next unused nonce for `address`.
pub(crate) async fn fetch_nonce(client: &RpcClient, address: &Address) -> Result<u64> {
    let value = client
        .call("kovanica_getNonce", json!([address.to_string()]))
        .await?;
    rpc::parse_quantity(&value)
}

/// Active and inactive validators known to the node.
pub(crate) async fn fetch_validators(client: &RpcClient) -> Result<Vec<ValidatorRow>> {
    let value = client.call("kovanica_getValidators", json!([])).await?;
    Ok(parse_validators(&value))
}

/// Parse `kovanica_getValidators`, skipping rows that are missing a stake or address.
pub(crate) fn parse_validators(value: &Value) -> Vec<ValidatorRow> {
    let Some(items) = value.as_array() else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let address = item.get("address")?.as_str()?.trim();
            if address.is_empty() {
                return None;
            }
            let stake = rpc::parse_quantity(item.get("stake")?).ok()?;
            let commission_bps = item
                .get("commission_bps")
                .and_then(|value| rpc::parse_quantity(value).ok())
                .unwrap_or(0);
            let active = item.get("active").and_then(Value::as_bool).unwrap_or(false);
            Some(ValidatorRow {
                address: address.to_string(),
                stake,
                commission_bps,
                active,
            })
        })
        .collect()
}

/// Sign `review` for `chain_id` and submit it with `kovanica_sendRawTransaction`.
pub(crate) async fn submit(
    client: &RpcClient,
    chain_id: u64,
    sender: Address,
    signing_key: &SigningKey,
    review: Review,
) -> Result<String> {
    let context = tx::signing_context(Some(chain_id))?;
    crate::node::ensure_node_chain_matches(client, Some(context.chain_id)).await?;
    let kind: TransactionKind = review.action.kind();
    let transaction = tx::build_signed(
        &context,
        sender,
        review.nonce,
        kind,
        review.fee,
        signing_key,
    )?;
    let raw = tx::encode_raw(&transaction)?;
    let result = client
        .call("kovanica_sendRawTransaction", json!([raw]))
        .await?;
    Ok(result.as_str().unwrap_or("").to_string())
}

fn ensure_new_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!("refusing to write through a symlink")
        }
        Ok(_) => bail!("keystore already exists at {}", path.display()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("checking {}", path.display())),
    }
}

async fn spawn_keystore<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result,
        Err(err) => Err(anyhow!("keystore task failed: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::TxAction;
    use serde_json::json;

    #[test]
    fn parses_validator_rows_and_skips_malformed_ones() {
        let value = json!([
            {
                "address": "kvncabcdag",
                "stake": "0x2a",
                "commission_bps": 500,
                "active": true
            },
            {
                "address": "skipped",
                "stake": "not-a-number",
                "commission_bps": 1,
                "active": false
            },
            { "address": "   ", "stake": "0x1" },
            {
                "address": "kvncefdag",
                "stake": 7,
                "active": false
            }
        ]);
        let rows = parse_validators(&value);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].address, "kvncabcdag");
        assert_eq!(rows[0].stake, 42);
        assert_eq!(rows[0].commission_bps, 500);
        assert!(rows[0].active);
        assert_eq!(rows[1].stake, 7);
        assert_eq!(rows[1].commission_bps, 0);
        assert!(!rows[1].active);
        assert!(parse_validators(&json!({})).is_empty());
    }

    #[tokio::test]
    async fn created_keystore_roundtrips_through_unlock_and_import() {
        let dir = tempfile::tempdir().unwrap();
        let created_path = dir.path().join("created.json");
        let created = create_keystore(
            created_path.clone(),
            Zeroizing::new("test-passphrase".to_string()),
        )
        .await
        .unwrap();
        assert_eq!(created.phrase.split_whitespace().count(), 24);

        let stored = fs::read_to_string(&created_path).unwrap();
        assert!(!stored.contains("test-passphrase"));
        assert!(!stored.contains(created.phrase.as_str()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&created_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let unlocked = unlock(created_path, Zeroizing::new("test-passphrase".to_string()))
            .await
            .unwrap();
        assert_eq!(unlocked.address, created.unlocked.address);
        assert!(unlock(
            dir.path().join("created.json"),
            Zeroizing::new("wrong-passphrase".to_string()),
        )
        .await
        .is_err());

        let imported_path = dir.path().join("imported.json");
        let imported = import_mnemonic(
            imported_path.clone(),
            created.phrase.clone(),
            Zeroizing::new("other-passphrase".to_string()),
        )
        .await
        .unwrap();
        assert_eq!(imported.address, created.unlocked.address);
        let opened = unlock(
            imported_path,
            Zeroizing::new("other-passphrase".to_string()),
        )
        .await
        .unwrap();
        assert_eq!(opened.address, created.unlocked.address);
        assert!(create_keystore(
            dir.path().join("created.json"),
            Zeroizing::new("test-passphrase".to_string()),
        )
        .await
        .is_err());
    }

    #[test]
    fn transaction_kind_preserves_the_reviewed_fields() {
        let to = Address([9u8; 32]);
        let validator = Address([4u8; 32]);
        let transfer = TxAction::Transfer {
            to,
            amount: 2_500_000_000,
        };
        assert!(matches!(
            transfer.kind(),
            TransactionKind::Transfer {
                to: recipient,
                amount: 2_500_000_000
            } if recipient == to
        ));
        assert!(matches!(
            TxAction::Stake {
                amount: 50_000_000_000_000
            }
            .kind(),
            TransactionKind::Stake {
                amount: 50_000_000_000_000
            }
        ));
        assert!(matches!(
            TxAction::Unstake { amount: 3 }.kind(),
            TransactionKind::Unstake { amount: 3 }
        ));
        assert!(matches!(
            TxAction::Delegate {
                validator,
                amount: 8
            }
            .kind(),
            TransactionKind::Delegate {
                validator: parsed,
                amount: 8
            } if parsed == validator
        ));
        assert!(matches!(
            TxAction::Claim { validator: None }.kind(),
            TransactionKind::ClaimRewards { validator: None }
        ));
        assert!(matches!(
            TxAction::Claim {
                validator: Some(validator)
            }
            .kind(),
            TransactionKind::ClaimRewards {
                validator: Some(parsed)
            } if parsed == validator
        ));
    }
}
