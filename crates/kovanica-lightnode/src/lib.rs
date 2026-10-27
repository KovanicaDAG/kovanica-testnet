//! Kovanica light node library.
//!
//! The binary follows sealed committed-leader headers, checks commit seals
//! with [`kovanica_light`], and submits transfers. It does not run consensus,
//! the DAG, or Wasmi. A rewarded light node is not a validator.
//!
//! Argon2id (64 MiB) runs on the thread that decrypts the keystore. Callers
//! that have a UI thread must not decrypt there.

#![deny(unsafe_code)]

pub mod config;
pub mod decode;
pub mod register;
pub mod rpc;
pub mod sync;
pub mod transfer;

use std::path::Path;

use anyhow::{bail, Context, Result};
use kovanica_keystore::{self, Keystore};
use kovanica_types::Address;

pub use config::LightConfig;
pub use sync::{platform_note, SyncOutcome};
pub use transfer::{confirm_account, encode_raw, signed_transfer};

/// Create a data directory, a config, and a new encrypted keystore.
///
/// Refuses to replace an existing keystore. `chain_id` is stored as given.
/// The local and live-testnet value is 1337.
pub fn init(dir: &Path, rpc: &str, chain_id: u64, passphrase: &str) -> Result<Address> {
    if passphrase.is_empty() {
        bail!("passphrase is empty");
    }
    let mut cfg = LightConfig::local_default();
    cfg.rpc = rpc.to_owned();
    cfg.chain_id = chain_id;
    cfg.save(dir)?;
    let path = cfg.keystore_path(dir);
    if path.exists() {
        bail!("keystore already exists at {}", path.display());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let keystore = kovanica_keystore::keygen(passphrase)?;
    let address = kovanica_keystore::address(&keystore)?;
    kovanica_keystore::save(&path, &keystore)?;
    Ok(address)
}

/// Address stored in the keystore plaintext. This does not decrypt the seed.
pub fn status_address(dir: &Path) -> Result<Address> {
    let cfg = LightConfig::load(dir)?;
    let keystore = kovanica_keystore::load(&cfg.keystore_path(dir))?;
    kovanica_keystore::address(&keystore)
}

/// Decrypt the keystore. This runs Argon2id on the calling thread.
pub fn open_keystore(
    dir: &Path,
    passphrase: &str,
) -> Result<(LightConfig, Keystore, kovanica_types::SigningKey)> {
    let cfg = LightConfig::load(dir)?;
    let keystore = kovanica_keystore::load(&cfg.keystore_path(dir))?;
    let signing_key = kovanica_keystore::signing_key(&keystore, Some(passphrase))?;
    Ok((cfg, keystore, signing_key))
}
