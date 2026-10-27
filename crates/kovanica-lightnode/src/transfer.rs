//! Sign a transfer and check the recipient against an account proof.

use anyhow::{bail, Result};
use kovanica_light::{sign_transfer, verify_account};
use kovanica_types::{Address, Hash, LeaderHeader, SigningKey, StateProof, Transaction};

/// Bincode the signed transaction and hex-encode it for `kovanica_sendRawTransaction`.
pub fn encode_raw(transaction: &Transaction) -> Result<String> {
    let bytes = bincode::serialize(transaction)
        .map_err(|err| anyhow::anyhow!("encoding transaction: {err}"))?;
    Ok(format!("0x{}", hex::encode(bytes)))
}

/// Sign a native transfer for the configured chain id.
pub fn signed_transfer(
    chain_id: u64,
    signing_key: &SigningKey,
    sender: Address,
    to: Address,
    amount: u64,
    nonce: u64,
    fee: u64,
) -> Transaction {
    sign_transfer(chain_id, signing_key, sender, to, amount, nonce, fee)
}

/// Confirm `proof` against a header this light node already accepted.
///
/// The proof height must be the header height. A proof that fails
/// [`verify_account`] is not a balance.
pub fn confirm_account(header: &LeaderHeader, proof_height: u64, proof: &StateProof) -> Result<()> {
    if proof_height != header.committed_height {
        bail!(
            "account proof height {proof_height} is not the verified header {}",
            header.committed_height
        );
    }
    if !verify_account(header, proof) {
        bail!("account proof does not match the sealed state root");
    }
    Ok(())
}

/// Transaction hash of a transfer this process just signed.
pub fn transfer_hash(transaction: &Transaction) -> Hash {
    transaction.hash
}
