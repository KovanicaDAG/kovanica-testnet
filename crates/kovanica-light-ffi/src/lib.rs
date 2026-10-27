//! UniFFI surface for the Kovanica light client.
//!
//! Ed25519, BLAKE3, and ECVRF stay in Rust. Callers pass the JSON the full
//! node already returns. Argon2id (64 MiB) runs on the calling thread, so a
//! UI thread must not call the wallet or signing functions.
//!
//! The scaffolding macro emits the only `unsafe` in this crate.

#![allow(unsafe_code)]

mod json;

use kovanica_comms_crypto::{e2e_aad, E2eCipher, Sealed, X25519Cipher, MAX_PLAINTEXT};
use kovanica_comms_relay::{comms_id_bytes, comms_id_from_hex, comms_id_hex, Envelope};
use kovanica_crypto::{derive_vrf_secret_from_seed, vrf_prove, VRFKeyPair};
use kovanica_keystore::{parse, to_json};
use kovanica_light::{
    change_passphrase, contract_address_for, reveal_mnemonic, sign_call, sign_deploy,
    sign_exit_light_node, sign_light_witness, sign_register_light_node, sign_transfer,
    verify_account, verify_sealed_header,
};
use kovanica_types::signing::chain_id;
use kovanica_types::{Address, Hash, SigningKey, Transaction};
use zeroize::Zeroize;

uniffi::setup_scaffolding!("kovanica_light");

/// Local chain id. The live testnet still uses this value.
pub const LOCAL_CHAIN_ID: u64 = chain_id::LOCAL;
/// Reserved testnet id. It is not the live testnet.
pub const TESTNET_CHAIN_ID: u64 = chain_id::TESTNET;

/// Domain separation prefix for comms message signing.
/// Matches `COMMS_MSG_DOMAIN` in the comms stack.
pub const COMMS_MSG_DOMAIN: &[u8] = b"kovanica/comms/msg/v1";

/// Why a light-client call failed.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum LightFfiError {
    /// A verification, decode, or keystore failure.
    #[error("{reason}")]
    Failed { reason: String },
}

/// A new wallet. The mnemonic is shown once by the caller.
#[derive(uniffi::Record)]
pub struct CreatedWallet {
    /// Canonical `kvnc…dag` address.
    pub address: String,
    /// 24-word raw seed. There is no BIP-39 passphrase.
    pub mnemonic: String,
    /// Encrypted v2 keystore JSON.
    pub keystore_json: String,
}

/// An imported wallet. The mnemonic is not returned.
#[derive(uniffi::Record)]
pub struct ImportedWallet {
    /// Canonical `kvnc…dag` address.
    pub address: String,
    /// Encrypted v2 keystore JSON.
    pub keystore_json: String,
}

/// A sealed header this client accepted.
#[derive(uniffi::Record)]
pub struct VerifiedHeader {
    /// Committed leader height.
    pub committed_height: u64,
    /// Header hash, `0x` hex.
    pub header_hash: String,
    /// Leader block digest, `0x` hex.
    pub leader_digest: String,
    /// Account state root, `0x` hex.
    pub state_root: String,
    /// Committee epoch stored on the header.
    pub epoch: u64,
}

/// Balance and nonce from an account proof.
#[derive(uniffi::Record)]
pub struct AccountSnapshot {
    /// Atoms.
    pub balance: u64,
    /// Account nonce.
    pub nonce: u64,
    /// True when the proof matched the sealed state root.
    pub verified: bool,
}

fn failed(err: impl std::fmt::Display) -> LightFfiError {
    LightFfiError::Failed {
        reason: err.to_string(),
    }
}

/// Owned secret text. Drop overwrites the buffer with zeroes.
struct SecretString(String);

impl SecretString {
    fn new(value: String) -> Self {
        Self(value)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        wipe_secret(&mut self.0);
    }
}

/// Overwrite a secret string, then drop its length so the text is not left behind.
fn wipe_secret(secret: &mut String) {
    secret.zeroize();
}

/// Create a 24-word wallet and encrypt it. Runs Argon2id.
#[uniffi::export]
pub fn create_wallet(passphrase: String) -> Result<CreatedWallet, LightFfiError> {
    let passphrase = SecretString::new(passphrase);
    if passphrase.as_str().is_empty() {
        return Err(failed("passphrase is empty"));
    }
    let (signing_key, _) = kovanica_crypto::generate_keypair();
    let mut seed = signing_key.to_bytes();
    let created = wallet_from_seed(&seed, passphrase.as_str());
    seed.zeroize();
    created
}

/// Import a 24-word seed and encrypt it. Runs Argon2id.
#[uniffi::export]
pub fn import_wallet(
    mnemonic: String,
    passphrase: String,
) -> Result<ImportedWallet, LightFfiError> {
    let mnemonic = SecretString::new(mnemonic);
    let passphrase = SecretString::new(passphrase);
    if passphrase.as_str().is_empty() {
        return Err(failed("passphrase is empty"));
    }
    let seed = kovanica_keystore::seed_from_mnemonic(mnemonic.as_str()).map_err(failed)?;
    let created = wallet_from_seed(&seed, passphrase.as_str())?;
    Ok(ImportedWallet {
        address: created.address,
        keystore_json: created.keystore_json,
    })
}

/// Address stored in the keystore plaintext. This does not decrypt the seed.
#[uniffi::export]
pub fn wallet_address(keystore_json: String) -> Result<String, LightFfiError> {
    let keystore = parse(keystore_json.as_bytes()).map_err(failed)?;
    Ok(kovanica_keystore::address(&keystore)
        .map_err(failed)?
        .to_string())
}

/// True when the app may show the testnet faucet.
///
/// The live testnet chain id is still [`LOCAL_CHAIN_ID`] (1337). [`TESTNET_CHAIN_ID`]
/// is included so a future network does not need a client change to hide or
/// show the faucet.
#[uniffi::export]
pub fn faucet_allowed(chain_id: u64) -> bool {
    chain_id == LOCAL_CHAIN_ID || chain_id == TESTNET_CHAIN_ID
}

/// Verify one sealed header.
///
/// `parent_json` is empty for a checkpoint. Later headers must name the
/// previous leader. `epoch` is the configured committee epoch (0 until
/// rotation is live).
#[uniffi::export]
pub fn verify_header(
    chain_id: u64,
    epoch: u64,
    committee_json: String,
    header_json: String,
    seals_json: String,
    parent_json: String,
) -> Result<VerifiedHeader, LightFfiError> {
    let committee =
        json::committee_from_json(epoch, &json::parse_json(&committee_json).map_err(failed)?)
            .map_err(failed)?;
    let header = json::leader_header_from_json(&json::parse_json(&header_json).map_err(failed)?)
        .map_err(failed)?;
    let seals =
        json::seals_from_json(&json::parse_json(&seals_json).map_err(failed)?).map_err(failed)?;
    let parent = if parent_json.is_empty() {
        None
    } else {
        Some(
            json::leader_header_from_json(&json::parse_json(&parent_json).map_err(failed)?)
                .map_err(failed)?,
        )
    };
    verify_sealed_header(chain_id, &committee, &header, &seals, parent.as_ref()).map_err(failed)?;
    Ok(VerifiedHeader {
        committed_height: header.committed_height,
        header_hash: hex_hash(&header.hash()),
        leader_digest: hex_hash(&header.leader_digest),
        state_root: hex_hash(&header.state_root),
        epoch: header.epoch,
    })
}

/// Check an account proof against a header this client already accepted.
#[uniffi::export]
pub fn confirm_account(
    header_json: String,
    proof_json: String,
) -> Result<AccountSnapshot, LightFfiError> {
    let header = json::leader_header_from_json(&json::parse_json(&header_json).map_err(failed)?)
        .map_err(failed)?;
    let (height, proof) =
        json::account_proof_from_json(&json::parse_json(&proof_json).map_err(failed)?)
            .map_err(failed)?;
    if height != header.committed_height {
        return Err(failed(format!(
            "account proof height {height} is not the sealed header {}",
            header.committed_height
        )));
    }
    if !verify_account(&header, &proof) {
        return Err(failed("account proof does not match the sealed state root"));
    }
    Ok(AccountSnapshot {
        balance: proof.balance,
        nonce: proof.nonce,
        verified: true,
    })
}

/// Sign a transfer. `fee_rate` is atoms per byte from `kovanica_estimateFee`.
#[uniffi::export]
pub fn sign_transfer_raw(
    keystore_json: String,
    passphrase: String,
    chain_id: u64,
    to: String,
    amount: u64,
    nonce: u64,
    fee_rate: u64,
) -> Result<String, LightFfiError> {
    let passphrase = SecretString::new(passphrase);
    let (signing_key, sender) = open_signing_key(&keystore_json, passphrase.as_str())?;
    let to = parse_address(&to, chain_id)?;
    priced_raw(fee_rate, |fee| {
        sign_transfer(chain_id, &signing_key, sender, to, amount, nonce, fee)
    })
}

/// Sign a contract call. `args_hex` is bincode-encoded calldata (`0x` optional).
///
/// `value` is the native KUNA (atoms) sent to the contract, `0` when unused.
/// `fee_rate` is atoms per byte from `kovanica_estimateFee`.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn sign_call_raw(
    keystore_json: String,
    passphrase: String,
    chain_id: u64,
    contract: String,
    value: u64,
    method: String,
    args_hex: String,
    gas_limit: u64,
    nonce: u64,
    fee_rate: u64,
) -> Result<String, LightFfiError> {
    let passphrase = SecretString::new(passphrase);
    let (signing_key, sender) = open_signing_key(&keystore_json, passphrase.as_str())?;
    let contract = parse_address(&contract, chain_id)?;
    let args = parse_hex_bytes(&args_hex, "args")?;
    priced_raw(fee_rate, |fee| {
        sign_call(
            chain_id,
            &signing_key,
            sender,
            nonce,
            fee,
            contract,
            value,
            method.clone(),
            args.clone(),
            gas_limit,
        )
    })
}

/// Sign a contract deploy. `code_hex` is the WASM bytecode (`0x` optional).
///
/// `fee_rate` is atoms per byte from `kovanica_estimateFee`.
#[uniffi::export]
pub fn sign_deploy_raw(
    keystore_json: String,
    passphrase: String,
    chain_id: u64,
    code_hex: String,
    nonce: u64,
    fee_rate: u64,
) -> Result<String, LightFfiError> {
    let passphrase = SecretString::new(passphrase);
    let (signing_key, sender) = open_signing_key(&keystore_json, passphrase.as_str())?;
    let code = parse_hex_bytes(&code_hex, "code")?;
    priced_raw(fee_rate, |fee| {
        sign_deploy(chain_id, &signing_key, sender, nonce, fee, code.clone())
    })
}

/// Sign a light-node bond. The stake does not enter the validator committee.
#[uniffi::export]
pub fn sign_bond_raw(
    keystore_json: String,
    passphrase: String,
    chain_id: u64,
    stake: u64,
    nonce: u64,
    fee_rate: u64,
) -> Result<String, LightFfiError> {
    let passphrase = SecretString::new(passphrase);
    let (signing_key, sender) = open_signing_key(&keystore_json, passphrase.as_str())?;
    let vrf = vrf_key(&signing_key)?;
    priced_raw(fee_rate, |fee| {
        sign_register_light_node(
            chain_id,
            &signing_key,
            sender,
            vrf.public_key_typed(),
            stake,
            nonce,
            fee,
        )
    })
}

/// Sign a light-node exit.
#[uniffi::export]
pub fn sign_exit_raw(
    keystore_json: String,
    passphrase: String,
    chain_id: u64,
    nonce: u64,
    fee_rate: u64,
) -> Result<String, LightFfiError> {
    let passphrase = SecretString::new(passphrase);
    let (signing_key, sender) = open_signing_key(&keystore_json, passphrase.as_str())?;
    priced_raw(fee_rate, |fee| {
        sign_exit_light_node(chain_id, &signing_key, sender, nonce, fee)
    })
}

/// Sign one witness for `epoch`. `beacon_hex` is the epoch-opening leader digest.
#[uniffi::export]
pub fn sign_witness_raw(
    keystore_json: String,
    passphrase: String,
    chain_id: u64,
    epoch: u64,
    beacon_hex: String,
    nonce: u64,
    fee_rate: u64,
) -> Result<String, LightFfiError> {
    let passphrase = SecretString::new(passphrase);
    let (signing_key, sender) = open_signing_key(&keystore_json, passphrase.as_str())?;
    let beacon = parse_beacon(&beacon_hex)?;
    let vrf = vrf_key(&signing_key)?;
    let input = kovanica_types::light_vrf_input(chain_id, epoch, &beacon);
    let output = vrf_prove(&vrf, &input);
    priced_raw(fee_rate, |fee| {
        sign_light_witness(
            chain_id,
            &signing_key,
            sender,
            epoch,
            output.hash,
            output.proof,
            nonce,
            fee,
        )
    })
}

fn wallet_from_seed(seed: &[u8; 32], passphrase: &str) -> Result<CreatedWallet, LightFfiError> {
    let mnemonic = kovanica_keystore::seed_to_mnemonic(seed).map_err(failed)?;
    let keystore = kovanica_keystore::from_seed(seed, passphrase).map_err(failed)?;
    let address = kovanica_keystore::address(&keystore)
        .map_err(failed)?
        .to_string();
    let keystore_json = to_json(&keystore).map_err(failed)?;
    Ok(CreatedWallet {
        address,
        mnemonic,
        keystore_json,
    })
}

fn open_signing_key(
    keystore_json: &str,
    passphrase: &str,
) -> Result<(SigningKey, Address), LightFfiError> {
    let keystore = parse(keystore_json.as_bytes()).map_err(failed)?;
    let sender = kovanica_keystore::address(&keystore).map_err(failed)?;
    let signing_key =
        kovanica_keystore::signing_key(&keystore, Some(passphrase)).map_err(failed)?;
    Ok((signing_key, sender))
}

fn vrf_key(signing_key: &SigningKey) -> Result<VRFKeyPair, LightFfiError> {
    let secret = derive_vrf_secret_from_seed(&signing_key.to_bytes());
    VRFKeyPair::from_secret(secret).map_err(failed)
}

fn parse_address(value: &str, chain_id: u64) -> Result<Address, LightFfiError> {
    kovanica_keystore::parse_address(value, "address", chain_id).map_err(failed)
}

fn parse_beacon(value: &str) -> Result<Hash, LightFfiError> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(raw).map_err(failed)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| failed("beacon must be 32 bytes"))?;
    Ok(Hash(bytes))
}

/// Decode a byte string from hex, `0x`/`0X` prefix optional and whitespace trimmed.
fn parse_hex_bytes(value: &str, field: &str) -> Result<Vec<u8>, LightFfiError> {
    let trimmed = value.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    hex::decode(stripped).map_err(|_| failed(format!("{field} is not valid hex")))
}

fn priced_raw(fee_rate: u64, sign: impl Fn(u64) -> Transaction) -> Result<String, LightFfiError> {
    let draft = bincode::serialize(&sign(1)).map_err(failed)?;
    let fee = fee_rate.saturating_mul(draft.len() as u64).max(1);
    let raw = bincode::serialize(&sign(fee)).map_err(failed)?;
    Ok(format!("0x{}", hex::encode(raw)))
}

fn hex_hash(hash: &Hash) -> String {
    format!("0x{}", hex::encode(hash.0))
}

/// Get the public key hex from a keystore JSON without decrypting.
/// This does not decrypt the seed.
#[uniffi::export]
pub fn wallet_pubkey_hex(keystore_json: String) -> Result<String, LightFfiError> {
    let keystore = parse(keystore_json.as_bytes()).map_err(failed)?;
    Ok(keystore.public_key.clone())
}

/// Reveal the 24-word seed phrase for backup.
///
/// **Note:** Runs off the UI thread (decrypts the keystore; Argon2id is expensive).
/// A wrong passphrase is an error, never a panic.
#[uniffi::export]
pub fn reveal_mnemonic_raw(
    keystore_json: String,
    passphrase: String,
) -> Result<String, LightFfiError> {
    let passphrase = SecretString::new(passphrase);
    reveal_mnemonic(&keystore_json, passphrase.as_str()).map_err(failed)
}

/// Re-encrypt the wallet under `new_passphrase`; returns the new keystore JSON.
///
/// The seed is preserved, so the address does not change. On success the caller
/// replaces its stored `keystore` value with the returned JSON.
///
/// **Note:** Runs off the UI thread (decrypts and re-encrypts; Argon2id runs twice).
/// A wrong `passphrase` is an error, never a panic.
#[uniffi::export]
pub fn change_passphrase_raw(
    keystore_json: String,
    passphrase: String,
    new_passphrase: String,
) -> Result<String, LightFfiError> {
    let passphrase = SecretString::new(passphrase);
    let new_passphrase = SecretString::new(new_passphrase);
    if new_passphrase.as_str().is_empty() {
        return Err(failed("passphrase is empty"));
    }
    change_passphrase(&keystore_json, passphrase.as_str(), new_passphrase.as_str()).map_err(failed)
}

/// Derive the address a `Deploy` transaction will create on-chain, off-node.
///
/// `sender_hex` is the `kvnc…dag` address, or a legacy hex form where
/// `chain_id` allows it (devnet 3, chain 4, local 1337). `nonce` is the
/// sender's account nonce **as it stands while the `Deploy` tx is being
/// signed** (i.e. the `tx.nonce`); the `+1` the node bakes into the address is
/// applied inside. Returns the bare 64-hex contract address.
///
/// **Note:** Pure BLAKE3 — safe to call on the UI thread.
#[uniffi::export]
pub fn contract_address_for_raw(
    sender_hex: String,
    nonce: u64,
    chain_id: u64,
) -> Result<String, LightFfiError> {
    contract_address_for(&sender_hex, nonce, chain_id).map_err(failed)
}

/// Derive comms identity hex from public key hex.
#[uniffi::export]
pub fn derive_comms_id(pubkey_hex: String) -> Result<String, LightFfiError> {
    let trimmed = pubkey_hex.trim();
    let stripped = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let bytes = hex::decode(stripped).map_err(failed)?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| failed("public key must be 32 bytes"))?;
    Ok(kovanica_comms_core::comms_id(&key).to_hex())
}

/// Sign a detached message with domain separation.
///
/// **Note:** Runs off UI thread (decrypts the keystore; Argon2id may be expensive).
#[uniffi::export]
pub fn sign_detached(
    keystore_json: String,
    passphrase: String,
    message_hex: String,
    domain: Option<String>,
) -> Result<String, LightFfiError> {
    let passphrase = SecretString::new(passphrase);
    let (sk, _) = open_signing_key(&keystore_json, passphrase.as_str())?;
    let msg_trim = message_hex.trim();
    let msg_stripped = msg_trim.strip_prefix("0x").unwrap_or(msg_trim);
    let msg_raw = hex::decode(msg_stripped).map_err(failed)?;
    let d = match domain.as_deref() {
        Some(dom) => dom.to_string(),
        None => core::str::from_utf8(COMMS_MSG_DOMAIN)
            .map_err(|_| failed("invalid domain"))?
            .to_string(),
    };
    let mut to_sign = Vec::with_capacity(d.len() + msg_raw.len());
    to_sign.extend_from_slice(d.as_bytes());
    to_sign.extend_from_slice(&msg_raw);
    let sig = kovanica_crypto::sign(&sk, &to_sign);
    Ok(hex::encode(sig.0))
}

/// Decode a 32-byte Ed25519 public key from hex (`0x` prefix optional).
fn parse_comms_pubkey(value: &str, field: &str) -> Result<[u8; 32], LightFfiError> {
    let trimmed = value.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let bytes = hex::decode(stripped).map_err(|_| failed(format!("{field} is not valid hex")))?;
    bytes
        .try_into()
        .map_err(|_| failed(format!("{field} must be 32 bytes")))
}

/// Seal and sign a comms envelope for a recipient.
///
/// Decrypts the keystore to recover the sender seed, derives the comms ids, and
/// calls [`kovanica_comms_relay::envelope::seal_and_sign`]. Returns the compact
/// envelope JSON (wire shape `v,id,to,from,sentAt,expiresAt,alg,epk,nonce,ct,sig`).
///
/// **Note:** Runs off UI thread (decrypts the keystore; Argon2id may be expensive).
#[uniffi::export]
pub fn comms_seal_envelope(
    keystore_json: String,
    passphrase: String,
    recipient_pubkey_hex: String,
    payload_json: String,
    sent_at_ms: u64,
    expires_at_ms: u64,
) -> Result<String, LightFfiError> {
    let passphrase = SecretString::new(passphrase);
    let (signing_key, _) = open_signing_key(&keystore_json, passphrase.as_str())?;
    let recipient = parse_comms_pubkey(&recipient_pubkey_hex, "recipient public key")?;
    if payload_json.len() > MAX_PLAINTEXT {
        return Err(failed("payload exceeds MAX_PLAINTEXT (16384)"));
    }
    let mut seed = signing_key.to_bytes();
    let sealed = kovanica_comms_relay::envelope::seal_and_sign(
        &seed,
        &recipient,
        payload_json.as_bytes(),
        sent_at_ms,
        expires_at_ms,
    );
    seed.zeroize();
    let envelope = sealed.map_err(failed)?;
    envelope.to_json().map_err(failed)
}

/// Open a comms envelope addressed to this keystore's comms id.
///
/// The envelope signature is **not** checked here (see [`comms_verify_envelope`]);
/// only the recipient match and the AEAD are enforced. Returns the trimmed
/// payload JSON exactly as sealed.
///
/// **Note:** Runs off UI thread (decrypts the keystore; Argon2id may be expensive).
#[uniffi::export]
pub fn comms_open_envelope(
    keystore_json: String,
    passphrase: String,
    envelope_json: String,
) -> Result<String, LightFfiError> {
    let passphrase = SecretString::new(passphrase);
    let (signing_key, _) = open_signing_key(&keystore_json, passphrase.as_str())?;
    let envelope = Envelope::from_json(envelope_json.as_bytes()).map_err(failed)?;

    let my_pub = signing_key.verifying_key().to_bytes();
    let my_id = comms_id_hex(&comms_id_bytes(&my_pub));
    let to_id = comms_id_from_hex(&envelope.to).map_err(failed)?;
    if to_id != comms_id_from_hex(&my_id).map_err(failed)? {
        return Err(failed(
            "envelope is not addressed to this keystore's comms id",
        ));
    }
    let from_id = comms_id_from_hex(&envelope.from).map_err(failed)?;

    let sealed = Sealed {
        alg: envelope.alg.clone(),
        epk: envelope
            .epk
            .clone()
            .try_into()
            .map_err(|_| failed("envelope epk must be 32 bytes"))?,
        nonce: envelope
            .nonce
            .clone()
            .try_into()
            .map_err(|_| failed("envelope nonce must be 24 bytes"))?,
        ct: envelope.ct.clone(),
    };

    let mut seed = signing_key.to_bytes();
    let mut cipher = X25519Cipher::from_seed(&seed);
    seed.zeroize();
    let aad = e2e_aad(&to_id, &from_id);
    let plain = cipher.open(&sealed, &aad).map_err(failed)?;

    // Validate the padded payload is compact JSON (shared helper), then return
    // the exact on-wire text so object key order is preserved.
    kovanica_comms_relay::trim_payload(&plain).map_err(failed)?;
    let end = plain
        .iter()
        .rposition(|b| *b != 0)
        .map(|i| i + 1)
        .ok_or_else(|| failed("envelope payload is empty"))?;
    let text = core::str::from_utf8(&plain[..end]).map_err(failed)?;
    Ok(text.to_string())
}

/// Verify an envelope against a claimed sender Ed25519 public key.
///
/// Checks the Ed25519 signature over [`Envelope::signing_bytes`] **and** that
/// `from == comms_id(sender_pubkey)`. Returns `false` for any verification or
/// shape failure; only malformed JSON or hex is an error.
#[uniffi::export]
pub fn comms_verify_envelope(
    envelope_json: String,
    sender_pubkey_hex: String,
) -> Result<bool, LightFfiError> {
    let envelope = Envelope::from_json(envelope_json.as_bytes()).map_err(failed)?;
    let sender = parse_comms_pubkey(&sender_pubkey_hex, "sender public key")?;
    Ok(envelope.verify(&sender).is_ok())
}

/// Normalise (ASCII lowercase) then validate a registry name.
///
/// Mirrors `kovanica_name_registry::normalise_name` (spec §7.2): 3..=32 bytes,
/// charset `[a-z0-9-]`, no leading/trailing `-`, no `--`. Returns the stored
/// (lowercase) form.
fn normalise_registry_name(name: &str) -> Result<String, LightFfiError> {
    let lowered: String = name.chars().map(|c| c.to_ascii_lowercase()).collect();
    let bytes = lowered.as_bytes();
    if bytes.len() < 3 || bytes.len() > 32 {
        return Err(failed("name must be 3..=32 bytes"));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return Err(failed("name may contain only [a-z0-9-]"));
    }
    if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
        return Err(failed("name must not start or end with '-'"));
    }
    if bytes.windows(2).any(|w| w == b"--") {
        return Err(failed("name must not contain '--'"));
    }
    Ok(lowered)
}

/// Compute the contract-storage slot for a name-registry entry.
///
/// `slot = BLAKE3(b"kvnc/v1/name/" ++ lowercase(name))`, returned as 64
/// lowercase hex (**no** `0x` prefix). The prefix is taken from
/// [`kovanica_name_registry::entry_key`] (single source of truth) and hashed with
/// the canonical [`kovanica_common::hash`], exactly matching the host storage key
/// the contract writes (`blake3(raw_key)`).
///
/// Names are normalised-then-validated: 3..=32 bytes, only `[a-z0-9-]`, no
/// leading/trailing `-`, no `--`. Invalid input is a [`LightFfiError`].
#[uniffi::export]
pub fn registry_slot_hex(name: String) -> Result<String, LightFfiError> {
    let name = normalise_registry_name(&name)?;
    let slot = kovanica_common::hash(&kovanica_name_registry::entry_key(&name));
    Ok(hex::encode(slot))
}

/// Decode a bincode 1.3 `NameEntry` read from a registry storage slot.
///
/// Accepts `"0x"+hex` or bare hex (case-insensitive). The value is
/// `owner[32] ‖ pubkey[32] ‖ u64le(count) ‖ count×(u64le(len) ‖ utf8)`.
/// Returns compact JSON
/// `{"owner":"<64hex>","pubkey":"<64hex>","relay_endpoints":["…"]}`.
///
/// Truncated or malformed bytes are a [`LightFfiError`]. Callers must check for
/// an empty slot (`""` / `"0x"`) **before** calling this — those are not
/// special-cased here and decode to an error.
#[uniffi::export]
pub fn registry_decode_entry(value_hex: String) -> Result<String, LightFfiError> {
    let trimmed = value_hex.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let bytes = hex::decode(stripped).map_err(|_| failed("entry value is not valid hex"))?;
    let entry: kovanica_name_registry::NameEntry = bincode::deserialize(&bytes).map_err(failed)?;
    // Key order `owner, pubkey, relay_endpoints` — compact JSON, no whitespace.
    let out = serde_json::json!({
        "owner": hex::encode(entry.owner),
        "pubkey": hex::encode(entry.pubkey),
        "relay_endpoints": entry.relay_endpoints,
    });
    serde_json::to_string(&out).map_err(failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_crypto::sign;

    #[test]
    fn wipe_secret_clears_every_byte() {
        use zeroize::Zeroize;
        let mut bytes = *b"hunter2-phrase!!";
        bytes.zeroize();
        assert_eq!(bytes, [0u8; 16]);

        let mut secret = String::from("hunter2-phrase!!");
        wipe_secret(&mut secret);
        assert!(secret.is_empty());

        let held = SecretString::new(String::from("hunter2-phrase!!"));
        assert_eq!(held.as_str(), "hunter2-phrase!!");
        drop(held);
    }

    #[test]
    fn contract_address_for_raw_takes_a_chain_id() {
        use kovanica_light::contract_address_for;
        use kovanica_types::signing::chain_id;
        use kovanica_types::Address;
        let sender = Address([0x11; 32]);
        let on_chain4 =
            contract_address_for_raw(sender.to_hex(), 41, chain_id::TESTNET_V2).unwrap();
        assert_eq!(
            on_chain4,
            contract_address_for(&sender.encode(), 41, chain_id::MAINNET).unwrap()
        );
        assert!(contract_address_for_raw(sender.to_hex(), 41, chain_id::MAINNET).is_err());
        assert!(contract_address_for_raw(
            format!("0X{}", sender.to_hex()),
            41,
            chain_id::TESTNET_V2
        )
        .is_err());
    }

    use kovanica_types::{
        committee_seal_hash, leader_header, CommittedSubDag, PublicKey, Signature, StatementBlock,
    };

    fn keys(n: u16) -> (Vec<SigningKey>, String) {
        let mut signers = Vec::new();
        let mut members = Vec::new();
        for index in 0..n {
            let signer = SigningKey::from_bytes(&[index as u8 + 1; 32]);
            let public_key = PublicKey::from(signer.verifying_key());
            let address = Address::from_public_key(&public_key);
            members.push(serde_json::json!({
                "index": index,
                "address": address.to_string(),
                "stake": "0x1",
                "publicKey": format!("0x{}", hex::encode(public_key.0)),
            }));
            signers.push(signer);
        }
        (signers, serde_json::Value::Array(members).to_string())
    }

    fn header_json(
        height: u64,
        parent: Hash,
        state: Hash,
        committee_json: &str,
    ) -> (String, kovanica_types::LeaderHeader) {
        let value: serde_json::Value = serde_json::from_str(committee_json).unwrap();
        let committee = json::committee_from_json(0, &value).unwrap();
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
        let header = leader_header(
            &subdag,
            height,
            parent,
            state,
            committee.epoch,
            committee_seal_hash(committee.epoch, &members),
            false,
        );
        let json = serde_json::json!({
            "committedHeight": format!("0x{height:x}"),
            "leaderRound": format!("0x{:x}", header.leader_round),
            "leaderDigest": hex_hash(&header.leader_digest),
            "leaderAuthor": header.leader_author,
            "parentLeaderDigest": hex_hash(&header.parent_leader_digest),
            "txMerkleRoot": hex_hash(&header.tx_merkle_root),
            "executedTxRoot": hex_hash(&header.executed_tx_root),
            "nonBlueRoot": hex_hash(&header.non_blue_root),
            "blueRoot": hex_hash(&header.blue_root),
            "mysticghost": header.mysticghost,
            "stateRoot": hex_hash(&header.state_root),
            "epoch": format!("0x{:x}", header.epoch),
            "committeeHash": hex_hash(&header.committee_hash),
            "timestamp": "0x0",
        });
        (json.to_string(), header)
    }

    fn seals_json(signers: &[SigningKey], header: &kovanica_types::LeaderHeader, n: u16) -> String {
        let seals: Vec<_> = (0..n)
            .map(|index| {
                let signature = sign(
                    &signers[index as usize],
                    &header.seal_message(LOCAL_CHAIN_ID),
                );
                serde_json::json!({
                    "authorityIndex": index,
                    "signature": format!("0x{}", hex::encode(signature.0)),
                })
            })
            .collect();
        serde_json::json!({ "seals": seals }).to_string()
    }

    #[test]
    fn three_seals_verify_and_the_faucet_follows_chain_id() {
        assert!(faucet_allowed(LOCAL_CHAIN_ID));
        assert!(faucet_allowed(TESTNET_CHAIN_ID));
        assert!(!faucet_allowed(chain_id::MAINNET));
        let (signers, committee) = keys(4);
        let (header_json, header) = header_json(0, Hash::zero(), Hash::new([4u8]), &committee);
        let seals = seals_json(&signers, &header, 3);
        let verified = verify_header(
            LOCAL_CHAIN_ID,
            0,
            committee,
            header_json,
            seals,
            String::new(),
        )
        .unwrap();
        assert_eq!(verified.committed_height, 0);
        assert_eq!(verified.epoch, 0);
    }

    #[test]
    fn a_short_seal_set_is_rejected() {
        let (signers, committee) = keys(4);
        let (header_json, header) = header_json(1, Hash::zero(), Hash::zero(), &committee);
        let seals = seals_json(&signers, &header, 2);
        assert!(verify_header(
            LOCAL_CHAIN_ID,
            0,
            committee,
            header_json,
            seals,
            String::new()
        )
        .is_err());
    }

    #[test]
    fn wallet_pubkey_hex_roundtrip() {
        let created = create_wallet("test-pass".to_string()).unwrap();
        let pubkey = wallet_pubkey_hex(created.keystore_json.clone()).unwrap();
        let clean = pubkey.trim().strip_prefix("0x").unwrap_or(&pubkey);
        assert_eq!(clean.len(), 64);
        assert!(hex::decode(clean).is_ok());
    }

    #[test]
    fn derive_comms_id_zeros() {
        // KAT from comms-core/TS: pubkey all ones (0x01)
        let ones = "01".repeat(32);
        let comms = derive_comms_id(ones.clone()).unwrap();
        assert_eq!(
            comms,
            "6076cc6f05dbd8ad851ba6aa6b7e85c8dce112186e16d3e267663641d9fa9339"
        );
    }

    #[test]
    fn sign_detached_produces_128_hex_sig() {
        let created = create_wallet("pw".to_string()).unwrap();
        let msg = hex::encode(b"hello");
        let sig = sign_detached(created.keystore_json, "pw".to_string(), msg, None).unwrap();
        assert_eq!(sig.len(), 128);
        assert!(hex::decode(&sig).is_ok());
    }

    #[test]
    fn sign_detached_error_cases() {
        let created = create_wallet("pw".to_string()).unwrap();
        let bad = sign_detached(
            created.keystore_json.clone(),
            "pw".to_string(),
            "gg".to_string(),
            None,
        );
        assert!(bad.is_err());
        let bad2 = sign_detached(
            created.keystore_json,
            "wrong".to_string(),
            hex::encode(b"hi"),
            None,
        );
        assert!(bad2.is_err());
    }

    /// §1 KAT: seal → open returns the exact original payload JSON.
    #[test]
    fn comms_seal_open_round_trip() {
        let sender = create_wallet("sender-pw".to_string()).unwrap();
        let recipient = create_wallet("recipient-pw".to_string()).unwrap();
        let recipient_pub = wallet_pubkey_hex(recipient.keystore_json.clone()).unwrap();
        let payload = r#"{"kind":"text","body":"hello kovanica","ts":1730000000000}"#;

        let envelope_json = comms_seal_envelope(
            sender.keystore_json,
            "sender-pw".to_string(),
            recipient_pub,
            payload.to_string(),
            1730000000000,
            1730000000000 + 24 * 60 * 60 * 1000,
        )
        .unwrap();

        // Envelope is the M1 wire shape and leaks no plaintext.
        assert!(envelope_json.contains("\"v\":1"));
        assert!(!envelope_json.contains("hello kovanica"));

        let opened = comms_open_envelope(
            recipient.keystore_json,
            "recipient-pw".to_string(),
            envelope_json,
        )
        .unwrap();
        assert_eq!(opened, payload);
    }

    #[test]
    fn comms_open_rejects_wrong_recipient() {
        let sender = create_wallet("s".to_string()).unwrap();
        let recipient = create_wallet("r".to_string()).unwrap();
        let other = create_wallet("o".to_string()).unwrap();
        let recipient_pub = wallet_pubkey_hex(recipient.keystore_json).unwrap();
        let env = comms_seal_envelope(
            sender.keystore_json,
            "s".to_string(),
            recipient_pub,
            r#"{"kind":"text","body":"hi","ts":1}"#.to_string(),
            1,
            2,
        )
        .unwrap();
        assert!(comms_open_envelope(other.keystore_json, "o".to_string(), env).is_err());
    }

    /// §1: `comms_verify_envelope` is true for the correct sender pubkey only.
    #[test]
    fn comms_verify_envelope_matches_sender() {
        let sender = create_wallet("s".to_string()).unwrap();
        let recipient = create_wallet("r".to_string()).unwrap();
        let other = create_wallet("o".to_string()).unwrap();
        let recipient_pub = wallet_pubkey_hex(recipient.keystore_json).unwrap();
        let env = comms_seal_envelope(
            sender.keystore_json.clone(),
            "s".to_string(),
            recipient_pub,
            r#"{"kind":"text","body":"hi","ts":1}"#.to_string(),
            1,
            2,
        )
        .unwrap();

        let sender_pub = wallet_pubkey_hex(sender.keystore_json).unwrap();
        assert!(comms_verify_envelope(env.clone(), sender_pub).unwrap());

        let other_pub = wallet_pubkey_hex(other.keystore_json).unwrap();
        assert!(!comms_verify_envelope(env.clone(), other_pub).unwrap());

        // Malformed JSON is an error, not `false`.
        let zeros = "00".repeat(32);
        assert!(comms_verify_envelope("not json".to_string(), zeros).is_err());
    }

    /// §7.2 KAT: the slot is BLAKE3 of the contract's own raw storage key.
    /// Expected values computed independently (raw `blake3(b"kvnc/v1/name/…")`),
    /// matching the key `wasmi_e2e.rs` reads straight out of storage.
    #[test]
    fn registry_slot_hex_matches_contract_storage_key() {
        assert_eq!(
            registry_slot_hex("alice".to_string()).unwrap(),
            "9a86b101401f2c4477d327e0ef510222296e27cb5f65da1f7a68cdf0d85db65c"
        );
        assert_eq!(
            registry_slot_hex("BOB".to_string()).unwrap(),
            "da4fd9d43a1014b06827bf80c50a1198c8be69579f1db836e99337847ab75f9c"
        );

        // Single source of truth: equals the contract key hashed with the
        // canonical `kovanica_common::hash`, for any valid name.
        for name in [
            "alice",
            "bob",
            "abc",
            "a-b-c",
            "abcdefghijklmnopqrstuvwxyz012345",
        ] {
            let expected = hex::encode(kovanica_common::hash(&kovanica_name_registry::entry_key(
                name,
            )));
            assert_eq!(registry_slot_hex(name.to_string()).unwrap(), expected);
        }

        // Output is 64 lowercase hex with no `0x`.
        let slot = registry_slot_hex("alice".to_string()).unwrap();
        assert_eq!(slot.len(), 64);
        assert!(!slot.starts_with("0x"));
        assert!(slot
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn registry_slot_hex_rejects_invalid_names() {
        let bad = [
            "ab",                                // too short
            "abcdefghijklmnopqrstuvwxyz0123456", // 33 bytes → too long
            "-alice",                            // leading hyphen
            "alice-",                            // trailing hyphen
            "al--ice",                           // consecutive hyphens
            "al ice",                            // space
            "ali.ce",                            // dot
            "ali_ce",                            // underscore
            "alïce",                             // non-ASCII
            "",                                  // empty
        ];
        for name in bad {
            assert!(
                registry_slot_hex(name.to_string()).is_err(),
                "name {name:?} should be rejected"
            );
        }

        // Mixed case normalises; boundary lengths are valid.
        assert_eq!(
            registry_slot_hex("Alice".to_string()).unwrap(),
            registry_slot_hex("alice".to_string()).unwrap()
        );
        assert!(registry_slot_hex("abc".to_string()).is_ok());
        assert!(registry_slot_hex("abcdefghijklmnopqrstuvwxyz012345".to_string()).is_ok());
    }

    /// §7.2 decode round-trip from raw `bincode::serialize(NameEntry)` bytes.
    #[test]
    fn registry_decode_entry_round_trip() {
        let entry = kovanica_name_registry::NameEntry {
            owner: [0x11; 32],
            pubkey: [0xAB; 32],
            relay_endpoints: vec![
                "https://relay.example.com".to_string(),
                "http://relay2.example.com".to_string(),
            ],
        };
        let raw = bincode::serialize(&entry).unwrap();
        let hexed = hex::encode(&raw);

        // Bare hex and `0x`-prefixed (mixed case) decode identically.
        let json = registry_decode_entry(hexed.clone()).unwrap();
        assert_eq!(json, registry_decode_entry(format!("0x{hexed}")).unwrap());
        assert_eq!(
            json,
            registry_decode_entry(format!("0X{}", hexed.to_uppercase())).unwrap()
        );

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["owner"], "11".repeat(32));
        assert_eq!(parsed["pubkey"], "ab".repeat(32));
        assert_eq!(
            parsed["relay_endpoints"],
            serde_json::json!(["https://relay.example.com", "http://relay2.example.com"])
        );
    }

    #[test]
    fn registry_decode_entry_rejects_malformed() {
        let entry = kovanica_name_registry::NameEntry {
            owner: [0x11; 32],
            pubkey: [0xAB; 32],
            relay_endpoints: vec!["https://relay.example.com".to_string()],
        };
        let raw = bincode::serialize(&entry).unwrap();

        // Truncated bytes.
        assert!(registry_decode_entry(hex::encode(&raw[..raw.len() - 1])).is_err());
        // Non-hex.
        assert!(registry_decode_entry("zzzz".to_string()).is_err());
        // Empty slot / `0x` are not special-cased here → error.
        assert!(registry_decode_entry(String::new()).is_err());
        assert!(registry_decode_entry("0x".to_string()).is_err());
        // Structurally wrong (offset/len) — count claims an entry that isn't there.
        let corrupt = bincode::serialize(&kovanica_name_registry::NameEntry {
            owner: [0; 32],
            pubkey: [0; 32],
            relay_endpoints: vec!["https://x.example.com".to_string()],
        })
        .unwrap();
        let mut truncated_after_count = corrupt[..64 + 8].to_vec();
        truncated_after_count[64..72].copy_from_slice(&5u64.to_le_bytes()); // claim 5 endpoints
        assert!(registry_decode_entry(hex::encode(&truncated_after_count)).is_err());
    }

    /// `sign_call_raw` / `sign_deploy_raw` emit a bincode `Transaction` that
    /// verifies under the configured chain id and carries the expected kind.
    #[test]
    fn sign_call_raw_and_sign_deploy_raw_round_trip() {
        let created = create_wallet("pw".to_string()).unwrap();
        let contract = Address([0x33; 32]).to_string();

        let raw = sign_call_raw(
            created.keystore_json.clone(),
            "pw".to_string(),
            LOCAL_CHAIN_ID,
            contract,
            500,
            "transfer".to_string(),
            "0x010203".to_string(),
            100_000,
            6,
            10,
        )
        .unwrap();
        assert!(raw.starts_with("0x"));
        let bytes = hex::decode(raw.strip_prefix("0x").unwrap()).unwrap();
        let tx: Transaction = bincode::deserialize(&bytes).unwrap();
        assert!(tx.verify_signature(&kovanica_types::SigningContext::new(LOCAL_CHAIN_ID)));
        assert!(!tx.verify_signature(&kovanica_types::SigningContext::new(2)));
        assert!(matches!(
            tx.kind,
            kovanica_types::TransactionKind::Call {
                value: 500,
                ref method,
                ref args,
                gas_limit: 100_000,
                ..
            } if method == "transfer" && args == &[1u8, 2, 3]
        ));

        // Bare hex (no `0x`) is accepted for the deploy bytecode.
        let raw_deploy = sign_deploy_raw(
            created.keystore_json,
            "pw".to_string(),
            LOCAL_CHAIN_ID,
            "00ff".to_string(),
            7,
            10,
        )
        .unwrap();
        let bytes = hex::decode(raw_deploy.strip_prefix("0x").unwrap()).unwrap();
        let deploy: Transaction = bincode::deserialize(&bytes).unwrap();
        assert!(deploy.verify_signature(&kovanica_types::SigningContext::new(LOCAL_CHAIN_ID)));
        assert!(matches!(
            deploy.kind,
            kovanica_types::TransactionKind::Deploy { ref code } if code == &[0x00, 0xff]
        ));

        // Malformed hex is an error, not a panic.
        assert!(sign_call_raw(
            created_wallet_json(),
            "pw".to_string(),
            LOCAL_CHAIN_ID,
            Address([0x33; 32]).to_string(),
            0,
            "m".to_string(),
            "zz".to_string(),
            1,
            0,
            1,
        )
        .is_err());
    }

    /// `sign_transfer_raw` and `sign_call_raw` pass `chain_id` into `parse_address`.
    /// Legacy hex is accepted only on chains 3, 4, and 1337.
    #[test]
    fn transfer_and_call_addresses_follow_the_chain_policy() {
        let key = Address([0x33; 32]);
        let canonical = key.to_string();
        let legacy = key.encode_legacy_hex();
        let bare = key.to_hex();
        let prefixed = format!("0x{bare}");
        let forms = [legacy.as_str(), bare.as_str(), prefixed.as_str()];
        let allowed = [chain_id::DEVNET, chain_id::TESTNET_V2, chain_id::LOCAL];
        let refused = [chain_id::MAINNET, chain_id::TESTNET, 0, 42];

        for chain in allowed {
            for form in forms {
                assert_eq!(
                    parse_address(form, chain).unwrap(),
                    key,
                    "{form} on {chain}"
                );
            }
            assert_eq!(parse_address(&canonical, chain).unwrap(), key);
        }
        for chain in refused {
            for form in forms {
                assert!(
                    parse_address(form, chain).is_err(),
                    "{form} must be refused on {chain}"
                );
            }
            assert_eq!(parse_address(&canonical, chain).unwrap(), key);
        }

        let created = create_wallet("pw".to_string()).unwrap();
        let transfer = sign_transfer_raw(
            created.keystore_json.clone(),
            "pw".to_string(),
            chain_id::TESTNET_V2,
            legacy.clone(),
            1,
            0,
            1,
        )
        .unwrap();
        let tx = decode_signed(&transfer);
        assert!(matches!(
            tx.kind,
            kovanica_types::TransactionKind::Transfer { to, amount: 1 } if to == key
        ));

        let call = sign_call_raw(
            created.keystore_json.clone(),
            "pw".to_string(),
            chain_id::LOCAL,
            prefixed.clone(),
            0,
            "m".to_string(),
            "01".to_string(),
            1,
            0,
            1,
        )
        .unwrap();
        let tx = decode_signed(&call);
        assert!(matches!(
            tx.kind,
            kovanica_types::TransactionKind::Call { contract, .. } if contract == key
        ));

        let mainnet = sign_transfer_raw(
            created.keystore_json.clone(),
            "pw".to_string(),
            chain_id::MAINNET,
            canonical,
            1,
            0,
            1,
        )
        .unwrap();
        let tx = decode_signed(&mainnet);
        assert!(matches!(
            tx.kind,
            kovanica_types::TransactionKind::Transfer { to, .. } if to == key
        ));
        assert!(sign_transfer_raw(
            created.keystore_json.clone(),
            "pw".to_string(),
            chain_id::MAINNET,
            bare.clone(),
            1,
            0,
            1,
        )
        .is_err());
        assert!(sign_call_raw(
            created.keystore_json,
            "pw".to_string(),
            chain_id::TESTNET,
            legacy.clone(),
            0,
            "m".to_string(),
            "01".to_string(),
            1,
            0,
            1,
        )
        .is_err());
    }

    fn decode_signed(raw: &str) -> Transaction {
        let bytes = hex::decode(raw.strip_prefix("0x").unwrap()).unwrap();
        bincode::deserialize(&bytes).unwrap()
    }

    fn created_wallet_json() -> String {
        create_wallet("pw".to_string()).unwrap().keystore_json
    }

    #[test]
    fn reveal_mnemonic_round_trips_and_rejects_wrong_passphrase() {
        let created = create_wallet("backup-pw".to_string()).unwrap();
        let revealed =
            reveal_mnemonic_raw(created.keystore_json.clone(), "backup-pw".to_string()).unwrap();
        assert_eq!(revealed, created.mnemonic);
        assert_eq!(revealed.split_whitespace().count(), 24);

        // A wrong passphrase is an error, never a panic.
        assert!(reveal_mnemonic_raw(created.keystore_json, "wrong-pw".to_string()).is_err());
    }

    #[test]
    fn change_passphrase_switches_the_passphrase() {
        let created = create_wallet("old-pw".to_string()).unwrap();

        let updated = change_passphrase_raw(
            created.keystore_json.clone(),
            "old-pw".to_string(),
            "new-pw".to_string(),
        )
        .unwrap();

        // New passphrase unlocks the same seed; the old one no longer does.
        assert_eq!(
            reveal_mnemonic_raw(updated.clone(), "new-pw".to_string()).unwrap(),
            created.mnemonic
        );
        assert!(reveal_mnemonic_raw(updated.clone(), "old-pw".to_string()).is_err());

        // Same seed, so the address is unchanged.
        assert_eq!(
            wallet_address(updated).unwrap(),
            wallet_address(created.keystore_json.clone()).unwrap()
        );

        // A wrong old passphrase fails and changes nothing.
        assert!(change_passphrase_raw(
            created.keystore_json,
            "wrong-old".to_string(),
            "another".to_string(),
        )
        .is_err());

        // An empty new passphrase is rejected.
        assert!(
            change_passphrase_raw(created_wallet_json(), "pw".to_string(), String::new()).is_err()
        );
    }
}
