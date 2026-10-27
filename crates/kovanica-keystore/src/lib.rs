#![deny(unsafe_code)]

//! Wallet / keystore operations.
//!
//! Version 2 stores use Argon2id (RFC 9106 constrained-memory profile) and
//! XChaCha20-Poly1305. Version 1 remains readable for explicit migration only.

use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use bip39::{Language, Mnemonic};
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use zeroize::Zeroizing;

use kovanica_types::{Address, Hash, PublicKey, SigningKey};

mod perms;

pub use perms::{ensure_owner_only, tighten_private_file};

pub const KEYSTORE_VERSION: u32 = 2;
const KDF_MEMORY_KIB: u32 = 64 * 1024;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u32 = 4;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const CIPHERTEXT_LEN: usize = 32 + 16;

/// On-disk keystore. It deliberately has no `Debug`/`Clone` implementation.
#[derive(Serialize)]
pub struct Keystore {
    pub version: u32,
    pub address: String,
    pub public_key: String,
    pub encrypted: bool,
    /// Seed in v1; authenticated ciphertext in v2.
    pub secret_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_memory_kib: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_iterations: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_parallelism: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V1Keystore {
    version: u32,
    address: String,
    public_key: String,
    #[serde(deserialize_with = "deserialize_zeroizing_string")]
    secret_key: Zeroizing<String>,
    #[serde(default)]
    encrypted: bool,
}

impl V1Keystore {
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }
}

fn deserialize_zeroizing_string<'de, D>(
    deserializer: D,
) -> std::result::Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V2Keystore {
    version: u32,
    address: String,
    public_key: String,
    secret_key: String,
    encrypted: bool,
    cipher: String,
    kdf: String,
    kdf_memory_kib: u32,
    kdf_iterations: u32,
    kdf_parallelism: u32,
    salt: String,
    nonce: String,
}

#[derive(Deserialize)]
struct VersionProbe {
    version: u32,
}

/// Generate a fresh encrypted keypair. Seed material is never persisted in cleartext.
pub fn keygen(passphrase: &str) -> Result<Keystore> {
    let (signing_key, public_key) = kovanica_crypto::generate_keypair();
    let seed = Zeroizing::new(signing_key.to_bytes());
    encrypted_keystore(&seed, public_key, passphrase)
}

/// Create an encrypted store from an exact Ed25519 seed.
pub fn from_seed(seed: &[u8; 32], passphrase: &str) -> Result<Keystore> {
    let signing_key = SigningKey::from_bytes(seed);
    let public_key = PublicKey::from_bytes(signing_key.verifying_key().to_bytes());
    encrypted_keystore(seed, public_key, passphrase)
}

fn encrypted_keystore(
    seed: &[u8; 32],
    public_key: PublicKey,
    passphrase: &str,
) -> Result<Keystore> {
    let address = Address::from_public_key(&public_key);
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = derive_key(passphrase, &salt)?;
    let aad = associated_data(&address.0, public_key.as_bytes(), &salt, &nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).expect("32-byte AEAD key");
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: seed,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("could not encrypt keystore"))?;

    Ok(Keystore {
        version: KEYSTORE_VERSION,
        address: address.encode(),
        public_key: hex::encode(public_key.as_bytes()),
        encrypted: true,
        secret_key: hex::encode(ciphertext),
        cipher: Some("xchacha20poly1305".into()),
        kdf: Some("argon2id".into()),
        kdf_memory_kib: Some(KDF_MEMORY_KIB),
        kdf_iterations: Some(KDF_ITERATIONS),
        kdf_parallelism: Some(KDF_PARALLELISM),
        salt: Some(hex::encode(salt)),
        nonce: Some(hex::encode(nonce)),
    })
}

/// Persist without clobbering an existing destination.
pub fn save(path: &Path, keystore: &Keystore) -> Result<()> {
    save_atomic(path, keystore, false)
}

/// Persist after the caller has explicitly confirmed replacement.
pub fn save_replace(path: &Path, keystore: &Keystore) -> Result<()> {
    save_atomic(path, keystore, true)
}

/// Atomically replace a validated legacy source with an already-verified destination file.
pub fn replace_file(source: &Path, verified_destination: &Path) -> Result<()> {
    let source_meta = fs::symlink_metadata(source).context("checking migration source")?;
    if source_meta.file_type().is_symlink() || !source_meta.is_file() {
        bail!("refusing to replace a symlink or non-regular migration source");
    }
    let destination_meta =
        fs::symlink_metadata(verified_destination).context("checking verified migration output")?;
    if destination_meta.file_type().is_symlink() || !destination_meta.is_file() {
        bail!("refusing to use a symlink or non-regular migration output");
    }
    fs::rename(verified_destination, source).context("atomically replacing legacy keystore")?;
    Ok(())
}

fn save_atomic(path: &Path, keystore: &Keystore, replace: bool) -> Result<()> {
    use tempfile::Builder;

    if keystore.version != KEYSTORE_VERSION || !keystore.encrypted {
        bail!("only encrypted v2 keystores may be written");
    }

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    path.file_name()
        .ok_or_else(|| anyhow!("keystore path has no file name"))?;
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            bail!("refusing to write through a symlink destination");
        }
        if !replace {
            bail!("keystore destination already exists");
        }
        if !meta.is_file() {
            bail!("refusing to replace a non-regular keystore destination");
        }
    }
    let json = serde_json::to_vec_pretty(keystore)?;
    let mut temp = Builder::new()
        .prefix(".kovanica-keystore-")
        .tempfile_in(parent)
        .with_context(|| format!("creating temporary keystore in {}", parent.display()))?;
    // Unix: mode 0600 on the open descriptor. Windows: owner-only DACL on
    // the same handle. The restriction happens before the secret bytes are
    // written. A rename keeps both.
    tighten_private_file(temp.as_file())?;
    temp.write_all(&json)?;
    temp.as_file().sync_all()?;
    if replace {
        temp.persist(path)
            .map_err(|e| e.error)
            .context("atomically replacing keystore")?;
    } else {
        temp.persist_noclobber(path)
            .map_err(|e| e.error)
            .context("atomically writing keystore")?;
    }
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

const MAX_KEYSTORE_BYTES: u64 = 64 * 1024;

/// Parse a v2 keystore from JSON bytes without decrypting it.
///
/// Legacy v1 bytes are rejected. The input must be at most 64 KiB.
pub fn parse(raw: &[u8]) -> Result<Keystore> {
    if raw.len() as u64 > MAX_KEYSTORE_BYTES {
        bail!("keystore is too large (maximum 64 KiB)");
    }
    let version: VersionProbe = serde_json::from_slice(raw).context("parsing keystore version")?;
    let ks = match version.version {
        1 => bail!("legacy v1 keystore is migration-only"),
        2 => {
            let v: V2Keystore = serde_json::from_slice(raw).context("parsing v2 keystore")?;
            Keystore {
                version: v.version,
                address: v.address,
                public_key: v.public_key,
                encrypted: v.encrypted,
                secret_key: v.secret_key,
                cipher: Some(v.cipher),
                kdf: Some(v.kdf),
                kdf_memory_kib: Some(v.kdf_memory_kib),
                kdf_iterations: Some(v.kdf_iterations),
                kdf_parallelism: Some(v.kdf_parallelism),
                salt: Some(v.salt),
                nonce: Some(v.nonce),
            }
        }
        _ => bail!("unsupported keystore version"),
    };
    validate_metadata(&ks)?;
    Ok(ks)
}

/// JSON encoding of a v2 keystore. The seed stays encrypted.
pub fn to_json(keystore: &Keystore) -> Result<String> {
    serde_json::to_string(keystore).context("encoding keystore")
}

/// Load and parse a v2 keystore without decrypting it. Legacy v1 files are
/// deliberately unavailable to ordinary wallet operations.
pub fn load(path: &Path) -> Result<Keystore> {
    let raw = read_bounded(path)?;
    parse(&raw).map_err(|err| {
        if err.to_string().contains("legacy v1") {
            anyhow::anyhow!(
                "legacy v1 keystore is migration-only; run `kovanica migrate --keystore {}`",
                path.display()
            )
        } else {
            err.context(format!("reading keystore {}", path.display()))
        }
    })
}

/// Load a legacy keystore only for the explicit migration command.
pub fn load_v1_for_migration(path: &Path) -> Result<V1Keystore> {
    let raw = read_bounded(path)?;
    let old: V1Keystore =
        serde_json::from_slice(&raw).context("parsing v1 keystore for migration")?;
    if old.version != 1 {
        bail!("only v1 keystores need migration");
    }
    validate_v1_metadata(&old)?;
    Ok(old)
}

fn read_bounded(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let file =
        fs::File::open(path).with_context(|| format!("reading keystore {}", path.display()))?;
    let mut raw = Zeroizing::new(Vec::with_capacity(MAX_KEYSTORE_BYTES as usize + 1));
    file.take(MAX_KEYSTORE_BYTES + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 > MAX_KEYSTORE_BYTES {
        bail!("keystore file is too large (maximum 64 KiB)");
    }
    Ok(raw)
}

fn validate_v1_metadata(ks: &V1Keystore) -> Result<()> {
    let _ = parse_stored_address(&ks.address, "keystore address")?;
    let pk_bytes = hex::decode(&ks.public_key).context("keystore public_key is not valid hex")?;
    if pk_bytes.len() != 32 {
        bail!("expected a 32-byte public key");
    }
    if !ks.encrypted {
        let data = Zeroizing::new(decode_secret(&ks.secret_key)?);
        if data.len() != 32 {
            bail!("malformed v1 seed length");
        }
        verify_v1_identity(ks, &data)?;
    } else {
        let data = Zeroizing::new(decode_secret(&ks.secret_key)?);
        if data.len() != 32 {
            bail!("malformed legacy encrypted seed");
        }
    }
    Ok(())
}

/// Recover and identity-check a legacy seed for migration only.
pub fn migration_seed(
    keystore: &V1Keystore,
    passphrase: Option<&str>,
) -> Result<Zeroizing<[u8; 32]>> {
    validate_v1_metadata(keystore)?;
    let encoded = Zeroizing::new(decode_secret(&keystore.secret_key)?);
    let decoded = if keystore.encrypted {
        let pass =
            passphrase.ok_or_else(|| anyhow!("keystore is encrypted; enter its passphrase"))?;
        Zeroizing::new(xor_keystream(&encoded, pass))
    } else {
        encoded
    };
    if decoded.len() != 32 {
        bail!("malformed v1 seed length");
    }
    verify_v1_identity(keystore, &decoded)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&decoded);
    Ok(seed)
}

fn verify_v1_identity(keystore: &V1Keystore, seed: &[u8]) -> Result<()> {
    if seed.len() != 32 {
        bail!("expected a 32-byte secret seed");
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(seed);
    let signing_key = SigningKey::from_bytes(&bytes);
    bytes.zeroize();
    let expected_pk = signing_key.verifying_key().to_bytes();
    let stored_pk =
        hex::decode(&keystore.public_key).context("keystore public_key is not valid hex")?;
    let stored_addr = parse_stored_address(&keystore.address, "keystore address")?;
    if stored_pk.as_slice() != expected_pk
        || Address::from_public_key(&PublicKey::from_bytes(expected_pk)) != stored_addr
    {
        bail!("keystore identity does not match its seed");
    }
    Ok(())
}

fn validate_metadata(ks: &Keystore) -> Result<()> {
    let _ = address(ks)?;
    let _ = public_key(ks)?;
    match ks.version {
        2 => {
            if !ks.encrypted
                || ks.cipher.as_deref() != Some("xchacha20poly1305")
                || ks.kdf.as_deref() != Some("argon2id")
                || ks.kdf_memory_kib != Some(KDF_MEMORY_KIB)
                || ks.kdf_iterations != Some(KDF_ITERATIONS)
                || ks.kdf_parallelism != Some(KDF_PARALLELISM)
            {
                bail!("unsupported or unsafe v2 encryption parameters");
            }
            let salt = decode_hex_field(ks.salt.as_deref(), "salt", SALT_LEN)?;
            let nonce = decode_hex_field(ks.nonce.as_deref(), "nonce", NONCE_LEN)?;
            let parsed_address = address(ks)?;
            let parsed_public_key = public_key(ks)?;
            // Accept the canonical 64-character `kvnc…dag` encoding, the
            // legacy `kvnc<hex>dag` form, or a bare lowercase hex address, so
            // keystores written before PRO-21 (or before the canonical
            // format) stay usable. The file is not bound to a chain, so
            // [`parse_stored_address`] still accepts legacy hex. An address
            // typed for a chain goes through [`parse_address`], which refuses
            // legacy hex where `legacy_address_allowed` is false.
            if (ks.address != parsed_address.encode()
                && ks.address != parsed_address.encode_legacy_hex()
                && ks.address != parsed_address.to_hex())
                || ks.public_key != hex::encode(parsed_public_key.as_bytes())
            {
                bail!("v2 identity fields must use canonical `kvnc…dag` or lowercase hex");
            }
            let ciphertext = decode_secret(&ks.secret_key)?;
            if ciphertext.len() != CIPHERTEXT_LEN {
                bail!("malformed v2 ciphertext length");
            }
            let _ = (salt, nonce);
        }
        1 => bail!("legacy v1 keystores are migration-only; run `kovanica migrate`"),
        _ => bail!("unsupported keystore version"),
    }
    Ok(())
}

/// Recover a seed, requiring the derived identity to match the stored metadata.
pub fn secret_seed(keystore: &Keystore, passphrase: Option<&str>) -> Result<Zeroizing<[u8; 32]>> {
    if keystore.version != KEYSTORE_VERSION {
        bail!("legacy v1 keystores are migration-only; run `kovanica migrate`");
    }
    validate_metadata(keystore)?;
    let bytes = Zeroizing::new(decode_secret(&keystore.secret_key)?);
    let mut seed = Zeroizing::new([0u8; 32]);
    match keystore.version {
        2 => {
            let pass =
                passphrase.ok_or_else(|| anyhow!("keystore is encrypted; enter its passphrase"))?;
            let salt = decode_hex_field(keystore.salt.as_deref(), "salt", SALT_LEN)?;
            let nonce = decode_hex_field(keystore.nonce.as_deref(), "nonce", NONCE_LEN)?;
            let salt: [u8; SALT_LEN] = salt.try_into().map_err(|_| anyhow!("invalid salt"))?;
            let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| anyhow!("invalid nonce"))?;
            let key = derive_key(pass, &salt)?;
            let address = address(keystore)?;
            let public_key = public_key(keystore)?;
            let aad = associated_data(&address.0, public_key.as_bytes(), &salt, &nonce);
            let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).expect("32-byte AEAD key");
            let plaintext = Zeroizing::new(
                cipher
                    .decrypt(
                        XNonce::from_slice(&nonce),
                        chacha20poly1305::aead::Payload {
                            msg: &bytes[..],
                            aad: &aad,
                        },
                    )
                    .map_err(|_| anyhow!("keystore authentication failed"))?,
            );
            if plaintext.len() != 32 {
                bail!("invalid decrypted seed length");
            }
            seed.copy_from_slice(&plaintext);
        }
        _ => bail!("unsupported keystore version"),
    }
    verify_identity(keystore, &seed[..])?;
    Ok(seed)
}

pub fn signing_key(keystore: &Keystore, passphrase: Option<&str>) -> Result<SigningKey> {
    let seed = secret_seed(keystore, passphrase)?;
    Ok(SigningKey::from_bytes(&seed))
}

fn verify_identity(keystore: &Keystore, seed: &[u8]) -> Result<()> {
    if seed.len() != 32 {
        bail!("expected a 32-byte secret seed");
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(seed);
    let signing_key = SigningKey::from_bytes(&bytes);
    bytes.zeroize();
    let expected_pk = signing_key.verifying_key().to_bytes();
    let stored_pk = public_key(keystore)?;
    let stored_addr = address(keystore)?;
    if expected_pk != *stored_pk.as_bytes()
        || Address::from_public_key(&PublicKey::from_bytes(expected_pk)) != stored_addr
    {
        bail!("keystore identity does not match its seed");
    }
    Ok(())
}

pub fn public_key(keystore: &Keystore) -> Result<PublicKey> {
    let bytes =
        hex::decode(&keystore.public_key).context("keystore public_key is not valid hex")?;
    if bytes.len() != 32 {
        bail!("expected a 32-byte public key");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(PublicKey::from_bytes(arr))
}

pub fn address(keystore: &Keystore) -> Result<Address> {
    parse_stored_address(&keystore.address, "keystore address")
}

/// Parse the address label stored in a keystore file.
///
/// The file is not bound to a chain (migration). [`Address::from_str`] is
/// base32 only, so this calls [`Address::parse_for_chain`] on chain 4, which
/// accepts the canonical form and the legacy hex forms. That does not assign
/// the key to chain 4. An address typed for a chain goes through
/// [`parse_address`].
fn parse_stored_address(value: &str, what: &str) -> Result<Address> {
    Address::parse_for_chain(value, kovanica_types::signing::chain_id::TESTNET_V2)
        .map_err(|e| anyhow!("{what}: {e}"))
}

/// Parse an address string for `chain_id`.
///
/// The canonical 64-character form is accepted on every chain. Legacy hex is
/// accepted only where [`kovanica_types::address::legacy_address_allowed`] is
/// true (devnet 3, chain 4, local 1337), so chain 1 refuses it.
pub fn parse_address(value: &str, what: &str, chain_id: u64) -> Result<Address> {
    Address::parse_for_chain(value, chain_id).map_err(|e| anyhow!("{what}: {e}"))
}

pub fn seed_from_raw_hex(raw: &str) -> Result<Zeroizing<[u8; 32]>> {
    let raw = raw.trim();
    let bytes = Zeroizing::new(
        hex::decode(raw.strip_prefix("0x").unwrap_or(raw)).context("invalid seed hex")?,
    );
    if bytes.len() != 32 {
        bail!("raw seed must be exactly 32 bytes");
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

/// English BIP-39 phrase encodes the exact 256-bit Ed25519 seed entropy. No BIP-39 passphrase or HD derivation is used.
pub fn seed_from_mnemonic(phrase: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mnemonic =
        Mnemonic::parse_in(Language::English, phrase).context("invalid English BIP-39 mnemonic")?;
    if mnemonic.word_count() != 24 {
        bail!("key mnemonic must contain exactly 24 English words");
    }
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    if entropy.len() != 32 {
        bail!("key mnemonic must encode exactly 32 bytes");
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&entropy);
    Ok(seed)
}

pub fn seed_to_mnemonic(seed: &[u8; 32]) -> Result<String> {
    Ok(Mnemonic::from_entropy_in(Language::English, seed)
        .context("encoding BIP-39 mnemonic")?
        .to_string())
}

fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(KDF_MEMORY_KIB, KDF_ITERATIONS, KDF_PARALLELISM, Some(32))
        .context("invalid fixed Argon2id parameters")?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .context("deriving keystore key")?;
    Ok(key)
}

fn associated_data(
    address: &[u8; 32],
    public_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut aad = b"KVNC keystore\0v2\0argon2id\0m=65536,t=3,p=4\0xchacha20poly1305\0".to_vec();
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad.extend_from_slice(address);
    aad.extend_from_slice(public_key);
    aad
}

fn decode_secret(value: &str) -> Result<Vec<u8>> {
    hex::decode(value).context("keystore secret_key is not valid hex")
}
fn decode_hex_field(value: Option<&str>, name: &str, len: usize) -> Result<Vec<u8>> {
    let bytes = hex::decode(value.ok_or_else(|| anyhow!("missing keystore {name}"))?)
        .with_context(|| format!("invalid keystore {name}"))?;
    if bytes.len() != len {
        bail!("invalid keystore {name} length");
    }
    Ok(bytes)
}

/// The v1 XOR format is retained solely for explicit, identity-checked migration.
fn xor_keystream(data: &[u8], passphrase: &str) -> Vec<u8> {
    let key = Hash::new(passphrase.as_bytes());
    data.iter()
        .enumerate()
        .map(|(i, byte)| byte ^ key.0[i % key.0.len()])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_roundtrip_authenticates_password_and_metadata() {
        let seed = [7u8; 32];
        let ks = from_seed(&seed, "correct horse").unwrap();
        assert_eq!(ks.kdf_memory_kib, Some(64 * 1024));
        assert_eq!(ks.kdf_iterations, Some(3));
        assert_eq!(ks.kdf_parallelism, Some(4));
        assert_eq!(&*secret_seed(&ks, Some("correct horse")).unwrap(), &seed);
        assert!(secret_seed(&ks, Some("wrong")).is_err());
        let mut tampered = serde_json::to_value(&ks).unwrap();
        tampered["address"] = serde_json::Value::String("11".repeat(32));
        let loaded = from_value(tampered).unwrap();
        assert!(secret_seed(&loaded, Some("correct horse")).is_err());
        let mut tampered = serde_json::to_value(&ks).unwrap();
        tampered["secret_key"] = serde_json::Value::String("00".repeat(CIPHERTEXT_LEN));
        let loaded = from_value(tampered).unwrap();
        assert!(secret_seed(&loaded, Some("correct horse")).is_err());
        let mut tampered = serde_json::to_value(&ks).unwrap();
        tampered["public_key"] = serde_json::Value::String("22".repeat(32));
        let loaded = from_value(tampered).unwrap();
        assert!(secret_seed(&loaded, Some("correct horse")).is_err());
    }

    #[test]
    fn v2_keystore_uses_canonical_address_and_accepts_legacy_hex() {
        let ks = from_seed(&[5u8; 32], "pw").unwrap();
        assert!(ks.address.starts_with("kvnc"));
        assert!(ks.address.ends_with("dag"));
        let parsed = address(&ks).unwrap();
        assert_eq!(parsed.encode(), ks.address);

        // A keystore written before the canonical format stays loadable.
        let mut legacy = serde_json::to_value(&ks).unwrap();
        legacy["address"] = serde_json::Value::String(parsed.to_hex());
        let loaded = from_value(legacy).unwrap();
        assert_eq!(address(&loaded).unwrap(), parsed);

        // New keystores carry the 64-character base32 address (PRO-21); one
        // written with the pre-PRO-21 `kvnc<hex>dag` form stays loadable.
        assert_eq!(ks.address.len(), 64);
        let mut old = serde_json::to_value(&ks).unwrap();
        old["address"] = serde_json::Value::String(parsed.encode_legacy_hex());
        let loaded = from_value(old).unwrap();
        assert_eq!(address(&loaded).unwrap(), parsed);

        // `FromStr` does not open those labels. Only the file reader does.
        assert!(parsed.to_hex().parse::<Address>().is_err());
        assert!(parsed.encode_legacy_hex().parse::<Address>().is_err());
        assert_eq!(parsed.encode().parse::<Address>().unwrap(), parsed);
    }

    /// Chain 1 refuses a legacy hex string. Devnet, local, and chain 4 accept it.
    #[test]
    fn parse_address_follows_the_chain_policy() {
        use kovanica_types::signing::chain_id;

        let address = Address([0x2a; 32]);
        let forms = [
            address.to_hex(),
            format!("0x{}", address.to_hex()),
            address.encode_legacy_hex(),
        ];
        for form in &forms {
            let err = parse_address(form, "address", chain_id::MAINNET).unwrap_err();
            assert!(
                err.to_string().contains("not accepted"),
                "{form} on chain 1: {err}"
            );
            for chain in [chain_id::DEVNET, chain_id::LOCAL, chain_id::TESTNET_V2] {
                assert_eq!(
                    parse_address(form, "address", chain).unwrap(),
                    address,
                    "{form} on chain {chain}"
                );
            }
        }
        assert_eq!(
            parse_address(&address.encode(), "address", chain_id::MAINNET).unwrap(),
            address
        );
    }

    #[test]
    fn rejects_hostile_kdf_and_unsupported_versions() {
        let ks = from_seed(&[1; 32], "pw").unwrap();
        let mut value = serde_json::to_value(&ks).unwrap();
        value["kdf_memory_kib"] = 4_294_967_000u64.into();
        assert!(from_value(value).is_err());
        let mut value = serde_json::to_value(&ks).unwrap();
        value["secret_key"] = serde_json::Value::String("ff".repeat(12));
        assert!(from_value(value).is_err());
        let mut value = serde_json::to_value(&ks).unwrap();
        value["version"] = 99.into();
        assert!(from_value(value).is_err());
    }

    #[test]
    fn raw_and_mnemonic_preserve_exact_entropy() {
        let seed = [0x42; 32];
        let phrase = seed_to_mnemonic(&seed).unwrap();
        assert_eq!(seed_from_mnemonic(&phrase).unwrap().as_ref(), &seed);
        assert_eq!(
            seed_from_raw_hex(&hex::encode(seed)).unwrap().as_ref(),
            &seed
        );
        // Trailing whitespace/newline from a seed file must be tolerated.
        assert_eq!(
            seed_from_raw_hex(&format!("{}\n", hex::encode(seed)))
                .unwrap()
                .as_ref(),
            &seed
        );
        assert!(seed_from_mnemonic("abandon abandon abandon").is_err());
    }

    #[test]
    fn v1_plaintext_and_encrypted_are_identity_checked() {
        let seed = [9u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pk = PublicKey::from_bytes(sk.verifying_key().to_bytes());
        let addr = Address::from_public_key(&pk);
        let plain = legacy_json(&seed, &addr, &pk, false, "");
        let parsed: V1Keystore = serde_json::from_value(plain).unwrap();
        validate_v1_metadata(&parsed).unwrap();
        assert_eq!(&*migration_seed(&parsed, None).unwrap(), &seed);

        let pass = "legacy-password";
        let encrypted = hex::encode(xor_keystream(&seed, pass));
        let parsed: V1Keystore =
            serde_json::from_value(legacy_json(&seed, &addr, &pk, true, &encrypted)).unwrap();
        assert_eq!(&*migration_seed(&parsed, Some(pass)).unwrap(), &seed);
        assert!(migration_seed(&parsed, Some("wrong-password")).is_err());

        let mut invalid = legacy_json(&seed, &addr, &pk, false, "");
        invalid["address"] = serde_json::Value::String("00".repeat(32));
        let parsed: V1Keystore = serde_json::from_value(invalid).unwrap();
        assert!(validate_v1_metadata(&parsed).is_err());
    }

    #[test]
    fn v1_migration_keeps_source_and_verifies_v2_output() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("old.json");
        let destination = dir.path().join("new.json");
        let seed = [0x31; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pk = PublicKey::from_bytes(sk.verifying_key().to_bytes());
        let addr = Address::from_public_key(&pk);
        let original = serde_json::to_vec(&legacy_json(&seed, &addr, &pk, false, "")).unwrap();
        fs::write(&source, &original).unwrap();
        let normal = load(&source).err().unwrap().to_string();
        assert!(normal.contains("migration-only"));
        assert!(normal.contains("kovanica migrate"));
        let old = load_v1_for_migration(&source).unwrap();
        let recovered = migration_seed(&old, None).unwrap();
        let migrated = from_seed(&recovered, "new password").unwrap();
        save(&destination, &migrated).unwrap();
        let verified = load(&destination).unwrap();
        assert_eq!(
            &*secret_seed(&verified, Some("new password")).unwrap(),
            &seed
        );
        assert_eq!(fs::read(&source).unwrap(), original);
    }

    #[test]
    fn rejects_oversized_keystore_while_reading_bounded_buffer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("too-large.json");
        fs::write(&path, vec![b' '; MAX_KEYSTORE_BYTES as usize + 1024 * 1024]).unwrap();
        let error = load(&path).err().unwrap().to_string();
        assert!(error.contains("maximum 64 KiB"));
    }

    #[test]
    fn atomic_save_refuses_overwrite_and_symlinks_and_sets_private_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let ks = from_seed(&[3; 32], "password").unwrap();
        save(&path, &ks).unwrap();
        assert!(save(&path, &ks).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let link = dir.path().join("link.json");
            symlink(&path, &link).unwrap();
            assert!(save_replace(&link, &ks).is_err());
            assert!(save(&link, &ks).is_err());
        }
    }

    fn from_value(value: serde_json::Value) -> Result<Keystore> {
        let version = value["version"]
            .as_u64()
            .ok_or_else(|| anyhow!("version"))?;
        if version == 2 {
            let v: V2Keystore = serde_json::from_value(value)?;
            let ks = Keystore {
                version: v.version,
                address: v.address,
                public_key: v.public_key,
                encrypted: v.encrypted,
                secret_key: v.secret_key,
                cipher: Some(v.cipher),
                kdf: Some(v.kdf),
                kdf_memory_kib: Some(v.kdf_memory_kib),
                kdf_iterations: Some(v.kdf_iterations),
                kdf_parallelism: Some(v.kdf_parallelism),
                salt: Some(v.salt),
                nonce: Some(v.nonce),
            };
            validate_metadata(&ks)?;
            Ok(ks)
        } else {
            bail!("unsupported")
        }
    }

    fn legacy_json(
        seed: &[u8; 32],
        address: &Address,
        public_key: &PublicKey,
        encrypted: bool,
        secret: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "address": address.to_hex(),
            "public_key": hex::encode(public_key.as_bytes()),
            "secret_key": if encrypted { secret.to_owned() } else { hex::encode(seed) },
            "encrypted": encrypted,
        })
    }
}
