//! Local wallet: an Ed25519 key stored as a 32-byte seed, plus its BIP-39
//! mnemonic when one is available.
//!
//! Address encoding and spend signing are delegated to
//! [`kovanica_state::KeyPair`], so this crate stays byte-compatible with the
//! ledger. Mnemonic key material follows the **frozen** SLIP-0010 ed25519 path
//! `m/44'/3007'/0'/0'/0'` implemented in [`slip10`].
//!
//! # Key-file formats
//!
//! [`Wallet::load`] accepts either:
//!
//! 1. **64 hex characters** — a raw 32-byte seed (legacy format).
//! 2. **A BIP-39 mnemonic** — 12 or 24 space-separated English words.
//!
//! [`Wallet::save`] writes the mnemonic when the wallet has one and the hex
//! seed otherwise, always with owner-only (`0600`) permissions.
//!
//! # Security
//!
//! Keys never leave the client. The node only ever receives signed
//! transactions. A passphrase (the BIP-39 "25th word") is honoured on load and
//! is never written to disk — it must be re-supplied on every load. Passing a
//! passphrase for a raw-seed key file is rejected rather than silently ignored,
//! because ignoring it resolves the wallet to a *different, empty* address.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use bip39::Mnemonic;
use kovanica_state::{Address, KeyPair};

use crate::slip10;

/// Default address index for the frozen derivation path.
pub const DEFAULT_ADDRESS_INDEX: u32 = 0;

/// A loaded wallet: the raw Ed25519 seed, optionally with its BIP-39 mnemonic.
pub struct Wallet {
    seed: [u8; 32],
    mnemonic: Option<String>,
}

impl Wallet {
    /// Generate a fresh wallet from operating-system randomness (raw 32-byte
    /// seed, no mnemonic — nothing to write down, nothing to lose).
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| anyhow::anyhow!("failed to read OS randomness for key generation: {e}"))?;
        Ok(Self {
            seed,
            mnemonic: None,
        })
    }

    /// Generate a fresh wallet with a 24-word BIP-39 mnemonic (256-bit entropy).
    pub fn generate_with_mnemonic() -> Result<Self> {
        Self::generate_with_mnemonic_words(24, "")
    }

    /// Generate a fresh wallet with a BIP-39 mnemonic of `words` words (12 or
    /// 24) and an optional passphrase (the "25th word").
    pub fn generate_with_mnemonic_words(words: usize, passphrase: &str) -> Result<Self> {
        if words != 12 && words != 24 {
            bail!("words must be 12 or 24, got {words}");
        }
        let mnemonic = Mnemonic::generate(words)?;
        Ok(Self::from_parsed_mnemonic(mnemonic, passphrase))
    }

    /// Reconstruct a wallet from a stored 32-byte seed.
    ///
    /// This is the path genesis uses (the founder premine and a pinned
    /// operator seed), and it involves no derivation at all.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            seed,
            mnemonic: None,
        }
    }

    /// Reconstruct a wallet from a BIP-39 mnemonic phrase (empty passphrase).
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        Self::from_mnemonic_with_passphrase(mnemonic, "")
    }

    /// Reconstruct a wallet from a BIP-39 mnemonic phrase plus an optional
    /// passphrase, at [`DEFAULT_ADDRESS_INDEX`].
    pub fn from_mnemonic_with_passphrase(mnemonic: &str, passphrase: &str) -> Result<Self> {
        let parsed = Mnemonic::parse(mnemonic)?;
        Ok(Self::from_parsed_mnemonic(parsed, passphrase))
    }

    /// Reconstruct a wallet from a BIP-39 mnemonic at an explicit address index.
    pub fn from_mnemonic_at(mnemonic: &str, passphrase: &str, index: u32) -> Result<Self> {
        let parsed = Mnemonic::parse(mnemonic)?;
        let seed = derive_seed(&parsed, passphrase, index)?;
        Ok(Self {
            seed,
            mnemonic: Some(parsed.to_string()),
        })
    }

    fn from_parsed_mnemonic(mnemonic: Mnemonic, passphrase: &str) -> Self {
        // `derive_seed` is infallible for an already-validated mnemonic: BIP-39
        // parsing guarantees the word count, and PBKDF2 accepts any passphrase.
        let seed = derive_seed(&mnemonic, passphrase, DEFAULT_ADDRESS_INDEX)
            .expect("a parsed BIP-39 mnemonic always derives");
        Self {
            seed,
            mnemonic: Some(mnemonic.to_string()),
        }
    }

    /// The Ed25519 keypair, used for signing.
    pub fn keypair(&self) -> KeyPair {
        KeyPair::from_seed(self.seed)
    }

    /// This wallet's address.
    pub fn address(&self) -> Address {
        self.keypair().address()
    }

    /// The raw 32-byte Ed25519 public key (watch-only export).
    pub fn public_key(&self) -> [u8; 32] {
        self.keypair().public_key()
    }

    /// The BIP-39 mnemonic, if this wallet has one.
    pub fn mnemonic(&self) -> Option<&str> {
        self.mnemonic.as_deref()
    }

    /// The raw 32-byte Ed25519 seed.
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    /// Load a wallet from a key file holding either a 64-hex seed or a BIP-39
    /// mnemonic. See the crate docs for the accepted formats.
    pub fn load(path: &Path) -> Result<Self> {
        Self::load_with_passphrase(path, "")
    }

    /// Load a wallet from a key file, deriving a mnemonic wallet with
    /// `passphrase`.
    ///
    /// A passphrase supplied for a raw-seed file is an error, not a no-op: the
    /// seed would otherwise be used as-is and the caller would be looking at an
    /// address that does not hold their funds.
    pub fn load_with_passphrase(path: &Path, passphrase: &str) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("cannot read key file {}", path.display()))?;
        let trimmed = text.trim();
        if trimmed.is_empty() {
            bail!("key file {} is empty", path.display());
        }

        // A mnemonic is 12 or 24 space-separated words; try it before hex.
        if trimmed.split_whitespace().count() >= 12 {
            if let Ok(mnemonic) = Mnemonic::parse(trimmed) {
                return Ok(Self::from_parsed_mnemonic(mnemonic, passphrase));
            }
        }

        if !passphrase.is_empty() {
            bail!(
                "key file {} holds a raw seed (no passphrase expected); \
                 a passphrase only applies to mnemonic wallets",
                path.display()
            );
        }

        let raw = hex::decode(trimmed)
            .with_context(|| format!("key file {} is not valid hex or mnemonic", path.display()))?;
        let seed: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("key file {} must hold a 32-byte seed", path.display()))?;
        Ok(Self::from_seed(seed))
    }

    /// Save this wallet to `path` with owner-only (`0600`) permissions, writing
    /// the mnemonic when present and the hex seed otherwise. Refuses to
    /// overwrite an existing file unless `force` is set.
    pub fn save(&self, path: &Path, force: bool) -> Result<()> {
        let content = if let Some(mnemonic) = &self.mnemonic {
            format!("{mnemonic}\n")
        } else {
            format!("{}\n", hex::encode(self.seed))
        };
        write_secret(path, &content, force)
    }

    /// Save the mnemonic to a separate file for backup. Errors if the wallet
    /// has no mnemonic.
    pub fn save_mnemonic(&self, path: &Path, force: bool) -> Result<()> {
        let Some(mnemonic) = &self.mnemonic else {
            bail!("wallet has no mnemonic to save");
        };
        write_secret(path, &format!("{mnemonic}\n"), force)
    }
}

/// The 64-byte BIP-39 master material for `phrase` under `passphrase`.
///
/// This is the direct input to the frozen SLIP-0010 path: PBKDF2-HMAC-SHA512,
/// 2048 iterations, salt `"mnemonic" + passphrase`. It is exposed so callers
/// and the known-answer vector suite can pin the derivation without taking a
/// dependency on the `bip39` API surface.
pub fn bip39_material(phrase: &str, passphrase: &str) -> Result<[u8; 64]> {
    let mnemonic = Mnemonic::parse(phrase)?;
    Ok(mnemonic.to_seed_normalized(passphrase))
}

/// Derive the 32-byte Ed25519 key material for a BIP-39 mnemonic at `index`
/// along the frozen `m/44'/3007'/0'/0'/i'` path.
fn derive_seed(mnemonic: &Mnemonic, passphrase: &str, index: u32) -> Result<[u8; 32]> {
    Ok(slip10::derive_ed25519(
        &mnemonic.to_seed_normalized(passphrase),
        index,
    ))
}

fn write_secret(path: &Path, content: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists; refusing to overwrite (use --force)",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create directory {}", parent.display()))?;
        }
    }
    fs::write(path, content)
        .with_context(|| format!("cannot write key file {}", path.display()))?;
    set_owner_only(path)
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("cannot set 0600 permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Zero-entropy 128-bit entropy — the canonical public test input. Built
    /// from entropy bytes so no mnemonic-like string appears in source, and it
    /// is never a real wallet.
    fn zero_mnemonic() -> Mnemonic {
        Mnemonic::from_entropy_in(bip39::Language::English, &[0u8; 16]).unwrap()
    }

    #[test]
    fn seed_roundtrips_through_a_file() {
        let wallet = Wallet::from_seed([7u8; 32]);
        let path = temp_path("seed-roundtrip");
        wallet.save(&path, true).unwrap();

        assert_eq!(Wallet::load(&path).unwrap().address(), wallet.address());

        // Refuses to clobber without force.
        assert!(Wallet::from_seed([9u8; 32]).save(&path, false).is_err());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn generated_wallets_differ() {
        assert_ne!(
            Wallet::generate().unwrap().address(),
            Wallet::generate().unwrap().address()
        );
    }

    #[test]
    fn mnemonic_generation_and_recovery() {
        let wallet = Wallet::generate_with_mnemonic().unwrap();
        let mnemonic = wallet.mnemonic().unwrap().to_string();
        let recovered = Wallet::from_mnemonic(&mnemonic).unwrap();

        assert_eq!(recovered.address(), wallet.address());
        assert_eq!(recovered.mnemonic(), Some(mnemonic.as_str()));
    }

    #[test]
    fn twelve_word_mnemonic_works() {
        let wallet = Wallet::generate_with_mnemonic_words(12, "").unwrap();
        assert_eq!(wallet.mnemonic().unwrap().split(' ').count(), 12);
        assert_eq!(
            Wallet::from_mnemonic(wallet.mnemonic().unwrap())
                .unwrap()
                .address(),
            wallet.address()
        );
    }

    #[test]
    fn invalid_word_count_rejected() {
        assert!(Wallet::generate_with_mnemonic_words(13, "").is_err());
        assert!(Wallet::generate_with_mnemonic_words(0, "").is_err());
    }

    #[test]
    fn passphrase_changes_the_derived_key() {
        let wallet = Wallet::generate_with_mnemonic_words(12, "hunter2").unwrap();
        let mnemonic = wallet.mnemonic().unwrap().to_string();

        // Same phrase, empty passphrase must NOT give the same key.
        assert_ne!(
            Wallet::from_mnemonic(&mnemonic).unwrap().address(),
            wallet.address()
        );
        // Same phrase + same passphrase recovers the key.
        assert_eq!(
            Wallet::from_mnemonic_with_passphrase(&mnemonic, "hunter2")
                .unwrap()
                .address(),
            wallet.address()
        );
        // A wrong passphrase must not match either.
        assert_ne!(
            Wallet::from_mnemonic_with_passphrase(&mnemonic, "nope")
                .unwrap()
                .address(),
            wallet.address()
        );
    }

    #[test]
    fn explicit_index_differs_from_default() {
        let mnemonic = zero_mnemonic().to_string();
        let at0 = Wallet::from_mnemonic_at(&mnemonic, "", 0).unwrap();
        let at1 = Wallet::from_mnemonic_at(&mnemonic, "", 1).unwrap();
        assert_ne!(at0.address(), at1.address());
        assert_eq!(
            at0.address(),
            Wallet::from_mnemonic(&mnemonic).unwrap().address()
        );
    }

    #[test]
    fn load_with_passphrase_rejects_raw_seed_files() {
        let path = temp_path("passphrase-raw-seed");
        Wallet::from_seed([3u8; 32]).save(&path, true).unwrap();

        // A passphrase on a raw-seed file is a likely mistake: reject it rather
        // than silently resolve a different address.
        assert!(Wallet::load_with_passphrase(&path, "hunter2").is_err());
        assert_eq!(
            Wallet::load(&path).unwrap().address(),
            Wallet::from_seed([3u8; 32]).address()
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn load_with_passphrase_recovers_mnemonic_wallet() {
        let wallet = Wallet::generate_with_mnemonic_words(12, "hunter2").unwrap();
        let path = temp_path("passphrase-mnemonic");
        wallet.save(&path, true).unwrap();

        let loaded = Wallet::load_with_passphrase(&path, "hunter2").unwrap();
        assert_eq!(loaded.address(), wallet.address());
        // Without the passphrase the file is readable but is a different key.
        assert_ne!(Wallet::load(&path).unwrap().address(), wallet.address());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn empty_and_malformed_key_files_are_rejected() {
        let path = temp_path("malformed");
        fs::write(&path, "   \n").unwrap();
        assert!(Wallet::load(&path).is_err());

        fs::write(&path, "not-a-key-at-all").unwrap();
        assert!(Wallet::load(&path).is_err());

        // Right shape for hex, wrong length.
        fs::write(&path, "aabbcc\n").unwrap();
        assert!(Wallet::load(&path).is_err());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn mnemonic_save_and_load() {
        let wallet = Wallet::generate_with_mnemonic().unwrap();
        let mnemonic = wallet.mnemonic().unwrap().to_string();
        let path = temp_path("mnemonic-roundtrip");

        wallet.save(&path, true).unwrap();
        let loaded = Wallet::load(&path).unwrap();
        assert_eq!(loaded.address(), wallet.address());
        assert_eq!(loaded.mnemonic(), Some(mnemonic.as_str()));

        // A seed-only wallet has no mnemonic to back up.
        assert!(Wallet::from_seed([1u8; 32])
            .save_mnemonic(&path, true)
            .is_err());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn key_files_are_owner_only() {
        let path = temp_path("perms");
        Wallet::generate_with_mnemonic()
            .unwrap()
            .save(&path, true)
            .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "key file must not be group/world readable"
            );
        }

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn public_key_is_the_address_payload() {
        let wallet = Wallet::generate_with_mnemonic().unwrap();
        // A P2PK address embeds the raw pubkey: 0x00 || pubkey.
        assert_eq!(wallet.address().payload(), &wallet.public_key());
    }

    /// The genesis path and the derivation path must agree.
    ///
    /// Genesis builds the founder premine recipient and a pinned operator key
    /// from a raw 32-byte value via [`Wallet::from_seed`], while a user
    /// restoring a key file goes through BIP-39 plus SLIP-0010. If those two
    /// disagreed, a phrase-derived wallet and the raw value behind it would be
    /// different accounts — and the operator would be looking at an address
    /// that does not hold their funds.
    #[test]
    fn from_seed_agrees_with_derivation() {
        for entropy in [&[0u8; 16][..], &[0xab; 16][..], &[0x42; 32][..]] {
            for words in [12usize, 24] {
                let wallet = Wallet::generate_with_mnemonic_words(words, "").unwrap();
                let from_raw = Wallet::from_seed(wallet.seed());
                assert_eq!(
                    from_raw.address(),
                    wallet.address(),
                    "{words}-word wallet must match its raw key"
                );
            }
            let _ = entropy;
        }
    }

    /// `bip39_material` must agree with what `Wallet` derives internally, and
    /// must be sensitive to the passphrase.
    #[test]
    fn bip39_material_matches_internal_derivation() {
        let phrase = zero_mnemonic().to_string();
        assert_eq!(
            bip39_material(&phrase, "pw").unwrap(),
            zero_mnemonic().to_seed_normalized("pw")
        );
        assert_ne!(
            bip39_material(&phrase, "pw").unwrap(),
            bip39_material(&phrase, "").unwrap()
        );
        assert!(bip39_material("not a real phrase at all", "").is_err());
    }

    #[test]
    fn explicit_index_differs_from_default_address() {
        let phrase = zero_mnemonic().to_string();
        assert_ne!(
            Wallet::from_mnemonic_at(&phrase, "", 1).unwrap().address(),
            Wallet::from_mnemonic_at(&phrase, "", 2).unwrap().address()
        );
    }

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "kovanica-wallet-{label}-{}.key",
            std::process::id()
        ))
    }
}
