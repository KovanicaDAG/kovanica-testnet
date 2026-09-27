//! Client-side Kovanica (KVNC) wallet: the frozen SLIP-0010 ed25519 key
//! derivation and local key storage shared by the node, the CLI, and the TUI.
//!
//! # Why this crate exists
//!
//! Key derivation used to be duplicated across binaries. Two copies of the
//! "same" mnemonic → address rule existed, and they disagreed: one used
//! SLIP-0010 `m/44'/3007'/0'/0'/0'`, the other truncated the BIP-39 seed to its
//! first 32 bytes. The same 24-word key file therefore resolved to a
//! *different address* depending on which binary loaded it, and the variant
//! without passphrase support silently ignored the passphrase — presenting an
//! empty address with no error.
//!
//! This crate is now the single implementation. Known-answer vectors in
//! `tests/` pin the result against both the official SLIP-0010 spec vectors and
//! the project's frozen Kovanica path, so a future divergence fails the build
//! rather than moving somebody's balance.
//!
//! # Layering
//!
//! **Client-side only — no consensus impact.** Nothing here touches GHOSTDAG,
//! the UTXO ledger, emission, or block validation. A node derives no addresses
//! from mnemonics: consensus addresses come from a 32-byte seed supplied to
//! [`kovanica_state::KeyPair::from_seed`], which is exactly what
//! [`Wallet::from_seed`] wraps. Genesis (the RFC-006 founder premine and a
//! pinned operator seed) goes through that path and is therefore unaffected by
//! anything in this crate.
//!
//! # Security
//!
//! Private keys and mnemonics stay on the client. The node only ever receives
//! signed transactions. Key files are written `0600`, passphrases are never
//! persisted, and a passphrase supplied for a raw-seed key file is rejected
//! rather than ignored.
//!
//! # Example
//!
//! ```
//! use kovanica_wallet::Wallet;
//!
//! // Restore from a phrase and get the address to receive at.
//! let wallet = Wallet::from_mnemonic("abandon abandon abandon abandon \
//!     abandon abandon abandon abandon abandon abandon abandon about").unwrap();
//! let address = wallet.address();
//! assert!(address.to_kvnc().starts_with("kvnc1"));
//!
//! // Signing happens here, locally — the node never sees the seed.
//! let signature = wallet.keypair().sign(b"sighash");
//! assert_eq!(signature.len(), 64);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod slip10;
mod wallet;

pub use slip10::{DERIVATION_ACCOUNT, DERIVATION_PATH, SLIP44_COIN_TYPE};
pub use wallet::{bip39_material, Wallet, DEFAULT_ADDRESS_INDEX};
