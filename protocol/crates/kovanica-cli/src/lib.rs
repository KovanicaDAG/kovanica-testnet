//! Kovanica CLI library — shared API client and wallet re-export.
//!
//! The [`Wallet`] type itself lives in [`kovanica_wallet`], which is also what
//! the node uses for genesis keys. It is re-exported here so that
//! `kovanica_cli::Wallet` keeps working for existing callers, while there is
//! exactly one implementation of key derivation in the tree.

pub use kovanica_wallet::Wallet;
