//! Keystore operations.
//!
//! The on-disk format and the Argon2id parameters live in `kovanica-keystore`.
//! This module re-exports that crate so existing `kovanica_cli::wallet` callers
//! keep the same paths. The format is unchanged.

pub use kovanica_keystore::*;
