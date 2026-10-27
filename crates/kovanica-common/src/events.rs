//! Canonical contract event topics for the indexer.
//!
//! These byte-string literals are the **single source of truth** for the
//! topics emitted by the four contract crates (`kovanica-htlc`, `kovanica-vault`,
//! `kovanica-multisig`, `kovanica-token`) via `Host::emit_event`. The indexer
//! matches on these exact topics; the emitted bytes must never change.
//!
//! Data payloads (current):
//!
//! | Topic | Data |
//! |-------|------|
//! | `htlc_created` / `htlc_claimed` / `htlc_refunded` | 32-byte swap id |
//! | `vault_created` / `vault_claimed` / `vault_cancelled` | 32-byte vault id |
//! | `multisig_created` | 32-byte config-fingerprint id |
//! | `multisig_proposed` / `multisig_confirmed` / `multisig_executed` | 8-byte tx id, little-endian |
//! | `token_created` / `transfer` / `approval` / `mint` / `burn` | empty |
//!
//! This module is plain constants only — no dependencies, `no_std` friendly.

// ---------- HTLC (KVP-104) ----------

/// Emitted by `Htlc::create` with the 32-byte swap id as data.
pub const HTLC_CREATED: &[u8] = b"htlc_created";
/// Emitted by `Htlc::claim` with the 32-byte swap id as data.
pub const HTLC_CLAIMED: &[u8] = b"htlc_claimed";
/// Emitted by `Htlc::refund` with the 32-byte swap id as data.
pub const HTLC_REFUNDED: &[u8] = b"htlc_refunded";

// ---------- Vault (KVP-105) ----------

/// Emitted by `Vault::create` with the 32-byte vault id as data.
pub const VAULT_CREATED: &[u8] = b"vault_created";
/// Emitted by `Vault::claim` with the 32-byte vault id as data.
pub const VAULT_CLAIMED: &[u8] = b"vault_claimed";
/// Emitted by `Vault::cancel` with the 32-byte vault id as data.
pub const VAULT_CANCELLED: &[u8] = b"vault_cancelled";

// ---------- Multisig (KVP-101) ----------

/// Emitted by `Multisig::create` with the 32-byte config-fingerprint id as data.
pub const MULTISIG_CREATED: &[u8] = b"multisig_created";
/// Emitted by `Multisig::propose` with the 8-byte tx id (LE) as data.
pub const MULTISIG_PROPOSED: &[u8] = b"multisig_proposed";
/// Emitted by `Multisig::confirm` with the 8-byte tx id (LE) as data.
pub const MULTISIG_CONFIRMED: &[u8] = b"multisig_confirmed";
/// Emitted by `Multisig::execute` with the 8-byte tx id (LE) as data.
pub const MULTISIG_EXECUTED: &[u8] = b"multisig_executed";

// ---------- Token (KVP-102) ----------

/// Emitted by `Token::create` with empty data.
pub const TOKEN_CREATED: &[u8] = b"token_created";
/// Emitted by `Token::transfer` / `Token::transfer_from` with empty data.
pub const TOKEN_TRANSFER: &[u8] = b"transfer";
/// Emitted by `Token::approve` with empty data.
pub const TOKEN_APPROVAL: &[u8] = b"approval";
/// Emitted by `Token::mint` with empty data.
pub const TOKEN_MINT: &[u8] = b"mint";
/// Emitted by `Token::burn` with empty data.
pub const TOKEN_BURN: &[u8] = b"burn";

#[cfg(test)]
mod tests {
    use super::*;

    /// Guard against typos: every constant must equal its expected byte string.
    #[test]
    fn topic_constants_match_expected_byte_strings() {
        assert_eq!(HTLC_CREATED, b"htlc_created");
        assert_eq!(HTLC_CLAIMED, b"htlc_claimed");
        assert_eq!(HTLC_REFUNDED, b"htlc_refunded");

        assert_eq!(VAULT_CREATED, b"vault_created");
        assert_eq!(VAULT_CLAIMED, b"vault_claimed");
        assert_eq!(VAULT_CANCELLED, b"vault_cancelled");

        assert_eq!(MULTISIG_CREATED, b"multisig_created");
        assert_eq!(MULTISIG_PROPOSED, b"multisig_proposed");
        assert_eq!(MULTISIG_CONFIRMED, b"multisig_confirmed");
        assert_eq!(MULTISIG_EXECUTED, b"multisig_executed");

        assert_eq!(TOKEN_CREATED, b"token_created");
        assert_eq!(TOKEN_TRANSFER, b"transfer");
        assert_eq!(TOKEN_APPROVAL, b"approval");
        assert_eq!(TOKEN_MINT, b"mint");
        assert_eq!(TOKEN_BURN, b"burn");
    }
}
