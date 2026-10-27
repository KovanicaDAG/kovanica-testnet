//! Shared types for kovanica contracts.
//! Designed for Wasmi (deterministic WASM) + account-model host.
//! Keep this crate `no_std` friendly.
//!
//! Contents:
//! - core value types ([`Address`], [`Hash`], [`Amount`], ...) and [`ContractError`]
//! - the [`Host`] trait — the only surface contracts may use to touch ledgers/storage
//! - [`hash`] — the canonical deterministic hash (BLAKE3-256) for all derived IDs
//! - [`MemHost`] — in-memory host for tests / native fallback (no_std + alloc friendly)
//! - [`WasmHost`] — wasm32-only host over the fixed `env`-module imports (Lane 3b ABI)
//!
//! ### Feature / no_std notes
//! The crate is `no_std`-friendly (`#![cfg_attr(not(feature = "std"), no_std)]` +
//! `alloc`). `blake3` is currently built with its default (std) backend because
//! the root workspace dependency does not disable default features; flipping to
//! `default-features = false` + `std = ["blake3/std"]` requires a root
//! `Cargo.toml` change (out of scope for this lane). On `wasm32-unknown-unknown`
//! std exists, so the default feature set compiles there.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use core::fmt;

pub mod events;
mod mem;
#[cfg(target_arch = "wasm32")]
mod wasm;

pub use mem::{MemHost, MemShared, SharedMem};
#[cfg(target_arch = "wasm32")]
pub use wasm::WasmHost;

/// 32-byte address (account or contract).
pub type Address = [u8; 32];

/// 32-byte hash (SHA-256 / Blake3 / whatever host uses).
pub type Hash = [u8; 32];

/// Native token amount (base units). kovanica uses 9 decimals.
pub type Amount = u128;

/// Block / round height.
pub type Height = u64;

/// Contract time, as reported by [`Host::timestamp`].
///
/// **Unit caveat:** blocks carry no wall-clock time, so on a live node this is
/// the *committed-leader height* (see [`contract_time_from_height`]), roughly
/// 12 s per unit at the default round duration — **not** unix seconds. Any
/// expiry / unlock / vesting value a contract stores must be expressed in the
/// same unit. Use [`looks_like_unix_seconds`] to reject values a client
/// obviously produced from a wall clock.
pub type Timestamp = u64;

/// The single definition of what the executor reports as contract time.
///
/// Execution passes the committed height straight through; keeping it in one
/// named function (instead of an inline `timestamp: block_height`) makes the
/// unit explicit and gives tests and clients one thing to point at.
pub const fn contract_time_from_height(height: Height) -> Timestamp {
    height
}

/// Smallest value treated as "obviously unix seconds" (2001-09-09).
///
/// At 12 s per height unit the chain would need ~380 years to reach this, so
/// any expiry/unlock at or above it that was meant as a height would be a
/// lock that never expires — almost certainly a unit mistake.
pub const UNIX_SECONDS_FLOOR: u64 = 1_000_000_000;

/// `true` if `t` is far more plausibly a unix-seconds value than a height.
pub const fn looks_like_unix_seconds(t: u64) -> bool {
    t >= UNIX_SECONDS_FLOOR
}

/// Activation height for rejecting unix-seconds-looking contract times when an
/// HTLC / vault is created.
///
/// Rejecting a value that was accepted before changes which transactions
/// succeed, so — like the other hardening gates — it stays `Height::MAX`
/// (inert) until it is switched on for every validator at a coordinated
/// genesis reset. The comparison is against [`Host::block_height`].
pub const REJECT_UNIX_SECONDS_FROM_HEIGHT: Height = Height::MAX;

/// Validate one expiry / unlock / vesting time at creation.
///
/// Returns `InvalidInput` when the gate is active at `height`
/// (`height >= reject_from`) and `t` looks like unix seconds
/// ([`looks_like_unix_seconds`]); otherwise `Ok`. Callers pass
/// [`REJECT_UNIX_SECONDS_FROM_HEIGHT`] as `reject_from` in production and an
/// explicit value in tests.
pub fn check_contract_time(
    height: Height,
    t: Timestamp,
    reject_from: Height,
) -> ContractResult<()> {
    if height >= reject_from && looks_like_unix_seconds(t) {
        Err(ContractError::InvalidInput)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod time_tests {
    use super::*;

    #[test]
    fn contract_time_is_the_block_height() {
        assert_eq!(contract_time_from_height(0), 0);
        assert_eq!(contract_time_from_height(123_456), 123_456);
    }

    #[test]
    fn unix_seconds_are_detected_and_plausible_heights_are_not() {
        // 2026-10-22 as unix seconds.
        assert!(looks_like_unix_seconds(1_792_000_000));
        // ~10 years of 12 s leaders.
        assert!(!looks_like_unix_seconds(26_280_000));
        assert!(!looks_like_unix_seconds(UNIX_SECONDS_FLOOR - 1));
        assert!(looks_like_unix_seconds(UNIX_SECONDS_FLOOR));
    }

    #[test]
    fn check_contract_time_is_gated_and_only_flags_unix_seconds() {
        let unix = 1_800_000_000;
        // Gate inert: everything passes (today's production behaviour).
        assert_eq!(check_contract_time(10, unix, Height::MAX), Ok(()));
        assert_eq!(
            check_contract_time(10, unix, REJECT_UNIX_SECONDS_FROM_HEIGHT),
            Ok(())
        );
        // Gate active: unix-looking time rejected, plausible heights accepted.
        assert_eq!(
            check_contract_time(10, unix, 0),
            Err(ContractError::InvalidInput)
        );
        assert_eq!(check_contract_time(10, 26_280_000, 0), Ok(()));
        // Gate not reached yet at this height.
        assert_eq!(check_contract_time(10, unix, 11), Ok(()));
    }
}

/// Simple result type used across contracts.
pub type ContractResult<T> = Result<T, ContractError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    Unauthorized,
    InsufficientBalance,
    InvalidInput,
    AlreadyExists,
    NotFound,
    Expired,
    NotExpired,
    HashMismatch,
    ThresholdNotMet,
    Paused,
    Overflow,
    Custom(u32),
}

impl ContractError {
    /// Stable numeric code used by the wasm entry-point ABI.
    ///
    /// Entry points pack errors as `-1 - code()` (always within `-12..=-1`).
    /// `Custom(_)` packs as `11`; the inner `u32` is **not** conveyed through
    /// the packed code — full fidelity is only available on the typed/native
    /// path. Lane 3b decodes: error iff `-12 <= ret <= -1`.
    pub fn code(&self) -> i32 {
        match self {
            Self::Unauthorized => 0,
            Self::InsufficientBalance => 1,
            Self::InvalidInput => 2,
            Self::AlreadyExists => 3,
            Self::NotFound => 4,
            Self::Expired => 5,
            Self::NotExpired => 6,
            Self::HashMismatch => 7,
            Self::ThresholdNotMet => 8,
            Self::Paused => 9,
            Self::Overflow => 10,
            Self::Custom(_) => 11,
        }
    }

    /// Decode a numeric error code (as returned by the wasm entry-point ABI) back
    /// into a typed [`ContractError`].
    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Unauthorized),
            1 => Some(Self::InsufficientBalance),
            2 => Some(Self::InvalidInput),
            3 => Some(Self::AlreadyExists),
            4 => Some(Self::NotFound),
            5 => Some(Self::Expired),
            6 => Some(Self::NotExpired),
            7 => Some(Self::HashMismatch),
            8 => Some(Self::ThresholdNotMet),
            9 => Some(Self::Paused),
            10 => Some(Self::Overflow),
            11 => Some(Self::Custom(11)),
            _ => None,
        }
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "unauthorized"),
            Self::InsufficientBalance => write!(f, "insufficient balance"),
            Self::InvalidInput => write!(f, "invalid input"),
            Self::AlreadyExists => write!(f, "already exists"),
            Self::NotFound => write!(f, "not found"),
            Self::Expired => write!(f, "expired"),
            Self::NotExpired => write!(f, "not yet expired"),
            Self::HashMismatch => write!(f, "hash mismatch"),
            Self::ThresholdNotMet => write!(f, "threshold not met"),
            Self::Paused => write!(f, "contract paused"),
            Self::Overflow => write!(f, "arithmetic overflow"),
            Self::Custom(c) => write!(f, "custom error {}", c),
        }
    }
}

/// Minimal host interface expected by contracts.
/// In real kovanica this is provided by the Wasmi runtime / host functions.
pub trait Host {
    fn caller(&self) -> Address;
    /// Address of the currently executing contract.
    ///
    /// **Why this was added (post-skeleton):** escrow-style contracts must move
    /// funds between the caller and *derived record addresses* (HTLC/vault
    /// escrow = `hash(domain || id)`), and the multisig must pay out from the
    /// contract's own account. The skeleton's zeroed `contract_self()` helper
    /// could not be fixed without exposing this; every `Host` impl must
    /// therefore report the executing contract's address.
    fn contract_address(&self) -> Address;
    fn block_height(&self) -> Height;
    fn timestamp(&self) -> Timestamp;
    fn balance_of(&self, addr: &Address) -> Amount;
    fn transfer(&mut self, from: &Address, to: &Address, amount: Amount) -> ContractResult<()>;
    fn emit_event(&mut self, topic: &[u8], data: &[u8]);
    // Optional: storage get/set if contracts use host storage instead of pure WASM memory
    fn storage_get(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn storage_set(&mut self, key: &[u8], value: &[u8]);
}

use alloc::vec::Vec;

/// Canonical deterministic hash for all contract ID / escrow-address derivation.
///
/// **BLAKE3-256** over the input bytes (`blake3::hash`), returned as a raw
/// 32-byte digest. Every derived identifier documents its exact input encoding
/// at the call site; the house convention is:
///
/// ```text
/// hash( domain_prefix_ascii || fixed_width_fields )
/// ```
///
/// with all integers little-endian and fixed-width, and domain prefixes that
/// differ between derivation kinds (e.g. `b"htlc/id"` vs `b"htlc/escrow"`) to
/// prevent cross-domain collisions.
pub fn hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_error_code_roundtrip() {
        let errors = [
            ContractError::Unauthorized,
            ContractError::InsufficientBalance,
            ContractError::InvalidInput,
            ContractError::AlreadyExists,
            ContractError::NotFound,
            ContractError::Expired,
            ContractError::NotExpired,
            ContractError::HashMismatch,
            ContractError::ThresholdNotMet,
            ContractError::Paused,
            ContractError::Overflow,
            ContractError::Custom(11),
        ];

        for err in &errors {
            let code = err.code();
            let decoded = ContractError::from_code(code).expect("should decode valid code");
            assert_eq!(&decoded, err);
        }

        assert_eq!(ContractError::from_code(-1), None);
        assert_eq!(ContractError::from_code(12), None);
    }
}
