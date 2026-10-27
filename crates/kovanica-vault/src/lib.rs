//! Time-lock / Vesting Vault for kovanica
//!
//! Supports:
//!   - Absolute time-lock (unlock after timestamp)
//!   - Linear vesting (claimable portion grows over time)
//!   - Cliff + linear (optional)
//!   - Beneficiary + optional admin (for cancel / emergency)
//!
//! Matches the spirit of Protocol KVP-105 and the treasury vesting model.
//!
//! ## Asset model
//! Vault moves **native** balances via `Host::transfer` into a per-record
//! escrow address derived from the vault id (`hash(b"vault/escrow" || id)`).
//! The record is serialized with bincode into host storage.
//!
//! ## Deterministic id derivation (FIXED — Lane 3b depends on it)
//!
//! ```text
//! id = hash( b"vault/id"                 // 9-byte ASCII domain prefix
//!           || creator                   // 32 bytes
//!           || beneficiary               // 32 bytes
//!           || total.to_le_bytes()       // 16 bytes (u128, little-endian)
//!           || schedule_encoding         // see below
//!           || created_ts.to_le_bytes()  // 8 bytes (u64, little-endian)
//!           || created_height.to_le_bytes() ) // 8 bytes (u64, little-endian)
//!
//! schedule_encoding:
//!   Absolute: 0x00 || unlock_at_le(8)
//!   Linear : 0x01 || start_le(8) || end_le(8) || cliff_flag(0x00|0x01)
//!                                             [|| cliff_le(8) when flag = 0x01]
//!
//! escrow = hash( b"vault/escrow" || id ) // 12-byte prefix ++ 32-byte id
//! ```
//!
//! `hash` is BLAKE3-256 (`kovanica_common::hash`); all integers little-endian and
//! fixed-width. The creation timestamp/height are bound into the id so two
//! identical schedules created at different times never collide. `create`
//! rejects a duplicate id with `AlreadyExists`.
//!
//! ## Storage keys (FIXED)
//!
//! - record: `b"kvnc/v1/vault/" ++ id` (14-byte prefix ++ 32-byte id)
//!
//! ## WASM entry points (wasm32 only; bincode args in, bincode results out)
//!
//! | export         | args tuple                                                   | Ok result  |
//! |----------------|--------------------------------------------------------------|------------|
//! | `vault_create` | `([u8;32] beneficiary, u128 amount, VestingSchedule)`         | `[u8;32]` id |
//! | `vault_claim`  | `([u8;32] id)`                                               | `u128` claimed |
//! | `vault_cancel` | `([u8;32] id)`                                               | `()`       |
//!
//! Return packing is identical to kovanica-htlc (crate docs): success
//! `((out_ptr as u32 as i64) << 32) | (out_len as u32 as i64)`, error
//! `-(1 + ContractError::code())` within `-12..=-1`; `kovanica_alloc` /
//! `kovanica_dealloc` are exported alongside.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;

use kovanica_common::events::{VAULT_CANCELLED, VAULT_CLAIMED, VAULT_CREATED};
use kovanica_common::{
    hash, Address, Amount, ContractError, ContractResult, Height, Host, Timestamp,
};

pub type VaultId = [u8; 32];

/// Activation height for the "cancel never takes vested funds" rule.
///
/// Historical behaviour (below this height): `cancel` refunds the creator
/// `total - claimed`, i.e. it also takes amounts that have **already vested
/// but not yet been claimed**, and blocks any later `claim`. A fully vested
/// vault can therefore be clawed back until the beneficiary claims.
///
/// From this height on: `cancel` refunds only the **unvested** remainder and
/// freezes the vault at what had vested; the beneficiary can still `claim`
/// the vested-but-unclaimed amount afterwards.
///
/// Changing this alters state transitions, so — like the other hardening
/// gates in `kovanica-types` — it stays `u64::MAX` (inert) until it is
/// switched on for every validator at a coordinated genesis reset. The
/// comparison is against [`Host::block_height`].
pub const CANCEL_PROTECTS_VESTED_FROM_HEIGHT: Height = Height::MAX;

/// bincode failed while serializing a vault record — infallible for these
/// field types in practice; surfaces state-layer corruption.
const ERR_BINCODE_SERIALIZE: u32 = 1;
/// bincode failed while deserializing a stored vault record (corrupt/foreign bytes).
const ERR_BINCODE_DESERIALIZE: u32 = 2;

/// Storage key for a vault record: `b"kvnc/v1/vault/" ++ id`.
fn record_key(id: &VaultId) -> Vec<u8> {
    let mut key = Vec::with_capacity(b"kvnc/v1/vault/".len() + id.len());
    key.extend_from_slice(b"kvnc/v1/vault/");
    key.extend_from_slice(id);
    key
}

/// Domain-separated escrow address for a vault id: `hash(b"vault/escrow" || id)`.
pub fn escrow_address(id: &VaultId) -> Address {
    let mut buf = Vec::with_capacity(b"vault/escrow".len() + id.len());
    buf.extend_from_slice(b"vault/escrow");
    buf.extend_from_slice(id);
    hash(&buf)
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VestingSchedule {
    /// Unlock everything after `unlock_at`.
    Absolute { unlock_at: Timestamp },
    /// Linear from `start` to `end`. Nothing before start.
    Linear {
        start: Timestamp,
        end: Timestamp,
        /// Optional cliff: nothing claimable before cliff.
        cliff: Option<Timestamp>,
    },
}

impl VestingSchedule {
    /// Apply [`kovanica_common::check_contract_time`] to every time in the schedule.
    fn check_times(&self, height: Height, reject_from: Height) -> ContractResult<()> {
        use kovanica_common::check_contract_time as check;
        match self {
            VestingSchedule::Absolute { unlock_at } => check(height, *unlock_at, reject_from),
            VestingSchedule::Linear { start, end, cliff } => {
                check(height, *start, reject_from)?;
                check(height, *end, reject_from)?;
                if let Some(c) = cliff {
                    check(height, *c, reject_from)?;
                }
                Ok(())
            }
        }
    }

    /// Append the FIXED hash encoding of this schedule to `buf`
    /// (tag byte 0x00/0x01, all timestamps u64 LE — see crate docs).
    fn encode_for_hash(&self, buf: &mut Vec<u8>) {
        match self {
            VestingSchedule::Absolute { unlock_at } => {
                buf.push(0x00);
                buf.extend_from_slice(&unlock_at.to_le_bytes());
            }
            VestingSchedule::Linear { start, end, cliff } => {
                buf.push(0x01);
                buf.extend_from_slice(&start.to_le_bytes());
                buf.extend_from_slice(&end.to_le_bytes());
                match cliff {
                    None => buf.push(0x00),
                    Some(c) => {
                        buf.push(0x01);
                        buf.extend_from_slice(&c.to_le_bytes());
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Vault {
    pub creator: Address,
    pub beneficiary: Address,
    pub total: Amount,
    pub claimed: Amount,
    pub schedule: VestingSchedule,
    pub cancelled: bool,
}

impl Vault {
    /// Create a vault. Funds are moved from the caller into the vault's
    /// escrow address.
    pub fn create(
        host: &mut impl Host,
        beneficiary: Address,
        amount: Amount,
        schedule: VestingSchedule,
    ) -> ContractResult<VaultId> {
        Self::create_with_gate(
            host,
            beneficiary,
            amount,
            schedule,
            kovanica_common::REJECT_UNIX_SECONDS_FROM_HEIGHT,
        )
    }

    /// [`Vault::create`] with an explicit activation height for the
    /// unix-seconds guard (tests drive both sides; production uses the constant).
    fn create_with_gate(
        host: &mut impl Host,
        beneficiary: Address,
        amount: Amount,
        schedule: VestingSchedule,
        reject_unix_from: Height,
    ) -> ContractResult<VaultId> {
        if amount == 0 {
            return Err(ContractError::InvalidInput);
        }
        Self::validate_schedule(&schedule, host.timestamp())?;
        // Contract time is the block height, not unix seconds: refuse any
        // schedule time that is obviously a wall-clock value.
        schedule.check_times(host.block_height(), reject_unix_from)?;

        let creator = host.caller();
        let vault = Vault {
            creator,
            beneficiary,
            total: amount,
            claimed: 0,
            schedule,
            cancelled: false,
        };

        // Creation metadata is bound into the id (see crate docs) so identical
        // schedules created at different times never collide.
        let id = Self::compute_id(&vault, host.timestamp(), host.block_height());
        if Self::load(host, &id).is_ok() {
            return Err(ContractError::AlreadyExists);
        }

        let escrow = escrow_address(&id);
        host.transfer(&creator, &escrow, amount)?;
        Self::store(host, &id, &vault)?;

        host.emit_event(VAULT_CREATED, &id);
        Ok(id)
    }

    /// Claim the currently vested (but not yet claimed) amount.
    /// Only the beneficiary may claim; returns 0 (no transfer) when nothing
    /// is vested yet.
    pub fn claim(host: &mut impl Host, id: VaultId) -> ContractResult<Amount> {
        Self::claim_with_gate(host, id, CANCEL_PROTECTS_VESTED_FROM_HEIGHT)
    }

    /// [`Vault::claim`] with an explicit activation height (tests drive both
    /// sides of the gate; production uses the constant).
    fn claim_with_gate(
        host: &mut impl Host,
        id: VaultId,
        protect_from: Height,
    ) -> ContractResult<Amount> {
        let mut vault = Self::load(host, &id)?;
        // Legacy rule: a cancelled vault can never be claimed. Under the
        // protective rule a cancelled vault is frozen at its vested amount and
        // the beneficiary may still collect what had vested before the cancel.
        if vault.cancelled && host.block_height() < protect_from {
            return Err(ContractError::InvalidInput);
        }
        if host.caller() != vault.beneficiary {
            return Err(ContractError::Unauthorized);
        }

        let vested = vault.vested_amount(host.timestamp());
        let claimable = vested.saturating_sub(vault.claimed);
        if claimable == 0 {
            return Ok(0);
        }

        // Pay escrow → beneficiary, then persist the new claimed total.
        let escrow = escrow_address(&id);
        host.transfer(&escrow, &vault.beneficiary, claimable)?;

        vault.claimed = vault.claimed.saturating_add(claimable);
        Self::store(host, &id, &vault)?;
        host.emit_event(VAULT_CLAIMED, &id);
        Ok(claimable)
    }

    /// Creator can cancel and reclaim everything not yet claimed.
    pub fn cancel(host: &mut impl Host, id: VaultId) -> ContractResult<()> {
        Self::cancel_with_gate(host, id, CANCEL_PROTECTS_VESTED_FROM_HEIGHT)
    }

    /// [`Vault::cancel`] with an explicit activation height (tests drive both
    /// sides of the gate; production uses the constant).
    fn cancel_with_gate(
        host: &mut impl Host,
        id: VaultId,
        protect_from: Height,
    ) -> ContractResult<()> {
        let mut vault = Self::load(host, &id)?;
        if host.caller() != vault.creator {
            return Err(ContractError::Unauthorized);
        }
        if vault.cancelled {
            return Err(ContractError::InvalidInput);
        }

        let remaining = if host.block_height() >= protect_from {
            // Refund only what has NOT vested. Whatever vested stays in escrow
            // for the beneficiary: freeze `total` at the vested amount and
            // make it fully vested from now on, so a later `claim` pays
            // `total - claimed` regardless of the original schedule.
            // (`max(claimed)` is belt-and-braces: vested is monotonic, so
            // claimed <= vested already.)
            let vested = vault.vested_amount(host.timestamp()).max(vault.claimed);
            let unvested = vault.total.saturating_sub(vested);
            vault.total = vested;
            // `Absolute { unlock_at: 0 }` cannot be created through `create`
            // (it requires unlock_at > now), so it doubles as the "frozen" marker.
            vault.schedule = VestingSchedule::Absolute { unlock_at: 0 };
            unvested
        } else {
            // Legacy behaviour: also takes vested-but-unclaimed funds.
            vault.total.saturating_sub(vault.claimed)
        };
        vault.cancelled = true;

        let escrow = escrow_address(&id);
        if remaining > 0 {
            host.transfer(&escrow, &vault.creator, remaining)?;
        }
        Self::store(host, &id, &vault)?;
        host.emit_event(VAULT_CANCELLED, &id);
        Ok(())
    }

    /// How much is vested at the given timestamp.
    pub fn vested_amount(&self, now: Timestamp) -> Amount {
        match &self.schedule {
            VestingSchedule::Absolute { unlock_at } => {
                if now >= *unlock_at {
                    self.total
                } else {
                    0
                }
            }
            VestingSchedule::Linear { start, end, cliff } => {
                if let Some(c) = cliff {
                    if now < *c {
                        return 0;
                    }
                }
                if now < *start {
                    return 0;
                }
                if now >= *end {
                    return self.total;
                }
                let duration = end.saturating_sub(*start);
                if duration == 0 {
                    return self.total;
                }
                let elapsed = now.saturating_sub(*start);
                // simple linear: total * elapsed / duration (u128 intermediate)
                self.total
                    .saturating_mul(elapsed as u128)
                    .saturating_div(duration as u128)
            }
        }
    }

    fn validate_schedule(schedule: &VestingSchedule, now: Timestamp) -> ContractResult<()> {
        match schedule {
            VestingSchedule::Absolute { unlock_at } => {
                if *unlock_at <= now {
                    return Err(ContractError::InvalidInput);
                }
            }
            VestingSchedule::Linear { start, end, cliff } => {
                if *end <= *start {
                    return Err(ContractError::InvalidInput);
                }
                if let Some(c) = cliff {
                    if *c > *end {
                        return Err(ContractError::InvalidInput);
                    }
                }
            }
        }
        Ok(())
    }

    /// Deterministic vault id — see crate docs for the exact encoding.
    fn compute_id(vault: &Vault, created_ts: Timestamp, created_height: Height) -> VaultId {
        let mut buf = Vec::with_capacity(b"vault/id".len() + 32 + 32 + 16 + 25 + 8 + 8);
        buf.extend_from_slice(b"vault/id");
        buf.extend_from_slice(&vault.creator);
        buf.extend_from_slice(&vault.beneficiary);
        buf.extend_from_slice(&vault.total.to_le_bytes());
        vault.schedule.encode_for_hash(&mut buf);
        buf.extend_from_slice(&created_ts.to_le_bytes());
        buf.extend_from_slice(&created_height.to_le_bytes());
        hash(&buf)
    }

    fn store(host: &mut impl Host, id: &VaultId, vault: &Vault) -> ContractResult<()> {
        let bytes =
            bincode::serialize(vault).map_err(|_| ContractError::Custom(ERR_BINCODE_SERIALIZE))?;
        host.storage_set(&record_key(id), &bytes);
        Ok(())
    }

    fn load(host: &impl Host, id: &VaultId) -> ContractResult<Vault> {
        let bytes = host
            .storage_get(&record_key(id))
            .ok_or(ContractError::NotFound)?;
        bincode::deserialize(&bytes).map_err(|_| ContractError::Custom(ERR_BINCODE_DESERIALIZE))
    }
}

// ---------- WASM entry points (wasm32 only) ----------

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    use kovanica_common::WasmHost;

    fn error_code(e: ContractError) -> i64 {
        -1 - e.code() as i64
    }

    fn pack_out(ptr: *const u8, len: usize) -> i64 {
        ((ptr as u32 as i64) << 32) | (len as u32 as i64)
    }

    fn success_out(bytes: &[u8]) -> i64 {
        if bytes.is_empty() {
            return 0;
        }
        // capacity == len so host-side kovanica_dealloc(ptr, len) is exact.
        let mut buf = Vec::with_capacity(bytes.len());
        buf.extend_from_slice(bytes);
        let ptr = buf.as_ptr();
        let len = buf.len();
        core::mem::forget(buf); // ownership → host
        pack_out(ptr, len)
    }

    fn ok_out<T: serde::Serialize>(value: &T) -> i64 {
        match bincode::serialize(value) {
            Ok(bytes) => success_out(&bytes),
            Err(_) => error_code(ContractError::Custom(ERR_BINCODE_SERIALIZE)),
        }
    }

    unsafe fn args_slice<'a>(ptr: i32, len: i32) -> Option<&'a [u8]> {
        if len < 0 || (ptr <= 0 && len > 0) {
            None
        } else if len == 0 {
            Some(&[])
        } else {
            Some(core::slice::from_raw_parts(ptr as *const u8, len as usize))
        }
    }

    fn decode_args<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, i64> {
        bincode::deserialize(bytes).map_err(|_| error_code(ContractError::InvalidInput))
    }

    /// Vec-based allocation for the host (fixed ABI).
    #[no_mangle]
    pub extern "C" fn kovanica_alloc(len: i32) -> i32 {
        if len <= 0 {
            return 0;
        }
        let mut v: Vec<u8> = Vec::with_capacity(len as usize);
        let ptr = v.as_mut_ptr();
        core::mem::forget(v);
        ptr as i32
    }

    /// # Safety
    /// `ptr`/`len` must be a pair previously handed to the host.
    #[no_mangle]
    pub extern "C" fn kovanica_dealloc(ptr: i32, len: i32) {
        if ptr == 0 || len <= 0 {
            return;
        }
        unsafe {
            drop(Vec::from_raw_parts(ptr as *mut u8, 0, len as usize));
        }
    }

    #[no_mangle]
    pub extern "C" fn vault_create(args_ptr: i32, args_len: i32) -> i64 {
        let Some(bytes) = (unsafe { args_slice(args_ptr, args_len) }) else {
            return error_code(ContractError::InvalidInput);
        };
        let (beneficiary, amount, schedule): (Address, Amount, VestingSchedule) =
            match decode_args(bytes) {
                Ok(v) => v,
                Err(c) => return c,
            };
        let mut host = WasmHost::new();
        match Vault::create(&mut host, beneficiary, amount, schedule) {
            Ok(id) => ok_out(&id),
            Err(e) => error_code(e),
        }
    }

    #[no_mangle]
    pub extern "C" fn vault_claim(args_ptr: i32, args_len: i32) -> i64 {
        let Some(bytes) = (unsafe { args_slice(args_ptr, args_len) }) else {
            return error_code(ContractError::InvalidInput);
        };
        let id: VaultId = match decode_args(bytes) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let mut host = WasmHost::new();
        match Vault::claim(&mut host, id) {
            Ok(amount) => ok_out(&amount),
            Err(e) => error_code(e),
        }
    }

    #[no_mangle]
    pub extern "C" fn vault_cancel(args_ptr: i32, args_len: i32) -> i64 {
        let Some(bytes) = (unsafe { args_slice(args_ptr, args_len) }) else {
            return error_code(ContractError::InvalidInput);
        };
        let id: VaultId = match decode_args(bytes) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let mut host = WasmHost::new();
        match Vault::cancel(&mut host, id) {
            Ok(()) => ok_out(&()),
            Err(e) => error_code(e),
        }
    }
}

// ---------- native tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_common::MemHost;

    fn addr(tag: u8) -> Address {
        [tag; 32]
    }

    const CREATOR: u8 = 1;
    const BENEFICIARY: u8 = 2;
    const CONTRACT: u8 = 9;

    fn setup(balance: Amount, ts: Timestamp) -> MemHost {
        let mut host = MemHost::new(addr(CREATOR), addr(CONTRACT));
        host.set_balance(addr(CREATOR), balance);
        host.set_timestamp(ts);
        host
    }

    #[test]
    fn linear_vesting_claims_at_0_50_100_percent() {
        let mut host = setup(1_000, 500);
        let schedule = VestingSchedule::Linear {
            start: 1_000,
            end: 2_000,
            cliff: None,
        };
        let id = Vault::create(&mut host, addr(BENEFICIARY), 100, schedule).unwrap();
        let escrow = escrow_address(&id);

        // create: creator → escrow
        assert_eq!(host.balance_of(&addr(CREATOR)), 900);
        assert_eq!(host.balance_of(&escrow), 100);

        host.set_caller(addr(BENEFICIARY));

        // 0%: before start → nothing claimable, no transfer.
        host.set_timestamp(900);
        assert_eq!(Vault::claim(&mut host, id).unwrap(), 0);
        assert_eq!(host.balance_of(&addr(BENEFICIARY)), 0);
        assert_eq!(host.balance_of(&escrow), 100);

        // 50%: midpoint.
        host.set_timestamp(1_500);
        assert_eq!(Vault::claim(&mut host, id).unwrap(), 50);
        assert_eq!(host.balance_of(&addr(BENEFICIARY)), 50);
        assert_eq!(host.balance_of(&escrow), 50);

        // 100%: after end → remaining half.
        host.set_timestamp(2_500);
        assert_eq!(Vault::claim(&mut host, id).unwrap(), 50);
        assert_eq!(host.balance_of(&addr(BENEFICIARY)), 100);
        assert_eq!(host.balance_of(&escrow), 0);

        let v = Vault::load(&host, &id).unwrap();
        assert_eq!(v.claimed, 100);
        assert!(!v.cancelled);
    }

    #[test]
    fn linear_vesting_with_cliff() {
        let mut host = setup(1_000, 100);
        let schedule = VestingSchedule::Linear {
            start: 1_000,
            end: 2_000,
            cliff: Some(1_500),
        };
        let id = Vault::create(&mut host, addr(BENEFICIARY), 100, schedule).unwrap();
        host.set_caller(addr(BENEFICIARY));

        // Before cliff → 0.
        host.set_timestamp(1_400);
        assert_eq!(Vault::claim(&mut host, id).unwrap(), 0);

        // At cliff: cliff is an all-or-nothing gate — once reached, vesting
        // follows the plain linear curve from `start`. 50% elapsed → 50%.
        host.set_timestamp(1_500);
        assert_eq!(Vault::claim(&mut host, id).unwrap(), 50);

        // After end → remaining 50%.
        host.set_timestamp(2_500);
        assert_eq!(Vault::claim(&mut host, id).unwrap(), 50);
        assert_eq!(host.balance_of(&addr(BENEFICIARY)), 100);
    }

    #[test]
    fn absolute_unlock_pays_only_after_unlock_at() {
        let mut host = setup(1_000, 100);
        let schedule = VestingSchedule::Absolute { unlock_at: 2_000 };
        let id = Vault::create(&mut host, addr(BENEFICIARY), 100, schedule).unwrap();
        let escrow = escrow_address(&id);

        host.set_caller(addr(BENEFICIARY));

        // Before unlock → nothing.
        host.set_timestamp(1_999);
        assert_eq!(Vault::claim(&mut host, id).unwrap(), 0);
        assert_eq!(host.balance_of(&escrow), 100);

        // At unlock → everything.
        host.set_timestamp(2_000);
        assert_eq!(Vault::claim(&mut host, id).unwrap(), 100);
        assert_eq!(host.balance_of(&addr(BENEFICIARY)), 100);
        assert_eq!(host.balance_of(&escrow), 0);
    }

    #[test]
    fn absolute_create_rejects_past_unlock() {
        let mut host = setup(1_000, 1_000);
        assert_eq!(
            Vault::create(
                &mut host,
                addr(BENEFICIARY),
                100,
                VestingSchedule::Absolute { unlock_at: 1_000 }
            ),
            Err(ContractError::InvalidInput)
        );
    }

    #[test]
    fn linear_create_rejects_invalid_schedule() {
        let mut host = setup(1_000, 100);
        // end <= start
        assert_eq!(
            Vault::create(
                &mut host,
                addr(BENEFICIARY),
                100,
                VestingSchedule::Linear {
                    start: 2_000,
                    end: 1_000,
                    cliff: None
                }
            ),
            Err(ContractError::InvalidInput)
        );
        // cliff after end
        assert_eq!(
            Vault::create(
                &mut host,
                addr(BENEFICIARY),
                100,
                VestingSchedule::Linear {
                    start: 1_000,
                    end: 2_000,
                    cliff: Some(3_000)
                }
            ),
            Err(ContractError::InvalidInput)
        );
        // zero amount
        assert_eq!(
            Vault::create(
                &mut host,
                addr(BENEFICIARY),
                0,
                VestingSchedule::Absolute { unlock_at: 2_000 }
            ),
            Err(ContractError::InvalidInput)
        );
    }

    #[test]
    fn cancel_returns_unclaimed_funds_to_creator() {
        let mut host = setup(1_000, 500);
        let schedule = VestingSchedule::Linear {
            start: 1_000,
            end: 2_000,
            cliff: None,
        };
        let id = Vault::create(&mut host, addr(BENEFICIARY), 100, schedule).unwrap();
        let escrow = escrow_address(&id);

        // Beneficiary claims 50% first.
        host.set_caller(addr(BENEFICIARY));
        host.set_timestamp(1_500);
        assert_eq!(Vault::claim(&mut host, id).unwrap(), 50);
        assert_eq!(host.balance_of(&escrow), 50);

        // Non-creator cannot cancel.
        host.set_caller(addr(BENEFICIARY));
        assert_eq!(
            Vault::cancel(&mut host, id),
            Err(ContractError::Unauthorized)
        );

        // Creator cancels → remaining 50 returns to creator.
        host.set_caller(addr(CREATOR));
        host.set_timestamp(1_600);
        Vault::cancel(&mut host, id).unwrap();
        assert_eq!(host.balance_of(&escrow), 0);
        assert_eq!(host.balance_of(&addr(CREATOR)), 950); // 900 + 50 returned

        let v = Vault::load(&host, &id).unwrap();
        assert!(v.cancelled);
        assert_eq!(v.claimed, 50);

        // Further claim / double cancel rejected.
        host.set_caller(addr(BENEFICIARY));
        assert_eq!(
            Vault::claim(&mut host, id),
            Err(ContractError::InvalidInput)
        );
        host.set_caller(addr(CREATOR));
        assert_eq!(
            Vault::cancel(&mut host, id),
            Err(ContractError::InvalidInput)
        );
    }

    #[test]
    fn cancel_with_zero_claimed_returns_everything() {
        let mut host = setup(1_000, 100);
        let id = Vault::create(
            &mut host,
            addr(BENEFICIARY),
            100,
            VestingSchedule::Absolute { unlock_at: 5_000 },
        )
        .unwrap();
        Vault::cancel(&mut host, id).unwrap();
        assert_eq!(host.balance_of(&addr(CREATOR)), 1_000);
        assert_eq!(host.balance_of(&escrow_address(&id)), 0);
    }

    #[test]
    fn claim_requires_beneficiary() {
        let mut host = setup(1_000, 100);
        let id = Vault::create(
            &mut host,
            addr(BENEFICIARY),
            100,
            VestingSchedule::Absolute { unlock_at: 2_000 },
        )
        .unwrap();
        host.set_timestamp(3_000);
        // Wrong caller (even the creator) cannot claim.
        assert_eq!(
            Vault::claim(&mut host, id),
            Err(ContractError::Unauthorized)
        );
    }

    #[test]
    fn state_survives_new_host_instance() {
        use kovanica_common::MemHost as MH;
        let mut h1 = setup(1_000, 500);
        let id = Vault::create(
            &mut h1,
            addr(BENEFICIARY),
            100,
            VestingSchedule::Linear {
                start: 1_000,
                end: 2_000,
                cliff: None,
            },
        )
        .unwrap();

        let mut h2 = MH::with_shared(h1.shared(), addr(BENEFICIARY), addr(CONTRACT));
        h2.set_timestamp(1_500);
        assert_eq!(Vault::claim(&mut h2, id).unwrap(), 50);

        // Fresh host cannot see the record.
        let mut fresh = MH::new(addr(BENEFICIARY), addr(CONTRACT));
        assert_eq!(Vault::claim(&mut fresh, id), Err(ContractError::NotFound));
    }

    #[test]
    fn id_is_deterministic_and_distinct() {
        let schedule = |unlock_at| VestingSchedule::Absolute { unlock_at };

        let mut h1 = setup(1_000, 100);
        h1.set_block_height(7);
        let id1 = Vault::create(&mut h1, addr(BENEFICIARY), 100, schedule(2_000)).unwrap();

        // Same inputs (incl. ts/height) on an isolated host → same id.
        let mut h2 = setup(1_000, 100);
        h2.set_block_height(7);
        let id2 = Vault::create(&mut h2, addr(BENEFICIARY), 100, schedule(2_000)).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(escrow_address(&id1), escrow_address(&id2));

        // Different creation timestamp → different id.
        let mut h3 = setup(1_000, 101);
        h3.set_block_height(7);
        let id3 = Vault::create(&mut h3, addr(BENEFICIARY), 100, schedule(2_000)).unwrap();
        assert_ne!(id1, id3);

        // Different amount → different id.
        let mut h4 = setup(1_000, 100);
        h4.set_block_height(7);
        let id4 = Vault::create(&mut h4, addr(BENEFICIARY), 101, schedule(2_000)).unwrap();
        assert_ne!(id1, id4);

        // Different schedule → different id.
        let mut h5 = setup(1_000, 100);
        h5.set_block_height(7);
        let id5 = Vault::create(&mut h5, addr(BENEFICIARY), 100, schedule(3_000)).unwrap();
        assert_ne!(id1, id5);
    }

    #[test]
    fn create_rejects_insufficient_creator_balance() {
        let mut host = setup(50, 100); // balance < amount
        assert_eq!(
            Vault::create(
                &mut host,
                addr(BENEFICIARY),
                100,
                VestingSchedule::Absolute { unlock_at: 2_000 }
            ),
            Err(ContractError::InsufficientBalance)
        );
        assert_eq!(host.balance_of(&addr(CREATOR)), 50);
    }

    #[test]
    fn unknown_vault_is_not_found() {
        let mut host = setup(1_000, 100);
        assert_eq!(
            Vault::claim(&mut host, [0xEE; 32]),
            Err(ContractError::NotFound)
        );
        assert_eq!(
            Vault::cancel(&mut host, [0xEE; 32]),
            Err(ContractError::NotFound)
        );
    }

    // ------------------------------------------------------------------
    // Cancel vs. vested funds (audit finding) and the contract-time unit.
    // `*_legacy_*` tests pin today's behaviour (gate inert); `*_protected_*`
    // tests pin the fixed behaviour by driving the gate explicitly.
    // ------------------------------------------------------------------

    const LEGACY: Height = Height::MAX; // gate off  — what production runs today
    const PROTECTED: Height = 0; //          gate on   — behaviour after activation

    fn linear_vault(host: &mut MemHost) -> VaultId {
        // 100 atoms vest linearly over [1_000, 2_000]; created at ts 500.
        Vault::create(
            host,
            addr(BENEFICIARY),
            100,
            VestingSchedule::Linear {
                start: 1_000,
                end: 2_000,
                cliff: None,
            },
        )
        .unwrap()
    }

    /// FINDING: the creator can cancel a FULLY VESTED vault before the
    /// beneficiary claims and take every atom back; the beneficiary is then
    /// locked out of `claim`.
    #[test]
    fn cancel_legacy_takes_fully_vested_unclaimed_funds() {
        let mut host = setup(1_000, 500);
        let id = linear_vault(&mut host);
        let escrow = escrow_address(&id);

        // Long after `end`: everything is vested, nothing claimed yet.
        host.set_timestamp(9_999);
        assert_eq!(Vault::load(&host, &id).unwrap().vested_amount(9_999), 100);

        host.set_caller(addr(CREATOR));
        Vault::cancel_with_gate(&mut host, id, LEGACY).unwrap();

        // Creator got ALL 100 back (900 + 100), escrow is empty ...
        assert_eq!(host.balance_of(&addr(CREATOR)), 1_000);
        assert_eq!(host.balance_of(&escrow), 0);

        // ... and the beneficiary, who was fully vested, can no longer claim.
        host.set_caller(addr(BENEFICIARY));
        assert_eq!(
            Vault::claim_with_gate(&mut host, id, LEGACY),
            Err(ContractError::InvalidInput)
        );
        assert_eq!(host.balance_of(&addr(BENEFICIARY)), 0);
    }

    /// Same finding, partial vesting: 60% vested at ts 1_600, 50 already
    /// claimed → the 10 vested-but-unclaimed atoms go to the creator too.
    #[test]
    fn cancel_legacy_takes_partially_vested_unclaimed_funds() {
        let mut host = setup(1_000, 500);
        let id = linear_vault(&mut host);

        host.set_caller(addr(BENEFICIARY));
        host.set_timestamp(1_500);
        assert_eq!(Vault::claim_with_gate(&mut host, id, LEGACY).unwrap(), 50);

        host.set_caller(addr(CREATOR));
        host.set_timestamp(1_600); // 60 vested, 50 claimed → 10 owed
        Vault::cancel_with_gate(&mut host, id, LEGACY).unwrap();

        // 900 + 50 refunded: creator took the 10 that were already vested.
        assert_eq!(host.balance_of(&addr(CREATOR)), 950);
        assert_eq!(host.balance_of(&addr(BENEFICIARY)), 50);
    }

    /// FIX: a fully vested vault keeps every atom for the beneficiary.
    #[test]
    fn cancel_protected_leaves_fully_vested_funds_claimable() {
        let mut host = setup(1_000, 500);
        let id = linear_vault(&mut host);
        let escrow = escrow_address(&id);

        host.set_timestamp(9_999);
        host.set_caller(addr(CREATOR));
        Vault::cancel_with_gate(&mut host, id, PROTECTED).unwrap();

        // Nothing unvested → creator refunded nothing; funds stay escrowed.
        assert_eq!(host.balance_of(&addr(CREATOR)), 900);
        assert_eq!(host.balance_of(&escrow), 100);

        host.set_caller(addr(BENEFICIARY));
        assert_eq!(
            Vault::claim_with_gate(&mut host, id, PROTECTED).unwrap(),
            100
        );
        assert_eq!(host.balance_of(&addr(BENEFICIARY)), 100);
        assert_eq!(host.balance_of(&escrow), 0);
    }

    /// FIX: partial vesting splits exactly at the cancel moment.
    #[test]
    fn cancel_protected_splits_at_the_cancel_moment() {
        let mut host = setup(1_000, 500);
        let id = linear_vault(&mut host);
        let escrow = escrow_address(&id);

        host.set_caller(addr(BENEFICIARY));
        host.set_timestamp(1_500);
        assert_eq!(
            Vault::claim_with_gate(&mut host, id, PROTECTED).unwrap(),
            50
        );

        host.set_caller(addr(CREATOR));
        host.set_timestamp(1_600); // 60 vested, 50 claimed, 40 unvested
        Vault::cancel_with_gate(&mut host, id, PROTECTED).unwrap();

        // Creator gets only the 40 unvested atoms (900 + 40).
        assert_eq!(host.balance_of(&addr(CREATOR)), 940);
        assert_eq!(host.balance_of(&escrow), 10);

        // Beneficiary collects the 10 vested-but-unclaimed atoms, even much
        // later — the schedule is frozen, not still running.
        host.set_caller(addr(BENEFICIARY));
        host.set_timestamp(9_999);
        assert_eq!(
            Vault::claim_with_gate(&mut host, id, PROTECTED).unwrap(),
            10
        );
        assert_eq!(host.balance_of(&addr(BENEFICIARY)), 60);
        assert_eq!(host.balance_of(&escrow), 0);

        // Nothing left; a further claim is a harmless no-op.
        assert_eq!(Vault::claim_with_gate(&mut host, id, PROTECTED).unwrap(), 0);

        let v = Vault::load(&host, &id).unwrap();
        assert!(v.cancelled);
        assert_eq!(v.total, 60);
        assert_eq!(v.claimed, 60);
    }

    /// FIX: cancelling before anything vests still refunds everything.
    #[test]
    fn cancel_protected_before_start_refunds_everything() {
        let mut host = setup(1_000, 500);
        let id = linear_vault(&mut host);

        host.set_caller(addr(CREATOR));
        host.set_timestamp(900); // before `start`
        Vault::cancel_with_gate(&mut host, id, PROTECTED).unwrap();
        assert_eq!(host.balance_of(&addr(CREATOR)), 1_000);

        host.set_caller(addr(BENEFICIARY));
        assert_eq!(Vault::claim_with_gate(&mut host, id, PROTECTED).unwrap(), 0);
    }

    /// FIX: authorization and double-cancel rules are unchanged.
    #[test]
    fn cancel_protected_keeps_auth_and_double_cancel_rules() {
        let mut host = setup(1_000, 500);
        let id = linear_vault(&mut host);

        host.set_caller(addr(BENEFICIARY));
        assert_eq!(
            Vault::cancel_with_gate(&mut host, id, PROTECTED),
            Err(ContractError::Unauthorized)
        );

        host.set_caller(addr(CREATOR));
        Vault::cancel_with_gate(&mut host, id, PROTECTED).unwrap();
        assert_eq!(
            Vault::cancel_with_gate(&mut host, id, PROTECTED),
            Err(ContractError::InvalidInput)
        );
    }

    /// The public entry points must still run the legacy rule until the gate
    /// is deliberately switched on.
    #[test]
    fn public_entry_points_use_the_declared_gate() {
        assert_eq!(CANCEL_PROTECTS_VESTED_FROM_HEIGHT, Height::MAX);
        let mut host = setup(1_000, 500);
        let id = linear_vault(&mut host);
        host.set_timestamp(9_999);
        host.set_caller(addr(CREATOR));
        Vault::cancel(&mut host, id).unwrap();
        assert_eq!(host.balance_of(&addr(CREATOR)), 1_000); // legacy: took it all
    }

    /// FINDING (unit mismatch): contract time on a live node is the block
    /// height, but the CLI documents `--unlock-at` as unix seconds. A vault
    /// created with a unix-seconds unlock never opens at any realistic height.
    #[test]
    fn unix_seconds_unlock_never_opens_under_a_height_clock() {
        let unix_unlock: Timestamp = 1_800_000_000; // ~Jan 2027 as unix seconds
        assert!(kovanica_common::looks_like_unix_seconds(unix_unlock));

        // Height clock at the very start of the chain.
        let mut host = setup(1_000, kovanica_common::contract_time_from_height(100));
        let id = Vault::create(
            &mut host,
            addr(BENEFICIARY),
            100,
            VestingSchedule::Absolute {
                unlock_at: unix_unlock,
            },
        )
        .unwrap(); // create accepts it: unlock_at > "now"

        // ~38 years of 12 s leaders later (100 million heights): still locked.
        host.set_caller(addr(BENEFICIARY));
        host.set_timestamp(kovanica_common::contract_time_from_height(100_000_000));
        assert_eq!(Vault::claim(&mut host, id).unwrap(), 0);
        assert_eq!(host.balance_of(&addr(BENEFICIARY)), 0);
    }

    /// FIX: with the guard active, any unix-seconds time in a schedule is
    /// refused at create and nothing is escrowed; height-style schedules pass.
    #[test]
    fn unix_seconds_schedule_is_rejected_when_the_guard_is_active() {
        let unix: Timestamp = 1_800_000_000;
        let mut host = setup(1_000, 100);

        let absolute = VestingSchedule::Absolute { unlock_at: unix };
        let linear_end = VestingSchedule::Linear {
            start: 1_000,
            end: unix,
            cliff: None,
        };
        let linear_all = VestingSchedule::Linear {
            start: unix,
            end: unix + 1_000,
            cliff: Some(unix + 10),
        };
        for schedule in [absolute, linear_end, linear_all] {
            assert_eq!(
                Vault::create_with_gate(&mut host, addr(BENEFICIARY), 100, schedule, 0),
                Err(ContractError::InvalidInput)
            );
        }
        assert_eq!(host.balance_of(&addr(CREATOR)), 1_000); // nothing escrowed

        let ok = VestingSchedule::Linear {
            start: 1_000,
            end: 2_000,
            cliff: Some(1_500),
        };
        assert!(Vault::create_with_gate(&mut host, addr(BENEFICIARY), 100, ok, 0).is_ok());
    }

    /// The public entry point keeps today's behaviour until the gate is
    /// deliberately switched on.
    #[test]
    fn public_create_still_accepts_unix_seconds_while_the_gate_is_inert() {
        assert_eq!(
            kovanica_common::REJECT_UNIX_SECONDS_FROM_HEIGHT,
            kovanica_common::Height::MAX
        );
        let mut host = setup(1_000, 100);
        let s = VestingSchedule::Absolute {
            unlock_at: 1_800_000_000,
        };
        assert!(Vault::create(&mut host, addr(BENEFICIARY), 100, s).is_ok());
    }
}
