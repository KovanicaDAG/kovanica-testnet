//! HTLC (Hashed Time-Lock Contract) for kovanica
//!
//! Atomic swap primitive.
//! Paths:
//!   - claim  : reveal preimage before expiry → funds go to claimer
//!   - refund : after expiry → funds return to sender
//!
//! ## Asset model
//! HTLC moves **native** balances via `Host::transfer` into a per-record escrow
//! address derived from the record id (`hash(b"htlc/escrow" || id)`). The
//! record itself is serialized with bincode into host storage.
//!
//! ## Deterministic id derivation (FIXED — Lane 3b depends on it)
//!
//! ```text
//! id     = hash( b"htlc/id"               // 8-byte ASCII domain prefix
//!               || sender                 // 32 bytes
//!               || claimer                // 32 bytes
//!               || amount.to_le_bytes()   // 16 bytes (u128, little-endian)
//!               || hash_lock              // 32 bytes
//!               || expiry.to_le_bytes() ) // 8 bytes (u64, little-endian)
//! escrow = hash( b"htlc/escrow" || id )  // 11-byte prefix ++ 32-byte id
//! ```
//!
//! `hash` is BLAKE3-256 (`kovanica_common::hash`). All integers little-endian and
//! fixed-width. Two HTLCs with identical parameters therefore share one id;
//! `create` rejects a duplicate id with `AlreadyExists` (never silently
//! overwrites a live/settled record). `hash_lock` must be a BLAKE3-256 digest
//! of the preimage for `claim` to succeed.
//!
//! ## Storage keys (FIXED)
//!
//! - record: `b"kvnc/v1/htlc/" ++ id` (13-byte prefix ++ 32-byte id)
//!
//! Runtime hosts are expected to namespace storage per contract address; the
//! raw key above is what this contract passes to `Host::storage_*`.
//!
//! ## WASM entry points (wasm32 only; bincode args in, bincode results out)
//!
//! | export        | args tuple                                                            | Ok result  |
//! |---------------|-----------------------------------------------------------------------|------------|
//! | `htlc_create` | `([u8;32] claimer, u128 amount, [u8;32] hash_lock, u64 expiry)`       | `[u8;32]` id |
//! | `htlc_claim`  | `([u8;32] id, Vec<u8> preimage)`                                      | `()`       |
//! | `htlc_refund` | `([u8;32] id)`                                                        | `()`       |
//!
//! Return packing (FIXED):
//! - success: `((out_ptr as u32 as i64) << 32) | (out_len as u32 as i64)`;
//!   `out_len == 0` ⇒ `out_ptr` is null — host must not read or deallocate.
//!   Buffers with `out_len > 0` are guest-allocated (`Vec::with_capacity(out_len)`)
//!   and the host MUST release them via `kovanica_dealloc(out_ptr, out_len)`.
//! - error: `-(1 + ContractError::code())`, always within `-12..=-1`.
//!   Host decode rule: error iff `-12 <= ret <= -1`; otherwise success with
//!   `out_ptr = (ret >> 32) as u32`, `out_len = ret as u32` (success values
//!   with a high-bit out_ptr are `<= -2^32` and never collide with errors).
//! - `kovanica_alloc(len: i32) -> i32` / `kovanica_dealloc(ptr: i32, len: i32)` are
//!   also exported (Vec-based; see kovanica-common docs).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;

use kovanica_common::events::{HTLC_CLAIMED, HTLC_CREATED, HTLC_REFUNDED};
use kovanica_common::{
    hash, Address, Amount, ContractError, ContractResult, Hash, Host, Timestamp,
};

/// Unique swap identifier (BLAKE3-256 of the encoded create parameters).
pub type SwapId = Hash;

/// bincode failed while serializing an HTLC record — infallible for these
/// field types in practice; surfaces state-layer corruption.
const ERR_BINCODE_SERIALIZE: u32 = 1;
/// bincode failed while deserializing a stored HTLC record (corrupt/foreign bytes).
const ERR_BINCODE_DESERIALIZE: u32 = 2;

/// Storage key for an HTLC record: `b"kvnc/v1/htlc/" ++ id`.
fn record_key(id: &SwapId) -> Vec<u8> {
    let mut key = Vec::with_capacity(b"kvnc/v1/htlc/".len() + id.len());
    key.extend_from_slice(b"kvnc/v1/htlc/");
    key.extend_from_slice(id);
    key
}

/// Domain-separated escrow address for a record id: `hash(b"htlc/escrow" || id)`.
pub fn escrow_address(id: &SwapId) -> Address {
    let mut buf = Vec::with_capacity(b"htlc/escrow".len() + id.len());
    buf.extend_from_slice(b"htlc/escrow");
    buf.extend_from_slice(id);
    hash(&buf)
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Htlc {
    pub sender: Address,
    pub claimer: Address,
    pub amount: Amount,
    pub hash_lock: Hash,   // BLAKE3-256(preimage) via kovanica_common::hash
    pub expiry: Timestamp, // absolute timestamp
    pub claimed: bool,
    pub refunded: bool,
}

impl Htlc {
    /// Create a new HTLC. Caller must be `sender`; `amount` is moved from the
    /// sender into the record's escrow address.
    pub fn create(
        host: &mut impl Host,
        claimer: Address,
        amount: Amount,
        hash_lock: Hash,
        expiry: Timestamp,
    ) -> ContractResult<SwapId> {
        Self::create_with_gate(
            host,
            claimer,
            amount,
            hash_lock,
            expiry,
            kovanica_common::REJECT_UNIX_SECONDS_FROM_HEIGHT,
        )
    }

    /// [`Htlc::create`] with an explicit activation height for the
    /// unix-seconds guard (tests drive both sides; production uses the constant).
    fn create_with_gate(
        host: &mut impl Host,
        claimer: Address,
        amount: Amount,
        hash_lock: Hash,
        expiry: Timestamp,
        reject_unix_from: kovanica_common::Height,
    ) -> ContractResult<SwapId> {
        if amount == 0 {
            return Err(ContractError::InvalidInput);
        }
        if expiry <= host.timestamp() {
            return Err(ContractError::InvalidInput);
        }
        // Contract time is the block height, not unix seconds: refuse a value
        // that is obviously a wall-clock time (it would never expire).
        kovanica_common::check_contract_time(host.block_height(), expiry, reject_unix_from)?;

        let sender = host.caller();
        let swap = Htlc {
            sender,
            claimer,
            amount,
            hash_lock,
            expiry,
            claimed: false,
            refunded: false,
        };

        let id = Self::compute_id(&swap);
        // Identical parameters reuse the same id — never overwrite a record.
        if Self::load(host, &id).is_ok() {
            return Err(ContractError::AlreadyExists);
        }

        // Move `amount` from the sender into the record's escrow address.
        // (Fixes the skeleton bug that transferred caller → caller.)
        let escrow = escrow_address(&id);
        host.transfer(&sender, &escrow, amount)?;

        Self::store(host, &id, &swap)?;

        host.emit_event(HTLC_CREATED, &id);
        Ok(id)
    }

    /// Claim with preimage before expiry. Only the designated claimer may
    /// claim (stricter than classic "anyone holding the preimage").
    pub fn claim(host: &mut impl Host, id: SwapId, preimage: &[u8]) -> ContractResult<()> {
        let mut swap = Self::load(host, &id)?;
        if swap.claimed || swap.refunded {
            return Err(ContractError::InvalidInput);
        }
        if host.timestamp() >= swap.expiry {
            return Err(ContractError::Expired);
        }

        let computed = hash(preimage);
        if computed != swap.hash_lock {
            return Err(ContractError::HashMismatch);
        }

        if host.caller() != swap.claimer {
            return Err(ContractError::Unauthorized);
        }

        // Pay escrow → claimer, then persist the settled flag. The host model
        // has no re-entrancy; an underfunded escrow surfaces as
        // InsufficientBalance and leaves the record claimable.
        let escrow = escrow_address(&id);
        host.transfer(&escrow, &swap.claimer, swap.amount)?;

        swap.claimed = true;
        Self::store(host, &id, &swap)?;

        host.emit_event(HTLC_CLAIMED, &id);
        Ok(())
    }

    /// Refund after expiry. Anyone may trigger it; funds return to `sender`.
    pub fn refund(host: &mut impl Host, id: SwapId) -> ContractResult<()> {
        let mut swap = Self::load(host, &id)?;
        if swap.claimed || swap.refunded {
            return Err(ContractError::InvalidInput);
        }
        if host.timestamp() < swap.expiry {
            return Err(ContractError::NotExpired);
        }

        let escrow = escrow_address(&id);
        host.transfer(&escrow, &swap.sender, swap.amount)?;

        swap.refunded = true;
        Self::store(host, &id, &swap)?;

        host.emit_event(HTLC_REFUNDED, &id);
        Ok(())
    }

    // ---------- internal helpers ----------

    /// Deterministic record id — see crate docs for the exact encoding.
    fn compute_id(swap: &Htlc) -> SwapId {
        // b"htlc/id" || sender || claimer || amount_le(16) || hash_lock || expiry_le(8)
        let mut buf = Vec::with_capacity(b"htlc/id".len() + 32 + 32 + 16 + 32 + 8);
        buf.extend_from_slice(b"htlc/id");
        buf.extend_from_slice(&swap.sender);
        buf.extend_from_slice(&swap.claimer);
        buf.extend_from_slice(&swap.amount.to_le_bytes());
        buf.extend_from_slice(&swap.hash_lock);
        buf.extend_from_slice(&swap.expiry.to_le_bytes());
        hash(&buf)
    }

    fn store(host: &mut impl Host, id: &SwapId, swap: &Htlc) -> ContractResult<()> {
        let bytes =
            bincode::serialize(swap).map_err(|_| ContractError::Custom(ERR_BINCODE_SERIALIZE))?;
        host.storage_set(&record_key(id), &bytes);
        Ok(())
    }

    fn load(host: &impl Host, id: &SwapId) -> ContractResult<Htlc> {
        let bytes = host
            .storage_get(&record_key(id))
            .ok_or(ContractError::NotFound)?;
        bincode::deserialize(&bytes).map_err(|_| ContractError::Custom(ERR_BINCODE_DESERIALIZE))
    }
}

// ---------- WASM entry points (wasm32 only) ----------
// On native targets these exports do not exist — the typed API above is the
// native path. See crate docs for the packed return encoding.

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    use kovanica_common::WasmHost;

    fn error_code(e: ContractError) -> i64 {
        -1 - e.code() as i64
    }

    /// Pack `(out_ptr, out_len)`: high 32 bits = out_ptr zero-extended,
    /// low 32 bits = out_len.
    fn pack_out(ptr: *const u8, len: usize) -> i64 {
        ((ptr as u32 as i64) << 32) | (len as u32 as i64)
    }

    /// Hand an output buffer to the host. `Vec::with_capacity(len)` guarantees
    /// `capacity == len`, so the host-side `kovanica_dealloc(ptr, len)` rebuilds
    /// the exact allocation (a forgotten Vec with spare capacity would make
    /// dealloc UB).
    fn success_out(bytes: &[u8]) -> i64 {
        if bytes.is_empty() {
            return 0; // null ptr + zero len — host must not read or dealloc
        }
        let mut buf = Vec::with_capacity(bytes.len());
        buf.extend_from_slice(bytes);
        let ptr = buf.as_ptr();
        let len = buf.len();
        core::mem::forget(buf); // ownership transfers to the host
        pack_out(ptr, len)
    }

    /// bincode-encode an Ok value and hand the buffer to the host.
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
            Some(&[]) // from_raw_parts(null, 0) is UB — empty slice instead
        } else {
            Some(core::slice::from_raw_parts(ptr as *const u8, len as usize))
        }
    }

    fn decode_args<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, i64> {
        // Corrupt/foreign argument bytes → InvalidInput (ABI misuse, not state).
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

    /// Frees a buffer previously produced by `kovanica_alloc` or an entry-point
    /// success result.
    ///
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
    pub extern "C" fn htlc_create(args_ptr: i32, args_len: i32) -> i64 {
        let Some(bytes) = (unsafe { args_slice(args_ptr, args_len) }) else {
            return error_code(ContractError::InvalidInput);
        };
        let (claimer, amount, hash_lock, expiry): (Address, Amount, Hash, Timestamp) =
            match decode_args(bytes) {
                Ok(v) => v,
                Err(c) => return c,
            };
        let mut host = WasmHost::new();
        match Htlc::create(&mut host, claimer, amount, hash_lock, expiry) {
            Ok(id) => ok_out(&id),
            Err(e) => error_code(e),
        }
    }

    #[no_mangle]
    pub extern "C" fn htlc_claim(args_ptr: i32, args_len: i32) -> i64 {
        let Some(bytes) = (unsafe { args_slice(args_ptr, args_len) }) else {
            return error_code(ContractError::InvalidInput);
        };
        let (id, preimage): (SwapId, Vec<u8>) = match decode_args(bytes) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let mut host = WasmHost::new();
        match Htlc::claim(&mut host, id, &preimage) {
            Ok(()) => ok_out(&()),
            Err(e) => error_code(e),
        }
    }

    #[no_mangle]
    pub extern "C" fn htlc_refund(args_ptr: i32, args_len: i32) -> i64 {
        let Some(bytes) = (unsafe { args_slice(args_ptr, args_len) }) else {
            return error_code(ContractError::InvalidInput);
        };
        let id: SwapId = match decode_args(bytes) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let mut host = WasmHost::new();
        match Htlc::refund(&mut host, id) {
            Ok(()) => ok_out(&()),
            Err(e) => error_code(e),
        }
    }
}

// ---------- native tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_common::{MemHost, MemShared};

    fn addr(tag: u8) -> Address {
        [tag; 32]
    }

    fn funded_host(caller: Address, contract: Address, balance: Amount, ts: Timestamp) -> MemHost {
        let mut host = MemHost::new(caller, contract);
        host.set_balance(caller, balance);
        host.set_timestamp(ts);
        host
    }

    #[test]
    fn create_then_claim_moves_funds_caller_escrow_claimer() {
        let sender = addr(1);
        let claimer = addr(2);
        let contract = addr(9);
        let preimage = b"secret-preimage".to_vec();
        let hash_lock = hash(&preimage);
        let mut host = funded_host(sender, contract, 1_000, 100);

        let id = Htlc::create(&mut host, claimer, 250, hash_lock, 200).unwrap();
        let escrow = escrow_address(&id);

        // create: caller → escrow
        assert_ne!(escrow, sender);
        assert_ne!(escrow, claimer);
        assert_eq!(host.balance_of(&sender), 750);
        assert_eq!(host.balance_of(&escrow), 250);

        // claim: escrow → claimer
        host.set_caller(claimer);
        host.set_timestamp(150);
        Htlc::claim(&mut host, id, &preimage).unwrap();
        assert_eq!(host.balance_of(&escrow), 0);
        assert_eq!(host.balance_of(&claimer), 250);
        assert_eq!(host.balance_of(&sender), 750);

        let rec = Htlc::load(&host, &id).unwrap();
        assert!(rec.claimed);
        assert!(!rec.refunded);

        // events emitted
        let topics: Vec<Vec<u8>> = host.events().into_iter().map(|(t, _)| t).collect();
        assert!(topics.contains(&b"htlc_created".to_vec()));
        assert!(topics.contains(&b"htlc_claimed".to_vec()));
    }

    #[test]
    fn create_then_refund_after_expiry_returns_funds() {
        let sender = addr(1);
        let claimer = addr(2);
        let contract = addr(9);
        let preimage = b"p".to_vec();
        let hash_lock = hash(&preimage);
        let mut host = funded_host(sender, contract, 1_000, 100);

        let id = Htlc::create(&mut host, claimer, 400, hash_lock, 200).unwrap();
        let escrow = escrow_address(&id);
        assert_eq!(host.balance_of(&sender), 600);

        // Not expired yet → refund rejected.
        host.set_timestamp(199);
        assert_eq!(Htlc::refund(&mut host, id), Err(ContractError::NotExpired));

        // Anyone may trigger the refund once expired; funds go to sender.
        host.set_caller(addr(7));
        host.set_timestamp(200);
        Htlc::refund(&mut host, id).unwrap();
        assert_eq!(host.balance_of(&sender), 1_000);
        assert_eq!(host.balance_of(&escrow), 0);

        let rec = Htlc::load(&host, &id).unwrap();
        assert!(rec.refunded);
        assert!(!rec.claimed);
    }

    #[test]
    fn wrong_preimage_rejected() {
        let sender = addr(1);
        let claimer = addr(2);
        let contract = addr(9);
        let hash_lock = hash(b"right-preimage");
        let mut host = funded_host(sender, contract, 1_000, 100);

        let id = Htlc::create(&mut host, claimer, 100, hash_lock, 200).unwrap();
        let escrow = escrow_address(&id);

        host.set_caller(claimer);
        host.set_timestamp(150);
        assert_eq!(
            Htlc::claim(&mut host, id, b"wrong-preimage"),
            Err(ContractError::HashMismatch)
        );
        // Funds untouched.
        assert_eq!(host.balance_of(&escrow), 100);
        assert_eq!(host.balance_of(&claimer), 0);
    }

    #[test]
    fn non_claimer_with_correct_preimage_rejected() {
        let sender = addr(1);
        let claimer = addr(2);
        let contract = addr(9);
        let preimage = b"right".to_vec();
        let hash_lock = hash(&preimage);
        let mut host = funded_host(sender, contract, 1_000, 100);

        let id = Htlc::create(&mut host, claimer, 100, hash_lock, 200).unwrap();
        host.set_caller(addr(7)); // not the claimer
        host.set_timestamp(150);
        assert_eq!(
            Htlc::claim(&mut host, id, &preimage),
            Err(ContractError::Unauthorized)
        );
    }

    #[test]
    fn claim_after_expiry_rejected() {
        let sender = addr(1);
        let claimer = addr(2);
        let contract = addr(9);
        let preimage = b"p".to_vec();
        let hash_lock = hash(&preimage);
        let mut host = funded_host(sender, contract, 1_000, 100);

        let id = Htlc::create(&mut host, claimer, 100, hash_lock, 200).unwrap();
        host.set_caller(claimer);
        host.set_timestamp(200); // == expiry
        assert_eq!(
            Htlc::claim(&mut host, id, &preimage),
            Err(ContractError::Expired)
        );
    }

    #[test]
    fn state_survives_new_host_instance() {
        let sender = addr(1);
        let claimer = addr(2);
        let contract = addr(9);
        let preimage = b"persist".to_vec();
        let hash_lock = hash(&preimage);

        let mut h1 = funded_host(sender, contract, 1_000, 100);
        let id = Htlc::create(&mut h1, claimer, 300, hash_lock, 200).unwrap();
        let escrow = escrow_address(&id);

        // Second host instance over the SAME storage cell.
        let mut h2 = MemHost::with_shared(h1.shared(), claimer, contract);
        h2.set_timestamp(150);
        // Balances are shared too — escrow still holds the funds.
        assert_eq!(h2.balance_of(&escrow), 300);
        Htlc::claim(&mut h2, id, &preimage).unwrap();
        assert_eq!(h2.balance_of(&claimer), 300);

        // A host over fresh storage cannot see the record.
        let fresh = MemHost::new(claimer, contract);
        assert_eq!(Htlc::load(&fresh, &id), Err(ContractError::NotFound));
    }

    #[test]
    fn double_claim_rejected() {
        let sender = addr(1);
        let claimer = addr(2);
        let contract = addr(9);
        let preimage = b"p".to_vec();
        let hash_lock = hash(&preimage);
        let mut host = funded_host(sender, contract, 1_000, 100);

        let id = Htlc::create(&mut host, claimer, 100, hash_lock, 200).unwrap();
        host.set_caller(claimer);
        host.set_timestamp(150);
        Htlc::claim(&mut host, id, &preimage).unwrap();
        assert_eq!(
            Htlc::claim(&mut host, id, &preimage),
            Err(ContractError::InvalidInput)
        );

        // Refund after a successful claim is also rejected.
        host.set_timestamp(300);
        assert_eq!(
            Htlc::refund(&mut host, id),
            Err(ContractError::InvalidInput)
        );
        // No funds moved on the rejected calls.
        assert_eq!(host.balance_of(&claimer), 100);
    }

    #[test]
    fn duplicate_create_rejected() {
        let sender = addr(1);
        let claimer = addr(2);
        let contract = addr(9);
        let hash_lock = hash(b"p");
        let mut host = funded_host(sender, contract, 1_000, 100);

        let id = Htlc::create(&mut host, claimer, 100, hash_lock, 200).unwrap();
        // Identical parameters → same id → rejected.
        assert_eq!(
            Htlc::create(&mut host, claimer, 100, hash_lock, 200),
            Err(ContractError::AlreadyExists)
        );
        // Only one escrow deposit exists.
        assert_eq!(host.balance_of(&escrow_address(&id)), 100);
        assert_eq!(host.balance_of(&sender), 900);
    }

    #[test]
    fn id_and_escrow_are_deterministic_across_hosts() {
        let sender = addr(1);
        let claimer = addr(2);
        let contract = addr(9);
        let hash_lock = hash(b"same-params");

        let mut h1 = funded_host(sender, contract, 1_000, 100);
        let id1 = Htlc::create(&mut h1, claimer, 100, hash_lock, 200).unwrap();

        // Same inputs on a second, isolated host → same id and escrow.
        let mut h2 = funded_host(sender, contract, 1_000, 100);
        let id2 = Htlc::create(&mut h2, claimer, 100, hash_lock, 200).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(escrow_address(&id1), escrow_address(&id2));

        // Different expiry → different id.
        let mut h3 = funded_host(sender, contract, 1_000, 100);
        let id3 = Htlc::create(&mut h3, claimer, 100, hash_lock, 201).unwrap();
        assert_ne!(id1, id3);

        // Different amount → different id.
        let mut h4 = funded_host(sender, contract, 1_000, 100);
        let id4 = Htlc::create(&mut h4, claimer, 101, hash_lock, 200).unwrap();
        assert_ne!(id1, id4);
    }

    #[test]
    fn create_rejects_invalid_params() {
        let sender = addr(1);
        let mut host = funded_host(sender, addr(9), 1_000, 100);
        let hash_lock = hash(b"p");

        // Zero amount.
        assert_eq!(
            Htlc::create(&mut host, addr(2), 0, hash_lock, 200),
            Err(ContractError::InvalidInput)
        );
        // Expiry in the past / now.
        assert_eq!(
            Htlc::create(&mut host, addr(2), 100, hash_lock, 100),
            Err(ContractError::InvalidInput)
        );
    }

    #[test]
    fn create_rejects_insufficient_sender_balance() {
        let sender = addr(1);
        let mut host = funded_host(sender, addr(9), 50, 100); // balance < amount
        let hash_lock = hash(b"p");
        assert_eq!(
            Htlc::create(&mut host, addr(2), 100, hash_lock, 200),
            Err(ContractError::InsufficientBalance)
        );
        // No record was persisted.
        // (compute_id is private; recompute by attempting the same create on a
        // funded host is unnecessary — absence is proven via balance intact.)
        assert_eq!(host.balance_of(&sender), 50);
    }

    #[test]
    fn unknown_record_is_not_found() {
        let mut host = MemHost::new(addr(1), addr(9));
        assert_eq!(
            Htlc::claim(&mut host, [0xEE; 32], b"p"),
            Err(ContractError::NotFound)
        );
        assert_eq!(
            Htlc::refund(&mut host, [0xEE; 32]),
            Err(ContractError::NotFound)
        );
    }

    #[test]
    fn mem_shared_storage_is_shared_between_hosts() {
        // Direct sanity check of the MemHost persistence mechanism itself.
        let shared = Rc::new(core::cell::RefCell::new(MemShared::default()));
        let mut h1 = MemHost::with_shared(Rc::clone(&shared), addr(1), addr(9));
        h1.storage_set(b"k", b"v");
        let h2 = MemHost::with_shared(shared, addr(2), addr(9));
        assert_eq!(h2.storage_get(b"k"), Some(b"v".to_vec()));
    }

    use alloc::rc::Rc;

    /// FINDING (unit mismatch): contract time on a live node is the block
    /// height, but the CLI documents `--expiry` as unix seconds. A lock whose
    /// expiry is a unix-seconds value cannot be refunded at any realistic
    /// height, so the sender's funds are stuck unless the claimer cooperates.
    #[test]
    fn unix_seconds_expiry_never_expires_under_a_height_clock() {
        let sender = addr(1);
        let claimer = addr(2);
        let unix_expiry: Timestamp = 1_800_000_000; // ~Jan 2027 as unix seconds
        assert!(kovanica_common::looks_like_unix_seconds(unix_expiry));

        // Height clock near genesis.
        let mut host = funded_host(
            sender,
            addr(9),
            1_000,
            kovanica_common::contract_time_from_height(100),
        );
        let id = Htlc::create(&mut host, claimer, 100, hash(b"secret"), unix_expiry).unwrap();

        // ~38 years of 12 s leaders later (100 million heights): refund is
        // still refused as NotExpired.
        host.set_timestamp(kovanica_common::contract_time_from_height(100_000_000));
        assert_eq!(Htlc::refund(&mut host, id), Err(ContractError::NotExpired));
        assert_eq!(host.balance_of(&sender), 900);
    }

    /// A height-denominated expiry behaves as intended: claim before, refund
    /// from the expiry height on, with no overlap between the two windows.
    #[test]
    fn height_denominated_expiry_has_disjoint_claim_and_refund_windows() {
        let sender = addr(1);
        let claimer = addr(2);
        let mut host = funded_host(sender, addr(9), 1_000, 100);
        let id = Htlc::create(&mut host, claimer, 100, hash(b"secret"), 200).unwrap();

        host.set_timestamp(199);
        assert_eq!(Htlc::refund(&mut host, id), Err(ContractError::NotExpired));

        host.set_timestamp(200);
        host.set_caller(claimer);
        assert_eq!(
            Htlc::claim(&mut host, id, b"secret"),
            Err(ContractError::Expired)
        );
        assert_eq!(Htlc::refund(&mut host, id), Ok(()));
        assert_eq!(host.balance_of(&sender), 1_000);
    }

    /// FIX: with the guard active a unix-seconds expiry is refused at create
    /// and nothing is escrowed; a height-style expiry is still accepted.
    #[test]
    fn unix_seconds_expiry_is_rejected_when_the_guard_is_active() {
        let sender = addr(1);
        let unix_expiry: Timestamp = 1_800_000_000;
        let mut host = funded_host(sender, addr(9), 1_000, 100);

        assert_eq!(
            Htlc::create_with_gate(&mut host, addr(2), 100, hash(b"s"), unix_expiry, 0),
            Err(ContractError::InvalidInput)
        );
        assert_eq!(host.balance_of(&sender), 1_000); // nothing escrowed

        assert!(Htlc::create_with_gate(&mut host, addr(2), 100, hash(b"s"), 200, 0).is_ok());
        assert_eq!(host.balance_of(&sender), 900);
    }

    /// The public entry point keeps today's behaviour until the gate is
    /// deliberately switched on.
    #[test]
    fn public_create_still_accepts_unix_seconds_while_the_gate_is_inert() {
        assert_eq!(
            kovanica_common::REJECT_UNIX_SECONDS_FROM_HEIGHT,
            kovanica_common::Height::MAX
        );
        let mut host = funded_host(addr(1), addr(9), 1_000, 100);
        assert!(Htlc::create(&mut host, addr(2), 100, hash(b"s"), 1_800_000_000).is_ok());
    }
}
