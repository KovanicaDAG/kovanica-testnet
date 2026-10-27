//! Multisig wallet for kovanica
//!
//! M-of-N threshold.
//! Supports:
//!   - Propose transaction
//!   - Confirm
//!   - Execute once threshold met
//!   - Owner management can be added later as special txs requiring threshold
//!
//! Clean, minimal state machine suitable for Wasmi.
//!
//! ## Asset model
//! Multisig moves **native** balances via `Host::transfer`, paying out from the
//! multisig contract's own account (`Host::contract_address()`), which must be
//! funded externally. State is serialized with bincode into host storage.
//!
//! ## Instance model & storage keys (FIXED)
//!
//! One multisig instance per contract address (singleton state):
//!
//! - singleton state: `b"kvnc/v1/state"`
//! - pending tx:      `b"kvnc/v1/mtx/" ++ tx_id.to_le_bytes()` (12-byte prefix ++ 8 bytes)
//!
//! Runtime hosts are expected to namespace storage per contract address.
//!
//! ## Deterministic id derivation (FIXED — Lane 3b depends on it)
//!
//! The returned `MultisigId` is a **configuration fingerprint** (state itself
//! lives under the singleton key; the id does not select storage):
//!
//! ```text
//! id = hash( b"multisig/id"                // 11-byte ASCII domain prefix
//!           || each owner (32 bytes, in BTreeSet ascending order)
//!           || threshold.to_le_bytes() )   // 4 bytes (u32, little-endian)
//! ```
//!
//! `hash` is BLAKE3-256 (`kovanica_common::hash`). `propose`/`confirm`/`execute`
//! load the singleton state and reject an `id` that does not match the loaded
//! configuration's fingerprint with `NotFound`.
//!
//! ## WASM entry points (wasm32 only; bincode args in, bincode results out)
//!
//! | export            | args tuple                                                  | Ok result |
//! |-------------------|-------------------------------------------------------------|-----------|
//! | `multisig_create` | `(Vec<[u8;32]> owners, u32 threshold)`                      | `[u8;32]` id |
//! | `multisig_propose`| `([u8;32] id, [u8;32] to, u128 amount, Vec<u8> data)`        | `u64` tx_id |
//! | `multisig_confirm`| `([u8;32] id, u64 tx_id)`                                   | `()`      |
//! | `multisig_execute`| `([u8;32] id, u64 tx_id)`                                   | `()`      |
//!
//! Return packing is identical to kovanica-htlc (crate docs): success
//! `((out_ptr as u32 as i64) << 32) | (out_len as u32 as i64)`, error
//! `-(1 + ContractError::code())` within `-12..=-1`; `kovanica_alloc` /
//! `kovanica_dealloc` are exported alongside.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use kovanica_common::events::{
    MULTISIG_CONFIRMED, MULTISIG_CREATED, MULTISIG_EXECUTED, MULTISIG_PROPOSED,
};
use kovanica_common::{hash, Address, Amount, ContractError, ContractResult, Host};

pub type MultisigId = [u8; 32];
pub type TxId = u64;

/// Singleton state key (FIXED): one multisig instance per contract address.
const STATE_KEY: &[u8] = b"kvnc/v1/state";

/// bincode failed while serializing multisig state — infallible for these
/// field types in practice; surfaces state-layer corruption.
const ERR_BINCODE_SERIALIZE: u32 = 1;
/// bincode failed while deserializing stored multisig state (corrupt/foreign bytes).
const ERR_BINCODE_DESERIALIZE: u32 = 2;

/// Storage key for a pending tx: `b"kvnc/v1/mtx/" ++ tx_id.to_le_bytes()`.
fn tx_key(tx_id: TxId) -> Vec<u8> {
    let mut key = Vec::with_capacity(b"kvnc/v1/mtx/".len() + 8);
    key.extend_from_slice(b"kvnc/v1/mtx/");
    key.extend_from_slice(&tx_id.to_le_bytes());
    key
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Multisig {
    pub owners: BTreeSet<Address>,
    pub threshold: u32,
    pub next_tx_id: TxId,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingTx {
    pub id: TxId,
    pub to: Address,
    pub amount: Amount,
    pub data: Vec<u8>, // optional call data
    pub confirmations: BTreeSet<Address>,
    pub executed: bool,
}

impl Multisig {
    /// Deploy a new multisig instance (singleton state — one per contract
    /// address). Owners are exactly the provided list; duplicates collapse
    /// into the set. Returns the configuration-fingerprint id.
    pub fn create(
        host: &mut impl Host,
        owners: Vec<Address>,
        threshold: u32,
    ) -> ContractResult<MultisigId> {
        if owners.is_empty() || threshold == 0 || threshold as usize > owners.len() {
            return Err(ContractError::InvalidInput);
        }
        if Self::load(host).is_ok() {
            // Singleton model: never silently replace an existing instance.
            return Err(ContractError::AlreadyExists);
        }

        let mut set = BTreeSet::new();
        for o in owners {
            set.insert(o);
        }

        let ms = Multisig {
            owners: set,
            threshold,
            next_tx_id: 1,
        };

        let id = Self::compute_id(&ms);
        Self::store(host, &ms)?;
        host.emit_event(MULTISIG_CREATED, &id);
        Ok(id)
    }

    /// Propose a transfer / call. Any owner can propose; the proposer
    /// auto-confirms.
    pub fn propose(
        host: &mut impl Host,
        id: MultisigId,
        to: Address,
        amount: Amount,
        data: Vec<u8>,
    ) -> ContractResult<TxId> {
        let mut ms = Self::load_checked(host, &id)?;
        let caller = host.caller();
        if !ms.owners.contains(&caller) {
            return Err(ContractError::Unauthorized);
        }

        let tx_id = ms.next_tx_id;
        ms.next_tx_id = ms.next_tx_id.saturating_add(1);

        let mut conf = BTreeSet::new();
        conf.insert(caller); // proposer auto-confirms

        let tx = PendingTx {
            id: tx_id,
            to,
            amount,
            data,
            confirmations: conf,
            executed: false,
        };

        Self::store_tx(host, &tx)?;
        Self::store(host, &ms)?;

        host.emit_event(MULTISIG_PROPOSED, &tx_id.to_le_bytes());
        Ok(tx_id)
    }

    /// Confirm a pending transaction. Double confirmation is rejected.
    pub fn confirm(host: &mut impl Host, id: MultisigId, tx_id: TxId) -> ContractResult<()> {
        let ms = Self::load_checked(host, &id)?;
        let caller = host.caller();
        if !ms.owners.contains(&caller) {
            return Err(ContractError::Unauthorized);
        }

        let mut tx = Self::load_tx(host, tx_id)?;
        if tx.executed {
            return Err(ContractError::InvalidInput);
        }

        if !tx.confirmations.insert(caller) {
            // BTreeSet::insert returns false when the caller already confirmed.
            return Err(ContractError::AlreadyExists);
        }
        Self::store_tx(host, &tx)?;

        host.emit_event(MULTISIG_CONFIRMED, &tx_id.to_le_bytes());
        Ok(())
    }

    /// Execute once the threshold is reached. Anyone may trigger execution;
    /// funds move from the multisig contract's own account to `tx.to`.
    pub fn execute(host: &mut impl Host, id: MultisigId, tx_id: TxId) -> ContractResult<()> {
        let ms = Self::load_checked(host, &id)?;
        let mut tx = Self::load_tx(host, tx_id)?;

        if tx.executed {
            return Err(ContractError::InvalidInput);
        }
        if tx.confirmations.len() < ms.threshold as usize {
            return Err(ContractError::ThresholdNotMet);
        }

        // Funds come from the multisig contract's own account (funded
        // externally; Host::contract_address was added to the trait for this).
        let self_addr = host.contract_address();
        host.transfer(&self_addr, &tx.to, tx.amount)?;
        // Optional: if data is non-empty, host could forward a call.

        tx.executed = true;
        Self::store_tx(host, &tx)?;

        host.emit_event(MULTISIG_EXECUTED, &tx_id.to_le_bytes());
        Ok(())
    }

    // Owner management can be added later as special txs that also require threshold.

    // ---------- internal helpers ----------

    /// Deterministic configuration fingerprint — see crate docs for encoding.
    fn compute_id(ms: &Multisig) -> MultisigId {
        // b"multisig/id" || owners (32B each, BTreeSet ascending) || threshold_le(4)
        let mut buf = Vec::with_capacity(b"multisig/id".len() + ms.owners.len() * 32 + 4);
        buf.extend_from_slice(b"multisig/id");
        for o in &ms.owners {
            buf.extend_from_slice(o);
        }
        buf.extend_from_slice(&ms.threshold.to_le_bytes());
        hash(&buf)
    }

    /// Load singleton state and verify the caller-supplied id matches its
    /// configuration fingerprint (see crate docs).
    fn load_checked(host: &impl Host, id: &MultisigId) -> ContractResult<Multisig> {
        let ms = Self::load(host)?;
        if Self::compute_id(&ms) != *id {
            return Err(ContractError::NotFound);
        }
        Ok(ms)
    }

    fn store(host: &mut impl Host, ms: &Multisig) -> ContractResult<()> {
        let bytes =
            bincode::serialize(ms).map_err(|_| ContractError::Custom(ERR_BINCODE_SERIALIZE))?;
        host.storage_set(STATE_KEY, &bytes);
        Ok(())
    }

    fn load(host: &impl Host) -> ContractResult<Multisig> {
        let bytes = host.storage_get(STATE_KEY).ok_or(ContractError::NotFound)?;
        bincode::deserialize(&bytes).map_err(|_| ContractError::Custom(ERR_BINCODE_DESERIALIZE))
    }

    fn store_tx(host: &mut impl Host, tx: &PendingTx) -> ContractResult<()> {
        let bytes =
            bincode::serialize(tx).map_err(|_| ContractError::Custom(ERR_BINCODE_SERIALIZE))?;
        host.storage_set(&tx_key(tx.id), &bytes);
        Ok(())
    }

    fn load_tx(host: &impl Host, tx_id: TxId) -> ContractResult<PendingTx> {
        let bytes = host
            .storage_get(&tx_key(tx_id))
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
    pub extern "C" fn multisig_create(args_ptr: i32, args_len: i32) -> i64 {
        let Some(bytes) = (unsafe { args_slice(args_ptr, args_len) }) else {
            return error_code(ContractError::InvalidInput);
        };
        let (owners, threshold): (Vec<Address>, u32) = match decode_args(bytes) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let mut host = WasmHost::new();
        match Multisig::create(&mut host, owners, threshold) {
            Ok(id) => ok_out(&id),
            Err(e) => error_code(e),
        }
    }

    #[no_mangle]
    pub extern "C" fn multisig_propose(args_ptr: i32, args_len: i32) -> i64 {
        let Some(bytes) = (unsafe { args_slice(args_ptr, args_len) }) else {
            return error_code(ContractError::InvalidInput);
        };
        let (id, to, amount, data): (MultisigId, Address, Amount, Vec<u8>) =
            match decode_args(bytes) {
                Ok(v) => v,
                Err(c) => return c,
            };
        let mut host = WasmHost::new();
        match Multisig::propose(&mut host, id, to, amount, data) {
            Ok(tx_id) => ok_out(&tx_id),
            Err(e) => error_code(e),
        }
    }

    #[no_mangle]
    pub extern "C" fn multisig_confirm(args_ptr: i32, args_len: i32) -> i64 {
        let Some(bytes) = (unsafe { args_slice(args_ptr, args_len) }) else {
            return error_code(ContractError::InvalidInput);
        };
        let (id, tx_id): (MultisigId, TxId) = match decode_args(bytes) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let mut host = WasmHost::new();
        match Multisig::confirm(&mut host, id, tx_id) {
            Ok(()) => ok_out(&()),
            Err(e) => error_code(e),
        }
    }

    #[no_mangle]
    pub extern "C" fn multisig_execute(args_ptr: i32, args_len: i32) -> i64 {
        let Some(bytes) = (unsafe { args_slice(args_ptr, args_len) }) else {
            return error_code(ContractError::InvalidInput);
        };
        let (id, tx_id): (MultisigId, TxId) = match decode_args(bytes) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let mut host = WasmHost::new();
        match Multisig::execute(&mut host, id, tx_id) {
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

    const A: u8 = 1;
    const B: u8 = 2;
    const C: u8 = 3;
    const TO: u8 = 5;
    const CONTRACT: u8 = 9;

    fn setup(threshold: u32) -> (MemHost, MultisigId) {
        let mut host = MemHost::new(addr(A), addr(CONTRACT));
        let id = Multisig::create(&mut host, vec![addr(A), addr(B), addr(C)], threshold).unwrap();
        // Fund the multisig contract account for payouts.
        host.set_balance(addr(CONTRACT), 1_000);
        (host, id)
    }

    #[test]
    fn m_of_n_happy_path_with_threshold_enforcement() {
        let (mut host, id) = setup(2);

        // Propose (A auto-confirms).
        let tx_id = Multisig::propose(&mut host, id, addr(TO), 100, Vec::new()).unwrap();
        assert_eq!(tx_id, 1);

        // Below threshold → execute rejected, no funds move.
        assert_eq!(
            Multisig::execute(&mut host, id, tx_id),
            Err(ContractError::ThresholdNotMet)
        );
        assert_eq!(host.balance_of(&addr(CONTRACT)), 1_000);
        assert_eq!(host.balance_of(&addr(TO)), 0);

        // Second owner confirms (caller switched via MemHost) → threshold met.
        host.set_caller(addr(B));
        Multisig::confirm(&mut host, id, tx_id).unwrap();

        // Anyone may trigger execution once the threshold is met.
        Multisig::execute(&mut host, id, tx_id).unwrap();
        assert_eq!(host.balance_of(&addr(CONTRACT)), 900);
        assert_eq!(host.balance_of(&addr(TO)), 100);

        // Double execute rejected.
        assert_eq!(
            Multisig::execute(&mut host, id, tx_id),
            Err(ContractError::InvalidInput)
        );
    }

    #[test]
    fn threshold_one_executes_with_single_confirmation() {
        let (mut host, id) = setup(1);
        let tx_id = Multisig::propose(&mut host, id, addr(TO), 250, Vec::new()).unwrap();
        Multisig::execute(&mut host, id, tx_id).unwrap();
        assert_eq!(host.balance_of(&addr(TO)), 250);
    }

    #[test]
    fn double_confirm_rejected() {
        let (mut host, id) = setup(2);
        let tx_id = Multisig::propose(&mut host, id, addr(TO), 10, Vec::new()).unwrap();
        // Proposer already confirmed during propose.
        assert_eq!(
            Multisig::confirm(&mut host, id, tx_id),
            Err(ContractError::AlreadyExists)
        );
        // Confirmations were not corrupted by the rejected attempt.
        let tx = Multisig::load_tx(&host, tx_id).unwrap();
        assert_eq!(tx.confirmations.len(), 1);
    }

    #[test]
    fn unknown_tx_is_not_found() {
        let (mut host, id) = setup(2);
        assert_eq!(
            Multisig::confirm(&mut host, id, 99),
            Err(ContractError::NotFound)
        );
        assert_eq!(
            Multisig::execute(&mut host, id, 99),
            Err(ContractError::NotFound)
        );
    }

    #[test]
    fn non_owner_cannot_propose_or_confirm() {
        let (mut host, id) = setup(2);
        host.set_caller(addr(7)); // not an owner
        assert_eq!(
            Multisig::propose(&mut host, id, addr(TO), 10, Vec::new()),
            Err(ContractError::Unauthorized)
        );
        assert_eq!(
            Multisig::confirm(&mut host, id, 1),
            Err(ContractError::Unauthorized)
        );
    }

    #[test]
    fn wrong_multisig_id_rejected() {
        let (mut host, id) = setup(2);
        let mut bad = id;
        bad[0] ^= 0xFF;
        assert_eq!(
            Multisig::propose(&mut host, bad, addr(TO), 10, Vec::new()),
            Err(ContractError::NotFound)
        );
    }

    #[test]
    fn invalid_parameters_rejected() {
        let mut host = MemHost::new(addr(A), addr(CONTRACT));
        assert_eq!(
            Multisig::create(&mut host, vec![], 1),
            Err(ContractError::InvalidInput)
        );
        assert_eq!(
            Multisig::create(&mut host, vec![addr(A)], 0),
            Err(ContractError::InvalidInput)
        );
        assert_eq!(
            Multisig::create(&mut host, vec![addr(A)], 2),
            Err(ContractError::InvalidInput)
        );
    }

    #[test]
    fn duplicate_create_rejected() {
        let mut host = MemHost::new(addr(A), addr(CONTRACT));
        Multisig::create(&mut host, vec![addr(A), addr(B)], 1).unwrap();
        assert_eq!(
            Multisig::create(&mut host, vec![addr(A), addr(B)], 1),
            Err(ContractError::AlreadyExists)
        );
    }

    #[test]
    fn state_survives_new_host_instance() {
        let (mut h1, id) = setup(2);
        let tx_id = Multisig::propose(&mut h1, id, addr(TO), 100, Vec::new()).unwrap();

        // Second host instance over the SAME storage cell.
        let mut h2 = MemHost::with_shared(h1.shared(), addr(B), addr(CONTRACT));
        Multisig::confirm(&mut h2, id, tx_id).unwrap();
        Multisig::execute(&mut h2, id, tx_id).unwrap();
        assert_eq!(h2.balance_of(&addr(TO)), 100);

        // Fresh host cannot see the instance.
        let mut fresh = MemHost::new(addr(A), addr(CONTRACT));
        assert_eq!(
            Multisig::propose(&mut fresh, id, addr(TO), 1, Vec::new()),
            Err(ContractError::NotFound)
        );
    }

    #[test]
    fn id_is_deterministic_and_order_independent() {
        let mk = |owners: Vec<Address>, threshold: u32| {
            let mut host = MemHost::new(addr(A), addr(CONTRACT));
            Multisig::create(&mut host, owners, threshold).unwrap()
        };

        // Same inputs (different insertion order) → same id.
        let id1 = mk(vec![addr(A), addr(B), addr(C)], 2);
        let id2 = mk(vec![addr(C), addr(A), addr(B)], 2);
        assert_eq!(id1, id2);

        // Different threshold → different id.
        let id3 = mk(vec![addr(A), addr(B), addr(C)], 3);
        assert_ne!(id1, id3);

        // Different owner set → different id.
        let id4 = mk(vec![addr(A), addr(B)], 2);
        assert_ne!(id1, id4);
    }

    #[test]
    fn executed_tx_cannot_be_confirmed() {
        let (mut host, id) = setup(1);
        let tx_id = Multisig::propose(&mut host, id, addr(TO), 10, Vec::new()).unwrap();
        Multisig::execute(&mut host, id, tx_id).unwrap();
        host.set_caller(addr(B));
        assert_eq!(
            Multisig::confirm(&mut host, id, tx_id),
            Err(ContractError::InvalidInput)
        );
    }

    #[test]
    fn execute_with_insufficient_contract_balance_fails() {
        let (mut host, id) = setup(2);
        // Contract holds 1_000; propose more than that.
        let tx_id = Multisig::propose(&mut host, id, addr(TO), 5_000, Vec::new()).unwrap();
        host.set_caller(addr(B));
        Multisig::confirm(&mut host, id, tx_id).unwrap();
        assert_eq!(
            Multisig::execute(&mut host, id, tx_id),
            Err(ContractError::InsufficientBalance)
        );
        // Not marked executed — can retry after funding.
        host.set_balance(addr(CONTRACT), 10_000);
        Multisig::execute(&mut host, id, tx_id).unwrap();
        assert_eq!(host.balance_of(&addr(TO)), 5_000);
    }
}
