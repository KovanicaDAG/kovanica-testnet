//! In-memory [`Host`] implementation for tests and native fallback.
//!
//! `MemHost` is `no_std` + `alloc` friendly: it is built from `alloc::rc::Rc`,
//! `core::cell::RefCell`, `alloc::collections::BTreeMap` and `alloc::vec::Vec`
//! only — it needs an allocator when it actually allocates, nothing else.
//!
//! Storage, native balances and the event log live in one shared [`MemShared`]
//! cell behind an `Rc<RefCell<..>>`. This is deliberate: a test can create
//! **two `MemHost` instances over the SAME storage** (via [`MemHost::with_shared`]
//! or by cloning a host) and prove that contract state persists across
//! "instances". `caller`, `contract_address`, `block_height` and `timestamp`
//! are per-instance and freely settable between calls.
//!
//! Note on namespacing: the raw storage map is *not* prefixed per contract
//! address. Production runtimes are expected to namespace storage per contract;
//! tests that run several contracts against one `MemShared` cell must either
//! use distinct record ids or separate cells.

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::{Address, Amount, ContractError, ContractResult, Height, Host, Timestamp};

/// Shared mutable state behind one or more [`MemHost`] instances.
#[derive(Debug, Default)]
pub struct MemShared {
    /// Contract storage (`Host::storage_get` / `Host::storage_set`).
    pub storage: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Native-token balances per address.
    pub balances: BTreeMap<Address, Amount>,
    /// Append-only event log: `(topic, data)` pairs in emission order.
    pub events: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Shared handle to a [`MemShared`] cell.
pub type SharedMem = Rc<RefCell<MemShared>>;

/// In-memory [`Host`] for tests / native fallback.
///
/// Cloning a `MemHost` copies the per-instance fields **and shares the
/// underlying [`MemShared`] cell** — that is the intended way to simulate a
/// second execution "instance" over persisted state. Use [`MemHost::new`] for
/// an isolated instance with fresh storage.
#[derive(Debug, Clone)]
pub struct MemHost {
    shared: SharedMem,
    caller: Address,
    contract_address: Address,
    block_height: Height,
    timestamp: Timestamp,
}

impl MemHost {
    /// Fresh instance with its own empty storage / balances / event log.
    pub fn new(caller: Address, contract_address: Address) -> Self {
        Self::with_shared(
            Rc::new(RefCell::new(MemShared::default())),
            caller,
            contract_address,
        )
    }

    /// Instance over an existing shared cell (persistence tests).
    pub fn with_shared(shared: SharedMem, caller: Address, contract_address: Address) -> Self {
        Self {
            shared,
            caller,
            contract_address,
            block_height: 0,
            timestamp: 0,
        }
    }

    /// Shared cell handle (already a fresh `Rc` clone — pass it to
    /// [`MemHost::with_shared`] to build a second host over the same state).
    pub fn shared(&self) -> SharedMem {
        Rc::clone(&self.shared)
    }

    pub fn set_caller(&mut self, caller: Address) {
        self.caller = caller;
    }

    pub fn set_contract_address(&mut self, addr: Address) {
        self.contract_address = addr;
    }

    pub fn set_block_height(&mut self, height: Height) {
        self.block_height = height;
    }

    pub fn set_timestamp(&mut self, timestamp: Timestamp) {
        self.timestamp = timestamp;
    }

    /// Directly set a native balance (test funding helper).
    pub fn set_balance(&mut self, addr: Address, amount: Amount) {
        self.shared.borrow_mut().balances.insert(addr, amount);
    }

    /// Snapshot of the emitted event log.
    pub fn events(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.shared.borrow().events.clone()
    }
}

impl Host for MemHost {
    fn caller(&self) -> Address {
        self.caller
    }

    fn contract_address(&self) -> Address {
        self.contract_address
    }

    fn block_height(&self) -> Height {
        self.block_height
    }

    fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    fn balance_of(&self, addr: &Address) -> Amount {
        self.shared
            .borrow()
            .balances
            .get(addr)
            .copied()
            .unwrap_or(0)
    }

    fn transfer(&mut self, from: &Address, to: &Address, amount: Amount) -> ContractResult<()> {
        let mut shared = self.shared.borrow_mut();
        let from_bal = shared.balances.get(from).copied().unwrap_or(0);
        if from_bal < amount {
            return Err(ContractError::InsufficientBalance);
        }
        if from == to {
            // Net-zero self transfer: only the balance floor is enforced.
            return Ok(());
        }
        let to_bal = shared.balances.get(to).copied().unwrap_or(0);
        let new_to = to_bal.checked_add(amount).ok_or(ContractError::Overflow)?;
        // Both checks passed — mutate atomically.
        shared.balances.insert(*from, from_bal - amount);
        shared.balances.insert(*to, new_to);
        Ok(())
    }

    fn emit_event(&mut self, topic: &[u8], data: &[u8]) {
        self.shared
            .borrow_mut()
            .events
            .push((topic.to_vec(), data.to_vec()));
    }

    fn storage_get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.shared.borrow().storage.get(key).cloned()
    }

    fn storage_set(&mut self, key: &[u8], value: &[u8]) {
        self.shared
            .borrow_mut()
            .storage
            .insert(key.to_vec(), value.to_vec());
    }
}
