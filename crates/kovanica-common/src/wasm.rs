//! wasm32 [`Host`] backed by `env`-module imports (the fixed kovanica contract ABI).
//!
//! This module only compiles for `target_arch = "wasm32"`; native builds use
//! the typed API directly and never see these imports. The importing side
//! (Lane 3b's runtime) must register every function below in module `"env"`.
//!
//! Import signatures (FIXED — do not change without a lane coordination):
//!
//! ```text
//! kovanica_caller(out_ptr: i32)                          // writes 32 bytes
//! kovanica_contract_address(out_ptr: i32)                // writes 32 bytes
//! kovanica_block_height() -> i64
//! kovanica_timestamp() -> i64
//! kovanica_balance_of(ptr: i32, len: i32) -> i64         // u64 balance as i64; -1 = error
//! kovanica_transfer(fp, fl, tp, tl: i32, amount: i64) -> i32   // 0 = ok
//! kovanica_storage_get(kp, kl, out_ptr: i32, out_cap: i32) -> i32
//!    // two-step: out_cap = 0 → needed len (> 0) or -1 (absent);
//!    // then alloc & call again; out_cap too small → -2
//! kovanica_storage_set(kp, kl, vp, vl: i32) -> i32      // 0 = ok
//! kovanica_emit_event(tp, tl, dp, dl: i32)
//! ```
//!
//! Notes for Lane 3b:
//! - `caller` / `contract_address` / `block_height` / `timestamp` are fetched
//!   from the host on every call (no caching) so values always reflect the
//!   current call frame.
//! - `balance_of` has no error channel in the `Host` trait: a host error (-1)
//!   is reported as balance 0; failures surface via the `transfer` path.
//! - `transfer` amounts that do not fit the i64 host slot (`> i64::MAX` as
//!   `u128`, which covers the ABI's `> u64::MAX` case) are rejected
//!   client-side with `ContractError::Overflow` before the import is called.
//! - `storage_set` has no error channel; a non-zero rc is swallowed (runtime
//!   level failure — the typed contract result has already been computed).
//!
//! Requires an allocator at link time: with the default `std` feature this is
//! std's allocator on `wasm32-unknown-unknown`; a pure no_std wasm build must
//! provide a `#[global_allocator]`.

use alloc::vec::Vec;

use crate::{Address, Amount, ContractError, ContractResult, Height, Host, Timestamp};

mod imports {
    #[link(wasm_import_module = "env")]
    extern "C" {
        pub fn kovanica_caller(out_ptr: i32);
        pub fn kovanica_contract_address(out_ptr: i32);
        pub fn kovanica_block_height() -> i64;
        pub fn kovanica_timestamp() -> i64;
        pub fn kovanica_balance_of(ptr: i32, len: i32) -> i64;
        pub fn kovanica_transfer(fp: i32, fl: i32, tp: i32, tl: i32, amount: i64) -> i32;
        pub fn kovanica_storage_get(kp: i32, kl: i32, out_ptr: i32, out_cap: i32) -> i32;
        pub fn kovanica_storage_set(kp: i32, kl: i32, vp: i32, vl: i32) -> i32;
        pub fn kovanica_emit_event(tp: i32, tl: i32, dp: i32, dl: i32);
    }
}

/// Host implementation over the `env` wasm imports.
pub struct WasmHost;

impl WasmHost {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WasmHost {
    fn default() -> Self {
        Self::new()
    }
}

impl Host for WasmHost {
    fn caller(&self) -> Address {
        let mut out = [0u8; 32];
        unsafe { imports::kovanica_caller(out.as_mut_ptr() as i32) };
        out
    }

    fn contract_address(&self) -> Address {
        let mut out = [0u8; 32];
        unsafe { imports::kovanica_contract_address(out.as_mut_ptr() as i32) };
        out
    }

    fn block_height(&self) -> Height {
        let v = unsafe { imports::kovanica_block_height() };
        if v < 0 {
            0 // negative = host error → treat as 0
        } else {
            v as u64
        }
    }

    fn timestamp(&self) -> Timestamp {
        let v = unsafe { imports::kovanica_timestamp() };
        if v < 0 {
            0
        } else {
            v as u64
        }
    }

    fn balance_of(&self, addr: &Address) -> Amount {
        // Host reports a u64 balance reinterpreted as i64; -1 = error → 0.
        let v = unsafe { imports::kovanica_balance_of(addr.as_ptr() as i32, addr.len() as i32) };
        if v < 0 {
            0
        } else {
            v as u64 as Amount
        }
    }

    fn transfer(&mut self, from: &Address, to: &Address, amount: Amount) -> ContractResult<()> {
        // ABI: u128 amounts that do not fit the i64 host slot are rejected
        // client-side with Overflow (covers `> u64::MAX` per the ABI note).
        if amount > i64::MAX as u128 {
            return Err(ContractError::Overflow);
        }
        let rc = unsafe {
            imports::kovanica_transfer(
                from.as_ptr() as i32,
                from.len() as i32,
                to.as_ptr() as i32,
                to.len() as i32,
                amount as i64,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            let code = -1 - rc;
            if let Some(err) = ContractError::from_code(code) {
                Err(err)
            } else {
                Err(ContractError::Custom(rc.unsigned_abs()))
            }
        }
    }

    fn emit_event(&mut self, topic: &[u8], data: &[u8]) {
        unsafe {
            imports::kovanica_emit_event(
                topic.as_ptr() as i32,
                topic.len() as i32,
                data.as_ptr() as i32,
                data.len() as i32,
            );
        }
    }

    fn storage_get(&self, key: &[u8]) -> Option<Vec<u8>> {
        // Two-step protocol (fixed ABI):
        //   1. out_cap = 0 → needed length (> 0), or -1 when absent.
        //   2. allocate `needed` bytes and call again; -2 = capacity too small.
        let needed =
            unsafe { imports::kovanica_storage_get(key.as_ptr() as i32, key.len() as i32, 0, 0) };
        if needed <= 0 {
            return None; // absent (or host error)
        }
        let mut buf = alloc::vec![0u8; needed as usize];
        let got = unsafe {
            imports::kovanica_storage_get(
                key.as_ptr() as i32,
                key.len() as i32,
                buf.as_mut_ptr() as i32,
                needed,
            )
        };
        if got < 0 {
            return None; // -2: capacity raced smaller; treat as absent
        }
        buf.truncate(got as usize);
        Some(buf)
    }

    fn storage_set(&mut self, key: &[u8], value: &[u8]) {
        let _rc = unsafe {
            imports::kovanica_storage_set(
                key.as_ptr() as i32,
                key.len() as i32,
                value.as_ptr() as i32,
                value.len() as i32,
            )
        };
    }
}
