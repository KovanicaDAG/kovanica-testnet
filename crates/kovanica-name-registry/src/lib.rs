//! On-chain comms **name registry** for kovanica (ledger-safe contract).
//!
//! Maps a human-readable name to a comms identity record so peers can find a
//! recipient's Ed25519 public key and relay endpoints without out-of-band
//! exchange. First-come, owner-updatable; no fee in M1 (spec D4).
//!
//! Spec: `docs/COMMS-M1-INTERFACES.md` §6 (semantics) + §8 (ABI/export recipe).
//! ABI/export style mirrors `crates/kovanica-token` / `crates/kovanica-htlc`.
//!
//! ## Rules (FIXED — §6)
//!
//! - `register(name, pubkey, relay_endpoints)` — first-come; the name is taken
//!   by **anyone** including the caller → `AlreadyExists`; `owner = caller()`.
//! - `resolve(name)` → [`NameEntry`] (owner, pubkey, relay_endpoints) or `NotFound`.
//! - `update_endpoints(name, relay_endpoints)` — `Unauthorized` unless
//!   `caller() == owner`.
//! - `transfer(name, new_owner)` — `Unauthorized` unless owner.
//!
//! Name: `3..=32` bytes, `[a-z0-9-]` only, no leading/trailing `-`, no `--`;
//! **normalise-then-validate** (ASCII lowercase), reject otherwise
//! (`InvalidInput`). Stored lowercase.
//!
//! `relay_endpoints`: `≤ 8` entries, each `≤ 256` bytes, `http(s)://` scheme
//! only, else `InvalidInput`.
//!
//! ## Storage keys (FIXED)
//!
//! `b"kvnc/v1/name/" ++ utf8(lowercase_name)` → `bincode(NameEntry)`.
//!
//! **No global name list** — the registry deliberately has no enumerable index
//! (avoids on-chain enumeration, spec R11). Runtime hosts namespace storage per
//! contract address; the raw key above is what this contract passes to
//! `Host::storage_*`.
//!
//! Errors reuse [`ContractError`] (`Unauthorized` 0, `InvalidInput` 2,
//! `AlreadyExists` 3, `NotFound` 4), packed by the wasm ABI as `-1 - code()`.
//!
//! ## WASM entry points (wasm32 only; bincode args in, bincode results out)
//!
//! | export                  | args tuple                                                  | Ok result   |
//! |-------------------------|-------------------------------------------------------------|-------------|
//! | `name_register`         | `(String name, [u8;32] pubkey, Vec<String> relay_endpoints)`| `()`        |
//! | `name_resolve`          | `(String name,)`                                            | `NameEntry` |
//! | `name_update_endpoints` | `(String name, Vec<String> relay_endpoints)`                | `()`        |
//! | `name_transfer`         | `(String name, [u8;32] new_owner)`                          | `()`        |
//!
//! Return packing is identical to `kovanica-token` / `kovanica-htlc` (see crate docs
//! there): success `((out_ptr as u32 as i64) << 32) | (out_len as u32 as i64)`,
//! `out_len == 0` ⇒ null ptr; error `-(1 + ContractError::code())` within
//! `-12..=-1`; `kovanica_alloc` / `kovanica_dealloc` are exported alongside.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use kovanica_common::{Address, ContractError, ContractResult, Host};

/// Raw Ed25519 public key bytes (comms identity) — 32 bytes / 64 hex.
pub type PublicKey = [u8; 32];

/// Storage-key prefix for a name entry: `b"kvnc/v1/name/"`.
const KEY_PREFIX: &[u8] = b"kvnc/v1/name/";

/// Minimum name length (bytes).
const NAME_MIN: usize = 3;
/// Maximum name length (bytes).
const NAME_MAX: usize = 32;
/// Maximum number of relay endpoints per entry.
const MAX_ENDPOINTS: usize = 8;
/// Maximum length of a single relay endpoint (bytes).
const MAX_ENDPOINT_LEN: usize = 256;

/// bincode failed while serializing an entry — infallible for these field
/// types in practice; surfaces state-layer corruption.
const ERR_BINCODE_SERIALIZE: u32 = 1;
/// bincode failed while deserializing a stored entry (corrupt/foreign bytes).
const ERR_BINCODE_DESERIALIZE: u32 = 2;

/// A name-registry record: owner + comms identity + relays.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NameEntry {
    /// Current owner (the address allowed to `update_endpoints` / `transfer`).
    pub owner: Address,
    /// Ed25519 public key bound to the name (comms identity).
    pub pubkey: PublicKey,
    /// Relay endpoints (`http(s)://…`), ≤ 8 entries, each ≤ 256 bytes.
    pub relay_endpoints: Vec<String>,
}

/// Storage key for a (already normalised, lowercase) name.
///
/// Public so clients that read the raw contract-storage slot (`hash(entry_key)`)
/// derive the **exact same** key as this contract — single source of truth for
/// the `b"kvnc/v1/name/"` prefix. `name` must already be normalised lowercase.
pub fn entry_key(name: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(KEY_PREFIX.len() + name.len());
    key.extend_from_slice(KEY_PREFIX);
    key.extend_from_slice(name.as_bytes());
    key
}

/// Normalise (ASCII lowercase) then validate; returns the stored form.
///
/// Non-ASCII bytes survive lowercasing and then fail the charset check, so
/// they are rejected with `InvalidInput`.
fn normalise_name(name: &str) -> ContractResult<String> {
    let lowered: String = name.chars().map(|c| c.to_ascii_lowercase()).collect();
    let bytes = lowered.as_bytes();

    if bytes.len() < NAME_MIN || bytes.len() > NAME_MAX {
        return Err(ContractError::InvalidInput);
    }
    // Charset: strictly ASCII `[a-z0-9-]` (lowercased above).
    let charset_ok = bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
    if !charset_ok {
        return Err(ContractError::InvalidInput);
    }
    // No leading/trailing hyphen.
    if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
        return Err(ContractError::InvalidInput);
    }
    // No consecutive hyphens.
    if bytes.windows(2).any(|w| w == b"--") {
        return Err(ContractError::InvalidInput);
    }

    Ok(lowered)
}

/// Validate the relay-endpoint list: ≤ 8 entries, each ≤ 256 bytes,
/// `http(s)://` scheme only.
fn validate_endpoints(endpoints: &[String]) -> ContractResult<()> {
    if endpoints.len() > MAX_ENDPOINTS {
        return Err(ContractError::InvalidInput);
    }
    for ep in endpoints {
        if ep.len() > MAX_ENDPOINT_LEN {
            return Err(ContractError::InvalidInput);
        }
        if !(ep.starts_with("http://") || ep.starts_with("https://")) {
            return Err(ContractError::InvalidInput);
        }
    }
    Ok(())
}

fn load(host: &impl Host, key: &[u8]) -> ContractResult<NameEntry> {
    let bytes = host.storage_get(key).ok_or(ContractError::NotFound)?;
    bincode::deserialize(&bytes).map_err(|_| ContractError::Custom(ERR_BINCODE_DESERIALIZE))
}

fn store(host: &mut impl Host, key: &[u8], entry: &NameEntry) -> ContractResult<()> {
    let bytes =
        bincode::serialize(entry).map_err(|_| ContractError::Custom(ERR_BINCODE_SERIALIZE))?;
    host.storage_set(key, &bytes);
    Ok(())
}

/// Typed name-registry contract API (one instance per deployed contract —
/// state is namespaced by the runtime per contract address).
pub struct NameRegistry;

impl NameRegistry {
    /// Register a new name. First-come: any existing entry (including the
    /// caller's own) makes this `AlreadyExists`. Caller becomes owner.
    pub fn register(
        host: &mut impl Host,
        name: String,
        pubkey: PublicKey,
        relay_endpoints: Vec<String>,
    ) -> ContractResult<()> {
        let name = normalise_name(&name)?;
        validate_endpoints(&relay_endpoints)?;

        let key = entry_key(&name);
        if host.storage_get(&key).is_some() {
            return Err(ContractError::AlreadyExists);
        }

        let entry = NameEntry {
            owner: host.caller(),
            pubkey,
            relay_endpoints,
        };
        store(host, &key, &entry)
    }

    /// Resolve a name to its entry, or `NotFound`.
    pub fn resolve(host: &impl Host, name: &str) -> ContractResult<NameEntry> {
        let name = normalise_name(name)?;
        load(host, &entry_key(&name))
    }

    /// Replace the relay endpoints. `Unauthorized` unless the caller is owner.
    pub fn update_endpoints(
        host: &mut impl Host,
        name: String,
        relay_endpoints: Vec<String>,
    ) -> ContractResult<()> {
        let name = normalise_name(&name)?;
        validate_endpoints(&relay_endpoints)?;

        let key = entry_key(&name);
        let mut entry = load(host, &key)?;
        if host.caller() != entry.owner {
            return Err(ContractError::Unauthorized);
        }
        entry.relay_endpoints = relay_endpoints;
        store(host, &key, &entry)
    }

    /// Transfer ownership of a name. `Unauthorized` unless the caller is owner.
    pub fn transfer(host: &mut impl Host, name: String, new_owner: Address) -> ContractResult<()> {
        let name = normalise_name(&name)?;

        let key = entry_key(&name);
        let mut entry = load(host, &key)?;
        if host.caller() != entry.owner {
            return Err(ContractError::Unauthorized);
        }
        entry.owner = new_owner;
        store(host, &key, &entry)
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

    fn ok_out<T: serde::Serialize>(value: &T) -> i64 {
        match bincode::serialize(value) {
            Ok(bytes) => {
                if bytes.is_empty() {
                    0 // () results — null ptr, zero len
                } else {
                    // capacity == len so host-side kovanica_dealloc(ptr, len) is exact.
                    let mut buf = Vec::with_capacity(bytes.len());
                    buf.extend_from_slice(&bytes);
                    let ptr = buf.as_ptr();
                    let len = buf.len();
                    core::mem::forget(buf); // ownership → host
                    ((ptr as u32 as i64) << 32) | (len as u32 as i64)
                }
            }
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
    pub extern "C" fn name_register(args_ptr: i32, args_len: i32) -> i64 {
        let Some(bytes) = (unsafe { args_slice(args_ptr, args_len) }) else {
            return error_code(ContractError::InvalidInput);
        };
        let (name, pubkey, relay_endpoints): (String, PublicKey, Vec<String>) =
            match decode_args(bytes) {
                Ok(v) => v,
                Err(c) => return c,
            };
        let mut host = WasmHost::new();
        match NameRegistry::register(&mut host, name, pubkey, relay_endpoints) {
            Ok(()) => ok_out(&()),
            Err(e) => error_code(e),
        }
    }

    #[no_mangle]
    pub extern "C" fn name_resolve(args_ptr: i32, args_len: i32) -> i64 {
        let Some(bytes) = (unsafe { args_slice(args_ptr, args_len) }) else {
            return error_code(ContractError::InvalidInput);
        };
        let (name,): (String,) = match decode_args(bytes) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let host = WasmHost::new();
        match NameRegistry::resolve(&host, &name) {
            Ok(entry) => ok_out(&entry),
            Err(e) => error_code(e),
        }
    }

    #[no_mangle]
    pub extern "C" fn name_update_endpoints(args_ptr: i32, args_len: i32) -> i64 {
        let Some(bytes) = (unsafe { args_slice(args_ptr, args_len) }) else {
            return error_code(ContractError::InvalidInput);
        };
        let (name, relay_endpoints): (String, Vec<String>) = match decode_args(bytes) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let mut host = WasmHost::new();
        match NameRegistry::update_endpoints(&mut host, name, relay_endpoints) {
            Ok(()) => ok_out(&()),
            Err(e) => error_code(e),
        }
    }

    #[no_mangle]
    pub extern "C" fn name_transfer(args_ptr: i32, args_len: i32) -> i64 {
        let Some(bytes) = (unsafe { args_slice(args_ptr, args_len) }) else {
            return error_code(ContractError::InvalidInput);
        };
        let (name, new_owner): (String, Address) = match decode_args(bytes) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let mut host = WasmHost::new();
        match NameRegistry::transfer(&mut host, name, new_owner) {
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
    const CONTRACT: u8 = 9;

    fn eps(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| String::from(*s)).collect()
    }

    fn host(caller: u8) -> MemHost {
        MemHost::new(addr(caller), addr(CONTRACT))
    }

    fn register(host: &mut MemHost, name: &str, caller: u8, endpoints: &[&str]) {
        host.set_caller(addr(caller));
        NameRegistry::register(host, String::from(name), addr(0xAB), eps(endpoints)).unwrap();
    }

    #[test]
    fn register_and_resolve_round_trip() {
        let mut h = host(A);
        h.set_caller(addr(A));
        NameRegistry::register(
            &mut h,
            String::from("alice"),
            addr(0xAB),
            eps(&["https://relay.example.com"]),
        )
        .unwrap();

        let entry = NameRegistry::resolve(&h, "alice").unwrap();
        assert_eq!(entry.owner, addr(A));
        assert_eq!(entry.pubkey, addr(0xAB));
        assert_eq!(entry.relay_endpoints, eps(&["https://relay.example.com"]));
    }

    #[test]
    fn name_is_stored_lowercase_and_resolves_case_insensitively() {
        let mut h = host(A);
        register(&mut h, "Alice-2", A, &["https://relay.example.com"]);

        // Raw storage key uses the lowercase form.
        let key = entry_key("alice-2");
        assert!(h.storage_get(&key).is_some());

        // Resolve normalises the query too.
        let entry = NameRegistry::resolve(&h, "ALICE-2").unwrap();
        assert_eq!(entry.owner, addr(A));
        assert_eq!(NameRegistry::resolve(&h, "aLiCe-2").unwrap(), entry);
    }

    #[test]
    fn duplicate_name_rejected_even_by_original_owner() {
        let mut h = host(A);
        register(&mut h, "alice", A, &["https://relay.example.com"]);

        // Same caller re-registering (even with different case) → AlreadyExists.
        h.set_caller(addr(A));
        assert_eq!(
            NameRegistry::register(&mut h, String::from("ALICE"), addr(1), eps(&[])),
            Err(ContractError::AlreadyExists)
        );

        // A different caller → AlreadyExists.
        h.set_caller(addr(B));
        assert_eq!(
            NameRegistry::register(&mut h, String::from("alice"), addr(B), eps(&[])),
            Err(ContractError::AlreadyExists)
        );

        // Original record untouched.
        assert_eq!(NameRegistry::resolve(&h, "alice").unwrap().owner, addr(A));
    }

    #[test]
    fn invalid_names_rejected() {
        let mut h = host(A);
        h.set_caller(addr(A));

        let bad = [
            "ab",                                // too short
            "abcdefghijklmnopqrstuvwxyz1234567", // 33 chars → too long
            "-alice",                            // leading hyphen
            "alice-",                            // trailing hyphen
            "al--ice",                           // consecutive hyphens
            "al ice",                            // space
            "ali.ce",                            // dot
            "ali_ce",                            // underscore
            "alïce",                             // non-ASCII
            "",                                  // empty
        ];
        for name in bad {
            assert_eq!(
                NameRegistry::register(&mut h, String::from(name), addr(B), eps(&[])),
                Err(ContractError::InvalidInput),
                "name {name:?} should be rejected"
            );
            assert_eq!(
                NameRegistry::resolve(&h, name),
                Err(ContractError::InvalidInput),
                "resolve {name:?} should be rejected"
            );
        }

        // Boundary: exactly 3 and exactly 32 chars are valid.
        assert!(NameRegistry::register(&mut h, String::from("abc"), addr(B), eps(&[])).is_ok());
        assert!(NameRegistry::register(
            &mut h,
            String::from("abcdefghijklmnopqrstuvwxyz012345"), // 32 chars
            addr(B),
            eps(&[]),
        )
        .is_ok());
        // 33 chars is not.
        assert_eq!(
            NameRegistry::register(
                &mut h,
                String::from("abcdefghijklmnopqrstuvwxyz0123456"),
                addr(B),
                eps(&[]),
            ),
            Err(ContractError::InvalidInput)
        );
    }

    #[test]
    fn invalid_endpoints_rejected() {
        let mut h = host(A);
        h.set_caller(addr(A));

        // More than 8 endpoints.
        let nine = vec![String::from("https://r.example.com"); 9];
        assert_eq!(
            NameRegistry::register(&mut h, String::from("alice"), addr(B), nine),
            Err(ContractError::InvalidInput)
        );

        // Single endpoint over 256 bytes.
        let long = alloc::format!("https://{}", "a".repeat(256));
        assert!(long.len() > 256);
        assert_eq!(
            NameRegistry::register(&mut h, String::from("alice"), addr(B), vec![long]),
            Err(ContractError::InvalidInput)
        );

        // Bad / non-http scheme.
        for bad in ["ftp://relay.example.com", "relay.example.com", "ws://x"] {
            assert_eq!(
                NameRegistry::register(&mut h, String::from("alice"), addr(B), eps(&[bad])),
                Err(ContractError::InvalidInput),
                "endpoint {bad:?} should be rejected"
            );
        }

        // 8 endpoints, each exactly 256 bytes, http+https → accepted.
        let max_ok = vec![
            alloc::format!("https://{}", "a".repeat(256 - "https://".len())),
            alloc::format!("http://{}", "b".repeat(256 - "http://".len())),
        ];
        assert!(max_ok.iter().all(|e| e.len() == 256));
        let mut eight = max_ok.clone();
        eight.extend(vec![String::from("https://r.example.com"); 6]);
        assert_eq!(eight.len(), 8);
        assert!(NameRegistry::register(&mut h, String::from("alice"), addr(B), eight).is_ok());

        // Empty endpoint list is allowed.
        assert!(NameRegistry::register(&mut h, String::from("bob"), addr(B), eps(&[])).is_ok());
    }

    #[test]
    fn resolve_unknown_is_not_found() {
        let h = host(A);
        assert_eq!(
            NameRegistry::resolve(&h, "nobody"),
            Err(ContractError::NotFound)
        );
    }

    #[test]
    fn update_endpoints_requires_owner_and_succeeds_for_owner() {
        let mut h = host(A);
        register(&mut h, "alice", A, &["https://old.example.com"]);

        // Non-owner → Unauthorized; record unchanged.
        h.set_caller(addr(B));
        assert_eq!(
            NameRegistry::update_endpoints(&mut h, String::from("alice"), eps(&["https://evil"])),
            Err(ContractError::Unauthorized)
        );
        assert_eq!(
            NameRegistry::resolve(&h, "alice").unwrap().relay_endpoints,
            eps(&["https://old.example.com"])
        );

        // Owner → ok; resolve reflects the update.
        h.set_caller(addr(A));
        NameRegistry::update_endpoints(
            &mut h,
            String::from("alice"),
            eps(&["https://new.example.com", "http://alt.example.com"]),
        )
        .unwrap();
        assert_eq!(
            NameRegistry::resolve(&h, "alice").unwrap().relay_endpoints,
            eps(&["https://new.example.com", "http://alt.example.com"])
        );

        // Invalid endpoints are rejected even for the owner (state unchanged).
        assert_eq!(
            NameRegistry::update_endpoints(&mut h, String::from("alice"), eps(&["ftp://x"])),
            Err(ContractError::InvalidInput)
        );
        assert_eq!(
            NameRegistry::resolve(&h, "alice").unwrap().relay_endpoints,
            eps(&["https://new.example.com", "http://alt.example.com"])
        );
    }

    #[test]
    fn transfer_requires_owner_and_moves_ownership() {
        let mut h = host(A);
        register(&mut h, "alice", A, &["https://relay.example.com"]);

        // Non-owner cannot transfer.
        h.set_caller(addr(B));
        assert_eq!(
            NameRegistry::transfer(&mut h, String::from("alice"), addr(B)),
            Err(ContractError::Unauthorized)
        );

        // Owner transfers to B; pubkey/endpoints preserved.
        h.set_caller(addr(A));
        NameRegistry::transfer(&mut h, String::from("alice"), addr(B)).unwrap();
        let entry = NameRegistry::resolve(&h, "alice").unwrap();
        assert_eq!(entry.owner, addr(B));
        assert_eq!(entry.pubkey, addr(0xAB));
        assert_eq!(entry.relay_endpoints, eps(&["https://relay.example.com"]));

        // Old owner is now Unauthorized; new owner can update.
        h.set_caller(addr(A));
        assert_eq!(
            NameRegistry::update_endpoints(&mut h, String::from("alice"), eps(&[])),
            Err(ContractError::Unauthorized)
        );
        h.set_caller(addr(B));
        NameRegistry::update_endpoints(
            &mut h,
            String::from("alice"),
            eps(&["https://b.example.com"]),
        )
        .unwrap();
        assert_eq!(
            NameRegistry::resolve(&h, "alice").unwrap().relay_endpoints,
            eps(&["https://b.example.com"])
        );
    }

    #[test]
    fn update_or_transfer_unknown_is_not_found() {
        let mut h = host(A);
        h.set_caller(addr(A));
        assert_eq!(
            NameRegistry::update_endpoints(&mut h, String::from("ghost"), eps(&[])),
            Err(ContractError::NotFound)
        );
        assert_eq!(
            NameRegistry::transfer(&mut h, String::from("ghost"), addr(B)),
            Err(ContractError::NotFound)
        );
    }

    #[test]
    fn state_survives_a_second_host_instance_over_shared_storage() {
        let mut h1 = host(A);
        register(&mut h1, "alice", A, &["https://relay.example.com"]);

        // Second instance over the SAME storage cell.
        let mut h2 = MemHost::with_shared(h1.shared(), addr(A), addr(CONTRACT));
        assert_eq!(NameRegistry::resolve(&h2, "alice").unwrap().owner, addr(A));
        NameRegistry::transfer(&mut h2, String::from("alice"), addr(B)).unwrap();

        // Fresh, isolated host sees nothing.
        let mut fresh = host(B);
        assert_eq!(
            NameRegistry::resolve(&fresh, "alice"),
            Err(ContractError::NotFound)
        );
        assert_eq!(
            NameRegistry::register(&mut fresh, String::from("alice"), addr(B), eps(&[])),
            Ok(())
        );
    }

    #[test]
    fn two_names_use_distinct_keys_no_global_list() {
        let mut h = host(A);
        register(&mut h, "alice", A, &["https://a.example.com"]);
        register(&mut h, "bob", A, &["https://b.example.com"]);

        assert_eq!(
            NameRegistry::resolve(&h, "alice").unwrap().pubkey,
            addr(0xAB)
        );
        assert_eq!(NameRegistry::resolve(&h, "bob").unwrap().pubkey, addr(0xAB));

        // Only the two per-name keys exist — there is no enumerable name index.
        let prefix_count = h
            .shared()
            .borrow()
            .storage
            .keys()
            .filter(|k| k.starts_with(KEY_PREFIX))
            .count();
        assert_eq!(prefix_count, 2);
    }
}
