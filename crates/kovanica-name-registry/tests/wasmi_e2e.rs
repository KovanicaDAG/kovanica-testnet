//! Stretch e2e: drive the compiled `kovanica-name-registry` **wasm** artifact
//! through the real wasmi runtime (`kovanica-execution` → `kovanica-runtime` → `env`
//! imports → `ContractHost`), mirroring
//! `crates/kovanica-execution/src/contracts.rs::wasmi_e2e_kovanica_token_wasm`.
//!
//! Skips gracefully (eprintln + return) when rustup or the
//! `wasm32-unknown-unknown` target is unavailable. Once the target is present,
//! a build failure is a real failure and fails the test (same policy as the
//! reference test).
//!
//! The wasm subprocess build uses an **isolated** `CARGO_TARGET_DIR` so the
//! outer `cargo test` does not hold the target-dir lock the subprocess would
//! wait on.

use std::path::{Path, PathBuf};

use kovanica_common::hash;
use kovanica_execution::{ContractRunner, ExecutionError, WasmCall};
use kovanica_name_registry::NameEntry;
use kovanica_runtime::{ExecutionConfig, RuntimeError};
use kovanica_storage::Storage;
use kovanica_types::Address;

/// Raw storage-key prefix (FIXED — see crate docs / spec §6).
const KEY_PREFIX: &[u8] = b"kvnc/v1/name/";

fn workspace_root() -> PathBuf {
    let start = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut dir = start;
    loop {
        if let Ok(text) = std::fs::read_to_string(dir.join("Cargo.toml")) {
            if text.contains("[workspace]") {
                return dir.to_path_buf();
            }
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => return start.to_path_buf(),
        }
    }
}

fn addr(tag: u8) -> Address {
    Address([tag; 32])
}

fn native_addr(tag: u8) -> kovanica_common::Address {
    [tag; 32]
}

/// Build the crate's cdylib for wasm32 in an isolated target dir and return
/// the `.wasm` bytes. Skips (returns `None`) when the toolchain can't target
/// wasm32.
fn build_wasm() -> Option<Vec<u8>> {
    let workspace_root = workspace_root();

    let probe = std::process::Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output();
    let probe = match probe {
        Ok(output) if output.status.success() => output,
        _ => {
            eprintln!("SKIP wasmi_e2e_name_registry_wasm: rustup unavailable");
            return None;
        }
    };
    let has_target = String::from_utf8_lossy(&probe.stdout)
        .lines()
        .any(|line| line.trim() == "wasm32-unknown-unknown");
    if !has_target {
        eprintln!("SKIP wasmi_e2e_name_registry_wasm: wasm32-unknown-unknown not installed");
        return None;
    }

    let target_dir = workspace_root.join("target").join("contract-wasm-e2e");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let build = std::process::Command::new(&cargo)
        .current_dir(&workspace_root)
        .env("CARGO_TARGET_DIR", &target_dir)
        .args([
            "build",
            "-p",
            "kovanica-name-registry",
            "--target",
            "wasm32-unknown-unknown",
            "--release",
        ])
        .output()
        .expect("failed to spawn cargo for the wasm contract build");
    assert!(
        build.status.success(),
        "wasm contract build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );

    let wasm_path = target_dir
        .join("wasm32-unknown-unknown")
        .join("release")
        .join("kovanica_name_registry.wasm");
    let wasm = std::fs::read(&wasm_path)
        .unwrap_or_else(|err| panic!("built wasm missing at {}: {err}", wasm_path.display()));
    assert!(!wasm.is_empty(), "empty wasm artifact");
    Some(wasm)
}

#[test]
fn wasmi_e2e_name_registry_wasm() {
    let Some(wasm) = build_wasm() else {
        return;
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Storage::new(dir.path().join("name-registry.redb")).expect("storage");

    let owner = addr(1);
    let contract = addr(40);
    let config = ExecutionConfig {
        gas_limit: 100_000_000,
        memory_limit_pages: 256, // rust-std contracts need more than the 16-page default
    };
    let mut runner = ContractRunner::new();

    // --- name_register via the real wasm path (name sent mixed-case: the
    // contract normalises to lowercase before storing) ---
    let pubkey: [u8; 32] = [0xAB; 32];
    let endpoints: Vec<String> = vec![
        String::from("https://relay.example.com"),
        String::from("http://relay2.example.com"),
    ];
    let register_args =
        bincode::serialize(&(String::from("Alice"), pubkey, endpoints.clone())).expect("encode");
    runner
        .execute_wasm_call(WasmCall {
            wasm: &wasm,
            entry: "name_register",
            contract,
            caller: owner,
            height: 1,
            timestamp: 1_000,
            args: &register_args,
            storage: &storage,
            txn: None,
            value: 0,
            config: &config,
        })
        .expect("wasm name_register");

    // --- name_resolve via the real wasm path, same runner (module cache);
    // the resolver need not be the owner ---
    let resolve_args = bincode::serialize(&(String::from("alice"),)).expect("encode");
    let (out, _events) = runner
        .execute_wasm_call(WasmCall {
            wasm: &wasm,
            entry: "name_resolve",
            contract,
            caller: addr(2),
            height: 2,
            timestamp: 1_100,
            args: &resolve_args,
            storage: &storage,
            txn: None,
            value: 0,
            config: &config,
        })
        .expect("wasm name_resolve");

    let entry: NameEntry = bincode::deserialize(&out).expect("resolve output decodes");
    assert_eq!(entry.owner, native_addr(1));
    assert_eq!(entry.pubkey, pubkey);
    assert_eq!(entry.relay_endpoints, endpoints);

    // --- prove the committed bytes straight out of persistent storage,
    // independently of any dispatch path (namespaced by contract address) ---
    let txn = storage.begin_read().expect("read txn");
    let raw = storage
        .state()
        .get_storage(&txn, &contract, &hash(&[KEY_PREFIX, b"alice"].concat()))
        .expect("storage read")
        .expect("entry after a successful register");
    let stored: NameEntry = bincode::deserialize(&raw).expect("stored entry decodes");
    assert_eq!(stored, entry);

    // --- duplicate register over wasm is rejected; the contract error code
    // (AlreadyExists = 3) survives the wasm ABI round-trip ---
    let err = runner
        .execute_wasm_call(WasmCall {
            wasm: &wasm,
            entry: "name_register",
            contract,
            caller: addr(2),
            height: 3,
            timestamp: 1_200,
            args: &register_args,
            storage: &storage,
            txn: None,
            value: 0,
            config: &config,
        })
        .expect_err("duplicate name_register must fail");
    assert!(
        matches!(
            err,
            ExecutionError::Runtime(RuntimeError::Contract(3)) // 3 = AlreadyExists
        ),
        "unexpected error: {err:?}"
    );

    // Nothing was committed by the rejected call — the record is intact.
    let txn = storage.begin_read().expect("read txn");
    let raw = storage
        .state()
        .get_storage(&txn, &contract, &hash(&[KEY_PREFIX, b"alice"].concat()))
        .expect("storage read")
        .expect("entry still present");
    let after: NameEntry = bincode::deserialize(&raw).expect("entry decodes");
    assert_eq!(after, entry);
}
