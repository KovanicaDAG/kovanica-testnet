// Kovanica Comms desktop shell (Tauri v2).
//
// M0 scaffold: the webview derives identity + RPC head via `@kovanica/comms`, and
// this Rust side exposes the *same* canonical identity through the IPC bridge
// using `kovanica-comms-core` (so Rust and TS agree on the comms id).

// Prevents an extra console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use kovanica_comms_core::comms_id_from_slice;

/// Minimal placeholder command proving the IPC bridge works.
#[tauri::command]
fn comms_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Derive the canonical comms id from a 32-byte Ed25519 public key (hex).
///
/// Mirrors `deriveCommsId` in `@kovanica/comms`; returns an error string on bad input.
#[tauri::command]
fn derive_comms_id(public_key_hex: String) -> Result<String, String> {
    let raw = public_key_hex.trim();
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex_decode(raw)?;
    comms_id_from_slice(&bytes)
        .map(|id| id.to_hex())
        .ok_or_else(|| "public key must be 32 bytes".to_string())
}

/// Tiny local hex decoder to avoid pulling an extra dependency into the shell.
fn hex_decode(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err("hex input must have an even length".to_string());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("invalid hex character: {}", c as char)),
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![comms_version, derive_comms_id])
        .run(tauri::generate_context!())
        .expect("error while running Kovanica Comms");
}
