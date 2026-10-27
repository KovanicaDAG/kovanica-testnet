//! `kovanica comms` — Kovanica comms app control-plane helpers.
//!
//! Currently exposes identity derivation: `kovanica comms id --keystore <FILE>`
//! prints the canonical address, Ed25519 public key and the derived comms id.
//!
//! Identity is derived purely from the keystore's *public* metadata, so this
//! command never prompts for a passphrase and never touches private key
//! material. Nothing here is consensus-critical.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use serde_json::json;

use kovanica_comms_core::comms_id_from_slice;

use crate::{output, wallet};

/// Subcommands under `kovanica comms`.
#[derive(Subcommand)]
pub enum CommsCommand {
    /// Derive the comms id from a keystore's Ed25519 public key
    Id(CommsIdArgs),
}

/// Arguments for `kovanica comms id`.
#[derive(Args)]
pub struct CommsIdArgs {
    /// Keystore file path
    #[arg(long, short, default_value = "keystore.json")]
    pub keystore: PathBuf,
}

/// Dispatch a `kovanica comms` subcommand.
pub fn run(command: CommsCommand, json_output: bool) -> Result<()> {
    match command {
        CommsCommand::Id(args) => id(args, json_output),
    }
}

fn id(args: CommsIdArgs, json_output: bool) -> Result<()> {
    let keystore = wallet::load(&args.keystore)?;
    let address = wallet::address(&keystore)?;
    let public_key = wallet::public_key(&keystore)?;
    let public_key_hex = hex::encode(public_key.as_bytes());
    // The keystore parser guarantees a 32-byte public key; fall back gracefully.
    let comms_id = comms_id_from_slice(public_key.as_bytes())
        .ok_or_else(|| anyhow::anyhow!("keystore public key is not 32 bytes"))?;

    if json_output {
        return output::print_json(&json!({
            "keystore": args.keystore.display().to_string(),
            "address": address.to_string(),
            "publicKey": public_key_hex,
            "commsId": comms_id.to_hex(),
        }));
    }

    println!("Keystore:   {}", args.keystore.display());
    println!("Address:    {address}");
    println!("Public key: {public_key_hex}");
    println!("Comms id:   {}", comms_id.to_hex());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    #[command(name = "kovanica")]
    struct TestCli {
        #[command(subcommand)]
        command: TestCommands,
    }

    #[derive(Subcommand)]
    enum TestCommands {
        Comms {
            #[command(subcommand)]
            command: CommsCommand,
        },
    }

    #[test]
    fn comms_id_defaults_to_keystore_json() {
        let cli = TestCli::try_parse_from(["kovanica", "comms", "id"]).unwrap();
        match cli.command {
            TestCommands::Comms {
                command: CommsCommand::Id(args),
            } => assert_eq!(args.keystore, PathBuf::from("keystore.json")),
        }
    }

    #[test]
    fn comms_id_accepts_explicit_keystore() {
        let cli = TestCli::try_parse_from(["kovanica", "comms", "id", "--keystore", "alice.json"])
            .unwrap();
        match cli.command {
            TestCommands::Comms {
                command: CommsCommand::Id(args),
            } => assert_eq!(args.keystore, PathBuf::from("alice.json")),
        }
    }

    // End-to-end through the real keystore API (no TTY: the command only needs
    // the keystore's *public* metadata, so it never prompts for a passphrase).
    #[test]
    fn id_derives_from_a_saved_keystore() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ks.json");

        let keystore = kovanica_keystore::from_seed(&[9u8; 32], "correct horse").unwrap();
        kovanica_keystore::save(&path, &keystore).unwrap();

        // JSON path: must succeed without any passphrase.
        id(CommsIdArgs { keystore: path }, true).unwrap();
    }
}
