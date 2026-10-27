#!/usr/bin/env rust
//! Generate 5 validator keystores and genesis_validators.toml for Chain 4 testnet

use std::fs;
use std::path::Path;

use kovanica_cli::wallet;

const PASSPHRASE: &str = "devnet-phase16.6";
const OUTDIR: &str = "genesis/chain4";

fn main() -> anyhow::Result<()> {
    fs::create_dir_all(OUTDIR)?;

    let mut validators = Vec::new();

    for i in 1..=5 {
        println!("Generating validator {i}...");
        let keystore = wallet::keygen(PASSPHRASE)?;

        let keystore_path = format!("{OUTDIR}/validator{i}.keystore");
        wallet::save_replace(Path::new(&keystore_path), &keystore)?;

        // Export raw seed
        let seed = wallet::secret_seed(&keystore, Some(PASSPHRASE))?;
        let seed_path = format!("{OUTDIR}/validator{i}.pem");
        fs::write(&seed_path, hex::encode(&seed))?;

        let address = wallet::address(&keystore)?;
        let public_key = wallet::public_key(&keystore)?;
        let public_key_hex = hex::encode(public_key.as_bytes());

        println!("  Address: {}", address);
        println!("  Public key: {}", public_key_hex);
        println!("  Seed: {}", hex::encode(&seed));

        validators.push((address, public_key_hex, seed));

        println!("  Saved to {}", keystore_path);
    }

    // Generate genesis_validators.toml with [[validator]] array-of-tables format
    let mut toml = String::from("# Chain 4 — 5-node validator set for genesis\n");
    toml.push_str("# Stakes = 100_000 KUNA (100_000_000_000_000 atoms)\n");
    toml.push_str("# Generated from keystores\n");
    toml.push_str("chain_id = 4\n\n");

    for (address, public_key_hex, _seed) in &validators {
        toml.push_str("[[validator]]\n");
        // Canonical 64-character base32 address (PRO-21)
        toml.push_str(&format!("address = \"{address}\"\n"));
        toml.push_str("stake = 100000000000000\n");
        toml.push_str(&format!("public_key = \"{public_key_hex}\"\n\n"));
    }

    let toml_path = format!("{OUTDIR}/genesis_validators.toml");
    fs::write(&toml_path, &toml)?;
    println!("Generated {toml_path}");

    // Generate Faucet keystore and funded_accounts.toml
    println!("Generating faucet keystore...");
    let faucet_keystore = wallet::keygen(PASSPHRASE)?;
    let faucet_keystore_path = format!("{OUTDIR}/faucet.keystore");
    wallet::save_replace(Path::new(&faucet_keystore_path), &faucet_keystore)?;

    let faucet_seed = wallet::secret_seed(&faucet_keystore, Some(PASSPHRASE))?;
    let faucet_seed_path = format!("{OUTDIR}/faucet.pem");
    fs::write(&faucet_seed_path, hex::encode(&faucet_seed))?;

    let faucet_address = wallet::address(&faucet_keystore)?;
    println!("  Faucet Address: {}", faucet_address);
    println!("  Faucet Seed: {}", hex::encode(&faucet_seed));

    let mut funded_toml = String::from("# Chain 4 — Funded Accounts for Testnet\n");
    funded_toml.push_str("# Pre-funded 1,000,000 KUNA for Faucet\n\n");
    funded_toml.push_str("[[account]]\n");
    funded_toml.push_str(&format!("address = \"{faucet_address}\"\n"));
    funded_toml.push_str("balance = 1000000000000000\n");

    let funded_path = format!("{OUTDIR}/funded_accounts.toml");
    fs::write(&funded_path, &funded_toml)?;
    println!("Generated {funded_path}");

    // Generate founder_premine.hex
    // Zero address KAT_ZERO = Address([0u8; 32])
    let founder_address = "kvncqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz4k5rcdag";
    let founder_path = format!("{OUTDIR}/founder_premine.hex");
    fs::write(&founder_path, format!("{founder_address}\n"))?;
    println!("Generated {founder_path}");

    // Also copy to ops/docker/validators/ for docker-compose if present
    let docker_dir = Path::new("ops/docker/validators");
    if docker_dir.exists() {
        let docker_toml_path = docker_dir.join("genesis_validators.toml");
        fs::write(&docker_toml_path, &toml)?;
        println!("Updated {}", docker_toml_path.display());

        // Copy pem files to docker validators dir
        for i in 1..=5 {
            let src = format!("{OUTDIR}/validator{i}.pem");
            let dst = docker_dir.join(format!("val{i}.pem"));
            fs::copy(&src, &dst)?;
            println!("Copied {src} -> {}", dst.display());
        }

        let docker_funded = docker_dir.join("funded_accounts.toml");
        fs::write(&docker_funded, &funded_toml)?;
        let docker_founder = docker_dir.join("founder_premine.hex");
        fs::write(&docker_founder, format!("{founder_address}\n"))?;
    }

    println!("\nAll 5 validator keys, faucet, and genesis files generated successfully!");
    Ok(())
}
