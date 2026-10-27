//! `kovanica-lightnode` — follow commit seals and submit transfers.
//!
//! This process is not a validator. It does not propose blocks or cast votes.

#![deny(unsafe_code)]

use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use kovanica_keystore::parse_address;
use kovanica_lightnode::config::LightConfig;
use kovanica_lightnode::register::{self, status_lines, LIGHT_TX_FEE};
use kovanica_lightnode::rpc::RpcClient;
use kovanica_lightnode::sync::{self, SyncOutcome};
use kovanica_lightnode::{
    confirm_account, encode_raw, init, open_keystore, platform_note, signed_transfer,
    status_address,
};
use kovanica_staking::MIN_LIGHT_BOND;
use zeroize::Zeroizing;

/// Committed-leader interval the full node targets (round 4s, wave 3).
const SYNC_INTERVAL: Duration = Duration::from_secs(12);

#[derive(Parser)]
#[command(
    name = "kovanica-lightnode",
    about = "Kovanica light node (seal verification and transfers)"
)]
struct Cli {
    /// Data directory (config, keystore, last verified header).
    #[arg(long, global = true, default_value = "kovanica-light-data")]
    data_dir: PathBuf,

    /// Override the RPC URL in the config for this invocation.
    #[arg(long, global = true)]
    rpc: Option<String>,

    /// Keystore passphrase. `KOVANICA_LIGHT_PASSPHRASE` is also read.
    #[arg(long, global = true, env = "KOVANICA_LIGHT_PASSPHRASE")]
    passphrase: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a config and a new keystore.
    Init {
        /// Full-node RPC base URL.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Chain id this light node will trust. Local and the live testnet use 1337.
        #[arg(long, default_value_t = 1337)]
        chain_id: u64,
    },
    /// Print the address, the last verified height, and the platform note.
    Status,
    /// Download sealed headers and reject a bad seal.
    Sync,
    /// Keep syncing. With a passphrase, submit one witness per epoch.
    Run,
    /// Sign a transfer, submit it, and check the recipient account proof.
    Transfer {
        /// Recipient `kvnc…dag` address.
        #[arg(long)]
        to: String,
        /// Amount in atoms (1 KUNA = 1_000_000_000 atoms).
        #[arg(long)]
        amount: u64,
        /// Fee in atoms.
        #[arg(long, default_value_t = 1)]
        fee: u64,
    },
    /// Bond KUNA and register this keystore's VRF key. Active next epoch.
    Bond {
        /// Bond in atoms. The default is 100 KUNA.
        #[arg(long, default_value_t = MIN_LIGHT_BOND)]
        stake: u64,
        /// Fee in atoms.
        #[arg(long, default_value_t = LIGHT_TX_FEE)]
        fee: u64,
    },
    /// Exit the light-node set. A pending bond is refunded by execution.
    Exit {
        /// Fee in atoms.
        #[arg(long, default_value_t = LIGHT_TX_FEE)]
        fee: u64,
    },
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let passphrase = cli.passphrase.map(Zeroizing::new);
    match cli.command {
        Command::Init { rpc, chain_id } => {
            let passphrase = passphrase
                .context("passphrase is required (`--passphrase` or KOVANICA_LIGHT_PASSPHRASE)")?;
            let address = init(&cli.data_dir, &rpc, chain_id, passphrase.as_str())?;
            println!("address: {address}");
            println!("chain id: {chain_id}");
            println!("data: {}", cli.data_dir.display());
            println!("{}", platform_note());
        }
        Command::Status => {
            let cfg = LightConfig::load(&cli.data_dir)?;
            let address = status_address(&cli.data_dir)?;
            let header = sync::load_header(&cli.data_dir)?;
            println!("address: {address}");
            println!("chain id: {}", cfg.chain_id);
            println!("rpc: {}", cli.rpc.as_deref().unwrap_or(&cfg.rpc));
            match header {
                Some(header) => {
                    println!("verified height: {}", header.committed_height);
                    println!("header hash: 0x{}", hex::encode(header.hash().0));
                }
                None => println!("verified height: none"),
            }
            let rpc_url = cli.rpc.as_deref().unwrap_or(&cfg.rpc);
            let view = RpcClient::new(rpc_url)
                .and_then(|rpc| rpc.light_set())
                .ok()
                .and_then(|value| register::LightView::from_value(&value).ok());
            for line in status_lines(view.as_ref(), &address) {
                println!("{line}");
            }
            println!("{}", platform_note());
        }
        Command::Sync => {
            let outcome = sync_once(&cli.data_dir, cli.rpc.as_deref())?;
            print_outcome(&outcome);
        }
        Command::Run => {
            let opened = match passphrase.as_ref() {
                Some(passphrase) => Some(open_keystore(&cli.data_dir, passphrase.as_str())?),
                None => {
                    println!("witness: no passphrase, syncing only");
                    None
                }
            };
            loop {
                match sync_once(&cli.data_dir, cli.rpc.as_deref()) {
                    Ok(outcome) => print_outcome(&outcome),
                    Err(err) => eprintln!("sync failed: {err:#}"),
                }
                if let Some((cfg, keystore, signing_key)) = &opened {
                    let sender = kovanica_keystore::address(keystore)?;
                    let rpc_url = cli.rpc.as_deref().unwrap_or(&cfg.rpc);
                    match RpcClient::new(rpc_url).and_then(|rpc| {
                        register::submit_witness_if_due(
                            &cli.data_dir,
                            &rpc,
                            cfg.chain_id,
                            signing_key,
                            sender,
                        )
                    }) {
                        Ok(Some(hash)) => println!("witness submitted: {hash}"),
                        Ok(None) => {}
                        Err(err) => eprintln!("witness failed: {err:#}"),
                    }
                }
                thread::sleep(SYNC_INTERVAL);
            }
        }
        Command::Transfer { to, amount, fee } => {
            let passphrase = passphrase
                .context("passphrase is required (`--passphrase` or KOVANICA_LIGHT_PASSPHRASE)")?;
            transfer(
                &cli.data_dir,
                cli.rpc.as_deref(),
                passphrase.as_str(),
                &to,
                amount,
                fee,
            )?;
        }
        Command::Bond { stake, fee } => {
            let passphrase = passphrase
                .context("passphrase is required (`--passphrase` or KOVANICA_LIGHT_PASSPHRASE)")?;
            let (cfg, keystore, signing_key) = open_keystore(&cli.data_dir, passphrase.as_str())?;
            let sender = kovanica_keystore::address(&keystore)?;
            let rpc = RpcClient::new(cli.rpc.as_deref().unwrap_or(&cfg.rpc))?;
            let hash = register::submit_bond(&rpc, cfg.chain_id, &signing_key, sender, stake, fee)?;
            println!("submitted: {hash}");
            println!("bond: {stake} atoms, active next epoch");
            println!(
                "a desktop `kovanica-lightnode run` submits the witness while this process is stopped"
            );
        }
        Command::Exit { fee } => {
            let passphrase = passphrase
                .context("passphrase is required (`--passphrase` or KOVANICA_LIGHT_PASSPHRASE)")?;
            let (cfg, keystore, signing_key) = open_keystore(&cli.data_dir, passphrase.as_str())?;
            let sender = kovanica_keystore::address(&keystore)?;
            let rpc = RpcClient::new(cli.rpc.as_deref().unwrap_or(&cfg.rpc))?;
            let hash = register::submit_exit(&rpc, cfg.chain_id, &signing_key, sender, fee)?;
            println!("submitted: {hash}");
        }
    }
    Ok(())
}

fn sync_once(dir: &Path, rpc_override: Option<&str>) -> Result<SyncOutcome> {
    let cfg = LightConfig::load(dir)?;
    let rpc_url = rpc_override.unwrap_or(&cfg.rpc);
    let rpc = RpcClient::new(rpc_url)?;
    sync::sync_rpc(dir, &cfg, &rpc)
}

fn print_outcome(outcome: &SyncOutcome) {
    match outcome {
        SyncOutcome::NoHeader => println!("no sealed header yet"),
        SyncOutcome::Verified { height, hash } => {
            println!("verified height: {height}");
            println!("header hash: 0x{}", hex::encode(hash.0));
        }
    }
}

fn transfer(
    dir: &Path,
    rpc_override: Option<&str>,
    passphrase: &str,
    to: &str,
    amount: u64,
    fee: u64,
) -> Result<()> {
    let (cfg, keystore, signing_key) = open_keystore(dir, passphrase)?;
    let sender = kovanica_keystore::address(&keystore)?;
    let to = parse_address(to, "recipient", cfg.chain_id)?;
    let rpc = RpcClient::new(rpc_override.unwrap_or(&cfg.rpc))?;
    let nonce = rpc.nonce(&sender)?;
    let transaction = signed_transfer(cfg.chain_id, &signing_key, sender, to, amount, nonce, fee);
    let raw = encode_raw(&transaction)?;
    let hash = rpc.send_raw(&raw)?;
    println!("submitted: {hash}");
    let outcome = sync::sync_rpc(dir, &cfg, &rpc)?;
    print_outcome(&outcome);
    let Some(header) = sync::load_header(dir)? else {
        println!("recipient: no sealed header yet, balance is unverified");
        return Ok(());
    };
    let Some((height, proof)) = rpc.account_proof(&to)? else {
        println!("recipient: the node has no account proof yet, balance is unverified");
        return Ok(());
    };
    confirm_account(&header, height, &proof)?;
    println!("recipient balance: {} atoms", proof.balance);
    println!("recipient nonce: {}", proof.nonce);
    if proof.balance < amount {
        println!("recipient proof is valid and does not yet include this transfer");
    }
    Ok(())
}
