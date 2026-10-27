//! Kovanica (KUNA) command-line interface.
//!
//! Wallet operations (keygen/import/export/sign/tui), node operations
//! (status/balance/history/staking/governance) and contract subcommands
//! (htlc/vault/multisig/token). All commands support `--json` for
//! machine-readable output and `--rpc-url` to target a specific node.

use std::{
    io::{self, Write},
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::json;

use kovanica_cli::amount::{format_kuna_fixed, parse_cli_amount};
use kovanica_cli::contracts::{
    ContractCommand, HtlcCommand, MultisigCommand, TokenCommand, VaultCommand,
};
use kovanica_cli::rpc::RpcClient;
use kovanica_cli::{comms, contracts, node, output, rpc, tui, tx, wallet};
use kovanica_types::transaction::TransactionKind;
use kovanica_types::{crypto::PublicKey, crypto::SigningKey, Address};
use zeroize::Zeroizing;

const UNSAFE_SIGN_WARNING: &str = "WARNING: arbitrary message signing is unsafe and cross-context; signatures may be replayed or misinterpreted by other protocols.";

#[derive(Parser)]
#[command(name = "kovanica", version, about = "Kovanica (KUNA) CLI", long_about = None)]
struct Cli {
    /// JSON-RPC endpoint of the node
    #[arg(long, global = true, default_value = "http://127.0.0.1:8545")]
    rpc_url: String,

    /// Network `chain_id` committed to by every transaction signature (1 mainnet, 2 testnet, 3 devnet, 4 testnet v2, 1337 local); falls back to the `KOVANICA_CHAIN_ID` environment variable.
    /// Required by commands that sign transactions; there is deliberately no default.
    #[arg(long, global = true)]
    chain_id: Option<u64>,

    /// Emit machine-readable JSON instead of human-readable tables
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 keypair and save a keystore
    Keygen(KeygenArgs),
    /// Load a keystore and print its address
    Import(KeystoreArgs),
    /// Explicitly export private seed material from a keystore
    Export(ExportArgs),
    /// Import a raw seed or 24-word English BIP-39 entropy phrase (hidden; no BIP-39 passphrase/HD derivation)
    ImportKey(ImportKeyArgs),
    /// Explicitly migrate a legacy v1 keystore to authenticated v2 encryption
    Migrate(MigrateArgs),
    /// Derive the canonical address + public key from a raw 32-byte hex seed file (offline; never prints the seed)
    Address(AddressArgs),
    /// Sign a message offline and print the signature as hex
    Sign(SignArgs),
    /// Open the interactive terminal wallet
    Tui {
        /// Keystore file path
        #[arg(long, short, default_value = "keystore.json")]
        keystore: PathBuf,
    },
    /// Submit a native KUNA transfer
    Transfer(TransferArgs),
    /// Show chain/node status
    Status,
    /// Show chain info (alias of `status`)
    Info,
    /// Query an account balance
    Balance {
        /// Kovanica address
        address: String,
    },
    /// Show stake, delegations, and rewards for a Kovanica address
    Staking {
        /// Kovanica address
        address: String,
    },
    /// List committed transactions for an address, newest first
    History(HistoryArgs),
    /// Stake KUNA (builds and submits a signed Stake transaction)
    Stake(AmountArgs),
    /// Unstake KUNA (builds and submits a signed Unstake transaction)
    Unstake(AmountArgs),
    /// Register a light node (bond + VRF key)
    RegisterLightNode(RegisterLightNodeArgs),
    /// Delegate stake to a validator
    Delegate(DelegateArgs),
    /// Claim staking rewards
    ClaimRewards(ClaimRewardsArgs),
    /// Submit a governance proposal (not yet supported by the node)
    Propose(ProposeArgs),
    /// Vote on a governance proposal (not yet supported by the node)
    Vote(VoteArgs),
    /// Set validator commission (basis points, 10000 = 100%)
    SetCommission(SetCommissionArgs),
    /// Claim vested treasury funds
    ClaimTreasury(ClaimTreasuryArgs),
    /// Deploy a WASM contract
    Deploy(DeployArgs),
    /// Call a contract method
    Call(CallArgs),
    /// HTLC atomic swaps (KVP-104)
    Htlc {
        #[command(subcommand)]
        command: HtlcCommand,
    },
    /// Time-lock vaults (KVP-105)
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    /// Multisig wallets (KVP-101)
    Multisig {
        #[command(subcommand)]
        command: MultisigCommand,
    },
    /// Native multi-asset tokens (KVP-102)
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
    /// Kovanica comms app control-plane helpers (identity derivation)
    Comms {
        #[command(subcommand)]
        command: comms::CommsCommand,
    },
}

/// Arguments for `kovanica history`.
#[derive(Args)]
struct HistoryArgs {
    /// Account address (`kvnc…dag` or 32-byte hex)
    address: String,
    /// Page size. The node defaults to 20 and clamps anything above 100.
    #[arg(long)]
    limit: Option<u64>,
    /// Opaque cursor returned as `next_cursor` by the previous page
    #[arg(long)]
    cursor: Option<String>,
    /// Only transactions sent by this address
    #[arg(long, conflicts_with = "received")]
    sent: bool,
    /// Only transactions received by this address
    #[arg(long, conflicts_with = "sent")]
    received: bool,
}

/// Arguments for `kovanica keygen`.
#[derive(Args)]
struct KeygenArgs {
    /// Output keystore path
    #[arg(long, short, default_value = "keystore.json")]
    out: PathBuf,
    /// Overwrite an existing keystore file
    #[arg(long)]
    force: bool,
}

/// Arguments selecting an existing keystore.
#[derive(Args)]
struct KeystoreArgs {
    /// Keystore file path
    #[arg(long, short, default_value = "keystore.json")]
    keystore: PathBuf,
}

#[derive(Clone, Copy, ValueEnum)]
enum SecretFormat {
    Raw,
    Mnemonic,
}

#[derive(Args)]
struct ExportArgs {
    #[command(flatten)]
    keystore: KeystoreArgs,
    /// Explicit secret export format; mnemonic is seed entropy, not BIP-39 passphrase/HD-derived
    #[arg(long, value_enum)]
    format: SecretFormat,
}

#[derive(Args)]
struct ImportKeyArgs {
    /// Input encoding for the hidden prompt
    #[arg(long, value_enum)]
    format: SecretFormat,
    /// Output keystore path
    #[arg(long, short, default_value = "keystore.json")]
    out: PathBuf,
    /// Overwrite only after explicit interactive confirmation
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct MigrateArgs {
    /// Legacy v1 source path
    #[arg(long, short, default_value = "keystore.json")]
    keystore: PathBuf,
    /// Destination path (defaults to <source>.v2.json)
    #[arg(long, short)]
    out: Option<PathBuf>,
    /// Replace the v1 source only after destination verification and typed confirmation
    #[arg(long)]
    replace_source: bool,
}

/// Arguments for `kovanica address`.
#[derive(Args)]
struct AddressArgs {
    /// File containing a 32-byte hex seed (the seed itself is never printed)
    #[arg(long, value_name = "FILE")]
    key_file: PathBuf,
    /// Allow raw hex seed import (disabled by default for security; enable with caution)
    #[arg(long, default_value_t = false)]
    allow_raw_hex: bool,
}

/// Arguments for `kovanica sign`.
#[derive(Args)]
struct SignArgs {
    /// Keystore file path
    #[arg(long, short, default_value = "keystore.json")]
    keystore: PathBuf,
    /// Message to sign
    #[arg(long)]
    message: String,
    /// Interpret `--message` as hex bytes instead of UTF-8 text
    #[arg(long)]
    hex: bool,
}

/// Arguments for `kovanica transfer`.
#[derive(Args)]
struct TransferArgs {
    /// Recipient Kovanica address
    #[arg(long)]
    to: String,
    /// Amount of KUNA (`1.5` or `1.5KUNA`) or atoms (`5atoms`). A bare integer is rejected.
    #[arg(long, value_parser = parse_cli_amount)]
    amount: u64,
    /// Keystore file path
    #[arg(long, short, default_value = "keystore.json")]
    keystore: PathBuf,
    /// Fee in atoms (the mempool rejects zero-fee transactions)
    #[arg(long, default_value_t = 1)]
    fee: u64,
}

/// Arguments carrying a single amount plus the signing keystore.
#[derive(Args)]
struct AmountArgs {
    /// Amount of KUNA (`1.5` or `1.5KUNA`) or atoms (`5atoms`). A bare integer is rejected.
    #[arg(long, value_parser = parse_cli_amount)]
    amount: u64,
    /// Keystore file path
    #[arg(long, short, default_value = "keystore.json")]
    keystore: PathBuf,
    /// Fee in atoms (the mempool rejects zero-fee transactions)
    #[arg(long, default_value_t = 1)]
    fee: u64,
}

/// Arguments for `kovanica register-light-node`.
#[derive(Args)]
struct RegisterLightNodeArgs {
    /// VRF public key (32-byte hex)
    #[arg(long)]
    vrf_public_key: String,
    /// Bond of at least 100 KUNA (`100KUNA` or `100.0`). Atoms need a suffix (`5atoms`). A bare integer is rejected.
    #[arg(long, value_parser = parse_cli_amount)]
    stake: u64,
    /// Keystore file path
    #[arg(long, short, default_value = "keystore.json")]
    keystore: PathBuf,
    /// Fee in atoms (the mempool rejects zero-fee transactions)
    #[arg(long, default_value_t = 1)]
    fee: u64,
}

/// Arguments for `kovanica delegate`.
#[derive(Args)]
struct DelegateArgs {
    /// Validator Kovanica address
    #[arg(long)]
    validator: String,
    /// Amount of KUNA (`1.5` or `1.5KUNA`) or atoms (`5atoms`). A bare integer is rejected.
    #[arg(long, value_parser = parse_cli_amount)]
    amount: u64,
    /// Keystore file path
    #[arg(long, short, default_value = "keystore.json")]
    keystore: PathBuf,
    /// Fee in atoms (the mempool rejects zero-fee transactions)
    #[arg(long, default_value_t = 1)]
    fee: u64,
}

/// Arguments for `kovanica claim-rewards`.
#[derive(Args)]
struct ClaimRewardsArgs {
    /// Validator Kovanica address (optional — claims all if omitted)
    #[arg(long)]
    validator: Option<String>,
    /// Keystore file path
    #[arg(long, short, default_value = "keystore.json")]
    keystore: PathBuf,
    /// Fee in atoms (the mempool rejects zero-fee transactions)
    #[arg(long, default_value_t = 1)]
    fee: u64,
}

/// Arguments for `kovanica set-commission`.
#[derive(Args)]
struct SetCommissionArgs {
    /// Validator Kovanica address
    #[arg(long)]
    validator: String,
    /// Commission in basis points (10000 = 100%)
    #[arg(long)]
    commission_bps: u16,
    /// Keystore file path
    #[arg(long, short, default_value = "keystore.json")]
    keystore: PathBuf,
    /// Fee in atoms (the mempool rejects zero-fee transactions)
    #[arg(long, default_value_t = 1)]
    fee: u64,
}

/// Arguments for `kovanica claim-treasury`.
#[derive(Args)]
struct ClaimTreasuryArgs {
    /// Amount of KUNA (`1.5` or `1.5KUNA`) or atoms (`5atoms`). A bare integer is rejected.
    #[arg(long, value_parser = parse_cli_amount)]
    amount: u64,
    /// Keystore file path
    #[arg(long, short, default_value = "keystore.json")]
    keystore: PathBuf,
    /// Fee in atoms (the mempool rejects zero-fee transactions)
    #[arg(long, default_value_t = 1)]
    fee: u64,
}

/// Arguments for `kovanica propose`.
#[derive(Args)]
struct ProposeArgs {
    /// Proposal title
    #[arg(long)]
    title: String,
}

/// Arguments for `kovanica vote`.
#[derive(Args)]
struct VoteArgs {
    /// Proposal id
    #[arg(long = "proposal-id")]
    proposal_id: u64,
    /// Vote in favour (omit for against)
    #[arg(long)]
    approve: bool,
}

/// Arguments for `kovanica deploy` — deploy a WASM contract.
///
/// There is deliberately **no** `--gas-limit` here: `TransactionKind::Deploy`
/// carries only the bytecode, and the node's `Deploy` path performs no
/// interpreter execution (no wasmi fuel to cap). Only `kovanica call` has a
/// gas limit, and that one is wired into `TransactionKind::Call { gas_limit }`.
#[derive(Args)]
struct DeployArgs {
    /// Path to the .wasm file
    #[arg(long)]
    wasm: PathBuf,
    /// Keystore file path
    #[arg(long, short, default_value = "keystore.json")]
    keystore: PathBuf,
    /// Fee in atoms (the mempool rejects zero-fee transactions)
    #[arg(long, default_value_t = 1)]
    fee: u64,
}

/// Arguments for `kovanica call` — call a contract method.
#[derive(Args)]
struct CallArgs {
    /// Contract Kovanica address
    #[arg(long)]
    contract: String,
    /// Method name (e.g., htlc_create, token_transfer)
    #[arg(long)]
    method: String,
    /// Arguments as JSON array (will be bincode encoded)
    #[arg(long)]
    args: String,
    /// Native KUNA to attach (`1.5` or `1.5KUNA`) or atoms (`5atoms`). A bare integer is rejected.
    #[arg(long, default_value = "0atoms", value_parser = parse_cli_amount)]
    value: u64,
    /// Gas limit for execution
    #[arg(long, default_value_t = kovanica_types::MAX_TX_GAS_LIMIT)]
    gas_limit: u64,
    /// Keystore file path
    #[arg(long, short, default_value = "keystore.json")]
    keystore: PathBuf,
    /// Fee in atoms (the mempool rejects zero-fee transactions)
    #[arg(long, default_value_t = 1)]
    fee: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let json = cli.json;
    let rpc_url = cli.rpc_url;
    let client = RpcClient::new(rpc_url.clone());
    let chain_id =
        match cli.chain_id {
            Some(id) => Some(id),
            None => match std::env::var("KOVANICA_CHAIN_ID") {
                Ok(v) => Some(v.trim().parse::<u64>().map_err(|_| {
                    anyhow::anyhow!("KOVANICA_CHAIN_ID must be an unsigned integer")
                })?),
                Err(_) => None,
            },
        };

    match cli.command {
        Commands::Keygen(args) => cmd_keygen(args, json),
        Commands::Import(args) => cmd_import(args, json),
        Commands::Export(args) => cmd_export(args, json),
        Commands::ImportKey(args) => cmd_import_key(args, json),
        Commands::Migrate(args) => cmd_migrate(args, json),
        Commands::Address(args) => cmd_address(args, json),
        Commands::Sign(args) => cmd_sign(args, json),
        Commands::Tui { keystore } => {
            tui::run(tui::TuiConfig {
                rpc_url,
                chain_id,
                keystore,
            })
            .await
        }
        Commands::Transfer(args) => cmd_transfer(&client, chain_id, args, json).await,
        Commands::Status | Commands::Info => node::status(&client, chain_id, json).await,
        Commands::Balance { address } => node::balance(&client, &address, chain_id, json).await,
        Commands::Staking { address } => node::staking(&client, &address, chain_id, json).await,
        Commands::History(args) => {
            node::history(
                &client,
                &args.address,
                chain_id,
                args.limit,
                args.cursor.as_deref(),
                args.sent,
                args.received,
                json,
            )
            .await
        }
        Commands::Stake(args) => cmd_stake(&client, chain_id, args, json).await,
        Commands::Unstake(args) => cmd_unstake(&client, chain_id, args, json).await,
        Commands::RegisterLightNode(args) => {
            cmd_register_light_node(&client, chain_id, args, json).await
        }
        Commands::Delegate(args) => cmd_delegate(&client, chain_id, args, json).await,
        Commands::ClaimRewards(args) => cmd_claim_rewards(&client, chain_id, args, json).await,
        Commands::SetCommission(args) => cmd_set_commission(&client, chain_id, args, json).await,
        Commands::ClaimTreasury(args) => cmd_claim_treasury(&client, chain_id, args, json).await,
        Commands::Propose(args) => node::not_implemented(
            "propose",
            "kovanica_propose",
            json!({ "title": args.title }),
            json,
        ),
        Commands::Vote(args) => node::not_implemented(
            "vote",
            "kovanica_vote",
            json!({ "proposal_id": args.proposal_id, "approve": args.approve }),
            json,
        ),
        Commands::Deploy(args) => cmd_deploy(&client, chain_id, args, json).await,
        Commands::Call(args) => cmd_call(&client, chain_id, args, json).await,
        Commands::Htlc { command } => {
            contracts::run(&client, chain_id, ContractCommand::Htlc { command }, json).await
        }
        Commands::Vault { command } => {
            contracts::run(&client, chain_id, ContractCommand::Vault { command }, json).await
        }
        Commands::Multisig { command } => {
            contracts::run(
                &client,
                chain_id,
                ContractCommand::Multisig { command },
                json,
            )
            .await
        }
        Commands::Token { command } => {
            contracts::run(&client, chain_id, ContractCommand::Token { command }, json).await
        }
        Commands::Comms { command } => comms::run(command, json),
    }
}

fn cmd_keygen(args: KeygenArgs, json_output: bool) -> Result<()> {
    if args.force {
        confirm_typed(&format!("OVERWRITE {}", args.out.display()))?;
    }
    let passphrase = prompt_confirmed_passphrase("New keystore passphrase: ")?;
    let keystore = wallet::keygen(&passphrase)?;
    if args.force {
        wallet::save_replace(&args.out, &keystore)?;
    } else {
        wallet::save(&args.out, &keystore)?;
    }

    if json_output {
        return output::print_json(&keystore_summary_json(&args.out, &keystore)?);
    }

    println!("Keystore written to {}", args.out.display());
    println!("Address:    {}", wallet::address(&keystore)?);
    println!("Public key: {}", keystore.public_key);
    Ok(())
}

fn cmd_import(args: KeystoreArgs, json_output: bool) -> Result<()> {
    let keystore = wallet::load(&args.keystore)?;
    let password = prompt_keystore_password(&keystore)?;
    // Inspection is not accepted as import until its seed-derived identity is verified.
    let _ = wallet::secret_seed(&keystore, password.as_ref().map(|p| p.as_str()))?;

    if json_output {
        return output::print_json(&keystore_summary_json(&args.keystore, &keystore)?);
    }

    let public_key = wallet::public_key(&keystore)?;
    println!("Keystore:   {}", args.keystore.display());
    println!("Address:    {}", wallet::address(&keystore)?);
    println!("Public key: {}", hex::encode(public_key.as_bytes()));
    println!("Encrypted:  {}", keystore.encrypted);
    Ok(())
}

fn cmd_export(args: ExportArgs, json_output: bool) -> Result<()> {
    if json_output {
        anyhow::bail!("secret export is disabled in JSON mode");
    }
    let keystore = wallet::load(&args.keystore.keystore)?;
    let password = prompt_keystore_password(&keystore)?;
    let seed = wallet::secret_seed(&keystore, password.as_ref().map(|p| p.as_str()))?;
    let label = match args.format {
        SecretFormat::Raw => "raw seed",
        SecretFormat::Mnemonic => "24-word English BIP-39 mnemonic",
    };
    if matches!(args.format, SecretFormat::Mnemonic) {
        eprintln!("This English BIP-39 phrase represents the exact seed entropy; no BIP-39 passphrase or HD derivation is used.");
    }
    let secret = export_after_confirmation(
        || confirm_typed(&format!("EXPORT {}", label.to_ascii_uppercase())),
        || printable_export(&seed, args.format),
    )?;
    writeln!(io::stdout().lock(), "{}", secret.as_str())?;
    Ok(())
}

fn printable_export(seed: &[u8; 32], format: SecretFormat) -> Result<Zeroizing<String>> {
    match format {
        SecretFormat::Raw => Ok(Zeroizing::new(hex::encode(seed))),
        SecretFormat::Mnemonic => Ok(Zeroizing::new(wallet::seed_to_mnemonic(seed)?)),
    }
}

fn keystore_summary_json(
    path: &std::path::Path,
    keystore: &wallet::Keystore,
) -> Result<serde_json::Value> {
    let public_key = wallet::public_key(keystore)?;
    Ok(json!({
        "keystore": path.display().to_string(),
        "address": wallet::address(keystore)?.to_string(),
        "publicKey": hex::encode(public_key.as_bytes()),
        "encrypted": keystore.encrypted,
    }))
}

fn cmd_sign(args: SignArgs, json_output: bool) -> Result<()> {
    let keystore = wallet::load(&args.keystore)?;
    let password = prompt_keystore_password(&keystore)?;

    let message = if args.hex {
        let raw = args.message.strip_prefix("0x").unwrap_or(&args.message);
        hex::decode(raw).context("--message is not valid hex")?
    } else {
        args.message.clone().into_bytes()
    };

    let signer = wallet::address(&keystore)?.to_string();
    let message_digest = hex::encode(kovanica_types::Hash::new(&message).0);
    eprintln!("{UNSAFE_SIGN_WARNING}");
    eprintln!("Signer: {signer}");
    eprintln!("Message digest: {message_digest}");
    confirm_typed(&format!("SIGN {signer} {message_digest}"))?;
    let signing_key = wallet::signing_key(&keystore, password.as_ref().map(|p| p.as_str()))?;

    let signature = kovanica_crypto::sign(&signing_key, &message);
    let signature_hex = hex::encode(signature.as_bytes());

    if json_output {
        return output::print_json(&json!({
            "address": wallet::address(&keystore)?.to_string(),
            "message": args.message,
            "messageHex": hex::encode(&message),
            "messageDigest": message_digest,
            "signature": signature_hex,
        }));
    }

    println!("{signature_hex}");
    Ok(())
}

async fn cmd_transfer(
    client: &RpcClient,
    chain_id: Option<u64>,
    args: TransferArgs,
    json_output: bool,
) -> Result<()> {
    let ctx = tx::signing_context(chain_id)?;
    let recipient = wallet::parse_address(&args.to, "to", ctx.chain_id)?;
    node::ensure_node_chain_matches(client, Some(ctx.chain_id)).await?;
    let keystore = wallet::load(&args.keystore)?;
    let password = prompt_keystore_password(&keystore)?;
    let signing_key = wallet::signing_key(&keystore, password.as_ref().map(|p| p.as_str()))?;
    let sender = wallet::address(&keystore)?;

    // The account nonce is the next unused nonce, so it is used as-is.
    let nonce_value = client
        .call("kovanica_getNonce", json!([sender.to_string()]))
        .await?;
    let nonce = rpc::parse_quantity(&nonce_value)?;

    let kind = TransactionKind::Transfer {
        to: recipient,
        amount: args.amount,
    };
    let transaction = tx::build_signed(&ctx, sender, nonce, kind, args.fee, &signing_key)?;
    let raw = tx::encode_raw(&transaction)?;

    let result = client
        .call("kovanica_sendRawTransaction", json!([raw]))
        .await?;
    let tx_hash = result.as_str().unwrap_or_default().to_string();

    if json_output {
        return output::print_json(&json!({
            "transactionHash": tx_hash,
            "sender": sender.to_string(),
            "to": recipient.to_string(),
            "amount": args.amount,
            "fee": args.fee,
            "nonce": nonce,
        }));
    }

    println!("Submitted transaction {tx_hash}");
    println!("  from:   {}", sender);
    println!("  to:     {}", recipient);
    println!("  amount: {}", format_kuna_fixed(args.amount));
    println!("  fee:    {} atoms", args.fee);
    println!("  nonce:  {nonce}");
    Ok(())
}

/// Sign a self-addressed transaction kind with the local keystore and submit it.
///
/// Mirrors [`cmd_transfer`]'s flow: nonce is read from `kovanica_getNonce`, the
/// signable hash is built offline, and only the bincode-encoded signed
/// transaction is sent over `kovanica_sendRawTransaction`. Private key material
/// never leaves the machine and no staking-specific node RPC is introduced.
async fn sign_and_submit_self(
    client: &RpcClient,
    chain_id: Option<u64>,
    keystore_path: &std::path::Path,
    kind: TransactionKind,
    fee: u64,
) -> Result<(String, kovanica_types::Address, u64)> {
    let ctx = tx::signing_context(chain_id)?;
    node::ensure_node_chain_matches(client, Some(ctx.chain_id)).await?;
    let keystore = wallet::load(keystore_path)?;
    let password = prompt_keystore_password(&keystore)?;
    let signing_key = wallet::signing_key(&keystore, password.as_ref().map(|p| p.as_str()))?;
    let sender = wallet::address(&keystore)?;

    // The account nonce is the next unused nonce, so it is used as-is.
    let nonce_value = client
        .call("kovanica_getNonce", json!([sender.to_string()]))
        .await?;
    let nonce = rpc::parse_quantity(&nonce_value)?;

    let transaction = tx::build_signed(&ctx, sender, nonce, kind, fee, &signing_key)?;
    let raw = tx::encode_raw(&transaction)?;

    let result = client
        .call("kovanica_sendRawTransaction", json!([raw]))
        .await?;
    let tx_hash = result.as_str().unwrap_or_default().to_string();
    Ok((tx_hash, sender, nonce))
}

async fn cmd_stake(
    client: &RpcClient,
    chain_id: Option<u64>,
    args: AmountArgs,
    json_output: bool,
) -> Result<()> {
    let (tx_hash, sender, nonce) = sign_and_submit_self(
        client,
        chain_id,
        &args.keystore,
        TransactionKind::Stake {
            amount: args.amount,
        },
        args.fee,
    )
    .await?;

    if json_output {
        return output::print_json(&json!({
            "transactionHash": tx_hash,
            "sender": sender.to_string(),
            "amount": args.amount,
            "fee": args.fee,
            "nonce": nonce,
        }));
    }

    println!("Submitted transaction {tx_hash}");
    println!("  from:   {}", sender);
    println!("  amount: {}", format_kuna_fixed(args.amount));
    println!("  fee:    {} atoms", args.fee);
    println!("  nonce:  {nonce}");
    Ok(())
}

async fn cmd_unstake(
    client: &RpcClient,
    chain_id: Option<u64>,
    args: AmountArgs,
    json_output: bool,
) -> Result<()> {
    let (tx_hash, sender, nonce) = sign_and_submit_self(
        client,
        chain_id,
        &args.keystore,
        TransactionKind::Unstake {
            amount: args.amount,
        },
        args.fee,
    )
    .await?;

    if json_output {
        return output::print_json(&json!({
            "transactionHash": tx_hash,
            "sender": sender.to_string(),
            "amount": args.amount,
            "fee": args.fee,
            "nonce": nonce,
        }));
    }

    println!("Submitted transaction {tx_hash}");
    println!("  from:   {}", sender);
    println!("  amount: {}", format_kuna_fixed(args.amount));
    println!("  fee:    {} atoms", args.fee);
    println!("  nonce:  {nonce}");
    Ok(())
}

async fn cmd_register_light_node(
    client: &RpcClient,
    chain_id: Option<u64>,
    args: RegisterLightNodeArgs,
    json_output: bool,
) -> Result<()> {
    let vrf_pk_bytes = hex::decode(&args.vrf_public_key)
        .map_err(|_| anyhow::anyhow!("invalid vrf_public_key hex"))?;
    if vrf_pk_bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "vrf_public_key must be 32 bytes (64 hex chars)"
        ));
    }
    let mut vrf_pk = [0u8; 32];
    vrf_pk.copy_from_slice(&vrf_pk_bytes);

    let (tx_hash, sender, nonce) = sign_and_submit_self(
        client,
        chain_id,
        &args.keystore,
        TransactionKind::RegisterLightNode {
            vrf_public_key: kovanica_types::crypto::PublicKey(vrf_pk),
            stake: args.stake,
        },
        args.fee,
    )
    .await?;

    if json_output {
        return output::print_json(&json!({
            "transactionHash": tx_hash,
            "sender": sender.to_string(),
            "vrfPublicKey": args.vrf_public_key,
            "stake": args.stake,
            "fee": args.fee,
            "nonce": nonce,
        }));
    }

    println!("Submitted transaction {tx_hash}");
    println!("  from:         {}", sender);
    println!("  vrfPublicKey: {}", args.vrf_public_key);
    println!("  stake:        {}", format_kuna_fixed(args.stake));
    println!("  fee:          {} atoms", args.fee);
    println!("  nonce:        {nonce}");
    Ok(())
}

async fn cmd_delegate(
    client: &RpcClient,
    chain_id: Option<u64>,
    args: DelegateArgs,
    json_output: bool,
) -> Result<()> {
    let chain = tx::signing_context(chain_id)?.chain_id;
    let validator = wallet::parse_address(&args.validator, "validator", chain)?;
    let (tx_hash, sender, nonce) = sign_and_submit_self(
        client,
        chain_id,
        &args.keystore,
        TransactionKind::Delegate {
            validator,
            amount: args.amount,
        },
        args.fee,
    )
    .await?;

    if json_output {
        return output::print_json(&json!({
            "transactionHash": tx_hash,
            "sender": sender.to_string(),
            "validator": validator.to_string(),
            "amount": args.amount,
            "fee": args.fee,
            "nonce": nonce,
        }));
    }

    println!("Submitted transaction {tx_hash}");
    println!("  from:      {}", sender);
    println!("  validator: {}", validator);
    println!("  amount:    {}", format_kuna_fixed(args.amount));
    println!("  fee:       {} atoms", args.fee);
    println!("  nonce:     {nonce}");
    Ok(())
}

async fn cmd_claim_rewards(
    client: &RpcClient,
    chain_id: Option<u64>,
    args: ClaimRewardsArgs,
    json_output: bool,
) -> Result<()> {
    let chain = tx::signing_context(chain_id)?.chain_id;
    let validator = match args.validator {
        Some(value) => Some(wallet::parse_address(&value, "validator", chain)?),
        None => None,
    };
    let (tx_hash, sender, nonce) = sign_and_submit_self(
        client,
        chain_id,
        &args.keystore,
        TransactionKind::ClaimRewards { validator },
        args.fee,
    )
    .await?;

    if json_output {
        return output::print_json(&json!({
            "transactionHash": tx_hash,
            "sender": sender.to_string(),
            "validator": validator.map(|v| v.to_string()),
            "fee": args.fee,
            "nonce": nonce,
        }));
    }

    println!("Submitted transaction {tx_hash}");
    println!("  from:      {}", sender);
    if let Some(v) = validator {
        println!("  validator: {}", v);
    } else {
        println!("  validator: all delegated validators");
    }
    println!("  fee:       {} atoms", args.fee);
    println!("  nonce:     {nonce}");
    Ok(())
}

/// Set the validator's commission via a signed SetCommission transaction.
async fn cmd_set_commission(
    client: &RpcClient,
    chain_id: Option<u64>,
    args: SetCommissionArgs,
    json_output: bool,
) -> Result<()> {
    if args.commission_bps > 10_000 {
        anyhow::bail!("commission_bps must be <= 10000 (100%)");
    }
    let chain = tx::signing_context(chain_id)?.chain_id;
    let validator = wallet::parse_address(&args.validator, "validator", chain)?;
    let (tx_hash, sender, nonce) = sign_and_submit_self(
        client,
        chain_id,
        &args.keystore,
        TransactionKind::SetCommission {
            validator,
            commission_bps: args.commission_bps,
        },
        args.fee,
    )
    .await?;

    if json_output {
        return output::print_json(&json!({
            "transactionHash": tx_hash,
            "sender": sender.to_string(),
            "validator": validator.to_string(),
            "commissionBps": args.commission_bps,
            "fee": args.fee,
            "nonce": nonce,
        }));
    }

    println!("Submitted transaction {tx_hash}");
    println!("  from:           {}", sender);
    println!("  validator:      {}", validator);
    println!("  commission_bps: {}", args.commission_bps);
    println!("  fee:            {} atoms", args.fee);
    println!("  nonce:          {nonce}");
    Ok(())
}

/// Claim vested treasury funds via a signed ClaimTreasury transaction.
async fn cmd_claim_treasury(
    client: &RpcClient,
    chain_id: Option<u64>,
    args: ClaimTreasuryArgs,
    json_output: bool,
) -> Result<()> {
    let (tx_hash, sender, nonce) = sign_and_submit_self(
        client,
        chain_id,
        &args.keystore,
        TransactionKind::ClaimTreasury {
            amount: args.amount,
        },
        args.fee,
    )
    .await?;

    if json_output {
        return output::print_json(&json!({
            "transactionHash": tx_hash,
            "sender": sender.to_string(),
            "amount": args.amount,
            "fee": args.fee,
            "nonce": nonce,
        }));
    }

    println!("Submitted transaction {tx_hash}");
    println!("  from:    {}", sender);
    println!("  amount:  {}", format_kuna_fixed(args.amount));
    println!("  fee:     {} atoms", args.fee);
    println!("  nonce:   {nonce}");
    Ok(())
}

/// Deploy a WASM contract via a signed Deploy transaction.
///
/// `TransactionKind::Deploy` carries only the bytecode — there is no gas field
/// to set (deploy has no interpreter execution), so this command has no gas
/// limit and prints none. From contract-hardening activation on, the node
/// validates the bytecode and refuses to overwrite an existing contract at the
/// derived address.
async fn cmd_deploy(
    client: &RpcClient,
    chain_id: Option<u64>,
    args: DeployArgs,
    json_output: bool,
) -> Result<()> {
    let wasm_bytes = std::fs::read(&args.wasm)
        .with_context(|| format!("reading wasm file {}", args.wasm.display()))?;
    if wasm_bytes.is_empty() {
        anyhow::bail!("WASM file is empty");
    }
    let wasm_size = wasm_bytes.len();

    let (tx_hash, sender, nonce) = sign_and_submit_self(
        client,
        chain_id,
        &args.keystore,
        TransactionKind::Deploy { code: wasm_bytes },
        args.fee,
    )
    .await?;

    if json_output {
        return output::print_json(&json!({
            "transactionHash": tx_hash,
            "sender": sender.to_string(),
            "wasm_size": wasm_size,
            "fee": args.fee,
            "nonce": nonce,
        }));
    }

    println!("Submitted deploy transaction {tx_hash}");
    println!("  from:      {}", sender);
    println!("  wasm_size: {} bytes", wasm_size);
    println!("  fee:       {} atoms", args.fee);
    println!("  nonce:     {nonce}");
    Ok(())
}

/// Call a contract method via a signed Call transaction.
///
/// `--gas-limit` is carried into `TransactionKind::Call { gas_limit }` (it is
/// part of the signed transaction and the node charges it as wasmi fuel), so
/// unlike `deploy` this option is real, not cosmetic.
async fn cmd_call(
    client: &RpcClient,
    chain_id: Option<u64>,
    args: CallArgs,
    json_output: bool,
) -> Result<()> {
    let chain = tx::signing_context(chain_id)?.chain_id;
    let contract = wallet::parse_address(&args.contract, "contract", chain)?;
    let method = args.method.clone();
    let args_bytes = {
        let json_val: serde_json::Value = serde_json::from_str(&args.args)
            .with_context(|| format!("--args must be valid JSON array, got: {}", args.args))?;
        bincode::serialize(&json_val).with_context(|| "bincode serialization of args failed")?
    };

    let (tx_hash, sender, nonce) = sign_and_submit_self(
        client,
        chain_id,
        &args.keystore,
        TransactionKind::Call {
            contract,
            value: args.value,
            method: args.method,
            args: args_bytes,
            gas_limit: args.gas_limit,
        },
        args.fee,
    )
    .await?;

    if json_output {
        return output::print_json(&json!({
            "transactionHash": tx_hash,
            "sender": sender.to_string(),
            "contract": contract.to_string(),
            "method": method,
            "value": args.value,
            "gas_limit": args.gas_limit,
            "fee": args.fee,
            "nonce": nonce,
        }));
    }

    println!("Submitted call transaction {tx_hash}");
    println!("  from:      {}", sender);
    println!("  contract:  {}", contract);
    println!("  method:    {}", method);
    println!("  value:     {}", format_kuna_fixed(args.value));
    println!("  gas_limit: {}", args.gas_limit);
    println!("  fee:       {} atoms", args.fee);
    println!("  nonce:     {nonce}");
    Ok(())
}

fn cmd_import_key(args: ImportKeyArgs, json_output: bool) -> Result<()> {
    if json_output {
        anyhow::bail!("secret import is disabled in JSON mode");
    }
    let input = Zeroizing::new(rpassword::prompt_password(match args.format {
        SecretFormat::Raw => "Raw 32-byte seed hex (hidden): ",
        SecretFormat::Mnemonic => "24 English BIP-39 words (hidden): ",
    })?);
    let seed = match args.format {
        SecretFormat::Raw => wallet::seed_from_raw_hex(&input)?,
        SecretFormat::Mnemonic => wallet::seed_from_mnemonic(&input)?,
    };
    if matches!(args.format, SecretFormat::Mnemonic) {
        eprintln!("Mnemonic import uses its exact entropy as the Ed25519 seed; no BIP-39 passphrase or HD derivation is used.");
    }
    if args.force {
        confirm_typed(&format!("OVERWRITE {}", args.out.display()))?;
    }
    let passphrase = prompt_confirmed_passphrase("New keystore passphrase: ")?;
    let keystore = wallet::from_seed(&seed, &passphrase)?;
    if args.force {
        wallet::save_replace(&args.out, &keystore)?;
    } else {
        wallet::save(&args.out, &keystore)?;
    }
    println!("Encrypted keystore written to {}", args.out.display());
    println!("Address: {}", wallet::address(&keystore)?);
    Ok(())
}

fn cmd_migrate(args: MigrateArgs, json_output: bool) -> Result<()> {
    if json_output {
        anyhow::bail!("migration is interactive and disabled in JSON mode");
    }
    let old = wallet::load_v1_for_migration(&args.keystore)?;
    let old_password = prompt_password_if_encrypted(old.is_encrypted())?;
    let seed = wallet::migration_seed(&old, old_password.as_ref().map(|p| p.as_str()))?;
    let destination = args.out.unwrap_or_else(|| {
        let mut name = args.keystore.as_os_str().to_os_string();
        name.push(".v2.json");
        PathBuf::from(name)
    });
    if destination == args.keystore {
        anyhow::bail!("migration destination must differ from source");
    }
    let new_password = prompt_confirmed_passphrase("New v2 keystore passphrase: ")?;
    let migrated = wallet::from_seed(&seed, &new_password)?;
    wallet::save(&destination, &migrated)?;
    let reloaded = wallet::load(&destination)?;
    let verified = wallet::secret_seed(&reloaded, Some(&new_password))?;
    if *verified != *seed {
        anyhow::bail!("migrated keystore verification failed");
    }
    if args.replace_source {
        confirm_typed(&format!("REPLACE {}", args.keystore.display()))?;
        wallet::replace_file(&args.keystore, &destination)?;
        let final_store = wallet::load(&args.keystore)?;
        let _ = wallet::secret_seed(&final_store, Some(&new_password))?;
    }
    println!(
        "Verified v2 keystore written to {}",
        if args.replace_source {
            args.keystore.display()
        } else {
            destination.display()
        }
    );
    Ok(())
}

/// `kovanica address --key-file <FILE>` — offline derivation of the canonical
/// address and public key from a raw 32-byte hex seed. Prints only public
/// identity material; the seed is never echoed.
///
/// Security: requires `--allow-raw-hex` flag and key file must have 0600 permissions.
fn cmd_address(args: AddressArgs, json_output: bool) -> Result<()> {
    if !args.allow_raw_hex {
        anyhow::bail!(
            "raw hex seed import is disabled by default for security. \
            Use --allow-raw-hex to enable, and keep the key file readable only by its owner."
        );
    }

    wallet::ensure_owner_only(&args.key_file)?;

    let raw = std::fs::read_to_string(&args.key_file)
        .with_context(|| format!("reading key file {}", args.key_file.display()))?;
    let seed = wallet::seed_from_raw_hex(&raw)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = PublicKey::from(signing_key.verifying_key());
    let address = Address::from_public_key(&public_key);
    let public_key_hex = hex::encode(public_key.as_bytes());

    if json_output {
        return output::print_json(&json!({
            "address": address.to_string(),
            "publicKey": public_key_hex,
        }));
    }

    println!("Address:    {address}");
    println!("Public key: {public_key_hex}");
    Ok(())
}

fn prompt_confirmed_passphrase(prompt: &str) -> Result<Zeroizing<String>> {
    let first = Zeroizing::new(rpassword::prompt_password(prompt)?);
    let second = Zeroizing::new(rpassword::prompt_password("Confirm passphrase: ")?);
    if first.is_empty() {
        anyhow::bail!("passphrase must not be empty");
    }
    if *first != *second {
        anyhow::bail!("passphrases do not match");
    }
    Ok(first)
}

fn prompt_keystore_password(keystore: &wallet::Keystore) -> Result<Option<Zeroizing<String>>> {
    prompt_password_if_encrypted(keystore.encrypted)
}

fn prompt_password_if_encrypted(encrypted: bool) -> Result<Option<Zeroizing<String>>> {
    if !encrypted {
        return Ok(None);
    }
    // Allow password via env var for non-interactive use
    if let Ok(pass) = std::env::var("KOVANICA_KEYSTORE_PASSWORD") {
        return Ok(Some(Zeroizing::new(pass)));
    }
    Ok(Some(Zeroizing::new(rpassword::prompt_password(
        "Keystore passphrase: ",
    )?)))
}

fn confirm_typed(expected: &str) -> Result<()> {
    eprintln!("DANGER: this action exposes or replaces private wallet material.");
    eprintln!("Type exactly: {expected}");
    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    if !typed_confirmation_matches(expected, &response) {
        anyhow::bail!("confirmation did not match");
    }
    Ok(())
}

fn typed_confirmation_matches(expected: &str, response: &str) -> bool {
    response.trim_end() == expected
}

fn export_after_confirmation<C, F>(confirm: C, construct: F) -> Result<Zeroizing<String>>
where
    C: FnOnce() -> Result<()>,
    F: FnOnce() -> Result<Zeroizing<String>>,
{
    confirm()?;
    construct()
}

#[cfg(test)]
mod wallet_cli_security_tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn amount_flag_requires_a_unit() {
        let to = "placeholder";
        let decimal =
            Cli::try_parse_from(["kovanica", "transfer", "--to", to, "--amount", "1.5KUNA"])
                .unwrap();
        let Commands::Transfer(args) = decimal.command else {
            panic!("expected transfer");
        };
        assert_eq!(args.amount, 1_500_000_000);

        let atoms =
            Cli::try_parse_from(["kovanica", "transfer", "--to", to, "--amount", "42atoms"])
                .unwrap();
        let Commands::Transfer(args) = atoms.command else {
            panic!("expected transfer");
        };
        assert_eq!(args.amount, 42);

        // `5` does not say KUNA or atoms.
        let bare = Cli::try_parse_from(["kovanica", "transfer", "--to", to, "--amount", "5"]);
        assert!(bare.is_err(), "a bare integer must be rejected");

        assert!(Cli::try_parse_from([
            "kovanica",
            "transfer",
            "--to",
            to,
            "--amount",
            "0.0000000001",
        ])
        .is_err());
    }

    #[test]
    fn secret_passphrases_are_not_cli_arguments() {
        let recipient = "00".repeat(32);
        for args in [
            vec!["kovanica", "keygen", "--passphrase", "secret"],
            vec![
                "kovanica",
                "sign",
                "--message",
                "hi",
                "--passphrase",
                "secret",
            ],
            vec![
                "kovanica",
                "transfer",
                "--to",
                &recipient,
                "--amount",
                "1",
                "--passphrase",
                "secret",
            ],
            vec![
                "kovanica",
                "export",
                "--format",
                "raw",
                "--passphrase",
                "secret",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn secret_export_is_rejected_in_json_mode() {
        let args = ExportArgs {
            keystore: KeystoreArgs {
                keystore: PathBuf::from("does-not-need-to-exist"),
            },
            format: SecretFormat::Raw,
        };
        assert!(cmd_export(args, true).is_err());
    }

    #[test]
    fn address_command_derives_and_rejects_bad_seed() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("validator.pem");
        std::fs::write(&key_path, hex::encode([0x2a; 32])).unwrap();
        // Owner-only: Unix mode 0600. Windows replaces the DACL.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        #[cfg(windows)]
        {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&key_path)
                .unwrap();
            wallet::tighten_private_file(&file).unwrap();
        }
        assert!(cmd_address(
            AddressArgs {
                key_file: key_path.clone(),
                allow_raw_hex: true,
            },
            false
        )
        .is_ok());
        std::fs::write(&key_path, "00").unwrap();
        assert!(cmd_address(
            AddressArgs {
                key_file: key_path,
                allow_raw_hex: true
            },
            false
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn address_command_rejects_a_group_readable_seed_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("validator.pem");
        std::fs::write(&key_path, hex::encode([0x2a; 32])).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = cmd_address(
            AddressArgs {
                key_file: key_path,
                allow_raw_hex: true,
            },
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("other users"), "{error}");
    }

    #[test]
    fn routine_keystore_json_contains_metadata_only() {
        let keystore = wallet::from_seed(&[8; 32], "test passphrase").unwrap();
        let value = keystore_summary_json(std::path::Path::new("wallet.json"), &keystore).unwrap();
        assert!(value.get("address").is_some());
        assert!(value.get("publicKey").is_some());
        let address = value["address"].as_str().unwrap();
        assert!(address.starts_with("kvnc") && address.ends_with("dag"));
        for secret_field in ["secret_key", "secretKey", "privateKey", "seed", "mnemonic"] {
            assert!(value.get(secret_field).is_none());
        }
    }

    #[test]
    fn typed_sign_confirmation_binds_signer_and_message_digest() {
        assert!(UNSAFE_SIGN_WARNING.contains("unsafe and cross-context"));
        assert!(UNSAFE_SIGN_WARNING.contains("replayed or misinterpreted"));
        let address = "11".repeat(32);
        let digest = "ab".repeat(32);
        let required = format!("SIGN {address} {digest}");
        assert!(typed_confirmation_matches(&required, &required));
        assert!(!typed_confirmation_matches(
            &required,
            &format!("SIGN {} {digest}", "22".repeat(32))
        ));
        assert!(!typed_confirmation_matches(
            &required,
            &format!("SIGN {address} {}", "cd".repeat(32))
        ));
        assert!(!typed_confirmation_matches(
            &required,
            &format!("SIGN {address} {digest} extra")
        ));
    }

    #[test]
    fn cancelled_export_never_constructs_printable_secret() {
        let seed = [0x5a; 32];
        let mut constructed = false;
        let result = export_after_confirmation(
            || anyhow::bail!("confirmation did not match"),
            || {
                constructed = true;
                printable_export(&seed, SecretFormat::Raw)
            },
        );
        assert!(result.is_err());
        assert!(!constructed);
    }

    #[test]
    fn stake_and_unstake_accept_keystore_and_fee() {
        let cli = Cli::try_parse_from([
            "kovanica",
            "stake",
            "--amount",
            "42atoms",
            "--fee",
            "3",
            "--keystore",
            "wallet.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Stake(args) => {
                assert_eq!(args.amount, 42);
                assert_eq!(args.fee, 3);
                assert_eq!(args.keystore, PathBuf::from("wallet.json"));
            }
            _ => panic!("expected stake command"),
        }

        let cli = Cli::try_parse_from(["kovanica", "unstake", "--amount", "7atoms"]).unwrap();
        match cli.command {
            Commands::Unstake(args) => {
                assert_eq!(args.amount, 7);
                assert_eq!(args.fee, 1);
                assert_eq!(args.keystore, PathBuf::from("keystore.json"));
            }
            _ => panic!("expected unstake command"),
        }
    }

    /// `kovanica deploy` must not advertise a gas limit: the `Deploy`
    /// transaction carries no gas field (the node runs no interpreter for it),
    /// so a `--gas-limit` flag would be misleading. `kovanica call` does own a
    /// gas limit, and it is wired into `TransactionKind::Call { gas_limit }`.
    #[test]
    fn deploy_has_no_gas_limit_but_call_does() {
        let cli = Cli::try_parse_from(["kovanica", "deploy", "--wasm", "c.wasm"]).unwrap();
        match cli.command {
            Commands::Deploy(args) => {
                assert_eq!(args.wasm, PathBuf::from("c.wasm"));
                assert_eq!(args.fee, 1);
            }
            _ => panic!("expected deploy command"),
        }

        // The misleading flag is gone: passing it is now an error, not a
        // silently ignored option.
        assert!(Cli::try_parse_from([
            "kovanica",
            "deploy",
            "--wasm",
            "c.wasm",
            "--gas-limit",
            "5"
        ])
        .is_err());

        let cli = Cli::try_parse_from([
            "kovanica",
            "call",
            "--contract",
            &"11".repeat(32),
            "--method",
            "token_transfer",
            "--args",
            "[]",
            "--gas-limit",
            "77",
        ])
        .unwrap();
        match cli.command {
            Commands::Call(args) => {
                assert_eq!(args.gas_limit, 77);
                assert_eq!(args.method, "token_transfer");
                // Omitted `--value` is zero atoms, not a bare `0` that needs a unit.
                assert_eq!(args.value, 0);
            }
            _ => panic!("expected call command"),
        }
    }

    #[tokio::test]
    async fn transfer_and_stake_refuse_chain_mismatch_reported_by_node() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await.unwrap();
                let body = r#"{"jsonrpc":"2.0","id":1,"result":{"committedHeight":1,"catchingUp":false,"networkTag":"4-0123456789abcdef"}}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let client = RpcClient::new(format!("http://{addr}"));
        let recipient = Address([0x22; 32]).to_string();

        let transfer_err = cmd_transfer(
            &client,
            Some(1),
            TransferArgs {
                to: recipient,
                amount: 1_000_000_000,
                keystore: PathBuf::from("unused-keystore.json"),
                fee: 1,
            },
            true,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(transfer_err.contains("--chain-id 1"), "{transfer_err}");
        assert!(transfer_err.contains("node's chain 4"), "{transfer_err}");

        let stake_err = cmd_stake(
            &client,
            Some(1),
            AmountArgs {
                amount: 50_000_000_000_000,
                keystore: PathBuf::from("unused-keystore.json"),
                fee: 1,
            },
            true,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(stake_err.contains("--chain-id 1"), "{stake_err}");
        assert!(stake_err.contains("node's chain 4"), "{stake_err}");

        server.await.unwrap();
    }

    #[test]
    fn history_command_parses_limit_cursor_and_exclusive_direction() {
        let cli = Cli::try_parse_from([
            "kovanica", "history", "11", "--limit", "7", "--cursor", "abc", "--sent",
        ])
        .unwrap();
        match cli.command {
            Commands::History(args) => {
                assert_eq!(args.address, "11");
                assert_eq!(args.limit, Some(7));
                assert_eq!(args.cursor.as_deref(), Some("abc"));
                assert!(args.sent);
                assert!(!args.received);
            }
            _ => panic!("expected history command"),
        }

        let received = Cli::try_parse_from(["kovanica", "history", "abc", "--received"]).unwrap();
        match received.command {
            Commands::History(args) => {
                assert!(args.received);
                assert!(!args.sent);
                assert!(args.limit.is_none());
                assert!(args.cursor.is_none());
            }
            _ => panic!("expected history command"),
        }

        assert!(
            Cli::try_parse_from(["kovanica", "history", "abc", "--sent", "--received"]).is_err()
        );
        assert!(Cli::try_parse_from(["kovanica", "history"]).is_err());
    }
}
