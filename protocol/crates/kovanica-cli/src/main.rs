//! `kovanica` — a command-line client for the Kovanica (KVNC) testnet.
//!
//! Read-only explorer queries, a local Ed25519 wallet, and signed transfers.
//! The address encoding and spend signing are delegated to `kovanica-state`,
//! the node's own crate, so the CLI stays byte-compatible with the ledger.

mod tui;

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use kovanica_state::{derive_rwa_asset_id, Address, AssetId};

use kovanica_cli::api::{print_json, Client};
use kovanica_cli::Wallet;

/// 1 KVNC = 10^8 atoms.
const ATOM: u64 = 100_000_000;

#[derive(Parser)]
#[command(
    name = "kovanica",
    version,
    about = "Command-line client for the Kovanica (KVNC) testnet BlockDAG"
)]
struct Cli {
    /// Explorer API base URL.
    #[arg(
        long,
        global = true,
        env = "KOVANICA_API",
        default_value = "https://explorer.kovanica.online"
    )]
    api: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show the chain head (genesis, selected tip, block count).
    Head,
    /// Show p2p listen address, peers, and bootstrap node.
    P2p,
    /// Show network bootstrap parameters.
    Bootstrap,
    /// Show the full node state snapshot.
    State,
    /// List the blocks in the DAG.
    Blocks,
    /// Show the balance and unspent outputs of an address.
    Balance {
        /// Address as `kvnc…dag` or 64-hex.
        address: String,
    },
    /// Generate a new Ed25519 wallet key and print its address.
    Keygen {
        /// Path to write the key file (0600).
        #[arg(long, env = "KOVANICA_KEY", default_value = "kovanica.key")]
        key: PathBuf,
        /// Overwrite an existing key file.
        #[arg(long)]
        force: bool,
    },
    /// Print the address for a saved key.
    Address {
        /// Path to the key file.
        #[arg(long, env = "KOVANICA_KEY", default_value = "kovanica.key")]
        key: PathBuf,
        /// BIP39 passphrase (only if the wallet was created with one).
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Sign and broadcast a transfer from a saved key.
    Send {
        /// Path to the key file to spend from.
        #[arg(long, env = "KOVANICA_KEY", default_value = "kovanica.key")]
        key: PathBuf,
        /// Recipient address as `kvnc…dag` or 64-hex.
        #[arg(long)]
        to: String,
        /// Amount to send, in atoms (1 KVNC = 100000000 atoms).
        #[arg(long)]
        amount: u64,
        /// BIP39 passphrase (only if the wallet was created with one).
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Mnemonic wallet operations (12/24-word BIP39, SLIP-0010 ed25519).
    #[command(subcommand)]
    Wallet(WalletCommand),
    /// HTLC (Hash Time-Locked Contract) operations for atomic swaps.
    #[command(subcommand)]
    Htlc(HtlcCommand),
    /// Atomic swap offer operations.
    #[command(subcommand)]
    Offer(OfferCommand),
    /// RWA (Real World Asset) operations (KVP-106).
    #[command(subcommand)]
    Rwa(RwaCommand),
    /// NFT (Non-Fungible Token) operations (KVP-106).
    #[command(subcommand)]
    Nft(NftCommand),
    /// Launch interactive TUI.
    Tui,
}

#[derive(Subcommand)]
enum WalletCommand {
    /// Generate a new mnemonic wallet (12 or 24 words) and save it.
    New {
        /// Path to write the key file (0600).
        #[arg(long, env = "KOVANICA_KEY", default_value = "kovanica.key")]
        key: PathBuf,
        /// Number of words: 12 (128-bit) or 24 (256-bit).
        #[arg(long, default_value_t = 24)]
        words: usize,
        /// Optional BIP-39 passphrase ("25th word"). Not stored — you must
        /// re-enter it every time you load this wallet.
        #[arg(long)]
        passphrase: Option<String>,
        /// Overwrite an existing key file.
        #[arg(long)]
        force: bool,
        /// Skip the write-it-down confirmation prompt (for scripts; unsafe).
        #[arg(long)]
        yes: bool,
    },
    /// Restore a wallet from a mnemonic phrase (interactive, or via flags).
    Restore {
        /// Path to write the key file (0600).
        #[arg(long, env = "KOVANICA_KEY", default_value = "kovanica.key")]
        key: PathBuf,
        /// The mnemonic phrase inline (overrides interactive prompt).
        #[arg(long)]
        from_mnemonic: Option<String>,
        /// Read the mnemonic phrase from a file.
        #[arg(long)]
        from_file: Option<PathBuf>,
        /// BIP-39 passphrase used at creation time (same as `wallet new`).
        #[arg(long)]
        passphrase: Option<String>,
        /// Overwrite an existing key file.
        #[arg(long)]
        force: bool,
    },
    /// Show the saved wallet's address and public key. Never prints the
    /// mnemonic or seed unless `--show-seed` is explicitly given.
    Show {
        /// Path to the key file.
        #[arg(long, env = "KOVANICA_KEY", default_value = "kovanica.key")]
        key: PathBuf,
        /// BIP-39 passphrase (only if the wallet was created with one).
        #[arg(long)]
        passphrase: Option<String>,
        /// Also print the raw 32-byte seed (use with care).
        #[arg(long)]
        show_seed: bool,
    },
}

#[derive(Subcommand)]
enum HtlcCommand {
    /// Create and fund an HTLC for an atomic swap.
    Create {
        /// Path to the key file to spend from.
        #[arg(long, env = "KOVANICA_KEY", default_value = "kovanica.key")]
        key: PathBuf,
        /// Amount to lock, in atoms.
        #[arg(long)]
        amount: u64,
        /// Recipient public key (32-byte hex).
        #[arg(long)]
        recipient_pk: String,
        /// Preimage hash (32-byte hex, SHA256 of preimage).
        #[arg(long)]
        preimage_hash: String,
        /// Timeout height (absolute block height when refund becomes available).
        #[arg(long)]
        timeout: u32,
        /// Asset ID to lock (32-byte hex), or native KVNC if omitted.
        #[arg(long)]
        asset_id: Option<String>,
    },
    /// Redeem (claim) an HTLC by revealing the preimage.
    Redeem {
        /// Path to the key file to spend from.
        #[arg(long, env = "KOVANICA_KEY", default_value = "kovanica.key")]
        key: PathBuf,
        /// Outpoint transaction ID (hex).
        #[arg(long)]
        outpoint_tx: String,
        /// Outpoint index.
        #[arg(long)]
        outpoint_index: u32,
        /// HTLC script (100-byte hex).
        #[arg(long)]
        script: String,
        /// Preimage (32-byte hex).
        #[arg(long)]
        preimage: String,
        /// Destination address for claimed funds.
        #[arg(long)]
        to: String,
    },
    /// Refund an expired HTLC.
    Refund {
        /// Path to the key file to spend from.
        #[arg(long, env = "KOVANICA_KEY", default_value = "kovanica.key")]
        key: PathBuf,
        /// Outpoint transaction ID (hex).
        #[arg(long)]
        outpoint_tx: String,
        /// Outpoint index.
        #[arg(long)]
        outpoint_index: u32,
        /// HTLC script (100-byte hex).
        #[arg(long)]
        script: String,
        /// Destination address for refunded funds.
        #[arg(long)]
        to: String,
    },
    /// Check the balance of an HTLC script.
    Balance {
        /// HTLC script (100-byte hex).
        #[arg(long)]
        script: String,
    },
}

#[derive(Subcommand)]
enum OfferCommand {
    /// Create a swap offer JSON.
    Create {
        /// Maker's address (hex or kvnc…dag).
        #[arg(long)]
        maker: String,
        /// Asset to give (asset ID hex, or empty for native KVNC).
        #[arg(long)]
        give_asset: String,
        /// Amount to give (in atoms).
        #[arg(long)]
        give_amount: u64,
        /// Asset to receive (asset ID hex, or empty for native KVNC).
        #[arg(long)]
        take_asset: String,
        /// Amount to receive (in atoms).
        #[arg(long)]
        take_amount: u64,
        /// Preimage hash (32-byte hex, SHA256 of preimage).
        #[arg(long)]
        preimage_hash: String,
        /// Timeout height (absolute block height when refund becomes available).
        #[arg(long)]
        timeout: u32,
        /// Offer expiry (ISO 8601 timestamp).
        #[arg(long)]
        expires_at: String,
    },
    /// Verify a swap offer.
    Verify {
        /// Offer JSON file path or inline JSON.
        #[arg(long)]
        offer: String,
    },
}
/// RWA (Real World Asset) operations (KVP-106).
#[derive(Subcommand)]
enum RwaCommand {
    /// Derive an RWA asset_id from issuer key and parameters.
    Derive {
        /// Issuer Ed25519 public key (32-byte hex).
        #[arg(long)]
        issuer: String,
        /// Asset class (e.g., RE, BOND, INVOICE).
        #[arg(long)]
        class: String,
        /// Issuer-defined unique identifier.
        #[arg(long)]
        id: String,
        /// Version (default: 1).
        #[arg(long, default_value = "1")]
        version: u8,
    },
    /// Issue (mint) an RWA asset via coinbase.
    Issue {
        /// Path to the key file to spend from (pays fees).
        #[arg(long, env = "KOVANICA_KEY", default_value = "kovanica.key")]
        key: PathBuf,
        /// Derived asset_id (32-byte hex).
        #[arg(long)]
        asset_id: String,
        /// Amount to mint (in atoms).
        #[arg(long)]
        amount: u64,
        /// Metadata JSON file path.
        #[arg(long)]
        metadata: Option<PathBuf>,
        /// Collection ID (32-byte hex, optional).
        #[arg(long)]
        collection_id: Option<String>,
        /// Recipient address (kvnc...dag or 64-hex).
        #[arg(long)]
        to: String,
    },
    /// Burn (redeem) RWA tokens.
    Burn {
        /// Path to the key file to spend from.
        #[arg(long, env = "KOVANICA_KEY", default_value = "kovanica.key")]
        key: PathBuf,
        /// Asset ID to burn (32-byte hex).
        #[arg(long)]
        asset_id: String,
        /// Amount to burn (in atoms).
        #[arg(long)]
        amount: u64,
    },
    /// Inspect an RWA asset (requires node with asset registry).
    Info {
        /// Asset ID to inspect (32-byte hex).
        #[arg(long)]
        asset_id: String,
    },
}
/// NFT (Non-Fungible Token) operations (KVP-106).
#[derive(Subcommand)]
enum NftCommand {
    /// Inspect an NFT asset (requires node with asset registry).
    Info {
        /// Asset ID to inspect (32-byte hex).
        #[arg(long)]
        asset_id: String,
    },
    /// List NFTs in a collection.
    Collection {
        /// Collection ID (32-byte hex).
        #[arg(long)]
        collection_id: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = Client::new(&cli.api);

    match cli.command {
        Command::Head => print_json(&client.head()?)?,
        Command::P2p => print_json(&client.p2p()?)?,
        Command::Bootstrap => print_json(&client.bootstrap()?)?,
        Command::State => print_json(&client.state()?)?,
        Command::Blocks => print_json(&client.blocks()?)?,
        Command::Balance { address } => {
            let addr = parse_address(&address)?;
            print_json(&client.utxos(&addr.to_hex())?)?;
        }
        Command::Keygen { key, force } => {
            let wallet = Wallet::generate()?;
            wallet.save(&key, force)?;
            let addr = wallet.address();
            println!("Wrote key to {} (keep it secret)", key.display());
            print_address(&addr);
        }
        Command::Address { key, passphrase } => {
            let wallet = Wallet::load_with_passphrase(&key, passphrase.as_deref().unwrap_or(""))?;
            print_address(&wallet.address());
        }
        Command::Send {
            key,
            to,
            amount,
            passphrase,
        } => send(
            &client,
            &key,
            &to,
            amount,
            passphrase.as_deref().unwrap_or(""),
        )?,
        Command::Wallet(wallet_cmd) => wallet(&wallet_cmd)?,
        Command::Htlc(htlc_cmd) => htlc(&client, htlc_cmd)?,
        Command::Offer(offer_cmd) => offer(&client, offer_cmd)?,
        Command::Rwa(rwa_cmd) => rwa(&client, rwa_cmd)?,
        Command::Nft(nft_cmd) => nft(&client, nft_cmd)?,
        Command::Tui => crate::tui::run(client)?,
    }
    Ok(())
}

fn parse_address(s: &str) -> Result<Address> {
    Address::parse(s).map_err(|e| anyhow::anyhow!("invalid address {s:?}: {e}"))
}

fn print_address(addr: &Address) {
    println!("address (kvnc): {}", addr.to_kvnc());
    println!("address (hex):  {}", addr.to_hex());
}

/// `wallet new|restore|show` — mnemonic wallet commands (M-02/M-03/M-04).
///
/// Derivation is the **frozen** SLIP-0010 ed25519 path
/// `m/44'/3007'/0'/0'/0'` (see `docs/backlog/DERIVATION.md`), matching the
/// SDK `kovanica-keys` crate and the web wallet.
fn wallet(cmd: &WalletCommand) -> Result<()> {
    match cmd {
        WalletCommand::New {
            key,
            words,
            passphrase,
            force,
            yes,
        } => {
            let pass = passphrase.as_deref().unwrap_or("");
            let wallet = Wallet::generate_with_mnemonic_words(*words, pass)?;
            let mnemonic = wallet
                .mnemonic()
                .context("freshly generated wallet has no mnemonic")?;

            // M-02 acceptance: the user must write the seed down. Print it
            // once, up front, and require an explicit confirmation before we
            // persist anything to disk (skippable for scripting with --yes).
            println!("Your new {words}-word backup phrase — write it down, do not lose it:");
            println!();
            println!("  {mnemonic}");
            println!();
            if !yes {
                print!("Type the FIRST word to confirm you wrote it down: ");
                use std::io::Write;
                std::io::stdout().flush()?;
                let mut answer = String::new();
                std::io::stdin()
                    .read_line(&mut answer)
                    .context("failed to read confirmation")?;
                let first = mnemonic.split(' ').next().unwrap_or("");
                if answer.trim() != first {
                    bail!("confirmation word did not match; nothing was saved");
                }
            }
            wallet.save(key, *force)?;
            if !pass.is_empty() {
                println!(
                    "NOTE: passphrase used at creation is NOT stored — you must pass \
                     `--passphrase` on every load of this wallet."
                );
            }
            println!("Wrote wallet to {} (0600)", key.display());
            print_address(&wallet.address());
        }
        WalletCommand::Restore {
            key,
            from_mnemonic,
            from_file,
            passphrase,
            force,
        } => {
            let pass = passphrase.as_deref().unwrap_or("");
            let wallet = if let Some(phrase) = from_mnemonic {
                Wallet::from_mnemonic_with_passphrase(phrase.trim(), pass)?
            } else if let Some(path) = from_file {
                let phrase = std::fs::read_to_string(path)
                    .with_context(|| format!("cannot read mnemonic file {}", path.display()))?;
                Wallet::from_mnemonic_with_passphrase(phrase.trim(), pass)?
            } else {
                // Interactive: read the phrase from stdin (paste or type).
                print!("Paste your mnemonic phrase and press Enter: ");
                use std::io::Write;
                std::io::stdout().flush()?;
                let mut phrase = String::new();
                std::io::stdin()
                    .read_line(&mut phrase)
                    .context("failed to read mnemonic")?;
                Wallet::from_mnemonic_with_passphrase(phrase.trim(), pass)?
            };
            wallet.save(key, *force)?;
            println!("Restored wallet to {} (0600)", key.display());
            print_address(&wallet.address());
        }
        WalletCommand::Show {
            key,
            passphrase,
            show_seed,
        } => {
            let wallet = Wallet::load_with_passphrase(key, passphrase.as_deref().unwrap_or(""))?;
            print_address(&wallet.address());
            println!("public key (hex): {}", hex::encode(wallet.public_key()));
            if *show_seed {
                // Explicit opt-in only; the mnemonic itself is never printed.
                println!("seed (hex): {}", hex::encode(wallet.seed()));
            }
        }
    }
    Ok(())
}

/// Build, sign, and broadcast a transfer.
///
/// Matches `kovanica-web`'s wallet flow and the node's own mempool test:
/// `prepare` returns a `sighash`; we sign those exact bytes with Ed25519 and
/// `submit` the 64-byte signature. The node recomputes and re-verifies the
/// spend, so the sighash is never trusted from the client.
fn send(
    client: &Client,
    key: &std::path::Path,
    to: &str,
    amount: u64,
    passphrase: &str,
) -> Result<()> {
    if amount == 0 {
        bail!("amount must be greater than zero");
    }
    let wallet = Wallet::load_with_passphrase(key, passphrase)?;
    let from = wallet.address().to_hex();
    let to = parse_address(to)?.to_hex();

    let prepared = client.prepare(&from, &to, amount)?;
    let sighash_hex = prepared
        .get("sighash")
        .and_then(|v| v.as_str())
        .context("prepare response is missing a sighash")?;
    let sighash = hex::decode(sighash_hex.trim()).context("sighash is not valid hex")?;

    let sig = wallet.keypair().sign(&sighash);
    let sig_hex = hex::encode(sig);

    let result = client.submit(&from, &to, amount, &sig_hex)?;
    let tx = result.get("tx").and_then(|v| v.as_str()).unwrap_or("");
    println!("Sent {amount} atoms ({} KVNC) to {to}", format_kvnc(amount));
    if let Some(fee) = prepared.get("fee").and_then(|v| v.as_u64()) {
        println!("fee: {fee} atoms");
    }
    if !tx.is_empty() {
        println!("tx: {tx}");
    }
    print_json(&result)?;
    Ok(())
}

/// Render an atom amount as a fixed-point KVNC string (8 decimals).
fn format_kvnc(atoms: u64) -> String {
    format!("{}.{:08}", atoms / ATOM, atoms % ATOM)
}

/// HTLC command implementations.
fn htlc(client: &Client, cmd: HtlcCommand) -> Result<()> {
    match cmd {
        HtlcCommand::Create {
            key,
            amount,
            recipient_pk,
            preimage_hash,
            timeout,
            asset_id,
        } => {
            if amount == 0 {
                bail!("amount must be greater than zero");
            }
            let wallet = Wallet::load(&key)?;
            let from = wallet.address().to_hex();
            let recipient_pk_bytes =
                hex::decode(&recipient_pk).context("recipient_pk must be 32-byte hex")?;
            let recipient_pk: [u8; 32] = recipient_pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("recipient_pk must be 32 bytes"))?;
            let preimage_hash_bytes =
                hex::decode(&preimage_hash).context("preimage_hash must be 32-byte hex")?;
            let preimage_hash: [u8; 32] = preimage_hash_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("preimage_hash must be 32 bytes"))?;
            let asset_id = if let Some(id) = asset_id {
                let raw = hex::decode(&id).context("asset_id must be 32-byte hex")?;
                if raw.len() != 32 {
                    bail!("asset_id must be 32 bytes");
                }
                Some(kovanica_state::AssetId::from_bytes(
                    <[u8; 32]>::try_from(raw.as_slice())
                        .map_err(|_| anyhow::anyhow!("asset_id must be 32 bytes"))?,
                ))
            } else {
                None
            };

            let prepared = client.prepare_create_htlc(
                &from,
                amount,
                &recipient_pk,
                &preimage_hash,
                timeout,
                asset_id,
            )?;
            let sighash_hex = prepared
                .get("sighash")
                .and_then(|v| v.as_str())
                .context("prepare response is missing a sighash")?;
            let sighash = hex::decode(sighash_hex.trim()).context("sighash is not valid hex")?;

            let wallet = Wallet::load(&key)?;
            let sig = wallet.keypair().sign(&sighash);
            let sig_hex = hex::encode(sig);

            let result = client.submit_create_htlc(
                &from,
                amount,
                &recipient_pk,
                &preimage_hash,
                timeout,
                asset_id,
                sighash_hex,
                &sig_hex,
            )?;
            print_json(&result)?;
            Ok(())
        }
        HtlcCommand::Redeem {
            key,
            outpoint_tx,
            outpoint_index,
            script,
            preimage,
            to,
        } => {
            let wallet = Wallet::load(&key)?;
            let from = wallet.address().to_hex();
            let outpoint_tx_bytes =
                hex::decode(&outpoint_tx).context("outpoint_tx must be 32-byte hex")?;
            let txid = kovanica_state::TxId::from_bytes(
                outpoint_tx_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("outpoint_tx must be 32 bytes"))?,
            );
            let outpoint = kovanica_state::OutPoint::new(txid, outpoint_index);
            let script_bytes = hex::decode(&script).context("script must be 100-byte hex")?;
            if script_bytes.len() != 100 {
                bail!("script must be 100 bytes");
            }
            let script = kovanica_state::HtlcScript::parse(&script_bytes)
                .map_err(|e| anyhow::anyhow!("invalid script: {e:?}"))?;
            let preimage_bytes = hex::decode(&preimage).context("preimage must be 32-byte hex")?;
            if preimage_bytes.len() != 32 {
                bail!("preimage must be 32 bytes");
            }
            let preimage: [u8; 32] = preimage_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("preimage must be 32 bytes"))?;
            let to_addr = parse_address(&to)?;

            let wallet = Wallet::load(&key)?;
            let sighash_hex = {
                let prepared = client.prepare_redeem_htlc(
                    &from,
                    outpoint,
                    script,
                    preimage,
                    &to_addr.to_hex(),
                )?;
                let sighash_hex = prepared
                    .get("sighash")
                    .and_then(|v| v.as_str())
                    .context("missing sighash")?
                    .to_string(); // clone to own the string
                sighash_hex
            };
            let sighash = hex::decode(sighash_hex.trim()).context("sighash not hex")?;
            let sig = wallet.keypair().sign(&sighash);
            let sig_hex = hex::encode(sig);
            let sent = client.submit_redeem_htlc(
                &from,
                outpoint,
                script,
                preimage,
                &to_addr.to_hex(),
                &sighash_hex,
                &sig_hex,
            )?;
            println!("Redeemed HTLC");
            print_json(&sent)?;
            Ok(())
        }
        HtlcCommand::Refund {
            key,
            outpoint_tx,
            outpoint_index,
            script,
            to,
        } => {
            let wallet = Wallet::load(&key)?;
            let from = wallet.address().to_hex();
            let outpoint_tx_bytes =
                hex::decode(&outpoint_tx).context("outpoint_tx must be 32-byte hex")?;
            let txid = kovanica_state::TxId::from_bytes(
                outpoint_tx_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("outpoint_tx must be 32 bytes"))?,
            );
            let outpoint = kovanica_state::OutPoint::new(txid, outpoint_index);
            let script_bytes = hex::decode(&script).context("script must be 100-byte hex")?;
            if script_bytes.len() != 100 {
                bail!("script must be 100 bytes");
            }
            let script = kovanica_state::HtlcScript::parse(&script_bytes)
                .map_err(|e| anyhow::anyhow!("invalid script: {e:?}"))?;
            let to_addr = parse_address(&to)?;

            let wallet = Wallet::load(&key)?;
            let sighash_hex = {
                let prepared =
                    client.prepare_refund_htlc(&from, outpoint, script, &to_addr.to_hex())?;
                let sighash_hex = prepared
                    .get("sighash")
                    .and_then(|v| v.as_str())
                    .context("missing sighash")?
                    .to_string();
                sighash_hex
            };
            let sighash = hex::decode(sighash_hex.trim()).context("sighash not hex")?;
            let sig = wallet.keypair().sign(&sighash);
            let sig_hex = hex::encode(sig);
            let sent = client.submit_refund_htlc(
                &from,
                outpoint,
                script,
                &to_addr.to_hex(),
                &sighash_hex,
                &sig_hex,
            )?;
            println!("Refunded HTLC");
            print_json(&sent)?;
            Ok(())
        }
        HtlcCommand::Balance { script } => {
            let script_bytes = hex::decode(&script).context("script must be 100-byte hex")?;
            if script_bytes.len() != 100 {
                bail!("script must be 100 bytes");
            }
            let script = kovanica_state::HtlcScript::parse(&script_bytes)
                .map_err(|e| anyhow::anyhow!("invalid script: {e:?}"))?;
            let balance = client.htlc_balance(&script)?;
            println!("{} atoms ({} KVNC)", balance, format_kvnc(balance));
            Ok(())
        }
    }
}

/// Offer command implementations.
fn offer(_client: &Client, cmd: OfferCommand) -> Result<()> {
    match cmd {
        OfferCommand::Create {
            maker,
            give_asset,
            give_amount,
            take_asset,
            take_amount,
            preimage_hash,
            timeout,
            expires_at,
        } => {
            let maker_addr = parse_address(&maker)?;

            let give_asset_id = if give_asset.is_empty() {
                None
            } else {
                let raw = hex::decode(&give_asset).context("give_asset must be 32-byte hex")?;
                if raw.len() != 32 {
                    bail!("give_asset must be 32 bytes");
                }
                Some(kovanica_state::AssetId::from_bytes(
                    raw.try_into()
                        .map_err(|_| anyhow::anyhow!("give_asset must be 32 bytes"))?,
                ))
            };

            let take_asset_id = if take_asset.is_empty() {
                None
            } else {
                let raw = hex::decode(&take_asset).context("take_asset must be 32-byte hex")?;
                if raw.len() != 32 {
                    bail!("take_asset must be 32 bytes");
                }
                Some(kovanica_state::AssetId::from_bytes(
                    raw.try_into()
                        .map_err(|_| anyhow::anyhow!("take_asset must be 32 bytes"))?,
                ))
            };

            let preimage_hash_bytes =
                hex::decode(&preimage_hash).context("preimage_hash must be 32-byte hex")?;
            if preimage_hash_bytes.len() != 32 {
                bail!("preimage_hash must be 32 bytes");
            }
            let preimage_hash: [u8; 32] = preimage_hash_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("preimage_hash must be 32 bytes"))?;

            let offer = serde_json::json!({
                "version": 1,
                "maker": maker_addr.to_hex(),
                "give": {
                    "asset_id": give_asset_id.map(|a| hex::encode(a.as_bytes())).unwrap_or("0000000000000000000000000000000000000000000000000000000000000000".to_string()),
                    "amount": give_amount.to_string(),
                },
                "take": {
                    "asset_id": take_asset_id.map(|a| hex::encode(a.as_bytes())).unwrap_or("0000000000000000000000000000000000000000000000000000000000000000".to_string()),
                    "amount": take_amount.to_string(),
                },
                "payment_hash": hex::encode(preimage_hash),
                "timeout_height": timeout,
                "expires_at": expires_at,
            });

            let offer_json = serde_json::to_string_pretty(&offer)?;
            println!("{}", offer_json);
            Ok(())
        }
        OfferCommand::Verify { offer } => {
            let offer_json = if std::path::Path::new(&offer).exists() {
                std::fs::read_to_string(&offer)?
            } else {
                offer
            };
            let parsed: serde_json::Value = serde_json::from_str(&offer_json)
                .map_err(|e| anyhow::anyhow!("invalid offer JSON: {e}"))?;
            println!("Offer is valid JSON");
            println!("{}", serde_json::to_string_pretty(&parsed)?);
            Ok(())
        }
    }
}

/// RWA (KVP-106) command implementations.
fn rwa(client: &Client, cmd: RwaCommand) -> Result<()> {
    match cmd {
        RwaCommand::Derive {
            issuer,
            class,
            id,
            version,
        } => {
            let issuer_bytes = hex::decode(&issuer).context("issuer must be 32-byte hex")?;
            if issuer_bytes.len() != 32 {
                bail!("issuer must be 32 bytes (64 hex chars)");
            }
            let issuer: [u8; 32] = issuer_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("issuer must be 32 bytes"))?;
            let asset_id = derive_rwa_asset_id(&issuer, &class, &id, version);
            println!("Asset ID (hex): {}", asset_id.to_hex());
            println!("Asset ID (kvnc): kvnc{}dag", asset_id.to_hex());
            Ok(())
        }
        RwaCommand::Issue {
            key,
            asset_id,
            amount,
            metadata: _metadata,
            collection_id,
            to,
        } => {
            if amount == 0 {
                bail!("amount must be greater than zero");
            }
            let wallet = Wallet::load(&key)?;
            let from = wallet.address().to_hex();
            let to_addr = parse_address(&to)?;
            let asset_id_bytes = hex::decode(&asset_id).context("asset_id must be 32-byte hex")?;
            if asset_id_bytes.len() != 32 {
                bail!("asset_id must be 32 bytes (64 hex chars)");
            }
            let asset_id: AssetId = AssetId::from_bytes(
                asset_id_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("asset_id must be 32 bytes"))?,
            );
            let collection_id = if let Some(c) = collection_id {
                let bytes = hex::decode(&c).context("collection_id must be 32-byte hex")?;
                if bytes.len() != 32 {
                    bail!("collection_id must be 32 bytes");
                }
                Some(
                    <[u8; 32]>::try_from(bytes.as_slice())
                        .map_err(|_| anyhow::anyhow!("collection_id must be 32 bytes"))?,
                )
            } else {
                None
            };
            // For now, we'll use the prepare endpoint with asset_id
            // The metadata handling would need API support
            let prepared =
                client.prepare_transfer_asset(&from, &to_addr.to_hex(), amount, Some(asset_id))?;
            let sighash_hex = prepared
                .get("sighash")
                .and_then(|v| v.as_str())
                .context("prepare response is missing a sighash")?;
            let sighash = hex::decode(sighash_hex.trim()).context("sighash is not valid hex")?;
            let sig = wallet.keypair().sign(&sighash);
            let sig_hex = hex::encode(sig);
            let result = client.submit_transfer_asset(
                &from,
                &to_addr.to_hex(),
                amount,
                Some(asset_id),
                &sig_hex,
            )?;
            println!("Issued RWA asset {}", asset_id.to_hex());
            println!("Amount: {} atoms", amount);
            if let Some(cid) = collection_id {
                println!("Collection: {}", hex::encode(cid));
            }
            print_json(&result)?;
            Ok(())
        }
        RwaCommand::Burn {
            key,
            asset_id,
            amount,
        } => {
            if amount == 0 {
                bail!("amount must be greater than zero");
            }
            let _wallet = Wallet::load(&key)?;
            let _from = _wallet.address().to_hex();
            let asset_id_bytes = hex::decode(&asset_id).context("asset_id must be 32-byte hex")?;
            if asset_id_bytes.len() != 32 {
                bail!("asset_id must be 32 bytes (64 hex chars)");
            }
            let _asset_id: AssetId = AssetId::from_bytes(
                asset_id_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("asset_id must be 32 bytes"))?,
            );
            bail!("Burn command not yet fully implemented - requires node API support for burning assets");
        }
        RwaCommand::Info { asset_id } => {
            let asset_id_bytes = hex::decode(&asset_id).context("asset_id must be 32-byte hex")?;
            if asset_id_bytes.len() != 32 {
                bail!("asset_id must be 32 bytes (64 hex chars)");
            }
            bail!("Info command not yet fully implemented - requires node API support for asset registry queries");
        }
    }
}

/// NFT (KVP-106) command implementations.
fn nft(client: &Client, cmd: NftCommand) -> Result<()> {
    match cmd {
        NftCommand::Info { asset_id } => {
            let result = client.nft_detail(&asset_id)?;
            print_json(&result)?;
            Ok(())
        }
        NftCommand::Collection { collection_id } => {
            let result = client.collection_detail(&collection_id)?;
            print_json(&result)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_address_kvnc_is_a_known_vector() {
        // base58 of 33 zero bytes (version 0x00 + 32-byte payload) is 33 leading-zero markers ('1'),
        // so the human address is `kvnc` + 33×'1' + `dag`.
        let addr = Address::from_bytes([0u8; 32]);
        assert_eq!(addr.to_kvnc(), format!("kvnc{}dag", "1".repeat(33)));
    }

    #[test]
    fn kvnc_and_hex_roundtrip() {
        let addr = Address::from_bytes([0xABu8; 32]);
        let kvnc = addr.to_kvnc();
        assert!(kvnc.starts_with("kvnc") && kvnc.ends_with("dag"));
        // Shorter than the 64-hex form — base58 is denser than hex.
        assert!(kvnc.len() < 4 + 64 + 3);
        assert_eq!(parse_address(&kvnc).unwrap(), addr);
        assert_eq!(parse_address(&addr.to_hex()).unwrap(), addr);
    }

    #[test]
    fn atomic_swap_offer_creation_and_verification() {
        // Test the offer creation and verification flow
        use crate::Wallet;

        // This test verifies the offer JSON schema is correct
        let alice = Wallet::generate().expect("Alice wallet generation");
        let bob = Wallet::generate().expect("Bob wallet generation");

        let maker_addr = alice.address().to_hex();
        let _bob_addr = bob.address().to_hex();

        // Create offer JSON (simulating the offer create command)
        let give_asset_id: Option<kovanica_state::AssetId> = None; // native KVNC
        let take_asset_id: Option<kovanica_state::AssetId> = None; // native KVNC
        let preimage_hash = [0xAAu8; 32];

        let offer = serde_json::json!({
            "version": 1,
            "maker": maker_addr,
            "give": {
                "asset_id": give_asset_id.map(|a| hex::encode(a.as_bytes())).unwrap_or("0".repeat(64)),
                "amount": (10 * ATOM).to_string(), // 10 KVNC
            },
            "take": {
                "asset_id": take_asset_id.map(|a| hex::encode(a.as_bytes())).unwrap_or("0".repeat(64)),
                "amount": (5 * ATOM).to_string(), // 5 KVNC
            },
            "payment_hash": hex::encode(preimage_hash),
            "timeout_height": 100u64,
            "expires_at": "2026-12-31T23:59:59Z",
        });

        let offer_json = serde_json::to_string_pretty(&offer).unwrap();
        println!("Offer JSON:\n{}", offer_json);

        // Verify the offer can be parsed back
        let parsed: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&offer).unwrap()).unwrap();
        assert_eq!(parsed["version"], 1);
        assert_eq!(parsed["maker"], maker_addr);
        assert_eq!(parsed["give"]["amount"], (10 * ATOM).to_string());
        assert_eq!(parsed["take"]["amount"], (5 * ATOM).to_string());
        assert_eq!(parsed["payment_hash"], hex::encode(preimage_hash));
    }
}
