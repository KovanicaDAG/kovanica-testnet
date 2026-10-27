//! Throughput benchmark client for a local `kovanica` devnet.
//!
//! Two-phase design:
//!
//! 1. **Funding** (unless `--skip-fund`): a small set of funded devnet keys
//!    (`--funder-key-file`) each send one transfer to every derived bench
//!    account. Bench accounts are derived deterministically from `--seed`, so
//!    no key material has to be generated or stored.
//! 2. **Burst**: every bench account pre-signs a contiguous run of transfers
//!    (the mempool keeps at most one contiguous nonce run per sender, capped
//!    at 64 in-flight), the run is submitted over `kovanica_sendRawTransaction`,
//!    and committed transactions are counted from the senders' account nonces.
//!
//! Transactions for a given sender are submitted **in nonce order**, because
//! the mempool rejects a nonce that would leave a gap ahead of the contiguous
//! run it already holds. Different senders are submitted concurrently.
//!
//! Commitment is measured by polling `kovanica_getNonce` until every sender has
//! reached its target nonce (or the deadline passes). With contiguous,
//! nonce-consuming transfers this equals the number of committed
//! transactions, and it avoids the block-query RPCs (which read the state
//! database while blocks live in the consensus database).
//!
//! Output is one stable, greppable summary line:
//! `BENCH total=… senders=… per_sender=… accepted=… rejected=… committed=… submit_ms=… elapsed_s=… tps=…`

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde_json::json;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::sleep;

use kovanica_cli::rpc::{self, RpcClient};
use kovanica_cli::{tx, wallet};
use kovanica_types::crypto::{PublicKey, SigningKey};
use kovanica_types::transaction::TransactionKind;
use kovanica_types::Address;

/// The mempool keeps at most this many in-flight transactions per sender.
const MAX_TXS_PER_SENDER: usize = 64;

#[derive(Parser)]
#[command(
    name = "kovanica-bench",
    about = "Submit signed transfers to a kovanica devnet and measure committed throughput"
)]
struct Args {
    /// JSON-RPC endpoint of a validator node.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc_url: String,

    /// Network `chain_id` pinned into every signature (must match the node).
    #[arg(long, default_value_t = 1337)]
    chain_id: u64,

    /// Raw 32-byte hex seed file of an already-funded devnet key (repeatable).
    #[arg(long = "key-file")]
    key_files: Vec<PathBuf>,

    /// Raw 32-byte hex seed file of a funded account that pays for funding
    /// transfers to the derived bench senders (repeatable).
    #[arg(long = "funder-key-file")]
    funder_key_files: Vec<PathBuf>,

    /// Number of bench senders derived deterministically from `--seed`.
    #[arg(long, default_value_t = 0)]
    senders: usize,

    /// Domain separator for deterministic bench-sender derivation.
    #[arg(long, default_value = "kovanica-bench")]
    seed: String,

    /// Atoms transferred from a funder to each derived bench sender.
    #[arg(long, default_value_t = 100_000_000)]
    fund_amount: u64,

    /// Skip the funding phase (assumes derived senders are already funded).
    #[arg(long)]
    skip_fund: bool,

    /// How long to wait for the funding burst to commit.
    #[arg(long, default_value_t = 60)]
    fund_wait_secs: u64,

    /// Transactions to pre-sign per sender (clamped to 64).
    #[arg(long, default_value_t = 32)]
    txs_per_sender: usize,

    /// Maximum number of senders submitting concurrently.
    #[arg(long, default_value_t = 64)]
    concurrency: usize,

    /// Transfer amount per transaction, in atoms.
    #[arg(long, default_value_t = 1)]
    amount: u64,

    /// Fee per transaction, in atoms.
    #[arg(long, default_value_t = 1)]
    fee: u64,

    /// Recipient address (defaults to the all-0x01 address).
    #[arg(long)]
    dest: Option<String>,

    /// How long to keep polling for commitment after submitting.
    #[arg(long, default_value_t = 60)]
    wait_secs: u64,
}

/// Deterministically derive a 32-byte Ed25519 seed for bench sender `index`.
fn derived_seed(domain: &str, index: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (j, byte) in out.iter_mut().enumerate() {
        let mut x = 0x9Eu8;
        for (k, tag) in domain.as_bytes().iter().enumerate() {
            x = x
                .wrapping_mul(31)
                .wrapping_add(*tag)
                .wrapping_add((k as u8).wrapping_mul(7));
        }
        x = x
            .wrapping_mul(17)
            .wrapping_add((index as u8).wrapping_mul(29))
            .wrapping_add(j as u8);
        *byte = x;
    }
    out
}

/// Load raw-hex seed files into `(address, signing_key)` pairs.
fn load_keys(paths: &[PathBuf], label: &str) -> Result<Vec<(Address, SigningKey)>> {
    let mut keys = Vec::new();
    for path in paths {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading {label} key {}", path.display()))?;
        let seed = wallet::seed_from_raw_hex(&raw)
            .with_context(|| format!("parsing {label} key {}", path.display()))?;
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = PublicKey::from(signing_key.verifying_key());
        keys.push((Address::from_public_key(&public_key), signing_key));
    }
    Ok(keys)
}

/// Read a sender's committed account nonce.
async fn nonce(client: &Arc<RpcClient>, address: &Address) -> Result<u64> {
    let value = client
        .call("kovanica_getNonce", json!([address.to_string()]))
        .await
        .with_context(|| format!("kovanica_getNonce {address}"))?;
    rpc::parse_quantity(&value)
}

/// Submit `groups` concurrently (at most `concurrency` groups at a time) while
/// keeping each group's transactions in order. Returns the accepted count, the
/// rejected count and the first error observed.
async fn submit_grouped(
    client: &Arc<RpcClient>,
    groups: Vec<Vec<String>>,
    concurrency: usize,
) -> (usize, usize, Option<String>) {
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set = JoinSet::new();
    for group in groups {
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => break,
        };
        let client = client.clone();
        set.spawn(async move {
            let _permit = permit;
            let mut accepted = 0usize;
            let mut rejected = 0usize;
            let mut first_error: Option<String> = None;
            for raw in group {
                match client
                    .call("kovanica_sendRawTransaction", json!([raw]))
                    .await
                {
                    Ok(_) => accepted += 1,
                    Err(e) => {
                        rejected += 1;
                        first_error.get_or_insert_with(|| e.to_string());
                    }
                }
            }
            (accepted, rejected, first_error)
        });
    }

    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut first_error: Option<String> = None;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((a, r, e)) => {
                accepted += a;
                rejected += r;
                if let Some(e) = e {
                    first_error.get_or_insert(e);
                }
            }
            Err(e) => {
                rejected += 1;
                first_error.get_or_insert_with(|| format!("submit task failed: {e}"));
            }
        }
    }
    (accepted, rejected, first_error)
}

/// Poll sender nonces until each reaches its target (or the deadline passes),
/// returning how many sent transactions are committed.
async fn wait_committed(
    client: &Arc<RpcClient>,
    targets: &[(Address, u64, u64)],
    wait: Duration,
) -> Result<u64> {
    let deadline = Instant::now() + wait;
    loop {
        let mut committed = 0u64;
        let mut remaining = 0usize;
        for (address, base, target) in targets {
            let current = nonce(client, address).await?;
            committed += current.min(*target).saturating_sub(*base);
            if current < *target {
                remaining += 1;
            }
        }
        if remaining == 0 || Instant::now() >= deadline {
            return Ok(committed);
        }
        sleep(Duration::from_millis(300)).await;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let ctx = tx::signing_context(Some(args.chain_id))?;
    let client = Arc::new(RpcClient::new(args.rpc_url.clone()));

    let dest = match &args.dest {
        Some(s) => wallet::parse_address(s, "dest", args.chain_id)?,
        None => Address([0x01; 32]),
    };

    let funders = load_keys(&args.funder_key_files, "funder")?;

    // Derived bench senders (deterministically generated from --seed).
    let mut derived: Vec<(Address, SigningKey)> = Vec::with_capacity(args.senders);
    for index in 0..args.senders {
        let seed = derived_seed(&args.seed, index);
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = PublicKey::from(signing_key.verifying_key());
        derived.push((Address::from_public_key(&public_key), signing_key));
    }

    // Optional explicit senders from files (e.g. the devnet validator keys).
    let explicit = load_keys(&args.key_files, "sender")?;

    if derived.is_empty() && explicit.is_empty() {
        bail!("no senders: pass --senders N and/or at least one --key-file");
    }

    let per_sender = args.txs_per_sender.clamp(1, MAX_TXS_PER_SENDER);

    // ---- Phase 1: fund every derived bench sender from the funders. ----
    if !args.skip_fund && !derived.is_empty() {
        if funders.is_empty() {
            bail!("--funder-key-file is required unless --skip-fund is set");
        }
        let needed = (args.amount + args.fee).saturating_mul(per_sender as u64);
        if args.fund_amount < needed {
            bail!(
                "--fund-amount {} cannot cover {} transactions of amount+fee {} (need {})",
                args.fund_amount,
                per_sender,
                args.amount + args.fee,
                needed
            );
        }
        // The mempool accepts at most MAX_TXS_PER_SENDER in-flight per sender.
        let per_funder = derived.len().div_ceil(funders.len());
        if per_funder > MAX_TXS_PER_SENDER {
            bail!(
                "{} senders split across {} funders is {} funding txs per funder (mempool cap {})",
                derived.len(),
                funders.len(),
                per_funder,
                MAX_TXS_PER_SENDER
            );
        }

        // One ordered group per funder (nonces must not be submitted out of order).
        let mut groups: Vec<Vec<String>> = vec![Vec::new(); funders.len()];
        let mut next: Vec<u64> = Vec::with_capacity(funders.len());
        for (address, _) in &funders {
            next.push(nonce(&client, address).await?);
        }
        let mut counts: Vec<u64> = vec![0; funders.len()];
        for (i, (address, _)) in derived.iter().enumerate() {
            let f = i % funders.len();
            let (funder_address, funder_key) = &funders[f];
            let nonce = next[f];
            next[f] = nonce + 1;
            counts[f] += 1;
            let transaction = tx::build_signed(
                &ctx,
                *funder_address,
                nonce,
                TransactionKind::Transfer {
                    to: *address,
                    amount: args.fund_amount,
                },
                args.fee,
                funder_key,
            )?;
            groups[f].push(tx::encode_raw(&transaction)?);
        }

        let expected = derived.len() as u64;
        let (accepted, rejected, first_error) =
            submit_grouped(&client, groups, args.concurrency).await;
        let fund_targets: Vec<(Address, u64, u64)> = funders
            .iter()
            .enumerate()
            .map(|(f, (address, _))| (*address, next[f] - counts[f], next[f]))
            .collect();
        let committed = wait_committed(
            &client,
            &fund_targets,
            Duration::from_secs(args.fund_wait_secs),
        )
        .await?;
        println!(
            "BENCH funding expected={expected} accepted={accepted} rejected={rejected} committed={committed}"
        );
        if let Some(error) = &first_error {
            println!("BENCH funding first_error={error}");
        }
        if committed < expected {
            bail!(
                "funding incomplete: committed {committed} of {expected} within {}s",
                args.fund_wait_secs
            );
        }
    }

    // ---- Phase 2: burst from every bench sender. ----
    let mut senders: Vec<(Address, SigningKey)> = derived;
    senders.extend(explicit);

    let mut groups: Vec<Vec<String>> = Vec::with_capacity(senders.len());
    let mut targets: Vec<(Address, u64, u64)> = Vec::with_capacity(senders.len());
    for (address, signing_key) in &senders {
        let base = nonce(&client, address).await?;
        let mut group = Vec::with_capacity(per_sender);
        for offset in 0..per_sender as u64 {
            let kind = TransactionKind::Transfer {
                to: dest,
                amount: args.amount,
            };
            let transaction =
                tx::build_signed(&ctx, *address, base + offset, kind, args.fee, signing_key)?;
            group.push(tx::encode_raw(&transaction)?);
        }
        targets.push((*address, base, base + per_sender as u64));
        groups.push(group);
    }
    let total: usize = groups.iter().map(Vec::len).sum();

    let started = Instant::now();
    let (accepted, rejected, first_error) = submit_grouped(&client, groups, args.concurrency).await;
    let submit_elapsed = started.elapsed();
    let committed = wait_committed(&client, &targets, Duration::from_secs(args.wait_secs)).await?;

    let elapsed = started.elapsed().as_secs_f64();
    let tps = if elapsed > 0.0 {
        committed as f64 / elapsed
    } else {
        0.0
    };
    println!(
        "BENCH total={total} senders={} per_sender={per_sender} accepted={accepted} rejected={rejected} committed={committed} submit_ms={} elapsed_s={:.3} tps={:.2}",
        senders.len(),
        submit_elapsed.as_millis(),
        elapsed,
        tps,
    );
    if let Some(error) = first_error {
        println!("BENCH first_error={error}");
    }
    if committed < accepted as u64 {
        println!(
            "BENCH WARNING committed {committed} < accepted {accepted} within {}s",
            args.wait_secs
        );
    }
    Ok(())
}
