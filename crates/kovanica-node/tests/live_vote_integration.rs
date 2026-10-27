//! Live 2-node TCP test: vote → commit → execute.
//!
//! Spawns two `kovanica-node` processes on a free loopback port pair, with a
//! private temp data directory each. It does not read or write the live
//! testnet data directory, and it does not bind ports 8000 or 8545.
//!
//! The genesis file is `[[validator]]` tables (`GenesisValidatorsFile`), which
//! is the shape `init_genesis` parses. An inline `validators = [...]` array
//! does not deserialize.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use kovanica_crypto::{generate_keypair, sign as crypto_sign};
use kovanica_staking::{MIN_VALIDATOR_STAKE, ONE_KUNA};
use kovanica_types::{
    hash::Hash,
    signing::{chain_id, SigningContext},
    transaction::{Transaction, TransactionKind},
    Address, PublicKey, Signature,
};
use reqwest::Client;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::time::sleep;
use tracing::info;

const NODES: usize = 2;
const ROUND_DURATION_MS: u64 = 1000;
const CHAIN_ID: u64 = chain_id::LOCAL;
const RPC_READY_TIMEOUT_SECS: u64 = 30;
const PEER_TIMEOUT_SECS: u64 = 30;
const COMMIT_TIMEOUT_SECS: u64 = 60;
const TX_TIMEOUT_SECS: u64 = 60;
const POLL_INTERVAL_MS: u64 = 500;
const PORT_ATTEMPTS: usize = 32;

/// Transfer submitted by the second test. The recipient is not a validator, so
/// a matching balance can only come from executing this transaction.
const TRANSFER_AMOUNT: u64 = 100 * ONE_KUNA;
const TRANSFER_FEE: u64 = 1_000_000;

struct NodeProc {
    index: usize,
    child: Child,
    /// Kept so the data directory is removed only after the process exits.
    #[allow(dead_code)]
    data_dir: TempDir,
    temp_log_path: PathBuf,
    log_path: PathBuf,
    rpc_port: u16,
    address: Address,
    signing_key: SigningKey,
}

impl NodeProc {
    #[allow(clippy::too_many_arguments)]
    fn start(
        index: usize,
        rpc_port: u16,
        p2p_port: u16,
        bootnodes: &[String],
        signing_key: SigningKey,
        address: Address,
        binary: &Path,
        genesis_toml: &str,
        log_dir: &Path,
    ) -> Result<Self> {
        let data_dir = TempDir::new().with_context(|| format!("node {index}: temp dir"))?;
        std::fs::write(
            data_dir.path().join("genesis_validators.toml"),
            genesis_toml,
        )
        .with_context(|| format!("node {index}: write genesis"))?;

        let key_path = data_dir.path().join("validator.key");
        write_private(&key_path, hex::encode(signing_key.to_bytes()))
            .with_context(|| format!("node {index}: write validator key"))?;

        let temp_log_path = data_dir.path().join(format!("node{index}.log"));
        let log_path = log_dir.join(format!("node{index}.log"));
        let log = std::fs::File::create(&temp_log_path)
            .with_context(|| format!("node {index}: create log"))?;
        let log_err = log.try_clone()?;

        let child = Command::new(binary)
            .current_dir(data_dir.path())
            .env("KOVANICA_DATA_DIR", data_dir.path())
            .env("KOVANICA_RPC_ADDR", "127.0.0.1")
            .env("KOVANICA_RPC_PORT", rpc_port.to_string())
            .env("KOVANICA_LISTEN_ADDR", format!("127.0.0.1:{p2p_port}"))
            .env("KOVANICA_MAX_PEERS", "8")
            .env("KOVANICA_ROUND_DURATION_MS", ROUND_DURATION_MS.to_string())
            .env("KOVANICA_RUN_VALIDATOR", "true")
            .env("KOVANICA_CHAIN_ID", CHAIN_ID.to_string())
            .env("KOVANICA_RPC_AUTH", "disable")
            .env("KOVANICA_RPC_RATE_LIMIT_PER_MIN", "0")
            .env("KOVANICA_VALIDATOR_KEY", key_path.as_os_str())
            .env("KOVANICA_BOOTNODES", bootnodes.join(","))
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .with_context(|| format!("node {index}: spawn {}", binary.display()))?;

        info!(
            node = index,
            rpc = rpc_port,
            p2p = p2p_port,
            "spawned live-vote validator"
        );

        Ok(Self {
            index,
            child,
            data_dir,
            temp_log_path,
            log_path,
            rpc_port,
            address,
            signing_key,
        })
    }
}

impl Drop for NodeProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(parent) = self.log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::copy(&self.temp_log_path, &self.log_path) {
            Ok(bytes) => eprintln!(
                "[live_vote] preserved node {} log ({} bytes) -> {}",
                self.index,
                bytes,
                self.log_path.display()
            ),
            Err(err) => eprintln!(
                "[live_vote] failed to preserve node {} log {} -> {}: {err}",
                self.index,
                self.temp_log_path.display(),
                self.log_path.display()
            ),
        }
    }
}

struct Cluster {
    nodes: Vec<NodeProc>,
    client: Client,
    log_dir: PathBuf,
}

impl Cluster {
    fn start(label: &str, port_start: u16, port_end: u16) -> Result<Self> {
        let binary = node_binary_path();
        if !binary.exists() {
            bail!("node binary {} not found", binary.display());
        }
        let log_dir = stable_log_dir(label);
        std::fs::create_dir_all(&log_dir)?;
        eprintln!("[live_vote] {label} logs under {}", log_dir.display());

        let mut validators = Vec::with_capacity(NODES);
        for _ in 0..NODES {
            let (sk, pk) = generate_keypair();
            let addr = Address::from_public_key(&pk);
            validators.push((sk, pk, addr));
        }
        let genesis = build_genesis_toml(&validators);
        let (rpc_base, p2p_base) = pick_free_ports(port_start, port_end)?;
        eprintln!("[live_vote] {label} ports: rpc base {rpc_base}, p2p base {p2p_base}");

        // Spawn both before waiting, so their round clocks stay close.
        let mut nodes = Vec::with_capacity(NODES);
        for (i, (sk, _pk, addr)) in validators.iter().enumerate() {
            let bootnodes = (0..NODES)
                .filter(|j| *j != i)
                .map(|j| format!("127.0.0.1:{}", p2p_base + j as u16))
                .collect::<Vec<_>>();
            nodes.push(NodeProc::start(
                i,
                rpc_base + i as u16,
                p2p_base + i as u16,
                &bootnodes,
                sk.clone(),
                *addr,
                &binary,
                &genesis,
                &log_dir,
            )?);
        }

        Ok(Self {
            nodes,
            client: Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .context("reqwest client")?,
            log_dir,
        })
    }

    async fn wait_ready(&self) -> Result<()> {
        for node in &self.nodes {
            let deadline = Instant::now() + Duration::from_secs(RPC_READY_TIMEOUT_SECS);
            loop {
                if get_height(&self.client, node.rpc_port).await.is_ok() {
                    break;
                }
                if Instant::now() >= deadline {
                    bail!(
                        "node {} RPC on 127.0.0.1:{} not ready after {RPC_READY_TIMEOUT_SECS}s (logs {})",
                        node.index,
                        node.rpc_port,
                        self.log_dir.display()
                    );
                }
                sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
            }
        }
        Ok(())
    }

    async fn wait_for_peers(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(PEER_TIMEOUT_SECS);
        loop {
            let mut counts = Vec::with_capacity(self.nodes.len());
            for node in &self.nodes {
                counts.push(peer_count(&self.client, node.rpc_port).await.unwrap_or(0));
            }
            if counts.iter().all(|c| *c >= 1) {
                info!(?counts, "validators connected");
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "validators did not peer within {PEER_TIMEOUT_SECS}s (counts {counts:?}, logs {})",
                    self.log_dir.display()
                );
            }
            sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
        }
    }

    async fn wait_same_height_above(&self, min_exclusive: u64) -> Result<u64> {
        let deadline = Instant::now() + Duration::from_secs(COMMIT_TIMEOUT_SECS);
        let mut last = vec![None; self.nodes.len()];
        loop {
            for (i, node) in self.nodes.iter().enumerate() {
                last[i] = get_height(&self.client, node.rpc_port).await.ok();
            }
            if let Some(height) = same_height(&last) {
                if height > min_exclusive {
                    info!(height, "both nodes committed the same height");
                    return Ok(height);
                }
            }
            if Instant::now() >= deadline {
                bail!(
                    "nodes did not reach a shared committed height > {min_exclusive} within {COMMIT_TIMEOUT_SECS}s (last {last:?}, logs {})",
                    self.log_dir.display()
                );
            }
            sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
        }
    }
}

fn same_height(sample: &[Option<u64>]) -> Option<u64> {
    let first = sample.first().copied().flatten()?;
    if sample.iter().all(|h| *h == Some(first)) {
        Some(first)
    } else {
        None
    }
}

fn build_genesis_toml(validators: &[(SigningKey, PublicKey, Address)]) -> String {
    let mut out = String::from("# generated by live_vote_integration\n");
    out.push_str(&format!("chain_id = {CHAIN_ID}\n\n"));
    for (_, pk, addr) in validators {
        out.push_str("[[validator]]\n");
        out.push_str(&format!("address = \"{}\"\n", hex::encode(addr.0)));
        out.push_str(&format!("stake = {MIN_VALIDATOR_STAKE}\n"));
        out.push_str(&format!("public_key = \"{}\"\n\n", hex::encode(pk.0)));
    }
    out
}

fn create_transfer(
    sender: Address,
    to: Address,
    amount: u64,
    fee: u64,
    nonce: u64,
    signing_key: &SigningKey,
) -> Transaction {
    let tx = Transaction {
        sender,
        nonce,
        fee,
        kind: TransactionKind::Transfer { to, amount },
        signature: Signature([0; 64]),
        hash: Hash::zero(),
    };
    let msg = tx.signing_hash(&SigningContext::new(CHAIN_ID));
    let signature = crypto_sign(signing_key, &msg.0);
    Transaction {
        signature,
        hash: msg,
        ..tx
    }
}

fn node_binary_path() -> PathBuf {
    std::env::var("KOVANICA_NODE_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_BIN_EXE_kovanica-node")))
}

fn stable_log_dir(label: &str) -> PathBuf {
    if let Ok(dir) = std::env::var("KOVANICA_TEST_LOG_DIR") {
        return PathBuf::from(dir).join(label);
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .map(|p| p.join("../.."))
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("target/quorum-logs")
        .join(format!("live-vote-{ts}"))
        .join(label)
}

fn pick_free_ports(start: u16, end: u16) -> Result<(u16, u16)> {
    let span = (2 * NODES) as u64;
    let blocks = (end - start) as u64 / span;
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ ((std::process::id() as u64) << 32);
    for _ in 0..PORT_ATTEMPTS {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let base = start + ((seed % blocks) * span) as u16;
        if (0..span as u16).all(|offset| TcpListener::bind(("127.0.0.1", base + offset)).is_ok()) {
            return Ok((base, base + NODES as u16));
        }
    }
    bail!("no free block of {span} ports in {start}..{end}")
}

fn write_private(path: &Path, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

async fn rpc_call(client: &Client, port: u16, method: &str, params: Value) -> Result<Value> {
    let resp = client
        .post(format!("http://127.0.0.1:{port}/rpc"))
        .json(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }))
        .send()
        .await
        .with_context(|| format!("RPC {method} on {port}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .with_context(|| format!("RPC body {method} on {port}"))?;
    if !status.is_success() {
        bail!("RPC {method} on {port}: HTTP {status} body {body}");
    }
    let value: Value = serde_json::from_str(&body)
        .with_context(|| format!("RPC {method} on {port}: invalid JSON {body}"))?;
    if let Some(err) = value.get("error") {
        bail!("RPC {method} on {port}: {err}");
    }
    Ok(value)
}

async fn get_height(client: &Client, port: u16) -> Result<u64> {
    let resp = rpc_call(client, port, "kovanica_blockNumber", json!([])).await?;
    parse_quantity(
        resp.get("result")
            .context("kovanica_blockNumber missing result")?,
        "kovanica_blockNumber",
    )
}

async fn get_balance(client: &Client, port: u16, address: &Address) -> Result<u64> {
    let resp = rpc_call(
        client,
        port,
        "kovanica_getBalance",
        json!([address.to_string()]),
    )
    .await?;
    parse_quantity(
        resp.get("result")
            .context("kovanica_getBalance missing result")?,
        "kovanica_getBalance",
    )
}

fn parse_quantity(value: &Value, what: &str) -> Result<u64> {
    let raw = value
        .as_str()
        .with_context(|| format!("{what}: expected a hex quantity string, got {value}"))?;
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    u64::from_str_radix(raw, 16).with_context(|| format!("{what}: invalid hex {raw}"))
}

async fn peer_count(client: &Client, port: u16) -> Result<u64> {
    let resp = client
        .get(format!("http://127.0.0.1:{port}/health"))
        .send()
        .await
        .with_context(|| format!("health on {port}"))?
        .json::<Value>()
        .await
        .with_context(|| format!("health JSON on {port}"))?;
    resp.get("peer_count")
        .and_then(Value::as_u64)
        .with_context(|| format!("health on {port}: missing peer_count in {resp}"))
}

/// Both validators commit the same height above genesis.
#[tokio::test]
async fn live_two_node_vote_commit_execute() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let cluster = Cluster::start("commit", 31_000, 34_000)?;
    cluster.wait_ready().await?;
    cluster.wait_for_peers().await?;
    let height = cluster.wait_same_height_above(0).await?;
    assert!(height > 0, "committed height must advance");
    Ok(())
}

/// A signed transfer is admitted, committed, and credited on both nodes.
#[tokio::test]
async fn live_transaction_commit() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let cluster = Cluster::start("transfer", 35_000, 39_000)?;
    cluster.wait_ready().await?;
    cluster.wait_for_peers().await?;
    cluster.wait_same_height_above(0).await?;

    let sender = cluster.nodes[0].address;
    let signing_key = cluster.nodes[0].signing_key.clone();
    let recipient = Address([0xbb; 32]);
    let before = get_balance(&cluster.client, cluster.nodes[0].rpc_port, &recipient).await?;
    assert_eq!(before, 0, "fresh recipient must start at zero");

    let tx = create_transfer(
        sender,
        recipient,
        TRANSFER_AMOUNT,
        TRANSFER_FEE,
        0,
        &signing_key,
    );
    let raw = hex::encode(bincode::serialize(&tx)?);
    let submitted = rpc_call(
        &cluster.client,
        cluster.nodes[0].rpc_port,
        "kovanica_sendRawTransaction",
        json!([raw]),
    )
    .await
    .with_context(|| format!("submit transfer (logs {})", cluster.log_dir.display()))?;
    info!(result = %submitted, "transfer submitted");

    let deadline = Instant::now() + Duration::from_secs(TX_TIMEOUT_SECS);
    let mut last = Vec::new();
    loop {
        last.clear();
        for node in &cluster.nodes {
            last.push(
                get_balance(&cluster.client, node.rpc_port, &recipient)
                    .await
                    .ok(),
            );
        }
        if last.iter().all(|b| *b == Some(TRANSFER_AMOUNT)) {
            info!("transfer executed on both nodes");
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "recipient balance did not reach {TRANSFER_AMOUNT} on both nodes within {TX_TIMEOUT_SECS}s (last {last:?}, logs {})",
                cluster.log_dir.display()
            );
        }
        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}
