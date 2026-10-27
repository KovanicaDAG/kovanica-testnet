//! Late-join catch-up test: three validators run first, a fourth joins after
//! the chain has advanced and must catch up.
//!
//! The late node only sees *new* gossip blocks whose parents it does not
//! have. The node buffers such blocks in its bounded orphan buffer, requests
//! the missing parents (`BlockSyncRequest::ByHash`) from the delivering peer,
//! and re-processes buffered children once parents arrive, recursively back
//! to history it already has. Without that path the late node can never
//! accept a block and its committed height stays at 0.
//!
//! Harness (process spawning, ports, logs, RPC polling) is shared in spirit
//! with `sustained_liveness_integration`; some helpers are unused here.
#![allow(dead_code)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use kovanica_crypto::generate_keypair;
use kovanica_staking::MIN_VALIDATOR_STAKE;
use kovanica_storage::Storage;
use kovanica_types::{Address, PublicKey};
use reqwest::Client;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::time::sleep;
use tracing::info;

// ---------------------------------------------------------------------------
// Test parameters (all tunable knobs live here)
// ---------------------------------------------------------------------------

/// Number of validators in the quorum (4 -> quorum threshold floor(2T/3)+1 = 3).
const NODES: usize = 4;

/// Consensus round duration, matching the Docker quorum.
const ROUND_DURATION_MS: u64 = 1000;

/// Sustained-liveness target: must commit at least this many leaders.
///
/// This is deliberately `> 4 * (k + 1)` with `k = 3` (i.e. `> 16`): it forces
/// the chain past the point where the buggy prune deletes the just-committed
/// leader (observed stall at height 4).
const TARGET_HEIGHT: u64 = 20;

/// Random per-run port blocks are drawn from this range (exclusive end).
/// Each block holds `NODES` RPC ports followed by `NODES` P2P ports.
const PORT_RANGE_START: u16 = 20_000;
const PORT_RANGE_END: u16 = 30_000;

/// How many random port blocks to try before giving up.
const PORT_ATTEMPTS: usize = 32;

/// How long to wait for a freshly started node's JSON-RPC to answer.
const RPC_READY_TIMEOUT_SECS: u64 = 30;

/// How long to wait for each node to see at least one peer.
const PEER_TIMEOUT_SECS: u64 = 30;

/// Bounded window for reaching [`TARGET_HEIGHT`].
const REACH_TARGET_TIMEOUT_SECS: u64 = 120;

/// Bounded window for all four nodes to agree on a height.
const SETTLE_TIMEOUT_SECS: u64 = 60;

/// Bounded window for observing commits *after* the target (proves the commit
/// loop no longer stalls on a dangling `last_committed`).
const GROWTH_TIMEOUT_SECS: u64 = 30;

/// Poll cadence for heights / peers.
const POLL_INTERVAL_MS: u64 = 500;

// ---------------------------------------------------------------------------
// Child process harness
// ---------------------------------------------------------------------------

/// A running `kovanica-node` validator plus everything needed to tear it down.
///
/// `std::process::Child` (not the tokio one) is used so cleanup can happen
/// synchronously from [`Drop`], which runs on both the success path and on
/// panic unwind.
struct QuorumNode {
    index: usize,
    child: Child,
    /// Dropping it removes the node's data dir; also read after shutdown for
    /// the committed-leader agreement check.
    data_dir: TempDir,
    /// Where the node writes stdout+stderr while it runs (inside `data_dir`).
    temp_log_path: PathBuf,
    /// Stable, temp-dir-independent archive of the log. `Drop` copies the temp
    /// log here *before* `data_dir` (and its `TempDir`) is removed, so the log
    /// survives both success and panic teardown.
    log_path: PathBuf,
    rpc_port: u16,
    #[allow(dead_code)]
    p2p_port: u16,
    #[allow(dead_code)]
    address: Address,
    #[allow(dead_code)]
    public_key: PublicKey,
}

impl QuorumNode {
    /// Provision a fresh data dir (genesis + key) and spawn the node.
    #[allow(clippy::too_many_arguments)]
    fn start(
        index: usize,
        rpc_port: u16,
        p2p_port: u16,
        bootnodes: Vec<String>,
        signing_key: SigningKey,
        public_key: PublicKey,
        address: Address,
        binary_path: &Path,
        genesis_toml: &str,
        log_dir: &Path,
    ) -> Result<Self> {
        let data_dir = TempDir::new().with_context(|| format!("node {index}: create data dir"))?;

        // Every node gets the *same* genesis validator set (all four members) so
        // that `build_committee` derives an identical committee everywhere.
        std::fs::write(
            data_dir.path().join("genesis_validators.toml"),
            genesis_toml,
        )
        .with_context(|| format!("node {index}: write genesis_validators.toml"))?;

        // 32-byte hex seed; the node derives its Ed25519 key from this.
        let key_path = data_dir.path().join("validator.key");
        write_private(&key_path, hex::encode(signing_key.to_bytes()))
            .with_context(|| format!("node {index}: write validator.key"))?;

        // Capture node stdout/stderr. The live log lives inside the data dir
        // (removed on teardown); `Drop` copies it into the stable `log_dir`
        // before that happens, so post-mortem survives either outcome.
        let temp_log_path = data_dir.path().join(format!("node{index}.log"));
        let log_path = log_dir.join(format!("node{index}.log"));
        let log = std::fs::File::create(&temp_log_path)
            .with_context(|| format!("node {index}: create {}", temp_log_path.display()))?;
        let log_err = log.try_clone()?;

        let child = Command::new(binary_path)
            .current_dir(data_dir.path())
            .env("KOVANICA_DATA_DIR", data_dir.path())
            .env("KOVANICA_RPC_ADDR", "127.0.0.1")
            .env("KOVANICA_RPC_PORT", rpc_port.to_string())
            .env("KOVANICA_LISTEN_ADDR", format!("127.0.0.1:{p2p_port}"))
            .env("KOVANICA_MAX_PEERS", "8")
            .env("KOVANICA_ROUND_DURATION_MS", ROUND_DURATION_MS.to_string())
            .env("KOVANICA_RUN_VALIDATOR", "true")
            .env("KOVANICA_MYSTICGHOST", "true")
            // Disable the RPC rate limiter: the poll-driven `kovanica_blockNumber`
            // calls would otherwise hit HTTP 429 under the default 60 req/min
            // (this is what the previous failure actually was, not a stall).
            .env("KOVANICA_RPC_RATE_LIMIT_PER_MIN", "0")
            .env("KOVANICA_VALIDATOR_KEY", key_path.as_os_str())
            .env("KOVANICA_BOOTNODES", bootnodes.join(","))
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .with_context(|| format!("node {index}: spawn {}", binary_path.display()))?;

        info!(
            node = index,
            rpc = rpc_port,
            p2p = p2p_port,
            bootnodes = ?bootnodes,
            log = %log_path.display(),
            "spawned validator node"
        );

        Ok(Self {
            index,
            child,
            data_dir,
            temp_log_path,
            log_path,
            rpc_port,
            p2p_port,
            address,
            public_key,
        })
    }

    /// Block until this node's JSON-RPC answers `kovanica_blockNumber`.
    async fn wait_ready(&self, client: &Client, timeout_secs: u64) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            if get_height(client, self.rpc_port).await.is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "node {} RPC on 127.0.0.1:{} not ready after {}s",
                    self.index,
                    self.rpc_port,
                    timeout_secs
                );
            }
            sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
        }
    }

    /// One-line liveness snapshot for the end-of-test report.
    ///
    /// Uses `try_wait`, which reaps the child if it already exited (and caches
    /// the status), or reports `running` if it is still alive.
    fn status_line(&mut self) -> String {
        match self.child.try_wait() {
            Ok(Some(status)) => format!("exited={status}"),
            Ok(None) => "running".to_string(),
            Err(e) => format!("try_wait-error={e}"),
        }
    }

    /// Print `node{i} pid=... exited=<status|running> log=<stable path>`.
    fn report_status(&mut self) {
        let status = self.status_line();
        eprintln!(
            "[late_join] node {} pid={} rpc=127.0.0.1:{} {} log={}",
            self.index,
            self.child.id(),
            self.rpc_port,
            status,
            self.log_path.display()
        );
    }

    /// Stop the node and wait for it to exit. Idempotent with the `Drop` guard.
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for QuorumNode {
    fn drop(&mut self) {
        // Best-effort SIGKILL so no node process ever outlives the test, even on
        // panic unwind.
        let _ = self.child.kill();
        let _ = self.child.wait();

        // `Drop::drop` runs *before* the fields are dropped, so `data_dir`
        // (and its `TempDir`) still exists here: copy the live log into the
        // stable archive before it is removed.
        match std::fs::copy(&self.temp_log_path, &self.log_path) {
            Ok(bytes) => eprintln!(
                "[late_join] preserved node {} log ({} bytes) -> {}",
                self.index,
                bytes,
                self.log_path.display()
            ),
            Err(e) => eprintln!(
                "[late_join] failed to preserve node {} log {} -> {}: {e}",
                self.index,
                self.temp_log_path.display(),
                self.log_path.display()
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// JSON-RPC helpers
// ---------------------------------------------------------------------------

/// One JSON-RPC round trip.
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
        .with_context(|| format!("RPC POST {method} on port {port} (connect/send)"))?;

    // Read the raw body first so we can distinguish connection refused (handled
    // by the `?` above) from an HTTP non-200 from a JSON-RPC `error` object from
    // a plain malformed body.
    let status = resp.status();
    let body = resp
        .text()
        .await
        .with_context(|| format!("RPC read body {method} on port {port}"))?;

    if !status.is_success() {
        bail!("RPC {method} on port {port}: HTTP {status} (non-200 body: {body})");
    }

    let value: Value = serde_json::from_str(&body)
        .with_context(|| format!("RPC decode {method} on port {port}: invalid JSON `{body}`"))?;

    if let Some(err) = value.get("error") {
        bail!("RPC {method} on port {port}: JSON-RPC error object: {err}");
    }

    Ok(value)
}

/// `kovanica_blockNumber` -> latest committed leader height.
async fn get_height(client: &Client, port: u16) -> Result<u64> {
    let resp = rpc_call(client, port, "kovanica_blockNumber", json!([])).await?;
    let raw = resp
        .get("result")
        .and_then(Value::as_str)
        .with_context(|| format!("kovanica_blockNumber on port {port}: missing string result"))?;
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    u64::from_str_radix(raw, 16)
        .with_context(|| format!("kovanica_blockNumber on port {port}: invalid hex `{raw}`"))
}

/// `/health` -> connected peer count.
async fn peer_count(client: &Client, port: u16) -> Result<u64> {
    let resp = client
        .get(format!("http://127.0.0.1:{port}/health"))
        .send()
        .await
        .with_context(|| format!("health GET on port {port}"))?
        .json::<Value>()
        .await
        .with_context(|| format!("health decode on port {port}"))?;
    resp.get("peer_count")
        .and_then(Value::as_u64)
        .with_context(|| format!("health on port {port}: missing peer_count"))
}

/// Wait (best-effort, bounded) for every node to have at least one peer, then
/// assert connectivity. Without peers no votes can reach quorum.
async fn wait_for_peers(client: &Client, nodes: &[QuorumNode], timeout_secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut counts = vec![0u64; nodes.len()];
    loop {
        for (i, node) in nodes.iter().enumerate() {
            match peer_count(client, node.rpc_port).await {
                Ok(c) => counts[i] = c,
                Err(e) => eprintln!(
                    "[late_join] node {i} (rpc 127.0.0.1:{}) /health peer_count probe failed: {e:#}",
                    node.rpc_port
                ),
            }
        }
        if counts.iter().all(|c| *c >= 1) || Instant::now() >= deadline {
            break;
        }
        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
    info!(?counts, "observed peer counts");
    for (i, c) in counts.iter().enumerate() {
        assert!(
            *c >= 1,
            "node {i} has no peers after {timeout_secs}s; the quorum cannot form"
        );
    }
}

// ---------------------------------------------------------------------------
// Sustained-liveness polling
// ---------------------------------------------------------------------------

/// Dump per-node liveness + RPC diagnostics. Called right before a convergence
/// failure so the report contains the *real* RPC error string and whether the
/// node process is still alive (rather than a bare "RPC unavailable").
async fn dump_diagnostics(client: &Client, nodes: &mut [QuorumNode]) {
    eprintln!("[late_join] ===== convergence diagnostics =====");
    for node in nodes.iter_mut() {
        node.report_status();
        match get_height(client, node.rpc_port).await {
            Ok(h) => eprintln!(
                "[late_join]   node {} kovanica_blockNumber ok height={h}",
                node.index
            ),
            Err(e) => eprintln!(
                "[late_join]   node {} kovanica_blockNumber error: {e:#}",
                node.index
            ),
        }
        match peer_count(client, node.rpc_port).await {
            Ok(c) => eprintln!("[late_join]   node {} /health peer_count={c}", node.index),
            Err(e) => eprintln!("[late_join]   node {} /health error: {e:#}", node.index),
        }
    }
    eprintln!("[late_join] ===== end diagnostics =====");
}

/// Poll all nodes until `done` is satisfied or `timeout` elapses.
///
/// While polling, each node's committed height must be **non-decreasing** once
/// it has been observed (`last_committed` must never dangle or roll back). The
/// returned vector contains one resolved height per node from the satisfying
/// sample.
///
/// Takes `&mut [QuorumNode]` so that a convergence failure can inspect each
/// child's exit status via [`QuorumNode::report_status`].
async fn wait_until(
    client: &Client,
    nodes: &mut [QuorumNode],
    timeout: Duration,
    monotonic: &mut [Option<u64>],
    mut done: impl FnMut(&[Option<u64>]) -> bool,
) -> Result<Vec<u64>> {
    let deadline = Instant::now() + timeout;
    let mut last: Vec<Option<u64>> = vec![None; nodes.len()];
    loop {
        for (i, node) in nodes.iter_mut().enumerate() {
            match get_height(client, node.rpc_port).await {
                Ok(h) => {
                    if let Some(prev) = monotonic[i] {
                        assert!(
                            h >= prev,
                            "node {i} committed height regressed from {prev} to {h}: \
                             a committed decision was rolled back (dangling last_committed)"
                        );
                    }
                    monotonic[i] = Some(h);
                    last[i] = Some(h);
                }
                Err(err) => {
                    // Surface the concrete transport/RPC error instead of
                    // collapsing it to `None`: connection refused vs timeout vs
                    // JSON-RPC error vs non-200.
                    eprintln!(
                        "[late_join] node {i} (rpc 127.0.0.1:{}) \
                         kovanica_blockNumber failed: {err:#}",
                        node.rpc_port
                    );
                    last[i] = None;
                }
            }
        }

        if done(&last) {
            if last.iter().any(Option::is_none) {
                dump_diagnostics(client, nodes).await;
            }
            return last
                .into_iter()
                .enumerate()
                .map(|(i, h)| h.with_context(|| format!("node {i} RPC unavailable at convergence")))
                .collect();
        }

        if Instant::now() >= deadline {
            dump_diagnostics(client, nodes).await;
            bail!(
                "timed out after {:?} waiting for sustained liveness; \
                 last committed heights per node: {:?}",
                timeout,
                last
            );
        }
        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}

/// Minimum height across all nodes, or `None` if any node is unreachable.
fn min_height(sample: &[Option<u64>]) -> Option<u64> {
    let heights: Option<Vec<u64>> = sample.iter().copied().collect();
    heights.and_then(|v| v.into_iter().min())
}

/// True when every node answers and the lowest height is `>= min`.
fn all_at_least(sample: &[Option<u64>], min: u64) -> bool {
    min_height(sample).is_some_and(|h| h >= min)
}

/// `true` if `port` can be bound on 127.0.0.1 right now (listener dropped
/// immediately).
fn port_is_free(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

/// Pick a random block of `2 * NODES` consecutive free ports (RPC block then
/// P2P block) and return the two base ports.
///
/// Random per run (seeded from time + pid, no extra dependency) so parallel
/// runs or a leftover node from a crashed run do not collide; every port is
/// probed with bind-then-drop so a busy block is skipped. A small race remains
/// between the probe and the node binding, which the random base makes
/// unlikely.
fn pick_free_ports() -> Result<(u16, u16)> {
    let span = (2 * NODES) as u64;
    let blocks = (PORT_RANGE_END - PORT_RANGE_START) as u64 / span;
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ ((std::process::id() as u64) << 32);
    for _ in 0..PORT_ATTEMPTS {
        // xorshift64
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let base = PORT_RANGE_START + ((seed % blocks) * span) as u16;
        if (0..span as u16).all(|offset| port_is_free(base + offset)) {
            return Ok((base, base + NODES as u16));
        }
    }
    bail!("no free block of {span} ports found in {PORT_RANGE_START}..{PORT_RANGE_END}")
}

/// Committed leader sequence of a stopped node, read from its consensus DB:
/// decided rounds in ascending order, flattened. Entry `H - 1` is the leader
/// committed at height `H`.
fn committed_leaders(data_dir: &Path) -> Result<Vec<[u8; 32]>> {
    let path = data_dir.join("consensus.redb");
    let storage =
        Storage::new(&path).with_context(|| format!("open consensus db {}", path.display()))?;
    let txn = storage.begin_read()?;
    let consensus = storage.consensus();
    let mut leaders = Vec::new();
    for round in consensus.get_decided_rounds(&txn, u64::MAX)? {
        for hash in consensus.get_decided_leaders(&txn, round)? {
            leaders.push(hash.0);
        }
    }
    Ok(leaders)
}

/// Max height observed in a sample (0 if none).
fn max_height(sample: &[Option<u64>]) -> u64 {
    sample.iter().flatten().copied().max().unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Resolve the node binary: `KOVANICA_NODE_BINARY` if set, otherwise the binary
/// Cargo built for this test run.
fn node_binary_path() -> PathBuf {
    std::env::var("KOVANICA_NODE_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_BIN_EXE_kovanica-node")))
}

/// Resolve the stable, temp-dir-independent directory that per-node logs are
/// archived into.
///
/// Overridable with `KOVANICA_TEST_LOG_DIR`; otherwise defaults to
/// `<workspace>/target/quorum-logs/<unix_ts>` so successive runs never clobber
/// each other.
fn stable_log_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("KOVANICA_TEST_LOG_DIR") {
        return PathBuf::from(dir);
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
        .join(ts.to_string())
}

/// Build the shared `genesis_validators.toml` (all four members, equal stake).
///
/// The node parses this file as `GenesisValidatorsFile { validator: Vec<_> }`,
/// so each entry is a `[[validator]]` table (singular).
fn build_genesis_toml(validators: &[(SigningKey, PublicKey, Address)]) -> String {
    let mut out = String::from("# generated by sustained_liveness_integration\n");
    // Explicit chain id (mandatory for mainnet/testnet, optional for local).
    out.push_str("chain_id = 1337\n\n");
    for (_, pk, addr) in validators {
        out.push_str("[[validator]]\n");
        out.push_str(&format!("address = \"{}\"\n", hex::encode(addr.0)));
        out.push_str(&format!("stake = {MIN_VALIDATOR_STAKE}\n"));
        out.push_str(&format!("public_key = \"{}\"\n\n", hex::encode(pk.0)));
    }
    out
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// Boot four real validators and prove the commit loop keeps running well past
/// the pruning boundary. See the module docs for the expected pre/post-fix
/// behaviour.
/// Committed height the first three nodes must reach before node 3 starts.
const JOIN_AFTER_HEIGHT: u64 = 4;
/// How far past the join point node 3 must commit, and within what window.
const CATCH_UP_MARGIN: u64 = 4;
const CATCH_UP_TIMEOUT_SECS: u64 = 120;

// PRO-40: with one of four validators offline until the join, every fourth
// leader slot never gets a block. Before the hotfix (#84) this test passed
// only because each node silently skipped those slots on its own schedule
// (on 38e6a74 node 1 committed 15, 18, 21... over the unseen slot 12 while
// node 0 stalled at 9). With the hotfix the walk stalled there on every node;
// with the quorum-certified skip (PR 3/4) the three online validators time the
// empty slots out together and skip them with a certificate. The late node
// proposes for its own old slots, votes for them, and gets past them when a
// peer answers its rebroadcast vote with the stored certificate.
#[tokio::test]
async fn late_joining_validator_catches_up_via_parent_sync() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let binary_path = node_binary_path();
    if !binary_path.exists() {
        bail!("node binary {} not found", binary_path.display());
    }
    let log_dir = stable_log_dir();
    std::fs::create_dir_all(&log_dir)?;
    eprintln!("[late_join] node logs under: {}", log_dir.display());

    let mut validators: Vec<(SigningKey, PublicKey, Address)> = Vec::with_capacity(NODES);
    for _ in 0..NODES {
        let (sk, pk) = generate_keypair();
        let addr = Address::from_public_key(&pk);
        validators.push((sk, pk, addr));
    }
    let genesis_toml = build_genesis_toml(&validators);
    let client = Client::new();
    let (rpc_base_port, p2p_base_port) = pick_free_ports()?;
    eprintln!("[late_join] ports: rpc base {rpc_base_port}, p2p base {p2p_base_port}");

    let start = |i: usize| -> Result<QuorumNode> {
        let (sk, pk, addr) = validators[i].clone();
        let bootnodes = (0..NODES)
            .filter(|j| *j != i)
            .map(|j| format!("127.0.0.1:{}", p2p_base_port + j as u16))
            .collect::<Vec<_>>();
        QuorumNode::start(
            i,
            rpc_base_port + i as u16,
            p2p_base_port + i as u16,
            bootnodes,
            sk,
            pk,
            addr,
            &binary_path,
            &genesis_toml,
            &log_dir,
        )
        .with_context(|| format!("starting validator node {i}"))
    };

    // --- Phase A: three of four validators (quorum 3/4) make progress ---------
    let mut quorum: Vec<QuorumNode> = Vec::with_capacity(NODES);
    for i in 0..NODES - 1 {
        let node = start(i)?;
        node.wait_ready(&client, RPC_READY_TIMEOUT_SECS).await?;
        quorum.push(node);
    }
    wait_for_peers(&client, &quorum, PEER_TIMEOUT_SECS).await;
    let mut early_mono: Vec<Option<u64>> = vec![None; NODES - 1];
    let early = wait_until(
        &client,
        &mut quorum,
        Duration::from_secs(REACH_TARGET_TIMEOUT_SECS),
        &mut early_mono,
        |s| all_at_least(s, JOIN_AFTER_HEIGHT),
    )
    .await
    .context("three validators did not reach the join height")?;
    let join_height = *early.iter().max().expect("nodes");
    info!(heights = ?early, "three validators progressed; starting late node");

    // --- Phase B: late node joins and must catch up ---------------------------
    let late = start(NODES - 1)?;
    late.wait_ready(&client, RPC_READY_TIMEOUT_SECS).await?;
    quorum.push(late);
    let mut mono: Vec<Option<u64>> = early_mono.into_iter().chain([None]).collect();
    let target = join_height + CATCH_UP_MARGIN;
    let caught_up = wait_until(
        &client,
        &mut quorum,
        Duration::from_secs(CATCH_UP_TIMEOUT_SECS),
        &mut mono,
        |s| s[NODES - 1].is_some_and(|h| h >= target),
    )
    .await
    .with_context(|| {
        format!("late node did not catch up to committed height {target} (joined at {join_height})")
    })?;
    info!(heights = ?caught_up, join_height, target, "late node caught up");

    for node in quorum.iter_mut() {
        node.stop();
    }

    // --- Agreement: every leader the late node committed is the same leader,
    // in the same order, as on node 0 (a contiguous run of node 0's sequence).
    // The late node does not replay commits from before its first committed
    // leader (no state sync here), so its sequence may start later.
    let early_leaders = committed_leaders(quorum[0].data_dir.path())?;
    let late_leaders = committed_leaders(quorum[NODES - 1].data_dir.path())?;
    assert!(!late_leaders.is_empty(), "late node committed nothing");
    let offset = early_leaders
        .iter()
        .position(|h| *h == late_leaders[0])
        .context("late node's first committed leader is unknown to node 0")?;
    let common = late_leaders.len().min(early_leaders.len() - offset);
    assert!(
        common >= CATCH_UP_MARGIN as usize,
        "too little overlap ({common})"
    );
    assert_eq!(
        early_leaders[offset..offset + common],
        late_leaders[..common],
        "late node's committed leader sequence diverges from node 0"
    );
    eprintln!("[late_join] late node first commit = node 0 leader #{offset}, overlap {common}");
    eprintln!(
        "[late_join] node logs archived under: {}",
        log_dir.display()
    );
    Ok(())
}

/// Write a validator seed file readable only by the owner (the node refuses
/// group/world-accessible key files).
fn write_private(
    path: impl AsRef<std::path::Path>,
    contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    let path = path.as_ref();
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
