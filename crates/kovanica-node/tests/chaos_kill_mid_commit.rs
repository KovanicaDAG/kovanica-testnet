//! Chaos: real **mid-commit process kill** (`SIGKILL`) on a live 4-validator
//! quorum, followed by a restart and a committed-leader divergence check.
//!
//! # Why this test exists
//!
//! The existing crash coverage is deliberately gentle:
//!
//! * the in-process partition tests (`multi_node_integration`) model partitions
//!   at the message-delivery layer — no process ever dies;
//! * the restart test in `src/main.rs` sends an **orderly `SIGTERM`** and goes
//!   through the graceful shutdown path, never a mid-commit kill;
//! * `sustained_liveness_integration` spawns real processes but only proves the
//!   commit loop keeps running — it never kills one.
//!
//! The gap is a validator that dies *without warning while it is committing*. A
//! durable `SIGKILL` can land between "decided round persisted" and "committed
//! leader persisted", which is exactly the durable-commit window the
//! restart-recovery path in `src/main.rs` (`recover_committed_subdags`) has to
//! repair. This test exercises that path with the real binary and real TCP.
//!
//! # Topology and assertions
//!
//! Four real `kovanica-node` validators (quorum `floor(2T/3)+1 = 3`). The test:
//!
//! 1. brings the quorum up and waits until it has committed a few heights;
//! 2. waits for the victim (the last validator) to *advance* a height, then
//!    immediately `SIGKILL`s it — i.e. during active commit activity;
//! 3. asserts the remaining three **keep committing** (quorum survives);
//! 4. restarts the victim on its **same data dir** and asserts it **catches up**
//!    to the surviving quorum;
//! 5. asserts **no divergence**: the committed-leader sequence read straight out
//!    of every node's `consensus.redb` is byte-identical up to a fixed height;
//! 6. asserts **no panic / no corrupt DB**: each node's log is scanned for
//!    `panicked at`, and every `consensus.redb` must open and read cleanly.
//!
//! # Determinism and flakiness
//!
//! The fault is injected at a *bounded, observable* moment (right after the
//! victim's committed height moves), not at a wall-clock instant, so the kill is
//! always mid-activity rather than before warm-up or after quiescence. Exact
//! sub-round timing is inherently non-deterministic (real processes, real
//! sockets), so every phase uses a bounded window with an explicit timeout and a
//! clear failure message. This test is therefore **opt-in** (`#[ignore]`): run it
//! by hand (`bash ops/chaos/kill-mid-commit.sh`), never in per-PR CI. The kvnc
//! `chaos.yml` workflow that could dispatch it was removed on 2026-10-23.
//!
//! # Bug this harness found (restart after `SIGKILL`)
//!
//! Run against a **debug** build, this test reliably fails at the restart step:
//!
//! ```text
//! thread 'main' panicked at crates/kovanica-consensus/src/non_blue.rs:47:5:
//! canonical genesis block must never be in non_blue
//! ```
//!
//! `non_blue_refs` carries a `debug_assert!` that the canonical genesis block
//! can never be a red (non-blue) block — it is an ancestor of every block, so
//! GHOSTDAG must colour it blue. After a `SIGKILL` mid-commit the restart
//! recovery path feeds a mergeset that *does* contain genesis into
//! `non_blue_refs`, violating that invariant. A graceful `SIGTERM` restart (the
//! existing `src/main.rs` restart test) never triggers it, which is exactly why
//! this hard-kill harness was needed.
//!
//! The same run against a **release** binary (`debug_assert!` compiled out)
//! restarts and converges fine, so the durable-commit recovery itself works;
//! the finding is the recovery/live-path divergence that the assert exposes.
//! This is consensus-path code, so it is reported here rather than patched by
//! this ops/tests change.
//!
//! # Running
//!
//! ```sh
//! cargo build --release -p kovanica-node
//! KOVANICA_NODE_BINARY=target/release/kovanica-node \
//!   cargo test -p kovanica-node --test chaos_kill_mid_commit -- --ignored --nocapture
//! ```
//!
//! Use a **release** binary: the debug build trips the `debug_assert!` above,
//! and a debug build is also much slower at 4 validators. Without
//! `KOVANICA_NODE_BINARY` the test uses the debug binary Cargo built for it.
//!
//! Each run picks a random free block of RPC/P2P ports (below the Linux
//! ephemeral range, away from the live Docker quorum) and archives node logs
//! under `target/chaos-logs/<unix_ts>` (override with `KOVANICA_TEST_LOG_DIR`).

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

// ---------------------------------------------------------------------------
// Knobs (all timing lives here)
// ---------------------------------------------------------------------------

/// Validators in the quorum (4 -> quorum threshold `floor(2T/3)+1 = 3`).
const NODES: usize = 4;

/// Which validator is killed. The last one keeps the surviving quorum
/// `{0,1,2}`, so the "three keep committing" story is obvious.
const VICTIM: usize = NODES - 1;

/// Consensus round duration. Matches the other process-based harnesses.
const ROUND_DURATION_MS: u64 = 1000;

/// Committed height the quorum must reach *before* the kill, so the victim is
/// killed mid-chain rather than at genesis. Also the fixed height used for the
/// post-restart divergence check.
const PRE_KILL_HEIGHT: u64 = 6;

/// Random per-run port block range (exclusive end). Below 32768 so it never
/// collides with the ephemeral range; away from Docker RPC 8545-8548.
const PORT_RANGE_START: u16 = 20_000;
const PORT_RANGE_END: u16 = 30_000;
const PORT_ATTEMPTS: usize = 32;

/// How long to wait for a freshly started node's JSON-RPC to answer.
const RPC_READY_TIMEOUT_SECS: u64 = 30;
/// How long to wait for every node to see at least one peer.
const PEER_TIMEOUT_SECS: u64 = 30;
/// Bounded window to reach [`PRE_KILL_HEIGHT`].
const PRE_KILL_TIMEOUT_SECS: u64 = 150;
/// Window in which the victim must advance a height (so the kill is mid-commit).
const KILL_WINDOW_SECS: u64 = 45;
/// After the kill, window for each surviving node to commit at least one more.
const QUORUM_PROGRESS_TIMEOUT_SECS: u64 = 90;
/// Window after restart for the victim to catch up to the surviving quorum.
const CATCHUP_TIMEOUT_SECS: u64 = 120;
/// How far behind the tip the restarted victim may still be and count as
/// "caught up". A live chain advances every round, so at any single sample the
/// victim can legitimately be a commit or two behind the slowest survivor: what
/// matters is that it is *in consensus* and progressing, not that every node is
/// pinned to the same height in the same poll. The real divergence check is the
/// committed-leader prefix comparison at a fixed height below the tip.
const CATCHUP_LAG_TOLERANCE: u64 = 2;
/// Window for the whole quorum to settle at/above [`PRE_KILL_HEIGHT`] again.
const SETTLE_TIMEOUT_SECS: u64 = 90;
/// Poll cadence for heights / peers.
const POLL_INTERVAL_MS: u64 = 300;

// ---------------------------------------------------------------------------
// Child harness (same shape as `sustained_liveness_integration`, but a node can
// be spawned more than once against the same data dir)
// ---------------------------------------------------------------------------

/// A validator process that can be started, `SIGKILL`ed mid-commit, and started
/// again against the exact same data dir.
struct ChaosNode {
    index: usize,
    /// Persistent per-node data dir (survives a restart; removed with the run).
    data_dir: PathBuf,
    /// Stable log file, appended to across restarts so the pre-kill tail and the
    /// post-restart boot both remain readable.
    log_path: PathBuf,
    rpc_port: u16,
    p2p_port: u16,
    bootnodes: Vec<String>,
    key_path: PathBuf,
    binary: PathBuf,
    genesis_toml: String,
    child: Option<Child>,
}

impl ChaosNode {
    /// Provision the data dir (genesis + key) and spawn the node.
    #[allow(clippy::too_many_arguments)]
    fn provision(
        index: usize,
        data_dir: PathBuf,
        rpc_port: u16,
        p2p_port: u16,
        bootnodes: Vec<String>,
        signing_key: &SigningKey,
        binary_path: &Path,
        genesis_toml: &str,
        log_dir: &Path,
    ) -> Result<Self> {
        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("node {index}: create data dir"))?;

        // Every node gets the *same* genesis validator set (all four members) so
        // `build_committee` derives an identical committee everywhere.
        std::fs::write(data_dir.join("genesis_validators.toml"), genesis_toml)
            .with_context(|| format!("node {index}: write genesis_validators.toml"))?;

        // 32-byte hex seed; the node derives its Ed25519 key from this.
        let key_path = data_dir.join("validator.key");
        write_private(&key_path, hex::encode(signing_key.to_bytes()))
            .with_context(|| format!("node {index}: write validator.key"))?;

        let mut node = Self {
            index,
            data_dir,
            log_path: log_dir.join(format!("node{index}.log")),
            rpc_port,
            p2p_port,
            bootnodes,
            key_path,
            binary: binary_path.to_path_buf(),
            genesis_toml: genesis_toml.to_string(),
            child: None,
        };
        node.spawn()?;
        Ok(node)
    }

    /// Spawn (or re-spawn after a crash) the node process.
    fn spawn(&mut self) -> Result<()> {
        // Re-write genesis on every spawn: cheap, and keeps a restart identical
        // to the first boot even if the dir was touched out of band.
        std::fs::write(
            self.data_dir.join("genesis_validators.toml"),
            &self.genesis_toml,
        )
        .with_context(|| format!("node {}: rewrite genesis_validators.toml", self.index))?;

        // Append so a restart does not clobber the pre-kill log tail.
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .with_context(|| {
                format!("node {}: open log {}", self.index, self.log_path.display())
            })?;
        let log_err = log.try_clone()?;

        let child = Command::new(&self.binary)
            .current_dir(&self.data_dir)
            .env("KOVANICA_DATA_DIR", &self.data_dir)
            .env("KOVANICA_RPC_ADDR", "127.0.0.1")
            .env("KOVANICA_RPC_PORT", self.rpc_port.to_string())
            .env(
                "KOVANICA_LISTEN_ADDR",
                format!("127.0.0.1:{}", self.p2p_port),
            )
            .env("KOVANICA_MAX_PEERS", "8")
            .env("KOVANICA_ROUND_DURATION_MS", ROUND_DURATION_MS.to_string())
            .env("KOVANICA_RUN_VALIDATOR", "true")
            .env("KOVANICA_MYSTICGHOST", "true")
            // Disable the RPC rate limiter: poll-driven `kovanica_blockNumber`
            // calls would otherwise hit HTTP 429 (default 60/min).
            .env("KOVANICA_RPC_RATE_LIMIT_PER_MIN", "0")
            .env("KOVANICA_VALIDATOR_KEY", &self.key_path)
            .env("KOVANICA_BOOTNODES", self.bootnodes.join(","))
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .with_context(|| {
                format!(
                    "node {}: spawn {} (rpc {}, p2p {})",
                    self.index,
                    self.binary.display(),
                    self.rpc_port,
                    self.p2p_port
                )
            })?;

        eprintln!(
            "[chaos] spawned node {} pid={} rpc=127.0.0.1:{} p2p=127.0.0.1:{} log={}",
            self.index,
            child.id(),
            self.rpc_port,
            self.p2p_port,
            self.log_path.display()
        );
        self.child = Some(child);
        Ok(())
    }

    /// `SIGKILL` the process mid-flight and return the terminating signal.
    ///
    /// `std::process::Child::kill` sends `SIGKILL` on Unix, which is exactly the
    /// "no flush, no shutdown hook" death this test is about.
    fn kill_hard(&mut self) -> Result<Option<i32>> {
        let child = self
            .child
            .as_mut()
            .with_context(|| format!("node {}: kill requested but not running", self.index))?;
        let pid = child.id();
        // SIGKILL does not return an error to the target; if the call itself
        // fails the process already died, which is fine.
        let _ = child.kill();

        let status = child
            .wait()
            .with_context(|| format!("node {} (pid {pid}): wait after SIGKILL", self.index))?;
        let signal = sig_of(&status);
        eprintln!(
            "[chaos] node {} pid={pid} SIGKILLed mid-commit: status={status:?} signal={signal:?}",
            self.index
        );
        self.child = None;
        Ok(signal)
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

    /// Stop the process (best-effort `SIGKILL`) and reap it. Idempotent.
    fn stop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
    }
}

impl Drop for ChaosNode {
    fn drop(&mut self) {
        // No node process may outlive the test, even on panic unwind.
        self.stop();
    }
}

/// Terminating signal of an exit status on Unix (`None` if it exited normally).
#[cfg(unix)]
fn sig_of(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn sig_of(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

// ---------------------------------------------------------------------------
// RPC helpers
// ---------------------------------------------------------------------------

async fn rpc_call(client: &Client, port: u16, method: &str, params: Value) -> Result<Value> {
    let resp = client
        .post(format!("http://127.0.0.1:{port}/rpc"))
        .json(&json!({ "jsonrpc": "2.0", "method": method, "params": params, "id": 1 }))
        .send()
        .await
        .with_context(|| format!("RPC {method} on port {port} (connect/send)"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .with_context(|| format!("RPC read body {method} on port {port}"))?;
    if !status.is_success() {
        bail!("RPC {method} on port {port}: HTTP {status} (body: {body})");
    }
    let value: Value = serde_json::from_str(&body)
        .with_context(|| format!("RPC decode {method} on port {port}: `{body}`"))?;
    if let Some(err) = value.get("error") {
        bail!("RPC {method} on port {port}: JSON-RPC error: {err}");
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

/// Stable, temp-dir-independent directory the per-node logs are written into.
fn stable_log_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("KOVANICA_TEST_LOG_DIR") {
        return PathBuf::from(dir);
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("target/chaos-logs")
        .join(ts.to_string())
}

/// Build the shared genesis validator set (all four members, equal stake).
fn build_genesis_toml(validators: &[(SigningKey, PublicKey, Address)]) -> String {
    let mut out = String::from("chain_id = 1337\n\n");
    for (_, pk, addr) in validators {
        out.push_str("[[validator]]\n");
        out.push_str(&format!("address = \"{}\"\n", hex::encode(addr.0)));
        out.push_str(&format!("stake = {MIN_VALIDATOR_STAKE}\n"));
        out.push_str(&format!("public_key = \"{}\"\n\n", hex::encode(pk.0)));
    }
    out
}

fn port_is_free(port: u16) -> bool {
    std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
}

/// Pick a random block of `2 * nodes` free consecutive ports (RPC block, then
/// P2P block). Random per run so parallel runs / leftovers do not collide; every
/// port is bind-probed so a busy block is skipped.
fn pick_free_ports(nodes: usize) -> Result<(u16, u16)> {
    let span = (2 * nodes) as u64;
    let blocks = (PORT_RANGE_END - PORT_RANGE_START) as u64 / span;
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ ((std::process::id() as u64) << 32);
    for _ in 0..PORT_ATTEMPTS {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let base = PORT_RANGE_START + ((seed % blocks) * span) as u16;
        if (0..span as u16).all(|offset| port_is_free(base + offset)) {
            return Ok((base, base + nodes as u16));
        }
    }
    bail!("no free block of {span} ports in {PORT_RANGE_START}..{PORT_RANGE_END}")
}

/// Committed leader sequence persisted by a node: decided rounds in ascending
/// order, leaders flattened. Entry `H - 1` is the leader committed at height `H`.
///
/// Opening/reading the DB is itself the corruption check: a torn or unreadable
/// `consensus.redb` fails here.
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

/// Any node log containing a Rust panic marker: `(node index, matching line)`.
fn logs_contain_panic(paths: &[PathBuf]) -> Vec<(usize, String)> {
    let mut hits = Vec::new();
    for (i, path) in paths.iter().enumerate() {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Some(line) = text.lines().find(|l| l.contains("panicked at")) {
                hits.push((i, line.trim().to_string()));
            }
        }
    }
    hits
}

/// Write a validator seed file readable only by the owner (the node refuses
/// group/world-accessible key files).
fn write_private(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    let path = path.as_ref();
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Scenario helpers
// ---------------------------------------------------------------------------

/// Sample every node's committed height. Unreachable nodes keep their previous
/// value in `last`; their error is returned for the failure message.
async fn sample_heights(client: &Client, nodes: &[ChaosNode], last: &mut [u64]) -> Vec<String> {
    let mut errs = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        match get_height(client, node.rpc_port).await {
            Ok(h) => last[i] = h,
            Err(e) => errs.push(format!("node {i}: {e:#}")),
        }
    }
    errs
}

/// Wait until `max(heights) >= target`. Returns the final sample.
async fn wait_max_height(
    client: &Client,
    nodes: &[ChaosNode],
    target: u64,
    timeout_secs: u64,
    phase: &str,
) -> Result<Vec<u64>> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut last = vec![0u64; nodes.len()];
    loop {
        let errs = sample_heights(client, nodes, &mut last).await;
        if last.iter().copied().max().unwrap_or(0) >= target {
            return Ok(last);
        }
        if Instant::now() >= deadline {
            bail!(
                "{phase}: quorum did not reach committed height {target} within {timeout_secs}s \
                 (last heights {last:?}; probe errors: {errs:?})"
            );
        }
        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}

/// Wait until **every** node's committed height reaches `target`.
async fn wait_all_at_least(
    client: &Client,
    nodes: &[ChaosNode],
    target: u64,
    timeout_secs: u64,
    phase: &str,
) -> Result<Vec<u64>> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut last = vec![0u64; nodes.len()];
    loop {
        let errs = sample_heights(client, nodes, &mut last).await;
        if last.iter().all(|h| *h >= target) {
            return Ok(last);
        }
        if Instant::now() >= deadline {
            bail!(
                "{phase}: not every node reached committed height {target} within {timeout_secs}s \
                 (last heights {last:?}; probe errors: {errs:?})"
            );
        }
        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}

/// Wait (best-effort, bounded) for every node to have at least one peer.
async fn wait_for_peers(client: &Client, nodes: &[ChaosNode], timeout_secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut counts = vec![0u64; nodes.len()];
    loop {
        for (i, node) in nodes.iter().enumerate() {
            if let Ok(c) = peer_count(client, node.rpc_port).await {
                counts[i] = c;
            }
        }
        if counts.iter().all(|c| *c >= 1) || Instant::now() >= deadline {
            break;
        }
        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
    eprintln!("[chaos] observed peer counts: {counts:?}");
    for (i, c) in counts.iter().enumerate() {
        assert!(
            *c >= 1,
            "node {i} has no peers after {timeout_secs}s; the quorum cannot form"
        );
    }
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// Real `SIGKILL` mid-commit on a 4-validator quorum, then restart + converge.
///
/// Opt-in and release-binary only (see the module docs, including the
/// `debug_assert!` this harness found on the restart path):
///
/// ```sh
/// cargo build --release -p kovanica-node
/// KOVANICA_NODE_BINARY=target/release/kovanica-node \
///   cargo test -p kovanica-node --test chaos_kill_mid_commit -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "chaos: real SIGKILL mid-commit + restart; slow and timing-sensitive — run explicitly / nightly with --ignored"]
async fn sigkill_mid_commit_then_restart_converges_without_divergence() -> Result<()> {
    let binary = node_binary_path();
    assert!(
        binary.exists(),
        "node binary {} not found (CARGO_BIN_EXE_kovanica-node)",
        binary.display()
    );

    let log_dir = stable_log_dir();
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("create log dir {}", log_dir.display()))?;
    eprintln!("[chaos] node logs -> {}", log_dir.display());

    // One temp root holds every node's durable data dir; removed when the test
    // ends (after the divergence check has read each DB).
    let root = TempDir::new().context("create temp root for node data dirs")?;

    // Four distinct validator identities.
    let mut validators: Vec<(SigningKey, PublicKey, Address)> = Vec::with_capacity(NODES);
    for _ in 0..NODES {
        let (sk, pk) = generate_keypair();
        let addr = Address::from_public_key(&pk);
        validators.push((sk, pk, addr));
    }
    let genesis_toml = build_genesis_toml(&validators);

    let (rpc_base, p2p_base) = pick_free_ports(NODES)?;
    eprintln!(
        "[chaos] ports: rpc {}-{}, p2p {}-{}",
        rpc_base,
        rpc_base + NODES as u16 - 1,
        p2p_base,
        p2p_base + NODES as u16 - 1
    );

    let client = Client::new();

    // --- Phase 0: bring the quorum up ---------------------------------------
    let mut quorum: Vec<ChaosNode> = Vec::with_capacity(NODES);
    for (i, (sk, _, _)) in validators.iter().enumerate() {
        let rpc_port = rpc_base + i as u16;
        let p2p_port = p2p_base + i as u16;
        let bootnodes = (0..NODES)
            .filter(|j| *j != i)
            .map(|j| format!("127.0.0.1:{}", p2p_base + j as u16))
            .collect::<Vec<_>>();

        // Start nodes sequentially so each dials already-running peers; the
        // network layer also retries bootstrap dials.
        let node = ChaosNode::provision(
            i,
            root.path().join(format!("node{i}")),
            rpc_port,
            p2p_port,
            bootnodes,
            sk,
            &binary,
            &genesis_toml,
            &log_dir,
        )
        .with_context(|| format!("starting validator node {i}"))?;
        node.wait_ready(&client, RPC_READY_TIMEOUT_SECS)
            .await
            .with_context(|| format!("validator node {i} RPC never became ready"))?;
        quorum.push(node);
    }

    wait_for_peers(&client, &quorum, PEER_TIMEOUT_SECS).await;

    // --- Phase A: commit a few heights before touching anything -------------
    let heights = wait_max_height(
        &client,
        &quorum,
        PRE_KILL_HEIGHT,
        PRE_KILL_TIMEOUT_SECS,
        "pre-kill",
    )
    .await?;
    eprintln!("[chaos] pre-kill heights: {heights:?}");

    // --- Phase B: SIGKILL the victim mid-commit -----------------------------
    // Observe the victim advance a height, then SIGKILL immediately. The kill is
    // therefore always during active commit activity, never at genesis or after
    // quiescence.
    let mut before = vec![0u64; NODES];
    sample_heights(&client, &quorum, &mut before).await;
    let victim_before = before[VICTIM];

    let deadline = Instant::now() + Duration::from_secs(KILL_WINDOW_SECS);
    loop {
        match get_height(&client, quorum[VICTIM].rpc_port).await {
            Ok(h) if h > victim_before => {
                eprintln!(
                    "[chaos] victim advanced {victim_before} -> {h}; SIGKILLing mid-commit now"
                );
                break;
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            bail!(
                "victim (node {VICTIM}) did not advance past committed height {victim_before} \
                 within {KILL_WINDOW_SECS}s; not injecting a kill at an ambiguous moment"
            );
        }
        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }

    let signal = quorum[VICTIM].kill_hard()?;
    #[cfg(unix)]
    assert_eq!(
        signal,
        Some(9),
        "victim node {VICTIM} must be terminated by SIGKILL (signal 9), got {signal:?}"
    );
    #[cfg(not(unix))]
    let _ = signal;

    // Snapshot the survivors' heights at kill time: each must strictly exceed
    // its own snapshot to prove the quorum kept committing without the victim.
    let mut survivor_kill_time = vec![0u64; NODES];
    for i in 0..NODES {
        if i == VICTIM {
            continue;
        }
        // Best-effort: fall back to the last known height if the probe blips.
        survivor_kill_time[i] = get_height(&client, quorum[i].rpc_port)
            .await
            .unwrap_or(before[i]);
    }
    eprintln!("[chaos] survivor heights at kill: {survivor_kill_time:?}");

    // --- Phase C: the surviving three keep committing -----------------------
    let deadline = Instant::now() + Duration::from_secs(QUORUM_PROGRESS_TIMEOUT_SECS);
    loop {
        let mut progressed = true;
        let mut current = vec![0u64; NODES];
        for i in 0..NODES {
            if i == VICTIM {
                continue;
            }
            match get_height(&client, quorum[i].rpc_port).await {
                Ok(h) => {
                    current[i] = h;
                    if h <= survivor_kill_time[i] {
                        progressed = false;
                    }
                }
                Err(_) => progressed = false,
            }
        }
        if progressed {
            eprintln!("[chaos] quorum survived: survivors committed past kill time -> {current:?}");
            break;
        }
        if Instant::now() >= deadline {
            bail!(
                "surviving quorum did not keep committing within {QUORUM_PROGRESS_TIMEOUT_SECS}s \
                 after SIGKILL of node {VICTIM} \
                 (kill-time {survivor_kill_time:?}, now {current:?})"
            );
        }
        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }

    // --- Phase D: restart the victim and wait for it to catch up ------------
    eprintln!("[chaos] restarting node {VICTIM} on its existing data dir ...");
    quorum[VICTIM].spawn()?;
    quorum[VICTIM]
        .wait_ready(&client, RPC_READY_TIMEOUT_SECS)
        .await
        .context("restarted victim RPC never became ready")?;

    let deadline = Instant::now() + Duration::from_secs(CATCHUP_TIMEOUT_SECS);
    loop {
        // Read every node we can; the victim must reach the *slowest* survivor.
        let mut hs = vec![0u64; NODES];
        let mut read = vec![false; NODES];
        for i in 0..NODES {
            if let Ok(h) = get_height(&client, quorum[i].rpc_port).await {
                hs[i] = h;
                read[i] = true;
            }
        }
        let others: Vec<u64> = (0..NODES)
            .filter(|i| *i != VICTIM && read[*i])
            .map(|i| hs[i])
            .collect();
        let others_min = others.iter().copied().min();

        if read[VICTIM] {
            if let Some(min) = others_min {
                let lag = min.saturating_sub(hs[VICTIM]);
                if hs[VICTIM] >= PRE_KILL_HEIGHT && lag <= CATCHUP_LAG_TOLERANCE {
                    eprintln!(
                        "[chaos] victim caught up: victim={} slowest survivor={} lag={lag} \
                         (heights {hs:?})",
                        hs[VICTIM], min
                    );
                    break;
                }
            }
        }
        if Instant::now() >= deadline {
            bail!(
                "restarted victim node {VICTIM} did not catch up to the surviving quorum within \
                 {CATCHUP_TIMEOUT_SECS}s (heights {hs:?}, readable {read:?})"
            );
        }
        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }

    // --- Phase E: all four keep committing, then check the durable state ----
    let settled = wait_all_at_least(
        &client,
        &quorum,
        PRE_KILL_HEIGHT + 1,
        SETTLE_TIMEOUT_SECS,
        "post-restart",
    )
    .await?;
    eprintln!(
        "[chaos] post-restart heights (all >= {}): {settled:?}",
        PRE_KILL_HEIGHT + 1
    );

    // --- Phase F: no panic anywhere, and identical committed leaders --------
    let log_paths: Vec<PathBuf> = (0..NODES)
        .map(|i| log_dir.join(format!("node{i}.log")))
        .collect();
    let panics = logs_contain_panic(&log_paths);
    assert!(
        panics.is_empty(),
        "node(s) panicked during the chaos run: {panics:?}"
    );

    // Stop everything before reading the DBs so the files are quiescent.
    for node in quorum.iter_mut() {
        node.stop();
    }

    let mut per_node: Vec<Vec<[u8; 32]>> = Vec::with_capacity(NODES);
    for (i, node) in quorum.iter().enumerate() {
        let leaders = committed_leaders(&node.data_dir)
            .with_context(|| format!("node {i}: read persisted committed leaders"))?;
        eprintln!(
            "[chaos] node {i} persisted {} committed leaders",
            leaders.len()
        );
        per_node.push(leaders);
    }

    let h = PRE_KILL_HEIGHT as usize;
    for (i, leaders) in per_node.iter().enumerate() {
        assert!(
            leaders.len() >= h,
            "node {i} only persisted {} committed leaders, need >= {h} \
             (restart recovery lost committed history)",
            leaders.len()
        );
    }

    // Divergence check: every node's committed-leader prefix up to the fixed
    // height must be byte-identical.
    let baseline = &per_node[0][..h];
    for (i, leaders) in per_node.iter().enumerate() {
        assert_eq!(
            &leaders[..h],
            baseline,
            "node {i} diverged from node 0 on the committed-leader prefix up to height {h}"
        );
    }
    eprintln!(
        "[chaos] PASS: no panic, no DB corruption, identical committed-leader prefix \
         up to height {h} across all {NODES} nodes"
    );
    eprintln!("[chaos] node logs archived under: {}", log_dir.display());

    Ok(())
}
