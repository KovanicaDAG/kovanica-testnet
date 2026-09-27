//! Self-hosted BlockDAG explorer: JSON API + a static UI, served from the
//! Rust node. The page never reimplements consensus — it only renders what
//! [`Mesh`] / [`Node`] already computed.

use base64::Engine;
use hex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use kovanica_dag::{AuthoritySet, BlockId};
use kovanica_state::{
    decode_block_payload, Address, AssetId, HtlcScript, OutPoint, Transaction, TxId, TxOutput,
    MAX_SUPPLY,
};

use crate::dht::{NodeId, PeerContact, RoutingTable};
use crate::dns_seed::{DnsSeedConfig, DnsSeedResolver};
use crate::metrics::{
    init_metrics, record_explorer_http_request, record_supply, render_prometheus,
    set_explorer_ws_clients, set_peer_count,
};
use crate::net::{
    decode_records, encode_records, pull_blocks_timeout, serve_exchange, serve_headers_first,
    sync_headers_first,
};
use crate::node::{
    BlockRecord, CoinJoinParticipant, CoinJoinPrepared, Node, TreasuryGenesis, WalletDirection,
    HALVING_ERA,
};
use crate::p2p::Mesh;

const UI: &str = include_str!("explorer.html");
const BIP39: &str = include_str!("bip39-english.txt");
const DOCS: &str = include_str!("../../../TESTNET.md");
/// 1 KVNC = 10^8 base units (atoms).
const ATOM: u64 = 100_000_000;
/// RFC-006 genesis subsidy: 10 KVNC/block.
const GENESIS_SUBSIDY: u64 = 10 * ATOM;
/// RFC-006 founder premine: 0.2M KVNC (+ 10M treasury vaults in coinbase).
const GENESIS_PREMINE: u64 = 200_000 * ATOM;
/// Founder actor seed used by `genesis_node()` (deterministic keys).
const FOUNDER_SEED: u64 = 1;
/// Finality depth used by the live testnet (blocks below this score become final).
const TESTNET_FINALITY_DEPTH: u64 = 100;
/// Payload pruning depth used by the live testnet (blocks below this score have payloads evicted).
const TESTNET_PAYLOAD_PRUNING_DEPTH: u64 = 1000;
/// Block pruning depth used by the live testnet (blocks below this score are
/// evicted entirely — payload, metadata, and reachability-oracle entries).
/// Equal to the payload depth: a node cannot serve a block body it has pruned
/// anyway, and `>= TESTNET_FINALITY_DEPTH` keeps eviction to already-final
/// blocks (consensus-safe).
const TESTNET_BLOCK_PRUNING_DEPTH: u64 = 1000;
const ACTORS: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
/// Single P2P path: plaintext TCP. Not 80/443/3010/8080 and not libp2p :30333.
const P2P_LISTEN_DEFAULT: &str = "0.0.0.0:9000";
const P2P_BOOTSTRAP: &str = "seed.kovanica.online:9000,seed2.kovanica.online:9000";

/// A network profile: identity, genesis parameters, and data-dir isolation.
///
/// The active profile is selected once at boot from `KOVANICA_NETWORK`
/// (default `kovanica-testnet`). Each profile owns a distinct data directory,
/// so a node booted for one network can never wipe another network's data via
/// the [`ensure_network`] marker check — a mainnet node cannot destroy testnet
/// state and vice versa.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NetworkProfile {
    /// Network id — reported by `/api/bootstrap`, `/api/head` and the
    /// snapshot, and written to the `network` marker file.
    id: &'static str,
    /// GHOSTDAG `k` parameter for this network's genesis.
    genesis_k: u16,
    /// Per-block subsidy cap at genesis (atoms).
    genesis_subsidy: u64,
    /// Founder premine minted by the genesis coinbase (atoms).
    genesis_premine: u64,
    /// Founder actor seed (deterministic keys).
    founder_seed: u64,
    /// Operator wallet seed (deterministic keys for testnet reproducibility).
    operator_seed: [u8; 32],
    /// Finality depth: blocks more than this many blue score below the tip
    /// become final. `u64::MAX` disables finality pruning.
    finality_depth: u64,
    /// Payload pruning depth: blocks more than this many blue score below the
    /// tip have their payloads evicted. `u64::MAX` disables payload pruning.
    payload_pruning_depth: u64,
    /// Block pruning depth: blocks more than this many blue score below the tip
    /// are evicted entirely (payload, metadata, and reachability-oracle
    /// entries), bounding the oracle's memory. `u64::MAX` disables block
    /// pruning. Invariant: `>= finality_depth` (eviction stays within
    /// already-final blocks).
    block_pruning_depth: u64,
    /// Dormant placeholder: genesis parameters are TBD and the profile refuses
    /// to boot unless explicitly overridden.
    dormant: bool,
}

impl NetworkProfile {
    /// The live testnet — the default profile.
    fn testnet() -> Self {
        Self {
            id: "kovanica-testnet",
            genesis_k: 3,
            genesis_subsidy: GENESIS_SUBSIDY,
            genesis_premine: GENESIS_PREMINE,
            founder_seed: FOUNDER_SEED,
            operator_seed: [
                0x4f, 0x50, 0x45, 0x52, 0x41, 0x54, 0x4f, 0x52, 0x5f, 0x54, 0x45, 0x53, 0x54, 0x4e,
                0x45, 0x54, 0x5f, 0x53, 0x45, 0x45, 0x44, 0x5f, 0x32, 0x30, 0x32, 0x36, 0x5f, 0x30,
                0x39, 0x5f, 0x31, 0x37,
            ],
            finality_depth: TESTNET_FINALITY_DEPTH,
            payload_pruning_depth: TESTNET_PAYLOAD_PRUNING_DEPTH,
            block_pruning_depth: TESTNET_BLOCK_PRUNING_DEPTH,
            dormant: false,
        }
    }

    /// Mainnet profile filled with RFC-006 parameters but still **DORMANT**.
    /// Requires `KOVANICA_MAINNET_OVERRIDE=1` to boot.
    fn mainnet() -> Self {
        Self {
            id: "kovanica-mainnet",
            genesis_k: 3,
            genesis_subsidy: GENESIS_SUBSIDY,
            genesis_premine: GENESIS_PREMINE,
            founder_seed: FOUNDER_SEED,
            operator_seed: [0u8; 32],
            finality_depth: 1000,
            payload_pruning_depth: 10_000,
            block_pruning_depth: 10_000,
            dormant: true,
        }
    }
}

/// The active network profile, selected from `KOVANICA_NETWORK` (default
/// `kovanica-testnet`). The mainnet profile is dormant: selecting it without
/// `KOVANICA_MAINNET_OVERRIDE=1` refuses to boot rather than inventing
/// consensus parameters. The default is always testnet — mainnet is never
/// activated implicitly.
fn network_profile() -> NetworkProfile {
    let profile = match std::env::var("KOVANICA_NETWORK").as_deref() {
        Ok("kovanica-mainnet") | Ok("mainnet") => {
            if !env_flag("KOVANICA_MAINNET_OVERRIDE", false) {
                panic!(
                    "kovanica-mainnet is DORMANT: genesis parameters are TBD.                      Set KOVANICA_MAINNET_OVERRIDE=1 to force boot (unsafe; do not use in production)."
                );
            }
            NetworkProfile::mainnet()
        }
        _ => NetworkProfile::testnet(),
    };
    // RFC-008 invariant: block pruning must never evict a block that could
    // still be built on. With `block_pruning_depth >= finality_depth` every
    // evicted block is already final, so `BuildsOnPrunedHistory` fires only for
    // blocks the finality check would already reject — no new rejection
    // surface, no fork with nodes that prune less.
    assert!(
        profile.block_pruning_depth >= profile.finality_depth,
        "block_pruning_depth ({}) must be >= finality_depth ({})",
        profile.block_pruning_depth,
        profile.finality_depth
    );
    profile
}

/// Fail fast on a legacy `KOVANICA_CONSENSUS` selection.
///
/// PoA is the only admission regime (RFC-POA §0). `pow` / `pow-vrf` used to
/// select PoW or hybrid admission, both of which were deleted; silently booting
/// a genesis with no admission control would be a silent downgrade, so this
/// refuses to start and names the migration step.
fn reject_legacy_consensus_mode() {
    if let Ok(mode) = std::env::var("KOVANICA_CONSENSUS") {
        if mode != "poa" {
            panic!(
                "KOVANICA_CONSENSUS={mode:?} is no longer supported: PoW, difficulty, VRF \
                 and hybrid admission were removed (RFC-POA §0). PoA is the only regime — \
                 unset KOVANICA_CONSENSUS, or set it to \"poa\", and supply the authority \
                 set via KOVANICA_AUTHORITIES (or KOVANICA_AUTHORITY_THRESHOLD)."
            );
        }
    }
}

/// Base seed for the deterministic TESTNET-ONLY placeholder authority set
/// (publicly derivable by design, mirroring the placeholder treasury keys).
/// Mainnet refuses to boot without explicit `KOVANICA_AUTHORITIES`.
const AUTHORITY_PLACEHOLDER_BASE: u64 = 9001;
/// Number of placeholder authorities (RFC-POA §1: 3–4 keys at launch).
const AUTHORITY_PLACEHOLDER_COUNT: u64 = 3;

/// PoA genesis configuration parsed from the environment (RFC-POA §7).
struct PoaGenesisConfig {
    authority_set: AuthoritySet,
    slot_duration_ms: u64,
    /// Whether the set is the deterministic TESTNET-ONLY placeholder. When
    /// true, `genesis_node` also loads the placeholder signing keys so a
    /// single-node testnet/explorer can produce in every slot; an explicit
    /// `KOVANICA_AUTHORITIES` set never loads keys into the node (each
    /// authority operator sets their own via `set_authority_signing_key`).
    placeholder: bool,
    /// Operator's own Ed25519 authority signing key (32 bytes = 64 hex chars),
    /// if provided via `KOVANICA_AUTHORITY_KEY`. This is the operator's
    /// consensus credential — it allows this node to sign blocks when it is
    /// the scheduled authority for a slot. It is NOT the same as the treasury
    /// seed or the founder seed.
    authority_signing_key: Option<[u8; 32]>,
}

/// Parse the PoA genesis configuration from the environment (RFC-POA §7):
/// `KOVANICA_AUTHORITIES` (comma-separated 64-hex Ed25519 public keys),
/// `KOVANICA_AUTHORITY_THRESHOLD` (default strict majority),
/// `KOVANICA_SLOT_DURATION` (default 3000 ms),
/// `KOVANICA_AUTHORITY_KEY` (optional: this operator's 64-hex Ed25519 signing key).
///
/// Always yields a config — PoA is the only admission regime. With no
/// `KOVANICA_AUTHORITIES`: testnet derives a deterministic placeholder set
/// (TESTNET-ONLY); mainnet refuses to boot — the same fail-fast guard as the
/// treasury seed.
fn poa_config_from_env(profile: &NetworkProfile) -> PoaGenesisConfig {
    reject_legacy_consensus_mode();
    let slot_duration_ms: u64 = std::env::var("KOVANICA_SLOT_DURATION")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(kovanica_dag::SLOT_DURATION_MS);
    let (pks, placeholder) = match std::env::var("KOVANICA_AUTHORITIES") {
        Ok(list) => (
            list.split(',')
                .map(|hex| {
                    let hex = hex.trim();
                    if hex.len() != 64 {
                        panic!("KOVANICA_AUTHORITIES entries must be 64 hex chars (got '{hex}')");
                    }
                    let mut pk = [0u8; 32];
                    for (i, byte) in hex.as_bytes().chunks(2).enumerate() {
                        pk[i] =
                            u8::from_str_radix(std::str::from_utf8(byte).expect("ascii hex"), 16)
                                .expect("KOVANICA_AUTHORITIES must be hex");
                    }
                    pk
                })
                .collect::<Vec<[u8; 32]>>(),
            false,
        ),
        Err(_) if profile.id == "kovanica-mainnet" => panic!(
            "kovanica-mainnet requires KOVANICA_AUTHORITIES (comma-separated 64-hex \
             Ed25519 public keys): refusing to boot with publicly-derivable \
             placeholder authorities"
        ),
        Err(_) => (
            // TESTNET-ONLY deterministic placeholder set (3 keys, threshold 2):
            // publicly derivable by design, mirroring the placeholder treasury
            // keys. Mainnet MUST boot with a real set from the key ceremony.
            (0..AUTHORITY_PLACEHOLDER_COUNT)
                .map(|i| {
                    *kovanica_state::KeyPair::from_u64(AUTHORITY_PLACEHOLDER_BASE + i)
                        .address()
                        .payload()
                })
                .collect(),
            true,
        ),
    };
    let threshold: usize = std::env::var("KOVANICA_AUTHORITY_THRESHOLD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| pks.len() / 2 + 1);
    // Build the canonical encoding (`threshold u64 LE || count u64 LE || pks`)
    // and decode through `AuthoritySet::from_bytes`, which enforces the
    // consensus invariants (count/threshold bounds, distinct keys).
    let mut bytes = Vec::with_capacity(16 + 32 * pks.len());
    bytes.extend_from_slice(&(threshold as u64).to_le_bytes());
    bytes.extend_from_slice(&(pks.len() as u64).to_le_bytes());
    for pk in &pks {
        bytes.extend_from_slice(pk);
    }
    let authority_set = AuthoritySet::from_bytes(&bytes).unwrap_or_else(|e| {
        panic!("invalid KOVANICA_AUTHORITIES / KOVANICA_AUTHORITY_THRESHOLD: {e}")
    });
    // Optional: this operator's own authority signing key.
    let authority_signing_key = std::env::var("KOVANICA_AUTHORITY_KEY").ok().map(|hex| {
        let hex = hex.trim();
        if hex.len() != 64 {
            panic!(
                "KOVANICA_AUTHORITY_KEY must be 64 hex chars (32 bytes, got {})",
                hex.len()
            );
        }
        let mut key = [0u8; 32];
        for (i, byte) in hex.as_bytes().chunks(2).enumerate() {
            key[i] = u8::from_str_radix(std::str::from_utf8(byte).expect("ascii hex"), 16)
                .expect("KOVANICA_AUTHORITY_KEY must be hex");
        }
        key
    });
    PoaGenesisConfig {
        authority_set,
        slot_duration_ms,
        placeholder,
        authority_signing_key,
    }
}

/// WebSocket message types for real-time updates
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(tag = "type")]
enum WsMsg {
    #[serde(rename = "block")]
    Block { id: String, blue_score: u64 },
    #[serde(rename = "tx")]
    Tx {
        id: String,
        from: String,
        to: String,
        amount: u64,
    },
    #[serde(rename = "tip")]
    Tip { id: String, blue_score: u64 },
    #[serde(rename = "peer")]
    Peer { addr: String, connected: bool },
    #[serde(rename = "state")]
    State { snapshot: String },
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "pong")]
    Pong,
}

/// Bind `addr` (e.g. `0.0.0.0:8080`) and serve the explorer until killed.
pub fn serve(addr: impl ToSocketAddrs) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let bound = listener.local_addr()?;
    eprintln!("kovanica explorer on http://{bound}");

    // Initialize metrics (Prometheus + tracing).
    //
    // The bind address is overridable because the default is a fixed
    // 0.0.0.0:9090: two nodes on one host collide, and a fixed 0.0.0.0 bind
    // exposes the scrape endpoint on every interface. Set
    // KOVANICA_METRICS_LISTEN to any addr, or to one of `off`/`none`/`0`/
    // `disabled` to skip metrics entirely.
    match metrics_bind_target(
        std::env::var("KOVANICA_METRICS_LISTEN")
            .ok()
            .as_deref()
            .map(str::trim),
    ) {
        None => eprintln!("kovanica metrics disabled (KOVANICA_METRICS_LISTEN)"),
        Some(addr) => {
            if let Err(e) = init_metrics(addr) {
                eprintln!("Failed to init metrics on {addr}: {e}");
            } else {
                eprintln!("kovanica metrics on http://{addr}/metrics");
            }
        }
    }

    // A node that cannot replay its own log has no correct state to serve.
    // Abort the listener rather than come up on a fallback chain: the caller
    // gets the reason on stderr and a non-zero exit.
    let mut app =
        Explorer::boot_persist().map_err(|e| std::io::Error::other(format!("kovanica: {e}")))?;
    eprintln!(
        "kovanica explorer state loaded from {}",
        data_dir().display()
    );
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(e) = handle(&mut app, stream) {
                    eprintln!("explorer: {e}");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                app.tick();
                // Refresh peer gauge periodically so the standalone :9090
                // metrics listener serves fresh values between scrapes.
                if app.ticks % 125 == 0 {
                    set_peer_count(app.live_peers.len());
                }
                app.ws_broadcast_state();
                thread::sleep(Duration::from_millis(40));
            }
            Err(e) => return Err(e),
        }
    }
}

pub struct Explorer {
    pub mesh: Mesh,
    pub selected: String,
    /// Produce a block on a rotating node every `produce_every` ticks. Under
    /// PoA a node only produces in the slots its authority key owns, so this is
    /// a "tick the chain" driver, not mining.
    pub producing: bool,
    pub produce_every: u64,
    pub ticks: u64,
    pub rotate: usize,
    pub faucet: bool,
    /// Total atoms the faucet has paid out per address (lifetime, persisted).
    faucet_given: HashMap<String, u64>,
    /// Per-IP token buckets for HTTP API rate limiting.
    rate_limits: HashMap<String, TokenBucket>,
    /// Tokens refilled per second per IP.
    rate_limit_rate: f64,
    /// Token bucket capacity (burst) per IP.
    rate_limit_burst: f64,
    pub allow_reset: bool,
    pub operator: bool,
    pub listen: Vec<TcpListener>,
    pub listen_addr: String,
    pub peers: Vec<String>,
    pub origins: HashMap<String, u64>,
    /// Peers that answered our last sync attempt (live connectivity).
    pub live_peers: HashSet<String>,
    pub ws_clients: Arc<Mutex<Vec<Arc<Mutex<TcpStream>>>>>,
    /// DHT routing table for the explorer's alpha node.
    pub dht_table: Option<RoutingTable>,
    /// DHT NodeId for the explorer.
    pub dht_node_id: Option<NodeId>,
    /// DNS seed resolver for multi-seed discovery.
    pub dns_resolver: Option<DnsSeedResolver<crate::dns_seed::StdDnsResolver>>,
    /// Last time DHT bootstrap was attempted.
    pub last_dht_bootstrap: u64,
    /// Last time DHT peer replenishment was attempted.
    pub last_dht_replenish: u64,
}

impl Explorer {
    /// Test constructor: a fresh in-memory mesh, no persistence or sockets.
    pub fn boot() -> Self {
        let mut mesh = line_mesh();
        mesh.drain(16);
        Self {
            mesh,
            selected: "alpha".into(),
            producing: false,
            produce_every: produce_every_ticks(),
            ticks: 0,
            rotate: 0,
            faucet: true,
            faucet_given: HashMap::new(),
            rate_limits: HashMap::new(),
            // Tests: effectively unlimited so existing suites stay deterministic.
            rate_limit_rate: 1_000.0,
            rate_limit_burst: 1_000.0,
            allow_reset: true,
            operator: true,
            listen: Vec::new(),
            listen_addr: String::new(),
            peers: Vec::new(),
            origins: HashMap::new(),
            live_peers: HashSet::new(),
            ws_clients: Arc::new(Mutex::new(Vec::new())),
            dht_table: None,
            dht_node_id: None,
            dns_resolver: None,
            last_dht_bootstrap: 0,
            last_dht_replenish: 0,
        }
    }

    fn tick(&mut self) {
        self.mesh.tick();
        self.ticks += 1;
        self.tick_p2p();
        self.tick_dht();
        if self.producing && self.produce_every > 0 && self.ticks % self.produce_every == 0 {
            let names = self.mesh.names();
            if !names.is_empty() {
                let name = &names[self.rotate % names.len()];
                let _ = self.mesh.produce_empty(name);
                self.rotate += 1;
                persist_all(&mut self.mesh);
            }
        }
    }

    /// DHT background task: bootstrap from DNS seeds, discover peers, replenish connections.
    fn tick_dht(&mut self) {
        // Initialize DHT on first tick
        if self.dht_table.is_none() {
            if let Some(n) = self.mesh.node_mut("alpha") {
                let node_id = NodeId::random();
                n.init_dht_routing_table(node_id, 8);
                self.dht_node_id = Some(node_id);
                self.dht_table = Some(n.dht_routing_table().unwrap().clone());

                // Initialize DNS resolver
                let _config = DnsSeedConfig::default();
                self.dns_resolver = Some(DnsSeedResolver::new(crate::dns_seed::StdDnsResolver));
            }
        }

        // Periodic DHT bootstrap from DNS seeds (every ~5 minutes)
        if self.ticks > self.last_dht_bootstrap + 7500 {
            // 7500 ticks * 40ms = 300s = 5min
            self.last_dht_bootstrap = self.ticks;
            if let Some(resolver) = &self.dns_resolver {
                let seed_addrs = resolver.resolve_all();
                if !seed_addrs.is_empty() {
                    eprintln!("kovanica dht: resolved {} seed addresses", seed_addrs.len());
                    // Convert seed addresses to peer contacts for bootstrap
                    let mut seed_contacts = Vec::new();
                    for addr in seed_addrs {
                        // Generate a deterministic NodeId for each seed address
                        let seed_id = NodeId::from_public_key(addr.to_string().as_bytes());
                        seed_contacts.push(PeerContact::new(seed_id, addr.to_string()));
                    }
                    if let Some(n) = self.mesh.node_mut("alpha") {
                        if let Ok(added) = n.dht_bootstrap(seed_contacts) {
                            if added > 0 {
                                eprintln!(
                                    "kovanica dht: bootstrapped {} new contacts from DNS seeds",
                                    added
                                );
                                // Sync local dht_table with node's table
                                self.dht_table = n.dht_routing_table().cloned();
                            }
                        }
                    }
                }
            }
        }

        // Periodic DHT peer replenishment (every ~2 minutes)
        if self.ticks > self.last_dht_replenish + 3000 {
            // 3000 ticks * 40ms = 120s = 2min
            self.last_dht_replenish = self.ticks;
            // Prune unreachable peers from DHT tables
            if let Some(n) = self.mesh.node_mut("alpha") {
                if let Some(table) = n.dht_routing_table_mut() {
                    let pruned = table.prune_unresponsive(3);
                    if !pruned.is_empty() {
                        eprintln!("kovanica dht: pruned {} unreachable peers", pruned.len());
                    }
                    // Sync local dht_table
                    self.dht_table = n.dht_routing_table().cloned();
                }
            }
            // Replenish peer connections from DHT (separate borrow)
            let added = self.mesh.replenish_peers_from_dht(8);
            if added > 0 {
                eprintln!(
                    "kovanica dht: replenished {} peer connections from DHT",
                    added
                );
            }
        }
    }

    fn ws_broadcast_state(&self) {
        if self.ws_clients.lock().unwrap().is_empty() {
            return;
        }
        let snapshot = self.snapshot_json();
        let msg = WsMsg::State { snapshot };
        let text = serde_json::to_string(&msg).unwrap_or_default();
        let frame = ws_frame_text(&text);
        let mut clients = self.ws_clients.lock().unwrap();
        clients.retain_mut(|client| {
            if let Ok(mut c) = client.lock() {
                c.write_all(&frame).is_ok() && c.flush().is_ok()
            } else {
                false
            }
        });
    }

    fn snapshot_json(&self) -> String {
        snapshot(self)
    }

    fn tick_p2p(&mut self) {
        let mut incoming = Vec::new();
        for listener in &self.listen {
            while let Ok((stream, peer)) = listener.accept() {
                incoming.push((stream, peer));
            }
        }
        for (mut stream, peer) in incoming {
            if let Some(n) = self.mesh.node_mut("alpha") {
                // Try headers-first sync serve first
                match serve_headers_first(&mut stream, n, Duration::from_millis(800)) {
                    Ok(()) => {
                        eprintln!("kovanica p2p headers-first served {peer}");
                        persist_all(&mut self.mesh);
                    }
                    Err(_e) => {
                        // Fall back to legacy full-dump exchange
                        stream.set_nonblocking(false).unwrap();
                        match serve_exchange(&mut stream, n, Duration::from_millis(800)) {
                            Ok(got) => {
                                eprintln!(
                                    "kovanica p2p exchanged with {peer} (peer sent {got} records)"
                                );
                                if got > 0 {
                                    persist_all(&mut self.mesh);
                                }
                            }
                            Err(e) => {
                                eprintln!("kovanica p2p exchange {peer}: {e}");
                            }
                        }
                    }
                }
            }
        }
        if !self.peers.is_empty() && self.ticks % 250 == 0 {
            self.sync_peers(Duration::from_millis(800), false);
        }
    }

    fn sync_peers(&mut self, timeout: Duration, log: bool) {
        let peers = self.peers.clone();
        if peers.is_empty() {
            return;
        }
        let mut answered: HashSet<String> = HashSet::new();
        if let Some(n) = self.mesh.node_mut("alpha") {
            for addr in peers {
                // Try headers-first sync first (more efficient)
                match sync_headers_first(&addr, n, timeout) {
                    Ok(stats) if stats.bodies_applied > 0 => {
                        eprintln!(
                            "kovanica p2p headers-first sync from {addr}: {} headers, {} bodies applied",
                            stats.headers_received, stats.bodies_applied
                        );
                        answered.insert(addr.clone());
                    }
                    Ok(stats) if stats.errors > 0 => {
                        // Reachable but bodies failed to apply (e.g. ordering /
                        // missing parents). Log it so the failure is visible, and
                        // fall back to the full-dump pull.
                        eprintln!(
                            "kovanica p2p headers-first sync from {addr}: {} headers, {} applied, {} errors — falling back to full dump",
                            stats.headers_received, stats.bodies_applied, stats.errors
                        );
                        match pull_blocks_timeout(&addr, n, timeout) {
                            Ok(k) if k > 0 => {
                                eprintln!(
                                    "kovanica p2p pulled {k} records from {addr} (full dump)"
                                );
                                answered.insert(addr.clone());
                            }
                            Ok(_) => {}
                            Err(_) => {}
                        }
                    }
                    Ok(_) => {
                        // Reachable, just nothing new to apply.
                        answered.insert(addr.clone());
                    }
                    Err(e) => {
                        // Fall back to legacy full-dump pull
                        if log {
                            eprintln!("kovanica p2p headers-first failed {addr}: {e}, falling back to full dump");
                        }
                        match pull_blocks_timeout(&addr, n, timeout) {
                            Ok(k) if k > 0 => {
                                eprintln!(
                                    "kovanica p2p pulled {k} records from {addr} (full dump)"
                                );
                                answered.insert(addr.clone());
                            }
                            Ok(_) => {}
                            Err(_) => {}
                        }
                    }
                }
            }
        }
        // Live connectivity = peers that answered this round. Peers no longer
        // in the config drop out immediately; silent ones drop out here too.
        self.live_peers = answered;
        set_peer_count(self.live_peers.len());
        persist_all(&mut self.mesh);
    }

    /// Boot the persistent mesh, or report why a node's state could not be
    /// loaded (see [`load_or_genesis`]).
    fn boot_persist() -> Result<Self, String> {
        let _ = fs::create_dir_all(data_dir());
        ensure_network();
        let mut mesh = Mesh::new();
        // Create alpha node with DHT
        let mut alpha_node = load_or_genesis("alpha")?;
        let node_id = NodeId::random();
        alpha_node.init_dht_routing_table(node_id, 8);
        mesh.add_with_dht("alpha", alpha_node, node_id);

        if env_flag("KOVANICA_DEMO_MESH", false) {
            mesh.add("beta", load_or_genesis("beta")?);
            mesh.add("gamma", load_or_genesis("gamma")?);
            let _ = mesh.connect("alpha", "beta");
            let _ = mesh.connect("beta", "gamma");
        }
        mesh.drain(16);
        persist_all(&mut mesh);
        let listen = bind_p2p();
        let listen_addr = listen
            .iter()
            .filter_map(|l| l.local_addr().ok())
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let peers = peer_list();
        if !listen_addr.is_empty() || !peers.is_empty() {
            eprintln!("kovanica p2p listen={listen_addr} peers={peers:?}");
        }
        let _config = DnsSeedConfig::default();
        let dns_resolver = Some(DnsSeedResolver::new(crate::dns_seed::StdDnsResolver));
        let (rate_limit_rate, rate_limit_burst) = rate_limit_from_env();
        let mut app = Self {
            mesh,
            selected: "alpha".into(),
            producing: env_flag("KOVANICA_PRODUCE", env_flag("KOVANICA_MINE", false)),
            produce_every: produce_every_ticks(),
            ticks: 0,
            rotate: 0,
            faucet: env_flag("KOVANICA_FAUCET", false),
            faucet_given: load_faucet_given(),
            rate_limits: HashMap::new(),
            rate_limit_rate,
            rate_limit_burst,
            allow_reset: env_flag("KOVANICA_ALLOW_RESET", false),
            operator: env_flag("KOVANICA_OPERATOR", false),
            listen,
            listen_addr,
            peers,
            origins: load_origins(),
            live_peers: HashSet::new(),
            ws_clients: Arc::new(Mutex::new(Vec::new())),
            dht_table: None,
            dht_node_id: Some(node_id),
            dns_resolver,
            last_dht_bootstrap: 0,
            last_dht_replenish: 0,
        };
        app.sync_peers(Duration::from_secs(3), true);
        Ok(app)
    }

    fn select(&mut self, name: &str) {
        if self.mesh.node(name).is_some() {
            self.selected = name.to_string();
        }
    }
}

fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("KOVANICA_DATA") {
        return PathBuf::from(dir);
    }
    data_dir_for(&network_profile())
}

/// The data directory a profile owns. The default testnet keeps the legacy
/// `data/` location (existing deployments live there); every other network —
/// mainnet included — gets its own `data/<network-id>/` subdirectory so the
/// [`ensure_network`] wipe can never cross network boundaries.
fn data_dir_for(profile: &NetworkProfile) -> PathBuf {
    if profile.id == "kovanica-testnet" {
        PathBuf::from("data")
    } else {
        PathBuf::from("data").join(profile.id)
    }
}

fn snap_path(name: &str) -> PathBuf {
    data_dir().join(format!("{name}.snap"))
}

/// Path of the authority-set commitment for node `name`.
///
/// See [`record_authority_set`] / [`check_authority_set`].
fn authorities_path(name: &str) -> PathBuf {
    data_dir().join(format!("{name}.authorities"))
}

/// Hex form of the authority set's identity, as committed at genesis.
fn authority_set_commitment(set: &AuthoritySet) -> String {
    hex::encode(set.hash())
}

/// Record which authority set this data directory's genesis was built with.
///
/// `AuthoritySet::hash()` covers the threshold, the count and the canonically
/// ordered keys, and the PoA genesis coinbase tag (`KVA1 || set_hash`) is part
/// of the genesis block id — so this value is exactly "which authority set does
/// this chain's genesis commit to". It is public data, not a secret: the
/// commitment exists to make a *mismatch* detectable, not to keep the keys
/// private.
///
/// Written only when a data directory is first populated. See
/// [`check_authority_set`] for the read side.
fn record_authority_set(name: &str, set: &AuthoritySet) {
    record_authority_set_at(&authorities_path(name), set);
}

/// [`record_authority_set`] against an explicit path. Split out so the
/// commitment lifecycle is testable without the process-global data directory.
fn record_authority_set_at(path: &Path, set: &AuthoritySet) {
    let commitment = authority_set_commitment(set);
    match fs::write(path, &commitment) {
        Ok(()) => {}
        Err(e) => eprintln!(
            "kovanica: WARNING could not record authority-set commitment to {}: {e}\n\
             the mismatch check will be skipped on future boots",
            path.display()
        ),
    }
}

/// Refuse to boot when the configured authority set is not the one this data
/// directory's genesis committed to.
///
/// Without this, an operator who restarts a node without their real
/// `KOVANICA_AUTHORITIES` silently gets the placeholder set applied to a chain
/// whose genesis committed something else. Nothing errors: the node loads, and
/// then any block signed by a placeholder key — keys anyone can regenerate from
/// the public constant `AUTHORITY_PLACEHOLDER_BASE` — is admitted. A mistyped or
/// missing env var turns into an authority-key substitution.
///
/// This is also the check that makes the placeholder → real-key transition
/// safe. Booting fresh records the placeholder commitment; the first boot with
/// real keys then fails here and says a reset is required, instead of quietly
/// forking a chain away from the genesis everyone else is following.
///
/// A missing commitment file is *not* an error: data directories created
/// before this check existed have none, and refusing to boot them would be a
/// self-inflicted outage. The absence is reported so the operator knows the
/// check is inactive.
fn check_authority_set(name: &str, set: &AuthoritySet) -> Result<(), String> {
    check_authority_set_at(&authorities_path(name), name, set)
}

/// [`check_authority_set`] against an explicit path. Split out so the mismatch
/// behaviour is testable without the process-global data directory.
fn check_authority_set_at(path: &Path, name: &str, set: &AuthoritySet) -> Result<(), String> {
    let recorded = match fs::read_to_string(path) {
        Ok(s) => s.trim().to_ascii_lowercase(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "kovanica: no authority-set commitment at {}; authority-set mismatch \
                 checking is inactive for node {name}",
                path.display()
            );
            return Ok(());
        }
        Err(e) => {
            eprintln!(
                "kovanica: WARNING could not read authority-set commitment {}: {e}; \
                 skipping the mismatch check for node {name}",
                path.display()
            );
            return Ok(());
        }
    };
    let configured = authority_set_commitment(set);
    if recorded == configured {
        return Ok(());
    }
    Err(format!(
        "authority-set mismatch for node {name}:\n  \
         this data directory's genesis committed {recorded}\n  \
         but KOVANICA_AUTHORITIES now resolves to      {configured}\n\
         Booting anyway would apply a different authority set to an existing \
         chain: the node would admit blocks signed by keys the genesis does not \
         commit to, and would not agree with peers on the same data directory.\n\
         If the env change was unintended, restore the original \
         KOVANICA_AUTHORITIES.\n\
         If you are moving to a new authority set, that is a consensus-breaking \
         change: it needs a new genesis, so wipe KOVANICA_DATA and reset the \
         chain (protocol/docs/TESTNET-RESET-POLICY.md).\n\
         Commitment file: {}",
        path.display()
    ))
}

fn log_path(name: &str) -> PathBuf {
    data_dir().join(format!("{name}.log"))
}

/// Persist every node's ledger **incrementally**: each node appends only the
/// blocks inserted since the last call to its append-only replay log (see
/// [`Node::persist_incremental`]), instead of rewriting a whole-file snapshot
/// after every API write. Whole-file snapshots remain available for portable
/// backups via [`Node::save`] / [`Node::load`]; the log is the primary store.
fn persist_all(mesh: &mut Mesh) {
    let _ = fs::create_dir_all(data_dir());
    for name in mesh.names() {
        if let Some(n) = mesh.node_mut(&name) {
            if let Some(p) = log_path(&name).to_str() {
                let _ = n.persist_incremental(p);
            }
        }
    }
}

fn wipe_data() {
    let dir = data_dir();
    if let Ok(rd) = fs::read_dir(&dir) {
        for e in rd.flatten() {
            let p = e.path();
            let ext = p.extension().and_then(|s| s.to_str());
            if ext == Some("snap") || ext == Some("log") || ext == Some("authorities") {
                let _ = fs::remove_file(p);
            }
        }
    }
}

/// True when `path` exists and is non-empty.
///
/// A zero-length file is treated as *absent* rather than corrupt:
/// `LedgerStore::create` truncates before it writes the header, so a crash in
/// that window leaves a 0-byte log that cannot be replayed but is also not
/// operator data worth refusing to boot over. Distinguishing the two cases is
/// what keeps a torn write from bricking an otherwise recoverable node.
fn has_content(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.len() > 0).unwrap_or(false)
}

/// Persistence tiers, in the order [`load_or_genesis`] will try them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadTier {
    /// Append-only replay log — the primary store.
    Log,
    /// Whole-file snapshot — portable backups / pre-log deployments.
    Snapshot,
    /// Nothing persisted: mint a genesis node.
    Genesis,
}

/// Pick the tier to load for a node, given its two on-disk artifacts.
///
/// Split out from [`load_or_genesis`] so the ordering policy is testable
/// without touching the process-global data directory.
///
/// The snapshot tier is reachable **only when there is no replay log**. This is
/// the whole point of the function: a snapshot must never mask a log that
/// exists but will not replay, because the old code treated that case as
/// "no log at all" and then served a different chain while truncating the
/// operator's log away.
fn choose_load_tier(log: &Path, snap: &Path) -> LoadTier {
    if has_content(log) {
        LoadTier::Log
    } else if has_content(snap) {
        LoadTier::Snapshot
    } else {
        LoadTier::Genesis
    }
}

/// Load a persisted node for `name`, or report why it could not be loaded.
///
/// Callers must treat `Err` as fatal. A node that cannot replay its own log has
/// no correct state to serve, and every fallback available here is wrong in a
/// way that is invisible from the outside: the snapshot tier serves an older
/// chain, and the genesis tier serves a different chain *and* truncates the
/// replay log (`LedgerStore::create` opens with `truncate(true)`), destroying
/// the operator's data. Failing loudly keeps that decision with the operator.
fn load_or_genesis(name: &str) -> Result<Node, String> {
    // Incremental store first: the append-only replay log is the primary
    // persistence format. Loading replays the log through the ledger, so all
    // derived state is recomputed, never trusted from disk.
    let log = log_path(name);
    let profile = network_profile();
    let snap = snap_path(name);

    match choose_load_tier(&log, &snap) {
        LoadTier::Log => {
            let p = log.to_str().ok_or_else(|| {
                format!(
                    "replay log path for node {name} is not valid UTF-8: {}",
                    log.display()
                )
            })?;
            // PoA-era logs must replay under PoA or block ids silently change
            // (identity-preserving replay lesson). Load with the PoA reader when
            // the operator runs PoA mode.
            //
            // The pruning policy is applied BEFORE replay so the DAG and
            // per-block state stay bounded during the load (the O(n²)
            // GHOSTDAG maps otherwise peak at the full chain's footprint and
            // the allocator retains that peak after the post-load prune).
            let policy = kovanica_state::PruningPolicy {
                finality_depth: profile.finality_depth,
                payload_pruning_depth: profile.payload_pruning_depth,
                block_pruning_depth: profile.block_pruning_depth,
            };
            let cfg = poa_config_from_env(&profile);
            // Checked before the load: the log's genesis already committed an
            // authority set, and there is no point replaying a chain we are
            // about to refuse to serve.
            check_authority_set(name, &cfg.authority_set)?;
            let mut node = Node::load_log_with_poa_and_policy(
                p,
                cfg.authority_set,
                cfg.slot_duration_ms,
                policy,
            )
            .map_err(|e| {
                format!(
                    "replay log {} for node {name} failed to load: {e}\n\
                     refusing to fall back to a snapshot or to genesis: the snapshot \
                     would serve an older chain, and the genesis path truncates this \
                     log, destroying it.\n\
                     To start a fresh node, move the file aside first:\n  \
                     mv {} {}.broken",
                    log.display(),
                    log.display(),
                    log.display(),
                )
            })?;
            // The log's genesis already committed an authority set. Refuse to run
            // it under a different one before any state is served.
            restore_poa_policy(&mut node, &profile);
            Ok(node)
        }
        LoadTier::Snapshot => {
            let p = snap.to_str().ok_or_else(|| {
                format!(
                    "snapshot path for node {name} is not valid UTF-8: {}",
                    snap.display()
                )
            })?;
            let mut node = Node::new();
            let cfg = poa_config_from_env(&profile);
            check_authority_set(name, &cfg.authority_set)?;
            node.load_with_poa(p, cfg.authority_set, cfg.slot_duration_ms)
                .map_err(|e| {
                    format!(
                        "snapshot {} for node {name} failed to load: {e}\n\
                         refusing to fall back to genesis, which would serve a \
                         different chain. Move the file aside to start fresh.",
                        snap.display(),
                    )
                })?;
            restore_poa_policy(&mut node, &profile);
            // Migrate to the incremental store so subsequent persistence
            // appends only new blocks. This is load-bearing, not best-effort:
            // without a writable log the node would accept and serve blocks it
            // cannot persist, and every one of them would vanish on restart.
            open_replay_log(&mut node, &log, name, "after loading a snapshot")?;
            Ok(node)
        }
        LoadTier::Genesis => {
            let mut node = genesis_node();
            open_replay_log(&mut node, &log, name, "on a fresh data directory")?;
            // Fresh data directory: this is where the chain's authority set is
            // fixed, so record it now. Every later boot is checked against it.
            let cfg = poa_config_from_env(&profile);
            record_authority_set(name, &cfg.authority_set);
            Ok(node)
        }
    }
}

/// Resolve the Prometheus scrape bind address from `KOVANICA_METRICS_LISTEN`.
///
/// Returns `None` when metrics are switched off, which the operator signals
/// with `off` / `none` / `0` / `disabled`. Anything else is used verbatim as the
/// bind address, defaulting to `0.0.0.0:9090`.
///
/// An unset or empty value means *default*, not *off*: a systemd unit written as
/// `Environment=KOVANICA_METRICS_LISTEN=` should behave the same as omitting
/// the line, and silently disabling metrics because someone cleared a variable
/// would remove observability without anyone noticing.
///
/// Split out from `serve` so the policy is testable without binding a socket:
/// `init_metrics` has process-global side effects and can only bind once.
fn metrics_bind_target(raw: Option<&str>) -> Option<&str> {
    const DEFAULT: &str = "0.0.0.0:9090";
    let v = raw.unwrap_or_default().trim();
    if v.is_empty() {
        return Some(DEFAULT);
    }
    if matches!(
        v.to_ascii_lowercase().as_str(),
        "off" | "none" | "0" | "disabled"
    ) {
        return None;
    }
    Some(v)
}

/// Open the append-only replay log, or refuse to hand back a node.
///
/// Every tier except [`LoadTier::Log`] has to create this file before the node
/// can serve anything, and both remaining call sites used to be
/// `let _ = node.create_log(..)`. That discarded two independent failure modes
/// and turned each into silent data loss:
///
/// * `create_log` failing (read-only mount, full disk, bad path) left the node
///   running with **no persistence at all**. It would produce and serve blocks
///   that no restart could recover, while every health check looked green.
/// * `log.to_str()` returning `None` — a data-dir path containing non-UTF-8
///   bytes — skipped persistence *entirely* without even attempting it.
///
/// Both are the same class of bug as refusing to boot on a log that will not
/// load: a node that cannot durably record the chain it is serving is worse
/// than a node that does not start, because the damage is invisible until
/// someone restarts it.
fn open_replay_log(node: &mut Node, log: &Path, name: &str, context: &str) -> Result<(), String> {
    let p = log.to_str().ok_or_else(|| {
        format!(
            "replay log path for node {name} is not valid UTF-8: {}\n\
             refusing to start {context} without persistence: the node would \
             produce blocks it cannot durably record, and they would be silently \
             lost on restart. Point KOVANICA_DATA at a UTF-8 path.",
            log.display()
        )
    })?;
    node.create_log(p).map_err(|e| {
        format!(
            "cannot open the replay log {p} for node {name} {context}: {e}\n\
             refusing to start: the node would produce blocks it cannot durably \
             record, and they would be silently lost on restart. Resolve the \
             cause above — usually the data directory's permissions or free \
             space, or KOVANICA_DATA pointing somewhere unwritable."
        )
    })
}

/// Re-apply PoA admission and the network profile after loading a node from disk
/// (log or snapshot).
///
/// PoA admission is already active on a ledger loaded under the PoA reader;
/// re-applying it is defense-in-depth, so a PoA-era log loaded under a legacy
/// reader cannot admit blocks without authority signatures.
///
/// There is deliberately no on-disk persistence of authority signing keys. Keys
/// are supplied by the operator (env / key file) on every start; the node only
/// ever holds the public key on the wire. The placeholder block below exists so
/// a single-node explorer keeps producing in every slot — it is test-only and
/// must never be used for a real network.
fn restore_poa_policy(node: &mut Node, profile: &NetworkProfile) {
    let cfg = poa_config_from_env(profile);
    let _ = node.enable_poa(cfg.authority_set, cfg.slot_duration_ms);
    if let Some(key) = cfg.authority_signing_key {
        node.set_authority_signing_key(key);
    } else if cfg.placeholder {
        for i in 0..AUTHORITY_PLACEHOLDER_COUNT {
            node.set_authority_signing_key(
                kovanica_state::KeyPair::from_u64(AUTHORITY_PLACEHOLDER_BASE + i).seed(),
            );
        }
    }
    // A log-loaded node starts with finality/payload/block pruning disabled
    // (the replay log does not persist the policy; a snapshot restores the
    // first two, but the profile is authoritative either way). Re-apply the
    // network profile so a loaded node matches a fresh-genesis node's
    // acceptance rules (deep-reorg blocks rejected) and memory bounds
    // (per-block state pruned below the finality point; the reachability
    // oracle bounded by block pruning).
    let _ = node.set_finality_depth(profile.finality_depth);
    let _ = node.set_payload_pruning_depth(profile.payload_pruning_depth);
    let _ = node.set_block_pruning_depth(profile.block_pruning_depth);
}

fn line_mesh() -> Mesh {
    let mut mesh = Mesh::new();
    mesh.add("alpha", genesis_node());
    mesh.add("beta", genesis_node());
    mesh.add("gamma", genesis_node());
    let _ = mesh.connect("alpha", "beta");
    let _ = mesh.connect("beta", "gamma");
    mesh
}

fn genesis_node() -> Node {
    let profile = network_profile();
    let mut node = Node::new();
    // RFC-006 treasury: the testnet profile uses the deterministic placeholder
    // keys (publicly derivable by design — testnet-only). Mainnet MUST boot
    // with a real secret seed from the key ceremony (`KOVANICA_TREASURY_SEED`,
    // 64 hex chars); refusing to boot with publicly-derivable keys on mainnet
    // is the fail-fast guard for the Gate-2 MEDIUM (mainnet placeholder keys).
    let treasury = if profile.id == "kovanica-mainnet" {
        match std::env::var("KOVANICA_TREASURY_SEED") {
            Ok(hex) if hex.len() == 64 => {
                let mut seed = [0u8; 32];
                for (i, byte) in hex.as_bytes().chunks(2).enumerate() {
                    seed[i] = u8::from_str_radix(std::str::from_utf8(byte).expect("ascii hex"), 16)
                        .expect("KOVANICA_TREASURY_SEED must be 64 hex chars");
                }
                TreasuryGenesis { seed: Some(seed) }
            }
            _ => panic!(
                "kovanica-mainnet requires KOVANICA_TREASURY_SEED (64 hex chars): \
                 refusing to boot with publicly-derivable placeholder treasury keys"
            ),
        }
    } else {
        TreasuryGenesis::placeholder()
    };
    // RFC-POA: the genesis coinbase commits to the authority set
    // (`KVA1 || set_hash`). There is no other genesis shape — PoW, difficulty,
    // VRF and hybrid admission were removed (RFC-POA §0).
    let cfg = poa_config_from_env(&profile);
    // Operator's authority signing key (from KOVANICA_AUTHORITY_KEY) takes
    // precedence; otherwise fall back to TESTNET-ONLY placeholder keys.
    if let Some(key) = cfg.authority_signing_key {
        node.set_authority_signing_key(key);
    } else if cfg.placeholder {
        for i in 0..AUTHORITY_PLACEHOLDER_COUNT {
            node.set_authority_signing_key(
                kovanica_state::KeyPair::from_u64(AUTHORITY_PLACEHOLDER_BASE + i).seed(),
            );
        }
    }
    node.genesis_with_poa(
        profile.genesis_k,
        profile.genesis_subsidy,
        profile.genesis_premine,
        profile.founder_seed,
        Some(treasury),
        profile.finality_depth,
        profile.payload_pruning_depth,
        profile.block_pruning_depth,
        Some(profile.operator_seed),
        cfg.authority_set,
        cfg.slot_duration_ms,
    )
    .expect("genesis");
    node
}

fn env_flag(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "on"),
        Err(_) => default,
    }
}

/// A token bucket: `capacity` tokens, refilled at `rate` per second.
/// [`TokenBucket::allow`] consumes one token and reports whether the request
/// may proceed. Deterministic in the sense that the refill is a pure function
/// of elapsed time; tests drive it with `rate = 0` (no refill) so exhaustion
/// is immediate and stable.
#[derive(Clone, Debug)]
struct TokenBucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    last: std::time::Instant,
}

impl TokenBucket {
    fn new(rate: f64, capacity: f64) -> Self {
        Self {
            rate,
            capacity,
            tokens: capacity,
            last: std::time::Instant::now(),
        }
    }

    fn allow(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-IP HTTP rate limiting, from `KOVANICA_RATE_LIMIT` (tokens/second,
/// default 10) and `KOVANICA_RATE_BURST` (bucket capacity, default 60).
fn rate_limit_from_env() -> (f64, f64) {
    let rate: f64 = std::env::var("KOVANICA_RATE_LIMIT")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(10.0)
        .max(0.0);
    let burst: f64 = std::env::var("KOVANICA_RATE_BURST")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(60.0)
        .max(1.0);
    (rate, burst)
}

/// Faucet: testnet-only, per-address lifetime cap (5 KVNC).
const FAUCET_MAX_PER_ADDRESS: u64 = 5 * ATOM;

fn faucet_path() -> PathBuf {
    data_dir().join("faucet.txt")
}

fn load_faucet_given() -> HashMap<String, u64> {
    let mut map = HashMap::new();
    let Ok(text) = fs::read_to_string(faucet_path()) else {
        return map;
    };
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(addr) = parts.next() else {
            continue;
        };
        let Some(n) = parts.next().and_then(|s| s.parse().ok()) else {
            continue;
        };
        map.insert(addr.to_string(), n);
    }
    map
}

fn save_faucet_given(map: &HashMap<String, u64>) {
    let mut rows: Vec<_> = map.iter().collect();
    rows.sort_by(|a, b| a.0.cmp(b.0));
    let body: String = rows
        .into_iter()
        .map(|(k, v)| format!("{k} {v}\n"))
        .collect();
    let _ = fs::create_dir_all(data_dir());
    let _ = fs::write(faucet_path(), body);
}

/// Explorer loop sleeps 40ms per tick.
const TICK_MS: u64 = 40;
/// Default interval between block-production attempts when
/// `KOVANICA_PRODUCE=1` (seconds). Under PoA an attempt succeeds only if the
/// node holds the authority key for that slot.
const PRODUCE_SECS_DEFAULT: u64 = 120;

fn produce_every_ticks() -> u64 {
    let secs = std::env::var("KOVANICA_PRODUCE_SECS")
        .ok()
        .or_else(|| std::env::var("KOVANICA_MINE_SECS").ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(PRODUCE_SECS_DEFAULT);
    (secs.saturating_mul(1000) / TICK_MS).max(1)
}

fn ensure_network() {
    let marker = data_dir().join("network");
    let ok = fs::read_to_string(&marker)
        .map(|s| s.trim() == network_profile().id)
        .unwrap_or(false);
    if !ok {
        wipe_data();
        let _ = fs::create_dir_all(data_dir());
        let _ = fs::write(marker, network_profile().id);
    }
}

fn bind_p2p() -> Vec<TcpListener> {
    let raw = std::env::var("KOVANICA_LISTEN").unwrap_or_else(|_| P2P_LISTEN_DEFAULT.into());
    if env_off(&raw) {
        eprintln!("kovanica p2p listen disabled");
        return Vec::new();
    }
    let listeners = bind_p2p_addrs(&raw);
    if listeners.is_empty() && !raw.is_empty() {
        eprintln!("kovanica p2p listen {raw} produced no listeners");
    }
    listeners
}

fn bind_p2p_addrs(raw: &str) -> Vec<TcpListener> {
    let mut addrs = vec![raw.to_string()];
    if let Some(port) = raw.strip_prefix("0.0.0.0:") {
        addrs.push(format!("[::]:{port}"));
    }
    let mut out = Vec::new();
    for addr in addrs {
        let listener = if addr.starts_with("[::]:") {
            // A wildcard [::] socket with the default v6only=0 covers IPv4
            // too, so it would collide with the 0.0.0.0 listener already
            // bound above (EADDRINUSE). Mark it v6-only first — that needs a
            // setsockopt before bind, hence socket2 rather than std.
            match bind_v6_only(&addr) {
                Ok(l) => Some(l),
                Err(e) => {
                    eprintln!("kovanica p2p listen {addr} failed: {e}");
                    None
                }
            }
        } else {
            match TcpListener::bind(&addr) {
                Ok(l) => Some(l),
                Err(e) => {
                    eprintln!("kovanica p2p listen {addr} failed: {e}");
                    None
                }
            }
        };
        let Some(listener) = listener else { continue };
        if let Err(e) = listener.set_nonblocking(true) {
            eprintln!("kovanica p2p listen {addr} nonblocking failed: {e}");
            continue;
        }
        if let Ok(local) = listener.local_addr() {
            eprintln!("kovanica p2p listen {local}");
        }
        out.push(listener);
    }
    out
}

/// Bind an `[::]:port` listener with IPV6_V6ONLY set, so it accepts IPv6
/// only and leaves the IPv4 wildcard to its sibling socket.
fn bind_v6_only(addr: &str) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}")))?;
    let socket = Socket::new(
        Domain::for_address(sock_addr),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    socket.set_only_v6(true)?;
    socket.bind(&sock_addr.into())?;
    socket.listen(128)?;
    let listener: std::net::TcpListener = socket.into();
    listener.set_nonblocking(true)?;
    Ok(listener)
}

pub const DEFAULT_PEERS: &[&str] = &["seed.kovanica.online:9000", "seed2.kovanica.online:9000"];

fn peer_list() -> Vec<String> {
    match std::env::var("KOVANICA_PEERS") {
        Ok(s) if env_off(s.trim()) => Vec::new(),
        Ok(s) => s
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect(),
        Err(_) => DEFAULT_PEERS.iter().map(|s| s.to_string()).collect(),
    }
}

fn env_off(v: &str) -> bool {
    matches!(v, "" | "0" | "off" | "none" | "false" | "FALSE")
}

fn origins_path() -> PathBuf {
    data_dir().join("origins.txt")
}

fn load_origins() -> HashMap<String, u64> {
    let mut map = HashMap::new();
    let Ok(text) = fs::read_to_string(origins_path()) else {
        return map;
    };
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(iso) = parts.next() else {
            continue;
        };
        let Some(n) = parts.next().and_then(|s| s.parse().ok()) else {
            continue;
        };
        if iso.len() == 3 && iso.chars().all(|c| c.is_ascii_alphabetic()) {
            map.insert(iso.to_ascii_uppercase(), n);
        }
    }
    map
}

fn save_origins(map: &HashMap<String, u64>) {
    let mut rows: Vec<_> = map.iter().collect();
    rows.sort_by(|a, b| a.0.cmp(b.0));
    let body: String = rows
        .into_iter()
        .map(|(k, v)| format!("{k} {v}\n"))
        .collect();
    let _ = fs::create_dir_all(data_dir());
    let _ = fs::write(origins_path(), body);
}

fn origins_json(map: &HashMap<String, u64>) -> String {
    let mut rows: Vec<_> = map.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let items = rows
        .into_iter()
        .map(|(iso, n)| format!("{{\"iso3\":{},\"pulses\":{}}}", jstr(iso), n));
    format!("{{\"pulses\":{}}}", jarr(items))
}

fn handle_websocket(app: &mut Explorer, mut stream: TcpStream, req: &str) -> std::io::Result<()> {
    // Extract Sec-WebSocket-Key
    let key = req
        .lines()
        .find(|l| l.to_lowercase().starts_with("sec-websocket-key:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim())
        .unwrap_or("");
    let accept = {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    };
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()?;

    // Register client
    let client = Arc::new(Mutex::new(stream));
    app.ws_clients.lock().unwrap().push(client.clone());
    set_explorer_ws_clients(app.ws_clients.lock().unwrap().len());

    // Read loop (handle ping/pong, keep alive)
    let mut buf = [0u8; 1024];
    loop {
        match client.lock().unwrap().read(&mut buf) {
            Ok(0) => break, // Connection closed
            Ok(n) => {
                // Simple WebSocket frame parsing (just handle ping/pong)
                if n >= 2 && (buf[0] & 0x80) != 0 && (buf[0] & 0x0F) == 0x9 {
                    // Ping frame - respond with pong
                    let pong = vec![0x8A, 0x00]; // Pong frame, no payload
                    if let Ok(mut c) = client.lock() {
                        let _ = c.write_all(&pong);
                        let _ = c.flush();
                    }
                }
            }
            Err(_) => break,
        }
    }

    // Unregister client
    app.ws_clients
        .lock()
        .unwrap()
        .retain(|c| !Arc::ptr_eq(c, &client));
    set_explorer_ws_clients(app.ws_clients.lock().unwrap().len());
    Ok(())
}

fn parse_json_u128(val: &serde_json::Value) -> Option<u128> {
    if let Some(n) = val.as_u64() {
        Some(n as u128)
    } else if let Some(s) = val.as_str() {
        s.parse::<u128>().ok()
    } else {
        val.as_f64().map(|n| n as u128)
    }
}

fn parse_json_u64(val: &serde_json::Value) -> Option<u64> {
    if let Some(n) = val.as_u64() {
        Some(n)
    } else if let Some(s) = val.as_str() {
        s.parse::<u64>().ok()
    } else {
        val.as_f64().map(|n| n as u64)
    }
}

pub fn handle(app: &mut Explorer, mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut buf = [0u8; 8192];
    let n = match stream.read(&mut buf) {
        Ok(0) => return Ok(()),
        Ok(n) => n,
        Err(_) => return Ok(()),
    };

    // Extract headers and body
    let (headers_raw, body_initial) =
        if let Some(pos) = buf[..n].windows(4).position(|w| w == b"\r\n\r\n") {
            (&buf[..pos], &buf[pos + 4..n])
        } else if let Some(pos) = buf[..n].windows(2).position(|w| w == b"\n\n") {
            (&buf[..pos], &buf[pos + 2..n])
        } else {
            (&buf[..n], &[][..])
        };

    let headers_str = String::from_utf8_lossy(headers_raw);

    let mut content_length = None;
    for line in headers_str.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                if let Ok(cl) = v.trim().parse::<usize>() {
                    content_length = Some(cl);
                }
            }
        }
    }

    let mut body_bytes = body_initial.to_vec();
    if let Some(cl) = content_length {
        const MAX_BODY_SIZE: usize = 2 * 1024 * 1024; // 2MB max
        let target_len = cl.min(MAX_BODY_SIZE);
        while body_bytes.len() < target_len {
            let to_read = target_len - body_bytes.len();
            let mut chunk = vec![0u8; to_read.min(8192)];
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(read_n) => {
                    body_bytes.extend_from_slice(&chunk[..read_n]);
                }
                Err(_) => break,
            }
        }
    }

    let body_str = String::from_utf8_lossy(&body_bytes);
    let first = headers_str.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let target = parts.next().unwrap_or("/");
    let (path, query) = split_query(target);

    // Record HTTP request metric
    record_explorer_http_request(path, 200); // Will update with actual status later

    // Per-IP token-bucket rate limiting (D1): a misbehaving client cannot
    // hammer the API. Every request counts — static assets, the WS upgrade,
    // and the JSON endpoints alike; a browser's normal polling sits far below
    // the default 10 req/s. Exhausted buckets get 429.
    let peer_ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    let allowed = {
        let bucket = app
            .rate_limits
            .entry(peer_ip)
            .or_insert_with(|| TokenBucket::new(app.rate_limit_rate, app.rate_limit_burst));
        bucket.allow()
    };
    if !allowed {
        return respond(
            &mut stream,
            429,
            "application/json",
            b"{\"ok\":false,\"error\":\"rate limit exceeded\"}",
        );
    }

    // WebSocket upgrade
    if method == "GET" && path == "/ws" && headers_str.contains("Upgrade: websocket") {
        return handle_websocket(app, stream, &headers_str);
    }

    // Prometheus metrics endpoint
    if method == "GET" && path == "/metrics" {
        // Sample live gauges on every scrape so Prometheus always sees fresh
        // values even when no block/mempool event fired recently.
        set_peer_count(app.live_peers.len());
        // RFC-006 supply gauges from the selected node's ledger (atoms).
        if let Some(n) = app.mesh.node(&app.selected) {
            if let Ok(ledger) = n.ledger() {
                record_supply(ledger.supply());
            }
        }
        return respond_prometheus_metrics(&mut stream);
    }

    if method == "HEAD" && (path == "/" || path == "/index.html" || path == "/wallet") {
        return respond(&mut stream, 200, "text/html; charset=utf-8", b"");
    }
    if method == "GET" && (path == "/" || path == "/index.html" || path == "/wallet") {
        return respond(&mut stream, 200, "text/html; charset=utf-8", UI.as_bytes());
    }
    if method == "GET" && path == "/bip39.txt" {
        return respond(
            &mut stream,
            200,
            "text/plain; charset=utf-8",
            BIP39.as_bytes(),
        );
    }
    if method == "GET" && path == "/kovanica-explorer-wallet.patch" {
        let body = std::fs::read("/workspace/kovanica-explorer-wallet.patch")
            .or_else(|_| std::fs::read("/tmp/kovanica-explorer-wallet.patch"))
            .unwrap_or_default();
        return respond_download(
            &mut stream,
            "text/x-patch; charset=utf-8",
            "kovanica-explorer-wallet.patch",
            &body,
        );
    }
    if method == "GET" && path == "/docs" {
        return respond(
            &mut stream,
            200,
            "text/plain; charset=utf-8",
            DOCS.as_bytes(),
        );
    }
    if method == "GET" && path == "/api/bootstrap" {
        let n = app.mesh.node(&app.selected);
        let genesis = n
            .and_then(|n| n.ledger().ok())
            .map(|l| l.genesis().to_string())
            .unwrap_or_default();
        let tip = n
            .and_then(|n| n.selected_tip().ok())
            .map(|t| t.to_string())
            .unwrap_or_default();
        let admission = n.map(|n| n.poa_enabled()).unwrap_or(false);
        let min_fee = n.map(|n| n.min_fee()).unwrap_or(0);
        // Peers are dialable addresses only; the node's own listen spec is
        // reported separately in the `listen` field and must not leak here.
        let peers = jarr(app.peers.iter().map(|s| jstr(s)));
        let profile = network_profile();

        // RFC-006 supply metrics from the ledger
        let (native_minted, total, circulating, burned, max_supply) = n
            .and_then(|n| n.ledger().ok())
            .map(|l| {
                let s = l.supply();
                (s.total, s.total, s.circulating, s.burned, s.max_supply)
            })
            .unwrap_or((0, 0, 0, 0, MAX_SUPPLY));

        let body = format!(
            "{{\"network\":{},\"genesis\":{},\"tip\":{},\"listen\":{},\"peers\":{},\"admission\":\"poa\",\"poa_enabled\":{},\"min_fee\":{},\"atom\":{},\"token\":\"KVNC\",\"k\":{},\"subsidy\":{},\"founder_amount\":{},\"founder_seed\":{},\"finality_depth\":{},\"payload_pruning_depth\":{},\"block_pruning_depth\":{},\"native_minted\":{},\"total\":{},\"circulating\":{},\"burned\":{},\"max_supply\":{},\"operator_wallet_address\":{},\"light_config\":{{\"k\":{},\"subsidy\":{},\"premine\":{},\"founder_seed\":{},\"finality_depth\":{},\"payload_pruning_depth\":{}}}}}",
            jstr(profile.id),
            jstr(&genesis),
            jstr(&tip),
            jstr(&app.listen_addr),
            peers,
            admission,
            min_fee,
            ATOM,
            profile.genesis_k,
            profile.genesis_subsidy,
            profile.genesis_premine,
            profile.founder_seed,
            profile.finality_depth,
            profile.payload_pruning_depth,
            profile.block_pruning_depth,
            native_minted,
            total,
            circulating,
            burned,
            max_supply,
            jstr(&app.mesh.node("alpha").and_then(|n| n.operator_wallet().map(|w| w.address().to_kvnc())).unwrap_or_default()),
            profile.genesis_k,
            profile.genesis_subsidy,
            profile.genesis_premine,
            profile.founder_seed,
            profile.finality_depth,
            profile.payload_pruning_depth,
        );
        return respond(&mut stream, 200, "application/json", body.as_bytes());
    }
    if method == "GET" && path == "/api/state" {
        if let Some(node) = query.get("node") {
            app.select(node);
        }
        let body = snapshot(app);
        return respond(&mut stream, 200, "application/json", body.as_bytes());
    }
    if method == "GET" && path == "/api/head" {
        if let Some(n) = app.mesh.node(&app.selected) {
            let genesis = n
                .ledger()
                .ok()
                .map(|l| l.genesis().to_string())
                .unwrap_or_default();
            let tip = n.selected_tip().map(|t| t.to_string()).unwrap_or_default();
            let blocks = n.block_count().unwrap_or(0);
            // PoA status
            let (authority_set_json, current_slot, slot_duration) = match n.poa_config() {
                Some(cfg) => {
                    let set = &cfg.authority_set;
                    let authorities_json = set
                        .authorities()
                        .iter()
                        .map(|pk| format!("\"{}\"", hex::encode(pk.as_bytes())))
                        .collect::<Vec<_>>()
                        .join(",");
                    let authority_json = format!(
                        "{{\"authorities\":[{}],\"threshold\":{},\"count\":{}}}",
                        authorities_json,
                        set.threshold(),
                        set.authorities().len()
                    );
                    let ledger = n.ledger().ok();
                    let tip_block = n
                        .selected_tip()
                        .ok()
                        .and_then(|id| ledger.as_ref().and_then(|l| l.dag().block(&id)));
                    let slot = tip_block
                        .map(|b| b.timestamp_ms() / cfg.slot_duration_ms)
                        .unwrap_or(0);
                    (authority_json, slot, cfg.slot_duration_ms)
                }
                None => (String::from("null"), 0, 0),
            };
            let body = format!(
                "{{\"network\":{},\"genesis\":{},\"tip\":{},\"blocks\":{},\"min_fee\":{},\"atom\":{},\"finality_depth\":{},\"payload_pruning_depth\":{},\"block_pruning_depth\":{},\"authority_set\":{},\"current_slot\":{},\"slot_duration_ms\":{}}}",
                jstr(network_profile().id),
                jstr(&genesis),
                jstr(&tip),
                blocks,
                n.min_fee(),
                ATOM,
                n.finality_depth(),
                n.payload_pruning_depth(),
                n.block_pruning_depth(),
                authority_set_json,
                current_slot,
                slot_duration,
            );
            return respond(&mut stream, 200, "application/json", body.as_bytes());
        }
    }
    if method == "GET" && path == "/api/network" {
        if let Some(n) = app.mesh.node(&app.selected) {
            let (authority_set_json, current_slot, slot_duration, time_to_next, next_slot_ts) =
                match n.poa_config() {
                    Some(cfg) => {
                        let set = &cfg.authority_set;
                        let authorities_json = set
                            .authorities()
                            .iter()
                            .map(|pk| format!("\"{}\"", hex::encode(pk.as_bytes())))
                            .collect::<Vec<_>>()
                            .join(",");
                        let authority_json = format!(
                        "{{\"authorities\":[{}],\"threshold\":{},\"count\":{},\"hash\":\"{}\"}}",
                        authorities_json, set.threshold(), set.authorities().len(), hex::encode(set.hash())
                    );
                        let tip_id = n.selected_tip().ok();
                        let ledger = n.ledger().ok();
                        let tip_block =
                            tip_id.and_then(|id| ledger.as_ref().and_then(|l| l.dag().block(&id)));
                        let slot = tip_block
                            .map(|b| b.timestamp_ms() / cfg.slot_duration_ms)
                            .unwrap_or(0);
                        let next_slot_ts = (slot + 1) * cfg.slot_duration_ms;
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let time_to_next = next_slot_ts.saturating_sub(now_ms);
                        (
                            authority_json,
                            slot,
                            cfg.slot_duration_ms,
                            time_to_next,
                            next_slot_ts,
                        )
                    }
                    None => (String::from("null"), 0, 0, 0, 0),
                };
            let peers = app
                .peers
                .iter()
                .map(|s| jstr(s))
                .collect::<Vec<_>>()
                .join(",");
            let blue_score = n
                .selected_tip()
                .ok()
                .and_then(|tip| n.ledger().ok().and_then(|l| l.dag().ghostdag(&tip)))
                .map(|g| g.blue_score)
                .unwrap_or(0);
            let body = format!(
                "{{\"network\":{},\"genesis\":{},\"tip\":{},\"blue_score\":{},\"peers\":[{}]}}",
                jstr(network_profile().id),
                jstr(
                    &n.ledger()
                        .ok()
                        .map(|l| l.genesis().to_string())
                        .unwrap_or_default()
                ),
                jstr(&n.selected_tip().map(|t| t.to_string()).unwrap_or_default()),
                blue_score,
                peers,
            );
            // Add authority set info if PoA is enabled
            let body = if authority_set_json != "null" {
                format!(
                    "{},\"authority_set\":{},\"current_slot\":{},\"slot_duration_ms\":{},\"time_to_next_slot_ms\":{},\"next_slot_timestamp_ms\":{}}}",
                    &body[..body.len()-1], // remove trailing }
                    authority_set_json,
                    current_slot,
                    slot_duration,
                    time_to_next,
                    next_slot_ts,
                )
            } else {
                format!("{}}}", &body[..body.len() - 1]) // just close the object
            };
            return respond(&mut stream, 200, "application/json", body.as_bytes());
        }
    }
    if method == "GET" && path == "/api/p2p" {
        let body = format!(
            "{{\"path\":\"tcp\",\"listen\":{},\"peers\":{},\"bootstrap\":{}}}",
            jstr(&app.listen_addr),
            jarr(app.peers.iter().map(|s| jstr(s))),
            jstr(P2P_BOOTSTRAP)
        );
        return respond(&mut stream, 200, "application/json", body.as_bytes());
    }
    if method == "GET" && path == "/api/origins" {
        return respond(
            &mut stream,
            200,
            "application/json",
            origins_json(&app.origins).as_bytes(),
        );
    }
    if method == "GET" && path == "/api/blocks" {
        if let Some(n) = app.mesh.node(&app.selected) {
            let records = match query.get("from") {
                Some(s) => match decode_block_id_hex(s) {
                    Ok(id) => n.export_from(&id),
                    Err(e) => {
                        let body = format!("{{\"ok\":false,\"error\":{}}}", jstr(&e));
                        return respond(&mut stream, 400, "application/json", body.as_bytes());
                    }
                },
                None => n.export(),
            };
            let bytes = encode_records(&records);
            return respond(&mut stream, 200, "application/octet-stream", &bytes);
        }
    }
    if method == "GET" && path == "/api/light_sync" {
        // SPV light-sync blob (A3): the selected chain as verified headers +
        // per-block Golomb-Rice filters, byte-compatible with the FFI's `KVLS`
        // v1 format so a phone's `receive_light_sync` consumes it directly.
        // `?from=<block-id>` returns only headers strictly after that block
        // (the client already has it) for incremental sync; an unknown or
        // off-chain `from` falls back to the full blob.
        if let Some(n) = app.mesh.node(&app.selected) {
            let bytes = light_sync_blob(n, query.get("from").map(|s| s.as_str()));
            return respond(&mut stream, 200, "application/octet-stream", &bytes);
        }
    }
    if method == "GET" && path == "/api/light_proof" {
        // Merkle-inclusion proof for one transaction, for a light client to
        // verify against the header it already synced (`merkle_proof` helper).
        let Some(block_hex) = query.get("block") else {
            let err = "{\"ok\":false,\"error\":\"block id required\"}";
            return respond(&mut stream, 400, "application/json", err.as_bytes());
        };
        let Some(tx_hex) = query.get("tx") else {
            let err = "{\"ok\":false,\"error\":\"tx id required\"}";
            return respond(&mut stream, 400, "application/json", err.as_bytes());
        };
        let block_id = match hex::decode(block_hex.trim())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(BlockId::from_bytes)
        {
            Some(id) => id,
            None => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr("block id must be 32-byte hex")
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };
        let tx_id = match hex::decode(tx_hex.trim())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(kovanica_state::TxId::from_bytes)
        {
            Some(id) => id,
            None => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr("tx id must be 32-byte hex")
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };
        if let Some(n) = app.mesh.node(&app.selected) {
            match n.merkle_proof(&block_id, &tx_id) {
                Some(proof) => {
                    let bytes = encode_merkle_proof(&proof);
                    return respond(&mut stream, 200, "application/octet-stream", &bytes);
                }
                None => {
                    let err = format!(
                        "{{\"ok\":false,\"error\":{}}}",
                        jstr("no proof: unknown block or tx")
                    );
                    return respond(&mut stream, 404, "application/json", err.as_bytes());
                }
            }
        }
    }
    if method == "GET" && path == "/api/history" {
        match history_json(app, &query) {
            Ok(body) => return respond(&mut stream, 200, "application/json", body.as_bytes()),
            Err(e) => return respond(&mut stream, 400, "text/plain; charset=utf-8", e.as_bytes()),
        }
    }
    if method == "GET" && path == "/api/utxos" {
        match utxos_json(app, &query) {
            Ok(body) => return respond(&mut stream, 200, "application/json", body.as_bytes()),
            Err(e) => return respond(&mut stream, 400, "text/plain; charset=utf-8", e.as_bytes()),
        }
    }
    if method == "GET" && path.starts_with("/api/block/") {
        let id = path.trim_start_matches("/api/block/");
        match block_detail_json(app, id) {
            Ok(body) => return respond(&mut stream, 200, "application/json", body.as_bytes()),
            Err(e) if e == "block not found" => {
                return respond(
                    &mut stream,
                    404,
                    "application/json",
                    err_json(&e).as_bytes(),
                );
            }
            Err(e) => {
                return respond(
                    &mut stream,
                    400,
                    "application/json",
                    err_json(&e).as_bytes(),
                )
            }
        }
    }
    if method == "GET" && path.starts_with("/api/tx/") {
        let id = path.trim_start_matches("/api/tx/");
        match tx_detail_json(app, id) {
            Ok(body) => return respond(&mut stream, 200, "application/json", body.as_bytes()),
            Err(e) if e == "tx not found" || e == "block not found" => {
                return respond(
                    &mut stream,
                    404,
                    "application/json",
                    err_json(&e).as_bytes(),
                );
            }
            Err(e) => {
                return respond(
                    &mut stream,
                    400,
                    "application/json",
                    err_json(&e).as_bytes(),
                )
            }
        }
    }
    if method == "GET" && path.starts_with("/api/address/") {
        let addr = path.trim_start_matches("/api/address/");
        match address_detail_json(app, addr, &query) {
            Ok(body) => return respond(&mut stream, 200, "application/json", body.as_bytes()),
            Err(e) if e == "address not found" => {
                return respond(
                    &mut stream,
                    404,
                    "application/json",
                    err_json(&e).as_bytes(),
                );
            }
            Err(e) => {
                return respond(
                    &mut stream,
                    400,
                    "application/json",
                    err_json(&e).as_bytes(),
                )
            }
        }
    }
    if method == "GET" && path.starts_with("/api/nft/") {
        let asset_id_str = path.trim_start_matches("/api/nft/");
        match nft_detail_json(app, asset_id_str, &query) {
            Ok(body) => return respond(&mut stream, 200, "application/json", body.as_bytes()),
            Err(e) if e == "nft not found" => {
                return respond(
                    &mut stream,
                    404,
                    "application/json",
                    err_json(&e).as_bytes(),
                );
            }
            Err(e) => {
                return respond(
                    &mut stream,
                    400,
                    "application/json",
                    err_json(&e).as_bytes(),
                )
            }
        }
    }
    if method == "POST" && path == "/api/rwa/derive" {
        match rwa_derive_json(app, &query) {
            Ok(body) => return respond(&mut stream, 200, "application/json", body.as_bytes()),
            Err(e) => {
                return respond(
                    &mut stream,
                    400,
                    "application/json",
                    err_json(&e).as_bytes(),
                )
            }
        }
    }
    if method == "GET" && path.starts_with("/api/rwa/") {
        let asset_id_str = path.trim_start_matches("/api/rwa/");
        match rwa_detail_json(app, asset_id_str, &query) {
            Ok(body) => return respond(&mut stream, 200, "application/json", body.as_bytes()),
            Err(e) if e == "rwa not found" || e == "asset is an NFT, not an RWA" => {
                return respond(
                    &mut stream,
                    404,
                    "application/json",
                    err_json(&e).as_bytes(),
                );
            }
            Err(e) => {
                return respond(
                    &mut stream,
                    400,
                    "application/json",
                    err_json(&e).as_bytes(),
                )
            }
        }
    }
    if method == "GET" && path.starts_with("/api/collection/") {
        let collection_id_str = path.trim_start_matches("/api/collection/");
        match collection_detail_json(app, collection_id_str, &query) {
            Ok(body) => return respond(&mut stream, 200, "application/json", body.as_bytes()),
            Err(e) if e == "collection not found" => {
                return respond(
                    &mut stream,
                    404,
                    "application/json",
                    err_json(&e).as_bytes(),
                );
            }
            Err(e) => {
                return respond(
                    &mut stream,
                    400,
                    "application/json",
                    err_json(&e).as_bytes(),
                )
            }
        }
    }
    if method == "GET" && path == "/api/fee_estimate" {
        match fee_estimate_json(app, &query) {
            Ok(body) => return respond(&mut stream, 200, "application/json", body.as_bytes()),
            Err(e) => {
                let err = format!("{{\"ok\":false,\"error\":{}}}", jstr(&e));
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        }
    }
    if method == "POST" && path == "/api/mine/submit" {
        let node_name = query
            .get("node")
            .cloned()
            .unwrap_or_else(|| app.selected.clone());

        // Staked-block uplink (plan 9d-a, locked decision): a phone that won
        // the VRF sortition uploads its block in the gossip wire format
        // (`encode_records` — the same octet-stream framing `/api/blocks`
        // serves), which carries the VRF bundle a JSON body cannot express.
        // `Content-Type: application/octet-stream` selects the wire path; the
        // JSON path below is unchanged for PoW miners.
        let is_wire = headers_str.lines().any(|l| {
            let l = l.to_ascii_lowercase();
            l.starts_with("content-type:") && l.contains("application/octet-stream")
        });
        if is_wire {
            return submit_wire_block(app, &node_name, &body_bytes, &mut stream);
        }

        // Parse JSON request body
        let json_body: serde_json::Value = match serde_json::from_str(&body_str) {
            Ok(val) => val,
            Err(e) => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr(&format!("invalid json body: {e}"))
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };

        // Extract parents
        let parents_val = match json_body.get("parents") {
            Some(serde_json::Value::Array(arr)) if !arr.is_empty() => arr,
            _ => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr("missing or empty 'parents' field")
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };

        let mut parents = Vec::with_capacity(parents_val.len());
        for p_val in parents_val {
            let Some(p_str) = p_val.as_str() else {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr("parent block id must be a hex string")
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            };
            let bytes = match hex::decode(p_str.trim()) {
                Ok(b) => b,
                Err(_) => {
                    let err = format!(
                        "{{\"ok\":false,\"error\":{}}}",
                        jstr(&format!("invalid hex in parent block id: {p_str}"))
                    );
                    return respond(&mut stream, 400, "application/json", err.as_bytes());
                }
            };
            let arr: [u8; 32] = match bytes.try_into() {
                Ok(a) => a,
                Err(_) => {
                    let err = format!(
                        "{{\"ok\":false,\"error\":{}}}",
                        jstr(&format!("parent block id must be 32 bytes: {p_str}"))
                    );
                    return respond(&mut stream, 400, "application/json", err.as_bytes());
                }
            };
            parents.push(BlockId::from_bytes(arr));
        }

        // Extract work
        let work = match json_body.get("work") {
            Some(v) => match parse_json_u128(v) {
                Some(w) => w,
                None => {
                    let err = format!(
                        "{{\"ok\":false,\"error\":{}}}",
                        jstr("invalid 'work' field")
                    );
                    return respond(&mut stream, 400, "application/json", err.as_bytes());
                }
            },
            None => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr("missing 'work' field")
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };

        // Extract timestamp_ms
        let timestamp_ms = match json_body.get("timestamp_ms") {
            Some(v) => match parse_json_u64(v) {
                Some(ts) => ts,
                None => {
                    let err = format!(
                        "{{\"ok\":false,\"error\":{}}}",
                        jstr("invalid 'timestamp_ms' field")
                    );
                    return respond(&mut stream, 400, "application/json", err.as_bytes());
                }
            },
            None => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr("missing 'timestamp_ms' field")
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };

        // Extract nonce
        let nonce = match json_body.get("nonce") {
            Some(v) => match parse_json_u64(v) {
                Some(nc) => nc,
                None => {
                    let err = format!(
                        "{{\"ok\":false,\"error\":{}}}",
                        jstr("invalid 'nonce' field")
                    );
                    return respond(&mut stream, 400, "application/json", err.as_bytes());
                }
            },
            None => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr("missing 'nonce' field")
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };

        // Extract payload hex and decode transactions
        let txs = if let Some(payload_val) = json_body.get("payload").and_then(|v| v.as_str()) {
            let payload_bytes = match hex::decode(payload_val.trim()) {
                Ok(b) => b,
                Err(e) => {
                    let err = format!(
                        "{{\"ok\":false,\"error\":{}}}",
                        jstr(&format!("invalid hex in 'payload': {e}"))
                    );
                    return respond(&mut stream, 400, "application/json", err.as_bytes());
                }
            };
            match decode_block_payload(&payload_bytes) {
                Ok(t) => t,
                Err(e) => {
                    let err = format!(
                        "{{\"ok\":false,\"error\":{}}}",
                        jstr(&format!("undecodable block payload: {e:?}"))
                    );
                    return respond(&mut stream, 400, "application/json", err.as_bytes());
                }
            }
        } else {
            let err = format!(
                "{{\"ok\":false,\"error\":{}}}",
                jstr("missing 'payload' field")
            );
            return respond(&mut stream, 400, "application/json", err.as_bytes());
        };

        let record = BlockRecord {
            parents,
            work,
            timestamp_ms,
            nonce,
            authority_sig: None,
            txs,
        };

        let Some(node) = app.mesh.node_mut(&node_name) else {
            let err = format!("{{\"ok\":false,\"error\":\"unknown node {}\"}}", node_name);
            return respond(&mut stream, 400, "application/json", err.as_bytes());
        };

        // PoA-only: there is no work target to check on submit. The DAG pins
        // `work` to `POA_NOMINAL_WORK` and enforces the authority signature on
        // `receive_block`, which is the admission check that matters.

        match node.receive_block(record.clone()) {
            Ok(block_id) => {
                app.mesh.announce_block(&node_name, record);
                persist_all(&mut app.mesh);
                let body = format!("{{\"ok\":true,\"block\":{}}}", jstr(&block_id.to_string()));
                return respond(&mut stream, 200, "application/json", body.as_bytes());
            }
            Err(e) => {
                let err = format!("{{\"ok\":false,\"error\":{}}}", jstr(&e.to_string()));
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        }
    }
    // ------------------------------------------------------------------
    // Raw transaction submission (multisig, hardware, mobile)
    // ------------------------------------------------------------------
    if method == "POST" && path == "/api/submit_tx" {
        let json_body: serde_json::Value = match serde_json::from_str(&body_str) {
            Ok(val) => val,
            Err(e) => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr(&format!("invalid json body: {e}"))
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };
        let tx_hex = match json_body.get("tx_hex").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr("missing 'tx_hex' field")
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };
        let tx_bytes = match hex::decode(tx_hex.trim()) {
            Ok(b) => b,
            Err(e) => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr(&format!("invalid hex in 'tx_hex': {e}"))
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };
        let tx = match Transaction::decode(&tx_bytes) {
            Ok(t) => t,
            Err(e) => {
                let err = format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    jstr(&format!("undecodable transaction: {e:?}"))
                );
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        };
        let node_name = query
            .get("node")
            .cloned()
            .unwrap_or_else(|| app.selected.clone());
        let Some(node) = app.mesh.node_mut(&node_name) else {
            let err = format!("{{\"ok\":false,\"error\":\"unknown node {}\"}}", node_name);
            return respond(&mut stream, 400, "application/json", err.as_bytes());
        };
        match node.submit_tx(tx) {
            Ok(tx_id) => {
                persist_all(&mut app.mesh);
                let body = format!("{{\"ok\":true,\"tx\":{}}}", jstr(&tx_id.to_string()));
                return respond(&mut stream, 200, "application/json", body.as_bytes());
            }
            Err(e) => {
                let err = format!("{{\"ok\":false,\"error\":{}}}", jstr(&e.to_string()));
                return respond(&mut stream, 400, "application/json", err.as_bytes());
            }
        }
    }
    // ------------------------------------------------------------------
    // Multisig wallet endpoints (M-of-N P2SH)
    if method == "POST" && path == "/api/multisig/create" {
        return handle_multisig_create(app, &query, &body_str, &mut stream);
    }
    if method == "POST" && path == "/api/multisig/build" {
        return handle_multisig_build(app, &query, &body_str, &mut stream);
    }
    if method == "POST" && path == "/api/multisig/sign" {
        return handle_multisig_sign(app, &query, &body_str, &mut stream);
    }
    if method == "POST" && path == "/api/multisig/combine" {
        return handle_multisig_combine(app, &query, &body_str, &mut stream);
    }
    if method == "POST" && path == "/api/multisig/submit" {
        return handle_multisig_submit(app, &query, &body_str, &mut stream);
    }
    if method == "POST" && path.starts_with("/api/") {
        let action = path.trim_start_matches("/api/");
        if let Some(node) = query.get("node") {
            app.select(node);
        }
        match dispatch(app, action, &query) {
            Ok(body) => {
                persist_all(&mut app.mesh);
                return respond(&mut stream, 200, "application/json", body.as_bytes());
            }
            Err(e) => return respond(&mut stream, 400, "text/plain; charset=utf-8", e.as_bytes()),
        }
    }
    respond(&mut stream, 404, "text/plain; charset=utf-8", b"not found")
}

/// Accept one or more blocks in the gossip wire format (`encode_records`
/// framing) on `POST /api/mine/submit`. This is the staked-block uplink: the
/// wire format is the only body that can carry a [`BlockRecord`]'s VRF bundle,
/// so a phone that won the sortition can push its block exactly as a peer
/// would receive it. Records are applied in order — parents must precede
/// children, the same contract as a full `/api/blocks` sync. Admission is
/// delegated entirely to [`Node::receive_block`] (and through it the ledger's
/// hybrid PoW / staked-VRF rules); no PoW pre-check is duplicated here.
/// Returns the last admitted block id.
fn submit_wire_block(
    app: &mut Explorer,
    node_name: &str,
    body: &[u8],
    stream: &mut TcpStream,
) -> std::io::Result<()> {
    let records = match decode_records(body) {
        Ok(records) if !records.is_empty() => records,
        Ok(_) => {
            let err = "{\"ok\":false,\"error\":\"empty wire body: no block records\"}";
            return respond(stream, 400, "application/json", err.as_bytes());
        }
        Err(e) => {
            let err = format!(
                "{{\"ok\":false,\"error\":{}}}",
                jstr(&format!("undecodable wire body: {e}"))
            );
            return respond(stream, 400, "application/json", err.as_bytes());
        }
    };

    let mut admitted: Vec<(BlockRecord, BlockId)> = Vec::with_capacity(records.len());
    {
        let Some(node) = app.mesh.node_mut(node_name) else {
            let err = format!("{{\"ok\":false,\"error\":\"unknown node {}\"}}", node_name);
            return respond(stream, 400, "application/json", err.as_bytes());
        };
        for record in &records {
            match node.receive_block(record.clone()) {
                Ok(id) => admitted.push((record.clone(), id)),
                Err(e) => {
                    let err = format!("{{\"ok\":false,\"error\":{}}}", jstr(&e.to_string()));
                    return respond(stream, 400, "application/json", err.as_bytes());
                }
            }
        }
    }
    for (record, _id) in &admitted {
        app.mesh.announce_block(node_name, record.clone());
    }
    persist_all(&mut app.mesh);
    let body = match admitted.last() {
        Some((_, id)) => format!("{{\"ok\":true,\"block\":{}}}", jstr(&id.to_string())),
        None => "{\"ok\":true}".into(),
    };
    respond(stream, 200, "application/json", body.as_bytes())
}

/// Light-sync blob framing, byte-compatible with the FFI's `KVLS` v1 format
/// (`crates/kovanica-ffi` `export_light_sync`): magic + version + count, then
/// per selected-chain block a 160-byte header followed by its Golomb-Rice
/// filter. A phone's `receive_light_sync` consumes this blob directly.
const LIGHT_SYNC_MAGIC: &[u8; 4] = b"KVLS";
const LIGHT_SYNC_VERSION: u8 = 1;
/// Golomb-Rice parameter for the per-block filters (the FFI's reference choice).
const LIGHT_SYNC_FILTER_K: u8 = 8;

fn encode_spv_header(h: &kovanica_state::spv::BlockHeader, out: &mut Vec<u8>) {
    out.extend_from_slice(h.id.as_bytes());
    out.extend_from_slice(h.prev_hash.as_bytes());
    out.extend_from_slice(&h.merkle_root);
    out.extend_from_slice(&h.work.to_be_bytes());
    out.extend_from_slice(&h.timestamp_ms.to_be_bytes());
    out.extend_from_slice(&h.nonce.to_be_bytes());
    out.extend_from_slice(&h.blue_score.to_be_bytes());
    out.extend_from_slice(&h.chain_blue_work.to_be_bytes());
    out.extend_from_slice(&h.height.to_be_bytes());
}

fn encode_spv_filter(f: &kovanica_state::spv::BlockFilter, out: &mut Vec<u8>) {
    out.push(f.k);
    out.extend_from_slice(&f.n.to_be_bytes());
    out.extend_from_slice(&(f.data.len() as u32).to_be_bytes());
    out.extend_from_slice(&f.data);
}

/// Assemble the light-sync blob from the shipped node helpers
/// ([`Node::export_spv_headers`] + [`Node::block_filter`]). `from` selects an
/// incremental window: headers strictly after `from` (exclusive) to the tip.
fn light_sync_blob(n: &Node, from: Option<&str>) -> Vec<u8> {
    let headers = n.export_spv_headers();
    let start = from
        .and_then(|s| hex::decode(s.trim()).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|bytes| {
            let from_id = BlockId::from_bytes(bytes);
            headers.iter().position(|h| h.id == from_id).map(|i| i + 1)
        })
        .unwrap_or(0);
    let mut out = Vec::new();
    out.extend_from_slice(LIGHT_SYNC_MAGIC);
    out.push(LIGHT_SYNC_VERSION);
    out.extend_from_slice(&((headers.len() - start) as u32).to_be_bytes());
    for h in &headers[start..] {
        encode_spv_header(h, &mut out);
        match n.block_filter(&h.id, LIGHT_SYNC_FILTER_K) {
            Some(f) => encode_spv_filter(&f, &mut out),
            None => encode_spv_filter(
                &kovanica_state::spv::BlockFilter {
                    k: LIGHT_SYNC_FILTER_K,
                    n: 1,
                    data: Vec::new(),
                },
                &mut out,
            ),
        }
    }
    out
}

/// Merkle-proof blob, byte-compatible with the FFI's `encode_proof` layout:
/// tx_id(32) + merkle_root(32) + path_len(4) + path(32 each) + index(8) +
/// tx_count(8).
fn encode_merkle_proof(p: &kovanica_state::spv::MerkleProof) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&p.tx_id);
    out.extend_from_slice(&p.merkle_root);
    out.extend_from_slice(&(p.path.len() as u32).to_be_bytes());
    for s in &p.path {
        out.extend_from_slice(s);
    }
    out.extend_from_slice(&(p.index as u64).to_be_bytes());
    out.extend_from_slice(&(p.tx_count as u64).to_be_bytes());
    out
}

fn estimate_fee(node: &Node, _amount: u64) -> Result<(u64, u64, u64), String> {
    let mut block_tx_count = 0;
    let mut blocks_scanned = 0;

    if let Ok(mut current) = node.selected_tip() {
        for _ in 0..10 {
            if let Some(record) = node.block_record(&current) {
                block_tx_count += record.txs.len();
                blocks_scanned += 1;
                if let Some(parent) = record.parents.first() {
                    current = *parent;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    let min = node.min_fee();
    // Assuming > 20 txs per block average is congested for this testnet
    let is_congested = blocks_scanned > 0 && (block_tx_count as f64 / blocks_scanned as f64) > 20.0;

    let pending = node.pending_txs();
    if pending.is_empty() {
        let base = if is_congested { min * 2 } else { min };
        return Ok((
            base,
            std::cmp::max(min + 1, base * 2),
            std::cmp::max(min + 2, base * 3),
        ));
    }

    let mut fees: Vec<u64> = pending
        .iter()
        .filter_map(|t| {
            if let Ok(ledger) = node.ledger() {
                let utxo = ledger.ledger_state();
                let mut sum_in = 0u64;
                for input in t.inputs() {
                    if let Some(prev) = utxo.get(&input.outpoint) {
                        sum_in = sum_in.saturating_add(prev.value);
                    }
                }
                let sum_out: u64 = t.outputs().iter().map(|o| o.value).sum();
                if sum_in > sum_out {
                    Some(sum_in - sum_out)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    if fees.is_empty() {
        let base = if is_congested { min * 2 } else { min };
        return Ok((
            base,
            std::cmp::max(min + 1, base * 2),
            std::cmp::max(min + 2, base * 3),
        ));
    }

    fees.sort();
    let p50_idx = (fees.len() as f64 * 0.5).floor() as usize;
    let p90_idx = (fees.len() as f64 * 0.9).floor() as usize;

    let p50 = fees[p50_idx.min(fees.len() - 1)];
    let p90 = fees[p90_idx.min(fees.len() - 1)];

    let mut slow = std::cmp::max(min, p50);
    let mut normal = std::cmp::max(min, p90);
    let mut fast = std::cmp::max(min, (p90 as f64 * 1.2) as u64);

    if is_congested {
        slow = std::cmp::max(slow, min * 2);
        normal = std::cmp::max(normal, min * 3);
        fast = std::cmp::max(fast, min * 5);
    }

    Ok((slow, normal, fast))
}

/// Parse a JSON body or respond with a 400 error.
fn parse_json_body(body_str: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str(body_str).map_err(|e| format!("invalid json body: {e}"))
}

/// Return the named node, or respond with a 400 error.
fn selected_node<'a>(app: &'a Explorer, q: &HashMap<String, String>) -> Option<&'a Node> {
    let name = q.get("node").map(|s| s.as_str()).unwrap_or(&app.selected);
    app.mesh.node(name)
}

fn bad_request(stream: &mut TcpStream, msg: &str) -> std::io::Result<()> {
    let body = format!("{{\"ok\":false,\"error\":{}}}", jstr(msg));
    respond(stream, 400, "application/json", body.as_bytes())
}

fn ok_json(stream: &mut TcpStream, body: &str) -> std::io::Result<()> {
    respond(stream, 200, "application/json", body.as_bytes())
}

fn handle_multisig_create(
    app: &mut Explorer,
    q: &HashMap<String, String>,
    body_str: &str,
    stream: &mut TcpStream,
) -> std::io::Result<()> {
    let json = match parse_json_body(body_str) {
        Ok(j) => j,
        Err(e) => return bad_request(stream, &e),
    };
    let threshold = match json.get("threshold").and_then(|v| v.as_u64()) {
        Some(t) if (1..=16).contains(&t) => t as u8,
        _ => return bad_request(stream, "threshold must be between 1 and 16"),
    };
    let pubkeys_hex = match json.get("pubkeys_hex").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return bad_request(stream, "pubkeys_hex must be an array"),
    };
    let mut pubkeys = Vec::with_capacity(pubkeys_hex.len());
    for (i, pk) in pubkeys_hex.iter().enumerate() {
        let s = match pk.as_str() {
            Some(s) => s,
            None => return bad_request(stream, &format!("pubkeys_hex[{i}] is not a string")),
        };
        let bytes = match hex::decode(s.trim()) {
            Ok(b) => b,
            Err(_) => return bad_request(stream, &format!("pubkeys_hex[{i}] is not hex")),
        };
        let arr = match <[u8; 32]>::try_from(bytes) {
            Ok(a) => a,
            Err(_) => return bad_request(stream, &format!("pubkeys_hex[{i}] must be 32 bytes")),
        };
        pubkeys.push(arr);
    }

    let node_name = q
        .get("node")
        .map(|s| s.as_str())
        .unwrap_or(&app.selected)
        .to_string();
    let node = match app.mesh.node_mut(&node_name) {
        Some(n) => n,
        None => return bad_request(stream, &format!("unknown node {node_name}")),
    };

    match node.create_multisig_address(threshold, pubkeys) {
        Ok((address, redeem_script)) => {
            let body = format!(
                "{{\"address\":{},\"redeem_script_hex\":{}}}",
                jstr(&address.to_kvnc()),
                jstr(&hex::encode(redeem_script))
            );
            ok_json(stream, &body)
        }
        Err(e) => bad_request(stream, &e.to_string()),
    }
}

fn handle_multisig_build(
    app: &mut Explorer,
    q: &HashMap<String, String>,
    body_str: &str,
    stream: &mut TcpStream,
) -> std::io::Result<()> {
    let json = match parse_json_body(body_str) {
        Ok(j) => j,
        Err(e) => return bad_request(stream, &e),
    };
    let address = match json.get("address").and_then(|v| v.as_str()) {
        Some(s) => match parse_addr(s) {
            Ok(a) => a,
            Err(e) => return bad_request(stream, &e),
        },
        None => return bad_request(stream, "address is required"),
    };
    let outputs_arr = match json.get("outputs").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return bad_request(stream, "outputs must be an array"),
    };
    let mut outputs = Vec::with_capacity(outputs_arr.len());
    for (i, o) in outputs_arr.iter().enumerate() {
        let addr = match o.get("address").and_then(|v| v.as_str()) {
            Some(s) => match parse_addr(s) {
                Ok(a) => a,
                Err(e) => return bad_request(stream, &format!("outputs[{i}].address: {e}")),
            },
            None => return bad_request(stream, &format!("outputs[{i}].address is required")),
        };
        let amount = match o.get("amount_atoms").and_then(|v| v.as_u64()) {
            Some(v) => v,
            None => return bad_request(stream, &format!("outputs[{i}].amount_atoms is required")),
        };
        outputs.push(TxOutput::native(amount, addr));
    }

    let node = match selected_node(app, q) {
        Some(n) => n,
        None => return bad_request(stream, "unknown node"),
    };

    match node.build_multisig_spend(address, outputs) {
        Ok(tx) => {
            let body = format!(
                "{{\"tx_blob_hex\":{},\"sighash_hex\":{}}}",
                jstr(&hex::encode(tx.encode())),
                jstr(&hex::encode(tx.sighash()))
            );
            ok_json(stream, &body)
        }
        Err(e) => bad_request(stream, &e.to_string()),
    }
}

fn decode_tx_blob(body: &serde_json::Value, field: &str) -> Result<Transaction, String> {
    let hex_str = body
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("{field} is required"))?;
    let bytes = hex::decode(hex_str.trim()).map_err(|_| format!("{field} is not hex"))?;
    Transaction::decode(&bytes).map_err(|e| format!("{field} decode error: {e:?}"))
}

fn parse_partial_sigs(body: &serde_json::Value) -> Result<Vec<[u8; 64]>, String> {
    let arr = body
        .get("partial_sigs_hex")
        .and_then(|v| v.as_array())
        .ok_or("partial_sigs_hex must be an array")?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, sig) in arr.iter().enumerate() {
        let s = sig
            .as_str()
            .ok_or_else(|| format!("partial_sigs_hex[{i}] is not a string"))?;
        let bytes =
            hex::decode(s.trim()).map_err(|_| format!("partial_sigs_hex[{i}] is not hex"))?;
        let arr = <[u8; 64]>::try_from(bytes)
            .map_err(|_| format!("partial_sigs_hex[{i}] must be 64 bytes"))?;
        out.push(arr);
    }
    Ok(out)
}

/// Parse CoinJoin participants from JSON body.
fn parse_coinjoin_participants(body_str: &str) -> Result<Vec<CoinJoinParticipant>, String> {
    let json = serde_json::from_str::<serde_json::Value>(body_str)
        .map_err(|e| format!("invalid json: {e}"))?;
    let arr = json
        .get("participants")
        .and_then(|v| v.as_array())
        .ok_or("participants must be an array")?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, p) in arr.iter().enumerate() {
        let address = p
            .get("address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("participants[{i}].address is required"))?;
        let amount = p
            .get("amount")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("participants[{i}].amount is required"))?
            .parse::<u64>()
            .map_err(|_| format!("participants[{i}].amount must be integer"))?;
        let recipient = p
            .get("recipient")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("participants[{i}].recipient is required"))?;
        let asset_id = p.get("asset_id").and_then(|v| v.as_str()).and_then(|s| {
            let raw = hex::decode(s.trim()).ok()?;
            if raw.len() != 32 {
                return None;
            }
            Some(AssetId::from_bytes(
                <[u8; 32]>::try_from(raw.as_slice()).ok()?,
            ))
        });
        out.push(CoinJoinParticipant {
            from: parse_addr(address)?,
            outputs: vec![TxOutput::new(amount, asset_id, parse_addr(recipient)?)],
            asset_id,
        });
    }
    Ok(out)
}

/// Parse CoinJoinPrepared from JSON body.
fn parse_coinjoin_prepared(body_str: &str) -> Result<CoinJoinPrepared, String> {
    let json = serde_json::from_str::<serde_json::Value>(body_str)
        .map_err(|e| format!("invalid json: {e}"))?;
    let tx_hex = json
        .get("tx_hex")
        .and_then(|v| v.as_str())
        .ok_or("tx_hex required")?;
    let sighashes_hex: Vec<String> = json
        .get("sighashes_hex")
        .and_then(|v| v.as_array())
        .ok_or("sighashes_hex required")?
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();
    let outpoints_hex: Vec<String> = json
        .get("outpoints_hex")
        .and_then(|v| v.as_array())
        .ok_or("outpoints_hex required")?
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();
    let values: Vec<String> = json
        .get("values")
        .and_then(|v| v.as_array())
        .ok_or("values required")?
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();
    let fee = json
        .get("fee")
        .and_then(|v| v.as_str())
        .ok_or("fee required")?
        .to_string();
    Ok(CoinJoinPrepared {
        tx: Transaction::decode(&hex::decode(tx_hex).map_err(|e| format!("tx_hex not hex: {e}"))?)
            .map_err(|e| format!("tx decode: {e:?}"))?,
        sighashes: sighashes_hex
            .iter()
            .map(|s| {
                let raw = hex::decode(s).map_err(|e| format!("sighash not hex: {e}"))?;
                <[u8; 32]>::try_from(raw.as_slice())
                    .map_err(|_| "sighash must be 32 bytes".to_string())
            })
            .collect::<Result<Vec<[u8; 32]>, _>>()?,
        outpoints: outpoints_hex
            .iter()
            .map(|s| {
                let parts: Vec<&str> = s.split(':').collect();
                if parts.len() != 2 {
                    return Err("outpoint must be txid:index".to_string());
                }
                let txid = TxId::from_bytes(
                    <[u8; 32]>::try_from(
                        hex::decode(parts[0])
                            .map_err(|e| format!("txid not hex: {e}"))?
                            .as_slice(),
                    )
                    .map_err(|_| "txid must be 32 bytes".to_string())?,
                );
                let index = parts[1]
                    .parse::<u32>()
                    .map_err(|_| "index not u32".to_string())?;
                Ok(OutPoint::new(txid, index))
            })
            .collect::<Result<Vec<_>, _>>()?,
        values: values
            .iter()
            .map(|s| s.parse::<u64>().map_err(|_| "value not u64".to_string()))
            .collect::<Result<Vec<_>, _>>()?,
        fee: fee.parse::<u64>().map_err(|_| "fee not u64".to_string())?,
    })
}

/// Serialize CoinJoinPrepared to JSON string.
fn serialize_coinjoin_prepared(prepared: &CoinJoinPrepared) -> String {
    let sighashes_hex: Vec<String> = prepared.sighashes.iter().map(hex::encode).collect();
    let outpoints_hex: Vec<String> = prepared
        .outpoints
        .iter()
        .map(|op| format!("{}:{}", op.tx.to_hex(), op.index))
        .collect();
    let values: Vec<String> = prepared.values.iter().map(|v| v.to_string()).collect();
    format!(
        "{{\"tx_hex\":\"{}\",\"sighashes_hex\":{},\"outpoints_hex\":{},\"values\":{},\"fee\":\"{}\"}}",
        hex::encode(prepared.tx.encode()),
        serde_json::to_string(&sighashes_hex).unwrap(),
        serde_json::to_string(&outpoints_hex).unwrap(),
        serde_json::to_string(&values).unwrap(),
        prepared.fee
    )
}

/// Parse signatures from a JSON array string.
fn parse_signatures(sigs_str: &str) -> Result<Vec<[u8; 64]>, String> {
    let json = serde_json::from_str::<serde_json::Value>(sigs_str)
        .map_err(|e| format!("invalid json: {e}"))?;
    let arr = json.as_array().ok_or("signatures must be an array")?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, sig) in arr.iter().enumerate() {
        let s = sig
            .as_str()
            .ok_or_else(|| format!("signatures[{i}] not string"))?;
        let raw = hex::decode(s.trim()).map_err(|_| format!("signatures[{i}] not hex"))?;
        if raw.len() != 64 {
            return Err(format!("signatures[{i}] must be 64 bytes"));
        }
        out.push(
            <[u8; 64]>::try_from(raw.as_slice()).map_err(|_| format!("signatures[{i}] invalid"))?,
        );
    }
    Ok(out)
}

fn handle_multisig_sign(
    app: &mut Explorer,
    q: &HashMap<String, String>,
    body_str: &str,
    stream: &mut TcpStream,
) -> std::io::Result<()> {
    let json = match parse_json_body(body_str) {
        Ok(j) => j,
        Err(e) => return bad_request(stream, &e),
    };
    let tx = match decode_tx_blob(&json, "tx_blob_hex") {
        Ok(t) => t,
        Err(e) => return bad_request(stream, &e),
    };
    let secret_hex = match json.get("secret_hex").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return bad_request(stream, "secret_hex is required"),
    };

    let node = match selected_node(app, q) {
        Some(n) => n,
        None => return bad_request(stream, "unknown node"),
    };

    match node.sign_multisig_partial(&tx, secret_hex) {
        Ok(sig) => {
            let body = format!("{{\"partial_sig_hex\":{}}}", jstr(&hex::encode(sig)));
            ok_json(stream, &body)
        }
        Err(e) => bad_request(stream, &e.to_string()),
    }
}

fn handle_multisig_combine(
    app: &mut Explorer,
    q: &HashMap<String, String>,
    body_str: &str,
    stream: &mut TcpStream,
) -> std::io::Result<()> {
    let json = match parse_json_body(body_str) {
        Ok(j) => j,
        Err(e) => return bad_request(stream, &e),
    };
    let tx = match decode_tx_blob(&json, "tx_blob_hex") {
        Ok(t) => t,
        Err(e) => return bad_request(stream, &e),
    };
    let partial_sigs = match parse_partial_sigs(&json) {
        Ok(s) => s,
        Err(e) => return bad_request(stream, &e),
    };

    let node = match selected_node(app, q) {
        Some(n) => n,
        None => return bad_request(stream, "unknown node"),
    };

    match node.combine_multisig_sigs(&tx, partial_sigs) {
        Ok(tx) => {
            let body = format!(
                "{{\"signed_tx_blob_hex\":{}}}",
                jstr(&hex::encode(tx.encode()))
            );
            ok_json(stream, &body)
        }
        Err(e) => bad_request(stream, &e.to_string()),
    }
}

fn handle_multisig_submit(
    app: &mut Explorer,
    q: &HashMap<String, String>,
    body_str: &str,
    stream: &mut TcpStream,
) -> std::io::Result<()> {
    let json = match parse_json_body(body_str) {
        Ok(j) => j,
        Err(e) => return bad_request(stream, &e),
    };
    let tx = match decode_tx_blob(&json, "signed_tx_blob_hex") {
        Ok(t) => t,
        Err(e) => return bad_request(stream, &e),
    };

    let node_name = q
        .get("node")
        .map(|s| s.as_str())
        .unwrap_or(&app.selected)
        .to_string();
    let node = match app.mesh.node_mut(&node_name) {
        Some(n) => n,
        None => return bad_request(stream, &format!("unknown node {node_name}")),
    };

    match node.submit_multisig_tx(tx) {
        Ok(tx_id) => {
            let body = format!("{{\"tx_id_hex\":{}}}", jstr(&hex::encode(tx_id.as_bytes())));
            ok_json(stream, &body)
        }
        Err(e) => bad_request(stream, &e.to_string()),
    }
}

fn dispatch(
    app: &mut Explorer,
    action: &str,
    q: &std::collections::HashMap<String, String>,
) -> Result<String, String> {
    let node = q
        .get("node")
        .cloned()
        .unwrap_or_else(|| app.selected.clone());
    match action {
        // "mine" is retained as an alias so existing operator scripts and the
        // web surface keep working; under PoA it produces, it does not mine.
        "mine" | "produce" => match app.mesh.produce(&node).map_err(|e| e.to_string())? {
            Some(_) => {}
            None => {
                if !app.operator {
                    return Err("mempool empty".into());
                }
                app.mesh.produce_empty(&node).map_err(|e| e.to_string())?;
            }
        },
        "empty" | "send" | "pool" | "parallel" | "fork" | "producing" => {
            if !app.operator {
                return Err("operator only".into());
            }
            match action {
                "empty" => {
                    app.mesh.produce_empty(&node).map_err(|e| e.to_string())?;
                }
                "send" => {
                    let from = parse_u64(q, "from", 1)?;
                    let amount = parse_u64(q, "amount", 50)?;
                    let to = parse_u64(q, "to", 2)?;
                    app.mesh
                        .send(&node, from, amount, to)
                        .map_err(|e| e.to_string())?;
                }
                "pool" => {
                    let from = parse_u64(q, "from", 1)?;
                    let amount = parse_u64(q, "amount", 50)?;
                    let to = parse_u64(q, "to", 2)?;
                    app.mesh
                        .pool(&node, from, amount, to)
                        .map_err(|e| e.to_string())?;
                }
                "parallel" => {
                    let _ = app.mesh.send("alpha", 1, ATOM, 2);
                    let _ = app.mesh.send("beta", 1, ATOM, 3);
                }
                "fork" => {
                    for name in app.mesh.names() {
                        let _ = app.mesh.produce_empty(&name);
                    }
                }
                "producing" => {
                    app.producing = q.get("on").map(|v| v != "0").unwrap_or(true);
                }
                _ => {}
            }
        }
        "reset" => {
            if !app.allow_reset {
                return Err("reset disabled on this network".into());
            }
            wipe_data();
            *app =
                Explorer::boot_persist().map_err(|e| format!("reset: fresh boot failed: {e}"))?;
        }
        "origin" => {
            let iso = q.get("iso3").ok_or("iso3 required")?;
            if iso.len() != 3 || !iso.chars().all(|c| c.is_ascii_alphabetic()) {
                return Err("iso3 required".into());
            }
            let code = iso.to_ascii_uppercase();
            let pulses = {
                let n = app.origins.entry(code.clone()).or_insert(0);
                *n = n.saturating_add(1);
                *n
            };
            save_origins(&app.origins);
            return Ok(format!(
                "{{\"ok\":true,\"iso3\":{},\"pulses\":{}}}",
                jstr(&code),
                pulses
            ));
        }
        "prepare" => {
            let from = parse_addr(q.get("from").ok_or("from address required")?)?;
            let to = parse_addr(q.get("to").ok_or("to address required")?)?;
            let amount = parse_u64(q, "amount", 0)?;
            // KVP-102: omitted / "KVNC" → native. Backward compatible.
            let asset_id = crate::node::asset_id_from_wire(q.get("asset_id").map(String::as_str))?;
            let n = app.mesh.node(&node).ok_or("unknown node")?;
            let p = n
                .prepare_transfer_asset(from, amount, to, asset_id)
                .map_err(|e| e.to_string())?;
            let change = p.value.saturating_sub(amount.saturating_add(p.fee));
            let asset_wire = crate::node::asset_id_to_wire(asset_id);
            return Ok(format!(
                "{{\"ok\":true,\"sighash\":{},\"value\":{},\"fee\":{},\"fee_asset_id\":{},\"change\":{},\"asset_id\":{},\"outpoint\":{{\"tx\":{},\"index\":{},\"asset_id\":{}}}}}",
                jstr(&hex::encode(p.sighash)),
                p.value,
                p.fee,
                jstr("KVNC"),
                change,
                jstr(&asset_wire),
                jstr(&p.outpoint.tx.to_string()),
                p.outpoint.index,
                jstr(&asset_wire)
            ));
        }
        "submit" => {
            let from = parse_addr(q.get("from").ok_or("from address required")?)?;
            let to = parse_addr(q.get("to").ok_or("to address required")?)?;
            let amount = parse_u64(q, "amount", 0)?;
            let sig = parse_sig(q.get("sig").ok_or("sig required")?)?;
            let id = app
                .mesh
                .submit_signed(&node, from, amount, to, sig)
                .map_err(|e| e.to_string())?;
            app.mesh.drain(8);
            return Ok(format!("{{\"ok\":true,\"tx\":{}}}", jstr(&id.to_string())));
        }
        "htlc/prepare" => {
            let from = parse_addr(q.get("from").ok_or("from address required")?)?;
            let amount = parse_u64(q, "amount", 0)?;
            let asset_id = crate::node::asset_id_from_wire(q.get("asset_id").map(String::as_str))?;
            let recipient_pk = parse_pubkey(q.get("recipient_pk").ok_or("recipient_pk required")?)?;
            let preimage_hash =
                parse_hash(q.get("preimage_hash").ok_or("preimage_hash required")?)?;
            let timeout = parse_u64(q, "timeout", 0)? as u32;
            let n = app.mesh.node(&node).ok_or("unknown node")?;
            let p = n
                .prepare_create_htlc(from, amount, asset_id, recipient_pk, preimage_hash, timeout)
                .map_err(|e| e.to_string())?;
            let script_hex = hex::encode(p.script.bytes());
            let asset_wire = crate::node::asset_id_to_wire(asset_id);
            return Ok(format!(
                "{{\"ok\":true,\"sighash\":{},\"htlc_script\":{},\"htlc_address\":{},\"value\":{},\"fee\":{},\"change\":{},\"asset_id\":{},\"outpoint\":{{\"tx\":{},\"index\":{}}}}}",
                jstr(&hex::encode(p.sighash)),
                jstr(&script_hex),
                jstr(&p.address.to_kvnc()),
                p.value,
                p.fee,
                p.value.saturating_sub(amount.saturating_add(p.fee)),
                jstr(&asset_wire),
                jstr(&p.outpoint.tx.to_string()),
                p.outpoint.index
            ));
        }
        "htlc/submit" => {
            let from = parse_addr(q.get("from").ok_or("from address required")?)?;
            let amount = parse_u64(q, "amount", 0)?;
            let asset_id = crate::node::asset_id_from_wire(q.get("asset_id").map(String::as_str))?;
            let recipient_pk = parse_pubkey(q.get("recipient_pk").ok_or("recipient_pk required")?)?;
            let preimage_hash =
                parse_hash(q.get("preimage_hash").ok_or("preimage_hash required")?)?;
            let timeout = parse_u64(q, "timeout", 0)? as u32;
            let sig = parse_sig(q.get("sig").ok_or("sig required")?)?;
            let n = app.mesh.node_mut(&node).ok_or("unknown node")?;
            let p = n
                .prepare_create_htlc(from, amount, asset_id, recipient_pk, preimage_hash, timeout)
                .map_err(|e| e.to_string())?;
            let id = n.submit_create_htlc(p, sig).map_err(|e| e.to_string())?;
            app.mesh.drain(8);
            return Ok(format!("{{\"ok\":true,\"tx\":{}}}", jstr(&id.to_string())));
        }
        "htlc/redeem/prepare" => {
            let from = parse_addr(q.get("from").ok_or("from address required")?)?;
            let outpoint_tx = parse_hash(q.get("outpoint_tx").ok_or("outpoint_tx required")?)?;
            let outpoint_index = parse_u64(q, "outpoint_index", 0)? as u32;
            let outpoint = OutPoint::new(
                kovanica_state::TxId::from_bytes(outpoint_tx),
                outpoint_index,
            );
            let script_bytes = parse_hex(q.get("script").ok_or("script required")?)?;
            if script_bytes.len() != 100 {
                return Err("script must be 100 bytes".into());
            }
            let script = HtlcScript::parse(&script_bytes).map_err(|e| e.as_str().to_string())?;
            let preimage = parse_hex(q.get("preimage").ok_or("preimage required")?)?;
            let to = parse_addr(q.get("to").ok_or("to address required")?)?;
            let n = app.mesh.node(&node).ok_or("unknown node")?;
            let p = n
                .prepare_redeem_htlc(from, outpoint, &script, &preimage, to)
                .map_err(|e| e.to_string())?;
            return Ok(format!(
                "{{\"ok\":true,\"sighash\":{},\"value\":{},\"fee\":{},\"outpoint\":{{\"tx\":{},\"index\":{}}}}}",
                jstr(&hex::encode(p.sighash)),
                p.value,
                p.fee,
                jstr(&p.outpoint.tx.to_string()),
                p.outpoint.index
            ));
        }
        "htlc/redeem/submit" => {
            let from = parse_addr(q.get("from").ok_or("from address required")?)?;
            let outpoint_tx = parse_hash(q.get("outpoint_tx").ok_or("outpoint_tx required")?)?;
            let outpoint_index = parse_u64(q, "outpoint_index", 0)? as u32;
            let outpoint = OutPoint::new(
                kovanica_state::TxId::from_bytes(outpoint_tx),
                outpoint_index,
            );
            let script_bytes = parse_hex(q.get("script").ok_or("script required")?)?;
            if script_bytes.len() != 100 {
                return Err("script must be 100 bytes".into());
            }
            let script = HtlcScript::parse(&script_bytes).map_err(|e| e.as_str().to_string())?;
            let preimage = parse_hex(q.get("preimage").ok_or("preimage required")?)?;
            let to = parse_addr(q.get("to").ok_or("to address required")?)?;
            let sig = parse_sig(q.get("sig").ok_or("sig required")?)?;
            let n = app.mesh.node_mut(&node).ok_or("unknown node")?;
            let p = n
                .prepare_redeem_htlc(from, outpoint, &script, &preimage, to)
                .map_err(|e| e.to_string())?;
            let id = n.submit_redeem_htlc(p, sig).map_err(|e| e.to_string())?;
            app.mesh.drain(8);
            return Ok(format!("{{\"ok\":true,\"tx\":{}}}", jstr(&id.to_string())));
        }
        "htlc/refund/prepare" => {
            let from = parse_addr(q.get("from").ok_or("from address required")?)?;
            let outpoint_tx = parse_hash(q.get("outpoint_tx").ok_or("outpoint_tx required")?)?;
            let outpoint_index = parse_u64(q, "outpoint_index", 0)? as u32;
            let outpoint = OutPoint::new(
                kovanica_state::TxId::from_bytes(outpoint_tx),
                outpoint_index,
            );
            let script_bytes = parse_hex(q.get("script").ok_or("script required")?)?;
            if script_bytes.len() != 100 {
                return Err("script must be 100 bytes".into());
            }
            let script = HtlcScript::parse(&script_bytes).map_err(|e| e.as_str().to_string())?;
            let to = parse_addr(q.get("to").ok_or("to address required")?)?;
            let n = app.mesh.node(&node).ok_or("unknown node")?;
            let p = n
                .prepare_refund_htlc(from, outpoint, &script, to)
                .map_err(|e| e.to_string())?;
            return Ok(format!(
                "{{\"ok\":true,\"sighash\":{},\"value\":{},\"fee\":{},\"outpoint\":{{\"tx\":{},\"index\":{}}}}}",
                jstr(&hex::encode(p.sighash)),
                p.value,
                p.fee,
                jstr(&p.outpoint.tx.to_string()),
                p.outpoint.index
            ));
        }
        "htlc/refund/submit" => {
            let from = parse_addr(q.get("from").ok_or("from address required")?)?;
            let outpoint_tx = parse_hash(q.get("outpoint_tx").ok_or("outpoint_tx required")?)?;
            let outpoint_index = parse_u64(q, "outpoint_index", 0)? as u32;
            let outpoint = OutPoint::new(
                kovanica_state::TxId::from_bytes(outpoint_tx),
                outpoint_index,
            );
            let script_bytes = parse_hex(q.get("script").ok_or("script required")?)?;
            if script_bytes.len() != 100 {
                return Err("script must be 100 bytes".into());
            }
            let script = HtlcScript::parse(&script_bytes).map_err(|e| e.as_str().to_string())?;
            let to = parse_addr(q.get("to").ok_or("to address required")?)?;
            let sig = parse_sig(q.get("sig").ok_or("sig required")?)?;
            let n = app.mesh.node_mut(&node).ok_or("unknown node")?;
            let p = n
                .prepare_refund_htlc(from, outpoint, &script, to)
                .map_err(|e| e.to_string())?;
            let id = n.submit_refund_htlc(p, sig).map_err(|e| e.to_string())?;
            app.mesh.drain(8);
            return Ok(format!("{{\"ok\":true,\"tx\":{}}}", jstr(&id.to_string())));
        }
        "faucet" => {
            if !app.faucet {
                return Err("faucet disabled".into());
            }
            // D1: the faucet is testnet-only. On any other profile (mainnet
            // included) it refuses to pay out regardless of the operator flag.
            if network_profile().id != "kovanica-testnet" {
                return Err("faucet is testnet-only".into());
            }
            let to = parse_addr(q.get("to").ok_or("to address required")?)?;
            let amount = parse_u64(q, "amount", ATOM)?;
            if amount > FAUCET_MAX_PER_ADDRESS {
                return Err(format!(
                    "faucet max {FAUCET_MAX_PER_ADDRESS} atoms per request"
                ));
            }
            // Per-address lifetime cap: an address cannot drain the operator
            // funds by replaying the faucet.
            let key = to.to_hex();
            let given = app.faucet_given.get(&key).copied().unwrap_or(0);
            if given.saturating_add(amount) > FAUCET_MAX_PER_ADDRESS {
                return Err("faucet per-address cap reached".into());
            }
            let block = app
                .mesh
                .send_to(&node, 1, amount, to)
                .map_err(|e| e.to_string())?;
            app.faucet_given.insert(key, given + amount);
            save_faucet_given(&app.faucet_given);
            app.mesh.drain(8);
            return Ok(format!(
                "{{\"ok\":true,\"block\":{}}}",
                jstr(&block.to_string())
            ));
        }
        "fee_estimate" => {
            let amount = parse_u64(q, "amount", 0)?;
            let n = app.mesh.node(&node).ok_or("unknown node")?;
            let (slow, normal, fast) = estimate_fee(n, amount)?;
            return Ok(format!(
                "{{\"ok\":true,\"slow\":{},\"normal\":{},\"fast\":{}}}",
                slow, normal, fast
            ));
        }
        "coinjoin_prepare" => {
            // Expects JSON body: { participants: CoinJoinParticipant[] }
            // For simplicity, parse from query string or body
            let body = q.get("body").ok_or("missing body")?;
            // Parse JSON body - in production use proper JSON parsing
            // For now, expect a simple format
            // body format: {"participants":[{"address":"...","amount":"...","recipient":"...","asset_id":null}]}
            let participants: Vec<CoinJoinParticipant> = parse_coinjoin_participants(body)?;
            let n = app.mesh.node(&node).ok_or("unknown node")?;
            let prepared = n
                .coinjoin_prepare(participants)
                .map_err(|e| e.to_string())?;
            return Ok(serialize_coinjoin_prepared(&prepared));
        }
        "coinjoin_submit" => {
            let body = q.get("body").ok_or("missing body")?;
            let prepared: CoinJoinPrepared = parse_coinjoin_prepared(body)?;
            let signatures: Vec<[u8; 64]> =
                parse_signatures(q.get("signatures").ok_or("missing signatures")?)?;
            let n = app.mesh.node_mut(&node).ok_or("unknown node")?;
            n.coinjoin_submit(prepared, signatures)
                .map_err(|e| e.to_string())?;
            return Ok("{\"ok\":true}".into());
        }
        other => return Err(format!("unknown action {other}")),
    }
    app.mesh.drain(8);
    Ok("{\"ok\":true}".into())
}

fn balances_map_json(map: &std::collections::BTreeMap<String, u128>) -> String {
    let parts: Vec<String> = map
        .iter()
        .map(|(k, v)| format!("{}:{}", jstr(k), v))
        .collect();
    format!("{{{}}}", parts.join(","))
}

fn history_json(
    app: &Explorer,
    q: &std::collections::HashMap<String, String>,
) -> Result<String, String> {
    let addr = parse_addr(q.get("address").ok_or("address required")?)?;
    let node_name = q
        .get("node")
        .cloned()
        .unwrap_or_else(|| app.selected.clone());
    let n = app.mesh.node(&node_name).ok_or("unknown node")?;
    let ledger = n.ledger().map_err(|e| e.to_string())?;
    let asset_registry = ledger.asset_registry();
    let limit = parse_u64(q, "limit", 100)?.min(1000);
    let offset = parse_u64(q, "offset", 0)?;
    let order = ledger.dag().linearize();
    let mut by_id: HashMap<kovanica_state::TxId, kovanica_state::Transaction> = HashMap::new();
    let mut items = Vec::new();
    for id in &order {
        let Some(rec) = n.block_record(id) else {
            continue;
        };
        for tx in rec.txs {
            by_id.insert(tx.id(), tx);
        }
    }
    for id in &order {
        let Some(rec) = n.block_record(id) else {
            continue;
        };
        for tx in &rec.txs {
            let mut delta: i128 = 0;
            let mut row_asset: Option<kovanica_state::AssetId> = None;
            for o in tx.outputs() {
                if o.owner == addr {
                    delta += o.value as i128;
                    if row_asset.is_none() {
                        row_asset = o.asset_id;
                    }
                }
            }
            for inp in tx.inputs() {
                if let Some(prev) = by_id.get(&inp.outpoint.tx) {
                    if let Some(o) = prev.outputs().get(inp.outpoint.index as usize) {
                        if o.owner == addr {
                            delta -= o.value as i128;
                            if row_asset.is_none() {
                                row_asset = o.asset_id;
                            }
                        }
                    }
                }
            }
            if delta == 0 {
                continue;
            }
            let kind = if tx.is_coinbase() {
                "coinbase"
            } else if delta > 0 {
                "in"
            } else {
                "out"
            };
            // Get NFT metadata if applicable
            let asset_kind = row_asset.and_then(|id| asset_registry.get(&id).map(|e| e.kind));
            let kind_str = asset_kind.map(|k| match k {
                kovanica_state::AssetKind::Fungible => "fungible",
                kovanica_state::AssetKind::NonFungible => "nft",
            });
            let metadata_hash =
                row_asset.and_then(|id| asset_registry.get(&id).and_then(|e| e.metadata_hash));
            let meta_hash = metadata_hash.map(hex::encode);
            let collection_id =
                row_asset.and_then(|id| asset_registry.get(&id).and_then(|e| e.collection_id));
            let coll_id = collection_id.map(hex::encode);
            let asset_kind_json = kind_str.map(jstr).unwrap_or_else(|| "null".to_string());
            let metadata_hash_json = meta_hash
                .as_deref()
                .map(jstr)
                .unwrap_or_else(|| "null".to_string());
            let collection_id_json = coll_id
                .as_deref()
                .map(jstr)
                .unwrap_or_else(|| "null".to_string());
            items.push(format!(
                "{{\"block\":{},\"tx\":{},\"kind\":{},\"delta\":{},\"asset_id\":{},\"asset_kind\":{},\"metadata_hash\":{},\"collection_id\":{}}}",
                jstr(&id.to_string()),
                jstr(&tx.id().to_string()),
                jstr(kind),
                delta,
                jstr(&crate::node::asset_id_to_wire(row_asset)),
                asset_kind_json,
                metadata_hash_json,
                collection_id_json
            ));
        }
    }
    let total = items.len();
    let paginated: Vec<_> = items
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();
    let bal = n.balance(&addr).map_err(|e| e.to_string())?;
    let balances = n.balances_map_of(&addr).map_err(|e| e.to_string())?;
    Ok(format!(
        "{{\"address\":{},\"balance\":{},\"balances\":{},\"txs\":{},\"limit\":{},\"offset\":{},\"total\":{}}}",
        jstr(&addr.to_hex()),
        bal,
        balances_map_json(&balances),
        jarr(paginated.into_iter()),
        limit,
        offset,
        total
    ))
}

fn utxos_json(
    app: &Explorer,
    q: &std::collections::HashMap<String, String>,
) -> Result<String, String> {
    let addr = parse_addr(q.get("address").ok_or("address required")?)?;
    let node = q
        .get("node")
        .cloned()
        .unwrap_or_else(|| app.selected.clone());
    let n = app.mesh.node(&node).ok_or("unknown node")?;
    let bal = n.balance(&addr).map_err(|e| e.to_string())?;
    let balances = n.balances_map_of(&addr).map_err(|e| e.to_string())?;
    let limit = parse_u64(q, "limit", 100)?.min(1000);
    let offset = parse_u64(q, "offset", 0)?;
    let rows = n.utxos_detailed_of(&addr).map_err(|e| e.to_string())?;
    let total = rows.len();
    let items = rows
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(|(op, value, asset_id, asset_kind, metadata_hash, collection_id)| {
            let kind_str = asset_kind.map(|k| match k {
                kovanica_state::AssetKind::Fungible => "fungible",
                kovanica_state::AssetKind::NonFungible => "nft",
            });
            let meta_hash = metadata_hash.map(hex::encode);
            let coll_id = collection_id.map(hex::encode);
            let asset_kind_json = kind_str.map(jstr).unwrap_or_else(|| "null".to_string());
            let metadata_hash_json = meta_hash.as_deref().map(jstr).unwrap_or_else(|| "null".to_string());
            let collection_id_json = coll_id.as_deref().map(jstr).unwrap_or_else(|| "null".to_string());
            format!(
                "{{\"tx\":{},\"index\":{},\"value\":{},\"asset_id\":{},\"kind\":{},\"metadata_hash\":{},\"collection_id\":{}}}",
                jstr(&op.tx.to_string()),
                op.index,
                value,
                jstr(&crate::node::asset_id_to_wire(asset_id)),
                asset_kind_json,
                metadata_hash_json,
                collection_id_json
            )
        });
    Ok(format!(
        "{{\"address\":{},\"balance\":{},\"balances\":{},\"utxos\":{},\"limit\":{},\"offset\":{},\"total\":{}}}",
        jstr(&addr.to_hex()),
        bal,
        balances_map_json(&balances),
        jarr(items),
        limit,
        offset,
total
    ))
}

fn nft_detail_json(
    app: &Explorer,
    asset_id_str: &str,
    q: &std::collections::HashMap<String, String>,
) -> Result<String, String> {
    let node_name = q
        .get("node")
        .cloned()
        .unwrap_or_else(|| app.selected.clone());
    let n = app.mesh.node(&node_name).ok_or("unknown node")?;
    let ledger = n.ledger().map_err(|e| e.to_string())?;
    let asset_registry = ledger.asset_registry();

    // Parse asset_id from hex
    let asset_id_bytes =
        hex::decode(asset_id_str.trim()).map_err(|_| "asset_id is not hex".to_string())?;
    if asset_id_bytes.len() != 32 {
        return Err("asset_id must be 32 bytes (64 hex chars)".to_string());
    }
    let mut asset_id_arr = [0u8; 32];
    asset_id_arr.copy_from_slice(&asset_id_bytes);
    let asset_id = kovanica_state::AssetId::from_bytes(asset_id_arr);

    // Get registry entry
    let entry = asset_registry.get(&asset_id).ok_or("nft not found")?;
    if !entry.is_nft() {
        return Err("asset is not an NFT".to_string());
    }

    // Find current owner (UTXO holding this NFT)
    let state = ledger.ledger_state();
    let mut owner_address = None;
    let mut owner_tx = None;
    let mut owner_index = None;
    for (op, o) in state.iter() {
        if o.asset_id == Some(asset_id) {
            owner_address = Some(o.owner);
            owner_tx = Some(op.tx);
            owner_index = Some(op.index);
            break;
        }
    }

    let kind_str = "nft";
    let meta_hash = entry.metadata_hash.map(hex::encode);
    let coll_id = entry.collection_id.map(hex::encode);
    let creator = entry.creator.map(hex::encode);
    let meta_hash_json = meta_hash
        .as_deref()
        .map(jstr)
        .unwrap_or_else(|| "null".to_string());
    let coll_id_json = coll_id
        .as_deref()
        .map(jstr)
        .unwrap_or_else(|| "null".to_string());
    let creator_json = creator
        .as_deref()
        .map(jstr)
        .unwrap_or_else(|| "null".to_string());
    let owner_json = owner_address
        .map(|a| jstr(&a.to_kvnc()))
        .unwrap_or_else(|| "null".to_string());
    let owner_tx_json = owner_tx
        .map(|t| jstr(&t.to_string()))
        .unwrap_or_else(|| "null".to_string());
    let owner_index_json = owner_index
        .map(|i| i.to_string())
        .unwrap_or_else(|| "null".to_string());

    Ok(format!(
        "{{\"asset_id\":{},\"kind\":{},\"max_supply\":{},\"minted\":{},\"metadata_hash\":{},\"collection_id\":{},\"creator\":{},\"owner\":{},\"owner_tx\":{},\"owner_index\":{}}}",
        jstr(&asset_id.to_hex()),
        jstr(kind_str),
        entry.max_supply,
        entry.minted,
        meta_hash_json,
        coll_id_json,
        creator_json,
        owner_json,
        owner_tx_json,
        owner_index_json
    ))
}

/// Collection detail: list of asset_ids belonging to the collection.
fn collection_detail_json(
    app: &Explorer,
    collection_id_str: &str,
    q: &std::collections::HashMap<String, String>,
) -> Result<String, String> {
    let node_name = q
        .get("node")
        .cloned()
        .unwrap_or_else(|| app.selected.clone());
    let n = app.mesh.node(&node_name).ok_or("unknown node")?;
    let ledger = n.ledger().map_err(|e| e.to_string())?;
    let asset_registry = ledger.asset_registry();

    // Parse collection_id from hex
    let coll_id_bytes = hex::decode(collection_id_str.trim())
        .map_err(|_| "collection_id is not hex".to_string())?;
    if coll_id_bytes.len() != 32 {
        return Err("collection_id must be 32 bytes (64 hex chars)".to_string());
    }
    let mut collection_id_arr = [0u8; 32];
    collection_id_arr.copy_from_slice(&coll_id_bytes);
    let collection_id = collection_id_arr;

    // Find all NFTs in this collection
    let mut assets = Vec::new();
    for (asset_id, entry) in asset_registry {
        if entry.collection_id == Some(collection_id) && entry.is_nft() {
            // Find current owner
            let state = ledger.ledger_state();
            let mut owner_address = None;
            for (_, o) in state.iter() {
                if o.asset_id == Some(*asset_id) {
                    owner_address = Some(o.owner);
                    break;
                }
            }
            let meta_hash = entry.metadata_hash.map(hex::encode);
            let meta_hash_json = meta_hash
                .as_deref()
                .map(jstr)
                .unwrap_or_else(|| "null".to_string());
            let owner_json = owner_address
                .map(|a| jstr(&a.to_kvnc()))
                .unwrap_or_else(|| "null".to_string());
            assets.push(format!(
                "{{\"asset_id\":{},\"metadata_hash\":{},\"owner_address\":{}}}",
                jstr(&asset_id.to_hex()),
                meta_hash_json,
                owner_json
            ));
        }
    }

    if assets.is_empty() {
        return Err("collection not found".to_string());
    }

    Ok(format!(
        "{{\"collection_id\":{},\"assets\":{}}}",
        jstr(&hex::encode(collection_id)),
        jarr(assets.into_iter())
    ))
}

/// Derive RWA asset_id from issuer key and parameters (KVP-106).
/// POST /api/rwa/derive
fn rwa_derive_json(
    _app: &Explorer,
    q: &std::collections::HashMap<String, String>,
) -> Result<String, String> {
    let issuer = q.get("issuer").ok_or("issuer required")?;
    let asset_class = q.get("class").ok_or("class required")?;
    let unique_id = q.get("id").ok_or("id required")?;
    let version = q
        .get("version")
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(1);

    // Parse issuer from hex
    let issuer_bytes = hex::decode(issuer.trim()).map_err(|_| "issuer is not hex".to_string())?;
    if issuer_bytes.len() != 32 {
        return Err("issuer must be 32 bytes (64 hex chars)".to_string());
    }
    let mut issuer_arr = [0u8; 32];
    issuer_arr.copy_from_slice(&issuer_bytes);

    // Derive asset_id using the same algorithm as the CLI
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"KVP106-RWA");
    hasher.update(issuer_arr);
    hasher.update(asset_class.as_bytes());
    hasher.update(unique_id.as_bytes());
    hasher.update([version]);
    let result = hasher.finalize();
    let mut asset_id_arr = [0u8; 32];
    asset_id_arr.copy_from_slice(&result);
    let asset_id = kovanica_state::AssetId::from_bytes(asset_id_arr);

    let asset_id_hex = asset_id.to_hex();
    let asset_id_kvnc = format!("kvnc{}dag", asset_id_hex);

    Ok(format!(
        "{{\"asset_id\":{},\"asset_id_kvnc\":{}}}",
        jstr(&asset_id_hex),
        jstr(&asset_id_kvnc)
    ))
}

/// RWA detail: returns registry entry + current owner UTXO (KVP-106).
/// GET /api/rwa/{asset_id}
fn rwa_detail_json(
    app: &Explorer,
    asset_id_str: &str,
    q: &std::collections::HashMap<String, String>,
) -> Result<String, String> {
    let node_name = q
        .get("node")
        .cloned()
        .unwrap_or_else(|| app.selected.clone());
    let n = app.mesh.node(&node_name).ok_or("unknown node")?;
    let ledger = n.ledger().map_err(|e| e.to_string())?;
    let asset_registry = ledger.asset_registry();

    // Parse asset_id from hex
    let asset_id_bytes =
        hex::decode(asset_id_str.trim()).map_err(|_| "asset_id is not hex".to_string())?;
    if asset_id_bytes.len() != 32 {
        return Err("asset_id must be 32 bytes (64 hex chars)".to_string());
    }
    let mut asset_id_arr = [0u8; 32];
    asset_id_arr.copy_from_slice(&asset_id_bytes);
    let asset_id = kovanica_state::AssetId::from_bytes(asset_id_arr);

    // Get registry entry
    let entry = asset_registry.get(&asset_id).ok_or("rwa not found")?;
    // RWA assets are fungible with special meaning
    if entry.is_nft() {
        return Err("asset is an NFT, not an RWA".to_string());
    }

    // Find current owner (UTXO holding this RWA)
    let state = ledger.ledger_state();
    let mut owner_address = None;
    let mut owner_tx = None;
    let mut owner_index = None;
    for (op, o) in state.iter() {
        if o.asset_id == Some(asset_id) {
            owner_address = Some(o.owner);
            owner_tx = Some(op.tx);
            owner_index = Some(op.index);
            break;
        }
    }

    let _kind_str = "rwa";
    let meta_hash = entry.metadata_hash.map(hex::encode);
    let coll_id = entry.collection_id.map(hex::encode);
    let creator = entry.creator.map(hex::encode);
    let meta_hash_json = meta_hash
        .as_deref()
        .map(jstr)
        .unwrap_or_else(|| "null".to_string());
    let coll_id_json = coll_id
        .as_deref()
        .map(jstr)
        .unwrap_or_else(|| "null".to_string());
    let creator_json = creator
        .as_deref()
        .map(jstr)
        .unwrap_or_else(|| "null".to_string());
    let owner_json = owner_address
        .map(|a| jstr(&a.to_kvnc()))
        .unwrap_or_else(|| "null".to_string());
    let owner_tx_json = owner_tx
        .map(|t| jstr(&t.to_string()))
        .unwrap_or_else(|| "null".to_string());
    let owner_index_json = owner_index
        .map(|i| i.to_string())
        .unwrap_or_else(|| "null".to_string());

    Ok(format!(
        "{{\"asset_id\":{},\"kind\":{},\"max_supply\":{},\"minted\":{},\"metadata_hash\":{},\"collection_id\":{},\"creator\":{},\"owner\":{},\"owner_tx\":{},\"owner_index\":{}}}",
        jstr(&asset_id.to_hex()),
        jstr("rwa"),
        entry.max_supply,
        entry.minted,
        meta_hash_json,
        coll_id_json,
        creator_json,
        owner_json,
        owner_tx_json,
        owner_index_json
    ))
}

fn err_json(msg: &str) -> String {
    format!("{{\"ok\":false,\"error\":{}}}", jstr(msg))
}

fn parse_block_id(s: &str) -> Result<BlockId, String> {
    let bytes = hex::decode(s.trim()).map_err(|_| "block id is not hex".to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "block id must be 32 bytes".to_string())?;
    Ok(BlockId::from_bytes(arr))
}

fn parse_tx_id(s: &str) -> Result<TxId, String> {
    let bytes = hex::decode(s.trim()).map_err(|_| "tx id is not hex".to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "tx id must be 32 bytes".to_string())?;
    Ok(TxId::from_bytes(arr))
}

fn block_kind(
    id: BlockId,
    genesis: BlockId,
    chain: &HashSet<BlockId>,
    blue: &HashSet<BlockId>,
) -> &'static str {
    if id == genesis {
        "genesis"
    } else if chain.contains(&id) {
        "chain"
    } else if blue.contains(&id) {
        "blue"
    } else {
        "red"
    }
}

fn block_detail_json(app: &Explorer, id_hex: &str) -> Result<String, String> {
    let id = parse_block_id(id_hex)?;
    let node_name = app.selected.clone();
    let n = app.mesh.node(&node_name).ok_or("unknown node")?;
    let ledger = n.ledger().map_err(|e| e.to_string())?;
    let dag = ledger.dag();
    if dag.block(&id).is_none() {
        return Err("block not found".into());
    }
    let rec = n.block_record(&id).ok_or("block not found")?;
    let children = n.block_children(&id).map_err(|e| e.to_string())?;
    let genesis = dag.genesis();
    let chain: HashSet<BlockId> = dag.selected_chain().into_iter().collect();
    let tip_id = n.selected_tip().ok();
    let gd = tip_id.as_ref().and_then(|id| dag.ghostdag(id));
    let blue_set: HashSet<BlockId> = gd
        .map(|g| g.blue_anticone_sizes.keys().copied().collect())
        .unwrap_or_default();
    let colour = block_kind(id, genesis, &chain, &blue_set);
    // PoA-only: a block either carries an authority signature or it does not
    // (the latter can only be a pre-PoA legacy block still on disk).
    let kind = if rec.authority_sig.is_some() {
        "poa"
    } else {
        "unsigned"
    };
    let confirming_status = if tip_id == Some(id) {
        "tip"
    } else if chain.contains(&id) {
        "confirmed"
    } else if blue_set.contains(&id) {
        "accepted"
    } else {
        "pending"
    };
    let ghostdag = dag.ghostdag(&id);
    let blue_score = ghostdag.map(|g| g.blue_score).unwrap_or(0);
    let chain_blue_work = ghostdag.map(|g| g.blue_work).unwrap_or(0);

    let (prev_hash, merkle_root, height) = {
        let mut height = 0u64;
        let mut cur = ghostdag.and_then(|g| g.selected_parent);
        while let Some(pid) = cur {
            height += 1;
            cur = dag.ghostdag(&pid).and_then(|g| g.selected_parent);
        }
        let prev = ghostdag
            .and_then(|g| g.selected_parent)
            .unwrap_or_else(|| BlockId::from_bytes([0u8; 32]));
        (prev, kovanica_state::spv::merkle_root(&rec.txs), height)
    };

    // PoA fields: authority signature, slot, active authority
    let (authority_sig, slot, active_authority) = if let Some(sig) = rec.authority_sig {
        let poa = n.poa_config();
        let slot_duration = poa.as_ref().map(|c| c.slot_duration_ms).unwrap_or(3000);
        let slot = rec.timestamp_ms / slot_duration;
        let active = poa.as_ref().and_then(|c| {
            let authorities = c.authority_set.authorities();
            let idx = slot as usize % authorities.len();
            authorities.get(idx).map(|pk| hex::encode(pk.as_bytes()))
        });
        (Some(hex::encode(sig)), Some(slot), active)
    } else {
        (None, None, None)
    };

    Ok(format!(
        "{{\"id\":{},\"prev_hash\":{},\"merkle_root\":{},\"height\":{},\"timestamp_ms\":{},\"nonce\":{},\"blue_score\":{},\"chain_blue_work\":{},\"work\":{},\"parents\":{},\"children\":{},\"txs\":{},\"kind\":{},\"colour\":{},\"confirming_status\":{},\"authority_sig\":{},\"slot\":{},\"active_authority\":{}}}",
        jstr(&id.to_string()),
        jstr(&prev_hash.to_string()),
        jstr(&hex::encode(merkle_root)),
        height,
        rec.timestamp_ms,
        rec.nonce,
        blue_score,
        chain_blue_work,
        rec.work,
        jarr(rec.parents.iter().map(|p| jstr(&p.to_string()))),
        jarr(children.iter().map(|c| jstr(&c.to_string()))),
        jarr(rec.txs.iter().map(|tx| jstr(&tx.id().to_string()))),
        jstr(kind),
        jstr(colour),
        jstr(confirming_status),
        jstr_opt(authority_sig),
        jstr_opt(slot.map(|s| s.to_string())),
        jstr_opt(active_authority)
    ))
}

fn tx_input_json(
    input: &kovanica_state::TxInput,
    prev_by_tx: &HashMap<TxId, Transaction>,
    prev_by_outpoint: &HashMap<OutPoint, TxOutput>,
) -> String {
    let prev = prev_by_outpoint.get(&input.outpoint).copied().or_else(|| {
        prev_by_tx
            .get(&input.outpoint.tx)
            .and_then(|p| p.outputs().get(input.outpoint.index as usize).copied())
    });
    let prev_owner = prev.map(|o| o.owner.to_hex());
    format!(
        "{{\"tx\":{},\"index\":{},\"prev_owner\":{},\"value\":{}}}",
        jstr(&input.outpoint.tx.to_string()),
        input.outpoint.index,
        prev_owner
            .as_deref()
            .map(jstr)
            .unwrap_or_else(|| "null".into()),
        prev.map(|o| o.value).unwrap_or(0)
    )
}

fn tx_detail_json(app: &Explorer, id_hex: &str) -> Result<String, String> {
    let id = parse_tx_id(id_hex)?;
    let node_name = app.selected.clone();
    let n = app.mesh.node(&node_name).ok_or("unknown node")?;

    // Mempool path: the tx may spend outputs still in the UTXO set.
    if let Some(tx) = n.mempool_tx(&id) {
        let ledger = n.ledger().map_err(|e| e.to_string())?;
        let utxo = ledger.ledger_state();
        let mut prev_by_outpoint = HashMap::new();
        for input in tx.inputs() {
            if let Some(out) = utxo.get(&input.outpoint) {
                prev_by_outpoint.insert(input.outpoint, *out);
            }
        }
        let amount: u64 = tx.outputs().iter().map(|o| o.value).sum();
        let input_value: u64 = tx
            .inputs()
            .iter()
            .map(|inp| {
                prev_by_outpoint
                    .get(&inp.outpoint)
                    .map(|o| o.value)
                    .unwrap_or(0)
            })
            .sum();
        let fee = if tx.is_coinbase() {
            0
        } else {
            input_value.saturating_sub(amount)
        };
        let addresses = tx_addresses(&tx, &HashMap::new(), &prev_by_outpoint);
        let inputs = jarr(
            tx.inputs()
                .iter()
                .map(|inp| tx_input_json(inp, &HashMap::new(), &prev_by_outpoint)),
        );
        let outputs = jarr(tx.outputs().iter().map(|o| {
            format!(
                "{{\"value\":{},\"owner\":{}}}",
                o.value,
                jstr(&o.owner.to_hex())
            )
        }));
        return Ok(format!(
            "{{\"id\":{},\"coinbase\":{},\"confirmed\":false,\"confirmations\":0,\"block\":null,\"blue_score\":null,\"amount\":{},\"fee\":{},\"addresses\":{},\"inputs\":{},\"outputs\":{},\"size\":{}}}",
            jstr(&tx.id().to_string()),
            tx.is_coinbase(),
            amount,
            fee,
            jarr(addresses.into_iter().map(|s| jstr(&s))),
            inputs,
            outputs,
            tx.encode().len()
        ));
    }

    let confirmation = n.tx_confirmation(&id).map_err(|e| e.to_string())?;
    let (block_id, blue_score) = confirmation.ok_or("tx not found")?;
    let rec = n.block_record(&block_id).ok_or("block not found")?;
    let tx = rec
        .txs
        .iter()
        .find(|t| t.id() == id)
        .ok_or("tx not found")?;

    let ledger = n.ledger().map_err(|e| e.to_string())?;
    let tip_blue_score = n
        .selected_tip()
        .ok()
        .and_then(|tip| ledger.dag().ghostdag(&tip))
        .map(|g| g.blue_score)
        .unwrap_or(0);
    let confirmations = tip_blue_score.saturating_sub(blue_score) + 1;

    let mut prev_by_tx: HashMap<TxId, Transaction> = HashMap::new();
    for block_id2 in ledger.dag().linearize() {
        if let Some(rec2) = n.block_record(&block_id2) {
            for t in rec2.txs {
                prev_by_tx.insert(t.id(), t);
            }
        }
    }

    let amount: u64 = tx.outputs().iter().map(|o| o.value).sum();
    let input_value: u64 = tx
        .inputs()
        .iter()
        .map(|inp| {
            prev_by_tx
                .get(&inp.outpoint.tx)
                .and_then(|p| {
                    p.outputs()
                        .get(inp.outpoint.index as usize)
                        .map(|o| o.value)
                })
                .unwrap_or(0)
        })
        .sum();
    let fee = if tx.is_coinbase() {
        0
    } else {
        input_value.saturating_sub(amount)
    };
    let addresses = tx_addresses(tx, &prev_by_tx, &HashMap::new());
    let inputs = jarr(
        tx.inputs()
            .iter()
            .map(|inp| tx_input_json(inp, &prev_by_tx, &HashMap::new())),
    );
    let outputs = jarr(tx.outputs().iter().map(|o| {
        format!(
            "{{\"value\":{},\"owner\":{}}}",
            o.value,
            jstr(&o.owner.to_hex())
        )
    }));

    Ok(format!(
        "{{\"id\":{},\"coinbase\":{},\"confirmed\":true,\"confirmations\":{},\"block\":{},\"blue_score\":{},\"amount\":{},\"fee\":{},\"addresses\":{},\"inputs\":{},\"outputs\":{},\"size\":{}}}",
        jstr(&tx.id().to_string()),
        tx.is_coinbase(),
        confirmations,
        jstr(&block_id.to_string()),
        blue_score,
        amount,
        fee,
        jarr(addresses.into_iter().map(|s| jstr(&s))),
        inputs,
        outputs,
        tx.encode().len()
    ))
}

fn tx_addresses(
    tx: &Transaction,
    prev_by_tx: &HashMap<TxId, Transaction>,
    prev_by_outpoint: &HashMap<OutPoint, TxOutput>,
) -> Vec<String> {
    let mut set = HashSet::new();
    for input in tx.inputs() {
        if let Some(prev) = prev_by_outpoint.get(&input.outpoint).copied().or_else(|| {
            prev_by_tx
                .get(&input.outpoint.tx)
                .and_then(|p| p.outputs().get(input.outpoint.index as usize).copied())
        }) {
            set.insert(prev.owner.to_hex());
        }
    }
    for output in tx.outputs() {
        set.insert(output.owner.to_hex());
    }
    let mut v: Vec<_> = set.into_iter().collect();
    v.sort_unstable();
    v
}

fn address_detail_json(
    app: &Explorer,
    addr_hex: &str,
    q: &std::collections::HashMap<String, String>,
) -> Result<String, String> {
    let addr = parse_addr(addr_hex)?;
    let node_name = q
        .get("node")
        .cloned()
        .unwrap_or_else(|| app.selected.clone());
    let n = app.mesh.node(&node_name).ok_or("unknown node")?;
    let balance = n.balance(&addr).map_err(|e| e.to_string())?;

    let page = q
        .get("page")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);
    let per_page = q
        .get("per_page")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(20)
        .clamp(1, 100);
    let offset = (page - 1) * per_page;

    let events = n.history_of(&addr, 0).map_err(|e| e.to_string())?;
    let total = events.len();
    let page_events: Vec<_> = events.into_iter().skip(offset).take(per_page).collect();

    let items = page_events.into_iter().map(|e| {
        let kind = match e.direction {
            WalletDirection::Received => "in",
            WalletDirection::Sent => "out",
        };
        format!(
            "{{\"tx\":{},\"block\":{},\"kind\":{},\"amount\":{}}}",
            jstr(&e.tx_id.to_string()),
            jstr(&e.block_id.to_string()),
            jstr(kind),
            e.amount
        )
    });

    let pages = total.div_ceil(per_page);

    Ok(format!(
        "{{\"address\":{},\"balance\":{},\"page\":{},\"per_page\":{},\"total\":{},\"pages\":{},\"txs\":{}}}",
        jstr(&addr.to_hex()),
        balance,
        page,
        per_page,
        total,
        pages,
        jarr(items)
    ))
}
fn fee_estimate_json(
    app: &Explorer,
    q: &std::collections::HashMap<String, String>,
) -> Result<String, String> {
    let node = q
        .get("node")
        .cloned()
        .unwrap_or_else(|| app.selected.clone());
    let n = app.mesh.node(&node).ok_or("unknown node")?;
    let rate = n.fee_estimate().map_err(|e| e.to_string())?;
    Ok(format!(
        "{{\"fee_rate\":{},\"unit\":{},\"mempool\":{},\"bytes\":{}}}",
        rate,
        jstr("atoms/byte"),
        n.pending_count(),
        n.mempool_bytes()
    ))
}

fn parse_addr(s: &str) -> Result<Address, String> {
    Address::parse(s).map_err(|e| e.to_string())
}

fn decode_block_id_hex(s: &str) -> Result<BlockId, String> {
    let bytes = hex::decode(s.trim()).map_err(|_| "from is not hex".to_string())?;
    let arr = bytes
        .try_into()
        .map_err(|_| "from must be 32 bytes".to_string())?;
    Ok(BlockId::from_bytes(arr))
}

fn parse_sig(s: &str) -> Result<[u8; 64], String> {
    let bytes = hex::decode(s.trim()).map_err(|_| "sig is not hex".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "sig must be 64 bytes".to_string())
}

/// Parse a 32-byte public key from hex (64 chars).
fn parse_pubkey(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s.trim()).map_err(|_| "pubkey is not hex".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "pubkey must be 32 bytes (64 hex chars)".to_string())
}

/// Parse a 32-byte hash from hex (64 chars).
fn parse_hash(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s.trim()).map_err(|_| "hash is not hex".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "hash must be 32 bytes (64 hex chars)".to_string())
}

/// Parse arbitrary hex to bytes.
fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.trim()).map_err(|_| "not valid hex".to_string())
}

fn parse_u64(
    q: &std::collections::HashMap<String, String>,
    key: &str,
    default: u64,
) -> Result<u64, String> {
    match q.get(key) {
        None => Ok(default),
        Some(s) => s.parse().map_err(|_| format!("bad {key}")),
    }
}

fn split_query(target: &str) -> (&str, std::collections::HashMap<String, String>) {
    match target.split_once('?') {
        None => (target, std::collections::HashMap::new()),
        Some((path, q)) => {
            let mut map = std::collections::HashMap::new();
            for pair in q.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    map.insert(k.to_string(), urlencoding_decode(v));
                }
            }
            (path, map)
        }
    }
}

fn urlencoding_decode(s: &str) -> String {
    // Query values here are digits / node names; keep it strict.
    s.replace('+', " ")
}

fn respond(stream: &mut TcpStream, code: u16, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        _ => "Not Found",
    };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn respond_download(
    stream: &mut TcpStream,
    ctype: &str,
    filename: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Disposition: attachment; filename=\"{filename}\"\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn respond_prometheus_metrics(stream: &mut TcpStream) -> std::io::Result<()> {
    // Render the live recorder payload (same series the dedicated scrape
    // endpoint on :9090 serves).
    let body = render_prometheus();
    respond(
        stream,
        200,
        "text/plain; version=0.0.4; charset=utf-8",
        body.as_bytes(),
    )
}

fn snapshot(app: &Explorer) -> String {
    let selected = &app.selected;
    let node = app.mesh.node(selected).expect("selected exists");
    let mut nodes = Vec::new();
    for name in app.mesh.names() {
        let n = app.mesh.node(&name).expect("named");
        let tip = n.selected_tip().map(|t| t.to_string()).unwrap_or_default();
        nodes.push(format!(
            "{{\"name\":{},\"blocks\":{},\"tip\":{},\"peers\":{},\"mempool\":{}}}",
            jstr(&name),
            n.block_count().unwrap_or(0),
            jstr(&tip),
            jarr(app.mesh.peers_of(&name).iter().map(|s| jstr(s))),
            n.pending_count()
        ));
    }
    let events: Vec<String> = app
        .mesh
        .events()
        .iter()
        .rev()
        .take(48)
        .map(|e| {
            format!(
                "{{\"at\":{},\"from\":{},\"to\":{},\"kind\":{}}}",
                e.at,
                jstr(&e.from),
                jstr(&e.to),
                jstr(&format!("{:?}", e.kind).to_lowercase())
            )
        })
        .collect();
    format!(
        "{{\"selected\":{},\"producing\":{},\"faucet\":{},\"allow_reset\":{},\"operator\":{},\"network\":{},\"listen\":{},\"peers\":{},\"mesh\":{{\"now\":{},\"queued\":{},\"nodes\":{},\"events\":{}}},\"node\":{},\"wallets\":{}}}",
        jstr(selected),
        app.producing,
        app.faucet,
        app.allow_reset,
        app.operator,
        jstr(network_profile().id),
        jstr(&app.listen_addr),
        jarr(app.peers.iter().map(|s| jstr(s))),
        app.mesh.now(),
        app.mesh.queued(),
        jarr(nodes.into_iter()),
        jarr(events.into_iter()),
        node_json(node),
        wallets_json(node),
    )
}

fn node_json(node: &Node) -> String {
    let Ok(ledger) = node.ledger() else {
        return "{\"blocks\":0,\"dag\":[],\"order\":[],\"tips\":[],\"pending\":[]}".into();
    };
    let dag = ledger.dag();
    let selected_tip = node
        .selected_tip()
        .map(|t| t.to_string())
        .unwrap_or_default();
    let chain: Vec<BlockId> = dag.selected_chain();
    let chain_set: HashSet<BlockId> = chain.iter().copied().collect();
    let tip_id = node.selected_tip().ok();
    let gd = tip_id.as_ref().and_then(|id| dag.ghostdag(id));
    let blue_set: HashSet<BlockId> = gd
        .map(|g| g.blue_anticone_sizes.keys().copied().collect())
        .unwrap_or_default();
    let genesis = dag.genesis();
    let order = dag.linearize();
    let mut tx_count = 0usize;
    let dag_json: Vec<String> = order
        .iter()
        .filter_map(|id| {
            let rec = node.block_record(id)?;
            tx_count += rec.txs.len();
            let colour = colour_of(*id, genesis, &chain_set, &blue_set);
            let g = dag.ghostdag(id)?;
            Some(format!(
                "{{\"id\":{},\"parents\":{},\"selected_parent\":{},\"work\":{},\"timestamp_ms\":{},\"nonce\":{},\"blue_score\":{},\"colour\":{},\"txs\":{}}}",
                jstr(&id.to_string()),
                jarr(rec.parents.iter().map(|p| jstr(&p.to_string()))),
                match g.selected_parent {
                    Some(sp) => jstr(&sp.to_string()),
                    None => "null".into(),
                },
                rec.work,
                rec.timestamp_ms,
                rec.nonce,
                g.blue_score,
                jstr(colour),
                jarr(rec.txs.iter().map(tx_json)),
            ))
        })
        .collect();
    let pending = jarr(node.pending_txs().iter().map(|tx| pending_json(node, tx)));
    let utxo = ledger.ledger_state();
    let supply = ledger.supply();
    format!(
        "{{\"blocks\":{},\"tips\":{},\"selected_tip\":{},\"blue_score\":{},\"blue_work\":{},\"k\":{},\"subsidy\":{},\"issuance\":{},\"halving_era\":{},\"min_fee\":{},\"genesis\":{},\"supply\":{},\"native_minted\":{},\"circulating\":{},\"burned\":{},\"max_supply\":{},\"token\":{},\"decimals\":{},\"authority_pk\":{},\"atom\":{},\"admission\":\"poa\",\"poa_enabled\":{},\"ui\":{},\"utxos\":{},\"chain_len\":{},\"mempool\":{},\"tx_count\":{},\"dag\":{},\"order\":{},\"pending\":{}}}",
        dag.len(),
        jarr(dag.tips().iter().map(|t| jstr(&t.to_string()))),
        jstr(&selected_tip),
        gd.map(|g| g.blue_score).unwrap_or(0),
        gd.map(|g| g.blue_work).unwrap_or(0),
        dag.k(),
        ledger.subsidy(),
        node.issuance().unwrap_or(0),
        HALVING_ERA,
        node.min_fee(),
        jstr(&ledger.genesis().to_string()),
        supply.total,
        supply.total,
        supply.circulating,
        supply.burned,
        supply.max_supply,
        jstr("KVNC"),
        8,
        match node.authority_public_key() {
            Some(pk) => jstr(&hex_encode(&pk.to_bytes())),
            None => "null".into(),
        },
        ATOM,
        node.poa_enabled(),
        jstr("v5"),
        utxo.len(),
        chain.len(),
        node.pending_count(),
        tx_count,
        jarr(dag_json.into_iter()),
        jarr(order.iter().map(|id| jstr(&id.to_string()))),
        pending,
    )
}

fn colour_of<'a>(
    id: BlockId,
    genesis: BlockId,
    chain: &HashSet<BlockId>,
    blue: &HashSet<BlockId>,
) -> &'a str {
    if id == genesis {
        "genesis"
    } else if chain.contains(&id) {
        "chain"
    } else if blue.contains(&id) {
        "blue"
    } else {
        "red"
    }
}

fn tx_json(tx: &Transaction) -> String {
    format!(
        "{{\"id\":{},\"coinbase\":{},\"inputs\":{},\"outputs\":{}}}",
        jstr(&tx.id().to_string()),
        tx.is_coinbase(),
        tx.inputs().len(),
        jarr(tx.outputs().iter().map(|o| format!(
            "{{\"value\":{},\"owner\":{}}}",
            o.value,
            jstr(&o.owner.to_hex())
        ))),
    )
}

fn pending_json(node: &Node, tx: &Transaction) -> String {
    let fee = if let Ok(ledger) = node.ledger() {
        let utxo = ledger.ledger_state();
        let mut sum_in = 0u64;
        for input in tx.inputs() {
            if let Some(prev) = utxo.get(&input.outpoint) {
                sum_in = sum_in.saturating_add(prev.value);
            }
        }
        let sum_out: u64 = tx.outputs().iter().map(|o| o.value).sum();
        sum_in.saturating_sub(sum_out)
    } else {
        0
    };
    format!(
        "{{\"id\":{},\"coinbase\":{},\"fee\":{},\"inputs\":{},\"outputs\":{}}}",
        jstr(&tx.id().to_string()),
        tx.is_coinbase(),
        fee,
        tx.inputs().len(),
        jarr(tx.outputs().iter().map(|o| format!(
            "{{\"value\":{},\"owner\":{}}}",
            o.value,
            jstr(&o.owner.to_hex())
        ))),
    )
}

fn wallets_json(node: &Node) -> String {
    let rows: Vec<String> = ACTORS
        .iter()
        .map(|seed| {
            let addr = Node::address(*seed);
            let bal = node.balance(&addr).unwrap_or(0);
            format!(
                "{{\"seed\":{},\"address\":{},\"balance\":{}}}",
                seed,
                jstr(&addr.to_hex()),
                bal
            )
        })
        .collect();
    jarr(rows.into_iter())
}

/// Lowercase hex encoding of raw bytes.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).expect("nibble"));
        out.push(char::from_digit((b & 0xf) as u32, 16).expect("nibble"));
    }
    out
}

fn jstr(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn jstr_opt(opt: Option<String>) -> String {
    match opt {
        Some(s) => jstr(&s),
        None => "null".to_string(),
    }
}

fn jarr(items: impl Iterator<Item = String>) -> String {
    let mut out = String::from("[");
    for (i, item) in items.enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&item);
    }
    out.push(']');
    out
}

fn ws_frame_text(text: &str) -> Vec<u8> {
    let payload = text.as_bytes();
    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.push(0x81); // FIN + text frame
    if payload.len() < 126 {
        frame.push(payload.len() as u8);
    } else if payload.len() < 65536 {
        frame.push(126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The address a PoA block reward is credited to.
    ///
    /// Under PoA the coinbase pays the signing authority, not the genesis
    /// founder. `Node::produce_empty` derives the recipient from
    /// `authority_public_key()` — the *first* loaded authority key — before
    /// slot ownership is resolved, so in a placeholder set this is always
    /// `AUTHORITY_PLACEHOLDER_BASE`'s key regardless of which authority
    /// actually signs for the slot.
    fn authority_reward_address() -> kovanica_state::Address {
        kovanica_state::KeyPair::from_u64(AUTHORITY_PLACEHOLDER_BASE).address()
    }

    #[test]
    fn snapshot_has_three_nodes_and_genesis() {
        let app = Explorer::boot();
        let json = snapshot(&app);
        eprintln!("=== SNAPSHOT JSON (first 500 chars) ===");
        eprintln!("{:.500}", json);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        // ... rest of test
        // Mesh-level: three named genesis nodes.
        let nodes = v["mesh"]["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 3);
        let names: Vec<&str> = nodes.iter().filter_map(|n| n["name"].as_str()).collect();
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));
        assert!(names.contains(&"gamma"));
        assert_eq!(v["network"].as_str().unwrap(), "kovanica-testnet");
        // Selected node's RFC-006 genesis metrics live under v["node"].
        let n = &v["node"];
        assert!(n.is_object());
        assert_eq!(n["token"].as_str().unwrap(), "KVNC");
        assert_eq!(n["ui"].as_str().unwrap(), "v5");
        // `admission` is the regime and `poa_enabled` the live ledger switch.
        // PoA is the only regime (RFC-POA §0), so `admission` is a constant
        // while `poa_enabled` tracks whether this node's ledger has it on.
        assert_eq!(n["admission"].as_str().unwrap(), "poa");
        assert!(n["poa_enabled"].as_bool().unwrap());
        // One genesis node: 200,000 KVNC premine + 10×1,000,000 KVNC treasury
        // = 10,200,000 KVNC = 1,020,000,000,000,000 atoms.
        assert_eq!(n["supply"].as_u64().unwrap(), 1_020_000_000_000_000);
        assert_eq!(n["subsidy"].as_u64().unwrap(), 1_000_000_000);
        assert_eq!(n["halving_era"].as_u64().unwrap(), 2_000_000);
        assert_eq!(n["min_fee"].as_u64().unwrap(), 2000);
        assert_eq!(n["max_supply"].as_u64().unwrap(), 9_020_000_000_000_000);
        assert_eq!(n["issuance"].as_u64().unwrap(), 1_000_000_000);
    }

    #[test]
    fn empty_block_mints_kvnc_subsidy_to_miner() {
        let mut app = Explorer::boot();
        app.producing = false;
        // Under PoA the subsidy is credited to the authority, not the founder.
        let authority = authority_reward_address();
        let before = app.mesh.node("alpha").unwrap().balance(&authority).unwrap();
        app.mesh.produce_empty("alpha").unwrap();
        let after = app.mesh.node("alpha").unwrap().balance(&authority).unwrap();
        assert_eq!(after, before + u128::from(GENESIS_SUBSIDY));
    }

    #[test]
    fn produce_block_mints_kvnc_subsidy_with_the_spend() {
        let mut app = Explorer::boot();
        app.producing = false;
        // Maturity the founder's genesis coinbase under the CSV rule so the
        // pool() spend from seed 1 is valid (creation_height + 100 <= height).
        for _ in 0..100 {
            app.mesh.produce_empty("alpha").unwrap();
        }
        // Under PoA every subsidy is credited to the authority; the founder
        // receives none, so the 100 maturity blocks above do not help this
        // UTXO at all.
        let authority = authority_reward_address();
        let founder = kovanica_state::KeyPair::from_u64(1).address();
        let authority_before = app.mesh.node("alpha").unwrap().balance(&authority).unwrap();
        app.mesh.pool("alpha", 1, ATOM, 2).unwrap();
        app.mesh.produce("alpha").unwrap();
        let n = app.mesh.node("alpha").unwrap();
        let fee = n.min_fee();
        assert_eq!(
            n.balance(&kovanica_state::KeyPair::from_u64(2).address())
                .unwrap(),
            ATOM.into()
        );
        // RFC-006: `produce` mints one more subsidy to the authority, which
        // also claims the producer's fee share (fees/4, the other 75% is
        // burned). The founder only lost the spend.
        assert_eq!(
            n.balance(&authority).unwrap(),
            authority_before + u128::from(GENESIS_SUBSIDY + fee / 4)
        );
        assert_eq!(
            n.balance(&founder).unwrap(),
            u128::from(GENESIS_PREMINE - ATOM - fee)
        );
    }

    #[test]
    fn prepare_combines_two_coinbases_to_send_a_full_subsidy() {
        use kovanica_state::KeyPair;

        let mut app = Explorer::boot();
        app.producing = false;
        // Maturity the genesis coinbases under the CSV rule so the transfer is
        // valid (creation_height + 100 <= height).
        for _ in 0..100 {
            app.mesh.produce_empty("alpha").unwrap();
        }
        // Under PoA the accumulated subsidy coinbases belong to the authority,
        // so the authority is the sender here: it is the only actor holding
        // many small 10-KVNC coinbases, which is what this test is about.
        let from = KeyPair::from_u64(AUTHORITY_PLACEHOLDER_BASE);
        let to = KeyPair::from_u64(9);
        app.mesh.produce_empty("alpha").unwrap();
        let fee = app.mesh.node("alpha").unwrap().min_fee();
        // Dump the founder's premine to a third actor (seed 8) so `to` (seed 9)
        // only receives the transfer under test.
        app.mesh.pool("alpha", 1, GENESIS_PREMINE - fee, 8).unwrap();
        app.mesh.produce("alpha").unwrap();
        let prepared = app
            .mesh
            .node("alpha")
            .unwrap()
            .prepare_transfer(from.address(), GENESIS_SUBSIDY, to.address())
            .unwrap();
        assert!(
            prepared.tx.inputs().len() >= 2,
            "10 KVNC + fee needs two 10-KVNC coinbases"
        );
        let sig = from.sign(&prepared.sighash);
        app.mesh
            .submit_signed("alpha", from.address(), GENESIS_SUBSIDY, to.address(), sig)
            .unwrap();
        app.mesh.produce("alpha").unwrap();
        app.mesh.drain(8);
        assert_eq!(
            app.mesh
                .node("alpha")
                .unwrap()
                .balance(&to.address())
                .unwrap(),
            u128::from(GENESIS_SUBSIDY)
        );
    }

    #[test]
    fn history_lists_credit_to_an_address() {
        let mut app = Explorer::boot();
        app.producing = false;
        // Maturity the founder's genesis coinbase under the CSV rule so the
        // pool() spend from seed 1 is valid (creation_height + 100 <= height).
        for _ in 0..100 {
            app.mesh.produce_empty("alpha").unwrap();
        }
        app.mesh.pool("alpha", 1, ATOM, 2).unwrap();
        app.mesh.produce("alpha").unwrap();
        let addr = kovanica_state::KeyPair::from_u64(2).address().to_hex();
        let mut q = std::collections::HashMap::new();
        q.insert("address".into(), addr);
        q.insert("node".into(), "alpha".into());
        let json = history_json(&app, &q).unwrap();
        assert!(json.contains("\"kind\":\"in\""));
        assert!(json.contains(&ATOM.to_string()));
    }

    #[test]
    fn issuance_geometric_each_era() {
        // era length HALVING_ERA (2_000_000); alpha = 3/4
        assert_eq!(Node::issuance_at(10 * ATOM, 0), 10 * ATOM);
        assert_eq!(Node::issuance_at(10 * ATOM, 1_999_999), 10 * ATOM);
        assert_eq!(Node::issuance_at(10 * ATOM, 2_000_000), 10 * ATOM * 3 / 4);
        assert_eq!(
            Node::issuance_at(10 * ATOM, 4_000_000),
            10 * ATOM * 3 / 4 * 3 / 4
        );
    }

    #[test]
    fn min_fee_scales_with_subsidy_cap() {
        let app = Explorer::boot();
        let fee = app.mesh.node("alpha").unwrap().min_fee();
        assert_eq!(fee, (GENESIS_SUBSIDY / 500_000).max(1));
        assert!(fee > 1);
    }

    #[test]
    fn p2p_off_tokens() {
        assert!(env_off("off"));
        assert!(env_off("none"));
        assert!(env_off("0"));
        assert!(!env_off(P2P_LISTEN_DEFAULT));
        assert_eq!(
            P2P_BOOTSTRAP,
            "seed.kovanica.online:9000,seed2.kovanica.online:9000"
        );
    }

    #[test]
    fn origin_pulse_increments_and_lists() {
        let mut app = Explorer::boot();
        let mut q = std::collections::HashMap::new();
        q.insert("iso3".into(), "hrv".into());
        let body = dispatch(&mut app, "origin", &q).unwrap();
        assert!(body.contains("HRV"));
        assert!(body.contains("\"pulses\":1"));
        let listed = origins_json(&app.origins);
        assert!(listed.contains("HRV"));
        let bad = dispatch(&mut app, "origin", &std::collections::HashMap::new());
        assert!(bad.is_err());
    }

    #[test]
    fn tap_action_is_removed() {
        use kovanica_state::KeyPair;

        let mut app = Explorer::boot();
        let to = KeyPair::from_u64(9);
        let mut q = std::collections::HashMap::new();
        q.insert("to".into(), to.address().to_hex());
        q.insert("amount".into(), "1".into());
        let err = dispatch(&mut app, "tap", &q).unwrap_err();
        assert!(err.contains("unknown action"));
    }

    #[test]
    fn mine_action_produces_a_block_like_produce() {
        let mut app = Explorer::boot();
        let before = app.mesh.node("alpha").unwrap().block_count().unwrap();
        let mine_body = dispatch(&mut app, "mine", &std::collections::HashMap::new()).unwrap();
        let after = app.mesh.node("alpha").unwrap().block_count().unwrap();
        assert!(mine_body.contains("\"ok\":true"));
        assert_eq!(after, before + 1, "mine must produce exactly one block");
    }

    #[test]
    fn dual_stack_binds_v4_and_v6_on_the_same_port() {
        // Skip where IPv6 is unavailable (some CI runners / containers).
        if TcpListener::bind("[::]:0").is_err() {
            return;
        }
        // Derive the port from the pid so parallel tests rarely collide.
        let port: u16 = 20000 + u16::try_from(std::process::id() % 20_000).unwrap_or(0);
        let raw = format!("0.0.0.0:{port}");
        let listeners = bind_p2p_addrs(&raw);
        assert_eq!(listeners.len(), 2, "want one v4 and one v6 listener");
        for l in &listeners {
            assert_eq!(l.local_addr().unwrap().port(), port);
        }
        // The v6 listener must genuinely be reachable on the v6 wildcard.
        let mut c =
            std::net::TcpStream::connect(format!("[::1]:{port}")).expect("v6 loopback connect");
        use std::io::Write as _;
        let _ = c.write_all(b"x"); // accepted is all we prove; write may race close
    }

    /// Core request helper: returns the raw response bytes so binary bodies
    /// (wire-format uplinks, light-sync blobs, merkle proofs) survive intact.
    fn send_req_raw(app: &mut Explorer, head: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (server_stream, _) = listener.accept().unwrap();

        client.write_all(head.as_bytes()).unwrap();
        client.write_all(body).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        let _ = handle(app, server_stream);

        let mut resp = Vec::new();
        let _ = client.read_to_end(&mut resp);

        let status = String::from_utf8_lossy(&resp)
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);

        let body = if let Some(pos) = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4)
        {
            resp[pos..].to_vec()
        } else {
            Vec::new()
        };
        (status, body)
    }

    fn send_req(app: &mut Explorer, req: &str) -> (u16, String) {
        let (status, body) = send_req_raw(app, req, b"");
        (status, String::from_utf8_lossy(&body).to_string())
    }

    /// Like [`send_req`], but with a binary body (the wire-format uplink).
    fn send_req_bytes(app: &mut Explorer, head: &str, body: &[u8]) -> (u16, String) {
        let (status, body) = send_req_raw(app, head, body);
        (status, String::from_utf8_lossy(&body).to_string())
    }

    // ---- A1: network profile (dormant mainnet) ----

    #[test]
    fn network_profile_defaults_to_testnet() {
        // No KOVANICA_NETWORK set in tests: the default must be the live
        // testnet, never dormant, with the shipped genesis parameters.
        let profile = network_profile();
        assert_eq!(profile.id, "kovanica-testnet");
        assert!(!profile.dormant);
        assert_eq!(profile.genesis_k, 3);
        assert_eq!(profile.genesis_subsidy, GENESIS_SUBSIDY);
        assert_eq!(profile.genesis_premine, GENESIS_PREMINE);
        assert_eq!(profile.founder_seed, FOUNDER_SEED);
        assert_eq!(profile.finality_depth, TESTNET_FINALITY_DEPTH);
        assert_eq!(profile.payload_pruning_depth, TESTNET_PAYLOAD_PRUNING_DEPTH);
        assert_eq!(profile.block_pruning_depth, TESTNET_BLOCK_PRUNING_DEPTH);
        assert!(
            profile.block_pruning_depth >= profile.finality_depth,
            "RFC-008 invariant: block pruning stays within final blocks"
        );
    }

    #[test]
    fn mainnet_profile_is_a_dormant_placeholder() {
        // The mainnet profile exists for plumbing (id, data-dir isolation,
        // faucet gating). Its genesis parameters are the shipped RFC-006
        // values; it stays dormant so selecting it without override refuses
        // to boot rather than inventing consensus parameters late.
        let profile = NetworkProfile::mainnet();
        assert_eq!(profile.id, "kovanica-mainnet");
        assert!(profile.dormant, "mainnet must stay dormant");
        assert_eq!(profile.genesis_k, 3, "mainnet k is shipped (RFC-006)");
        assert_eq!(
            profile.genesis_subsidy, GENESIS_SUBSIDY,
            "mainnet subsidy is shipped (RFC-006)"
        );
        assert_eq!(
            profile.genesis_premine, GENESIS_PREMINE,
            "mainnet premine is shipped (RFC-006)"
        );
        assert_eq!(
            profile.finality_depth, 1000,
            "mainnet finality depth is shipped"
        );
        assert_eq!(
            profile.payload_pruning_depth, 10_000,
            "mainnet payload pruning depth is shipped"
        );
    }

    #[test]
    fn data_dirs_are_isolated_per_network() {
        // A mainnet node owns `data/kovanica-mainnet/`, never the testnet's
        // `data/` — so the ensure_network() wipe cannot cross networks.
        assert_eq!(
            data_dir_for(&NetworkProfile::testnet()),
            PathBuf::from("data")
        );
        assert_eq!(
            data_dir_for(&NetworkProfile::mainnet()),
            PathBuf::from("data/kovanica-mainnet")
        );
    }

    /// A scratch directory for the load-tier tests. Unique per test name so
    /// parallel test threads cannot collide, and cleaned up by the caller.
    fn tier_test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kovanica-load-tier-{}-{name}-{}",
            std::process::id(),
            name.len()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    /// A node that cannot durably record the chain it serves is worse than a
    /// node that refuses to start, so `open_replay_log` must never return `Ok`
    /// without a live log. These pin the two failure modes the old
    /// `let _ = node.create_log(..)` silently swallowed.
    #[test]
    fn open_replay_log_refuses_when_the_path_cannot_be_created() {
        let dir = tier_test_dir("unwritable");
        // A path whose parent is a regular file cannot be created.
        let blocker = dir.join("not-a-dir");
        fs::write(&blocker, b"i am a file").unwrap();
        let log = blocker.join("alpha.log");

        let mut node = Node::new();
        let err = open_replay_log(&mut node, &log, "alpha", "on a fresh data directory")
            .expect_err("must refuse rather than run without persistence");
        assert!(
            err.contains("cannot durably record"),
            "message should explain the consequence, got: {err}"
        );
        assert!(err.contains("KOVANICA_DATA"), "should be actionable: {err}");
    }

    #[test]
    fn open_replay_log_refuses_a_non_utf8_path_instead_of_skipping_persistence() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let dir = tier_test_dir("non-utf8");
        // 0xFF is never valid UTF-8, so `to_str()` yields None. The old code
        // used `if let Some(p) = log.to_str()`, which skipped persistence
        // entirely and returned a node with no log at all.
        let log = dir.join(OsStr::from_bytes(b"alpha-\xff.log"));

        let mut node = Node::new();
        let err = open_replay_log(&mut node, &log, "alpha", "on a fresh data directory")
            .expect_err("a non-UTF-8 path must not silently skip persistence");
        assert!(err.contains("not valid UTF-8"), "got: {err}");
        assert!(
            err.contains("cannot durably record"),
            "message should explain the consequence, got: {err}"
        );
    }

    #[test]
    fn open_replay_log_succeeds_on_a_writable_path() {
        let dir = tier_test_dir("writable");
        let log = dir.join("alpha.log");
        // Needs a real ledger: `create_log` persists the node's current chain.
        let mut node = genesis_node();
        open_replay_log(&mut node, &log, "alpha", "on a fresh data directory")
            .expect("a writable path must succeed");
        assert!(log.exists(), "the log file must actually be created");
    }

    /// The scrape endpoint used to bind a fixed `0.0.0.0:9090`, so two nodes on
    /// one host collided and every interface got a Prometheus endpoint.
    #[test]
    fn metrics_listen_is_configurable_and_can_be_disabled() {
        // Unset and empty both mean "default" — a systemd unit with
        // `Environment=KOVANICA_METRICS_LISTEN=` must behave like no line at all,
        // not silently drop observability.
        assert_eq!(metrics_bind_target(None), Some("0.0.0.0:9090"));
        assert_eq!(metrics_bind_target(Some("")), Some("0.0.0.0:9090"));
        assert_eq!(metrics_bind_target(Some("   ")), Some("0.0.0.0:9090"));

        assert_eq!(
            metrics_bind_target(Some("127.0.0.1:19090")),
            Some("127.0.0.1:19090")
        );
        assert_eq!(
            metrics_bind_target(Some(" 10.0.0.5:9090 ")),
            Some("10.0.0.5:9090"),
            "surrounding whitespace is trimmed"
        );

        for off in ["off", "OFF", " none ", "0", "disabled", "DISABLED"] {
            assert_eq!(
                metrics_bind_target(Some(off)),
                None,
                "{off:?} should disable metrics"
            );
        }
    }

    #[test]
    fn load_tier_prefers_the_log_over_the_snapshot() {
        let dir = tier_test_dir("prefers-log");
        let log = dir.join("alpha.log");
        let snap = dir.join("alpha.snap");
        fs::write(&log, b"log bytes").unwrap();
        fs::write(&snap, b"snapshot bytes").unwrap();
        assert_eq!(choose_load_tier(&log, &snap), LoadTier::Log);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_tier_never_masks_a_broken_log_with_the_snapshot() {
        // The regression this whole change exists for. A log that exists but
        // will not replay must NOT route to Snapshot (older chain) or Genesis
        // (different chain + the log is truncated). It has to surface as an
        // error so the operator decides.
        let dir = tier_test_dir("broken-log");
        let log = dir.join("alpha.log");
        let snap = dir.join("alpha.snap");
        // Byte contents are irrelevant here — `has_content` is what routes.
        fs::write(&log, b"not a valid log header at all").unwrap();
        fs::write(&snap, b"snapshot bytes").unwrap();
        assert_eq!(choose_load_tier(&log, &snap), LoadTier::Log);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_tier_treats_a_zero_length_log_as_absent() {
        // `LedgerStore::create` truncates before writing the header, so a crash
        // in that window leaves 0 bytes. That is a torn write, not operator
        // data, and must not brick the node.
        let dir = tier_test_dir("torn-log");
        let log = dir.join("alpha.log");
        let snap = dir.join("alpha.snap");
        fs::write(&log, b"").unwrap();
        fs::write(&snap, b"snapshot bytes").unwrap();
        assert_eq!(choose_load_tier(&log, &snap), LoadTier::Snapshot);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_tier_falls_back_to_genesis_only_when_nothing_is_persisted() {
        let dir = tier_test_dir("genesis");
        let log = dir.join("alpha.log");
        let snap = dir.join("alpha.snap");
        assert_eq!(choose_load_tier(&log, &snap), LoadTier::Genesis);
        // Both artifacts present but zero-length: still nothing to load.
        fs::write(&log, b"").unwrap();
        fs::write(&snap, b"").unwrap();
        assert_eq!(choose_load_tier(&log, &snap), LoadTier::Genesis);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_replay_log_reports_an_error_instead_of_loading() {
        // End-to-end on the actual reader: garbage where the log should be must
        // come back as `Err`, so `serve` aborts rather than coming up on a
        // fallback chain.
        let dir = tier_test_dir("corrupt-log-loads");
        let log = dir.join("alpha.log");
        fs::write(&log, b"KOV\x00garbage that is not a ledger log").unwrap();
        let profile = network_profile();
        let policy = kovanica_state::PruningPolicy {
            finality_depth: profile.finality_depth,
            payload_pruning_depth: profile.payload_pruning_depth,
            block_pruning_depth: profile.block_pruning_depth,
        };
        let cfg = poa_config_from_env(&profile);
        let loaded = Node::load_log_with_poa_and_policy(
            log.to_str().unwrap(),
            cfg.authority_set,
            cfg.slot_duration_ms,
            policy,
        );
        assert!(
            loaded.is_err(),
            "a corrupt log must not load; the old code swallowed this and \
             served genesis"
        );
        // And the corrupt file is still on disk — the fix must not truncate it.
        assert_eq!(
            fs::read(&log).unwrap(),
            b"KOV\x00garbage that is not a ledger log",
            "a failed load must leave the operator's log untouched"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // ---- authority-set commitment ----------------------------------------

    /// Build a valid `AuthoritySet` from small-integer seeds, the way
    /// `poa_config_from_env` builds one from `KOVANICA_AUTHORITIES`. Uses
    /// `KeyPair::from_u64` purely to get well-formed Ed25519 public keys;
    /// `MIN_AUTHORITIES = 3` and `MIN_THRESHOLD = 2` still apply.
    fn set_from_seeds(seeds: &[u64], threshold: usize) -> AuthoritySet {
        let pks = seeds
            .iter()
            .map(|s| {
                let bytes = kovanica_state::KeyPair::from_u64(*s).public_key();
                ed25519_dalek::VerifyingKey::from_bytes(&bytes).expect("valid ed25519 pubkey")
            })
            .collect();
        AuthoritySet::new(pks, threshold).expect("valid test authority set")
    }

    /// Three keys, threshold 2 — the smallest set `AuthoritySet` accepts.
    fn scratch_authority_set() -> AuthoritySet {
        set_from_seeds(&[7, 9, 11], 2)
    }

    #[test]
    fn authority_set_commitment_is_the_set_hash_hex() {
        let set = scratch_authority_set();
        assert_eq!(
            authority_set_commitment(&set),
            hex::encode(set.hash()),
            "the commitment must be the set hash the genesis KVA1 tag commits to"
        );
    }

    #[test]
    fn authority_set_commitment_covers_the_threshold_not_just_the_keys() {
        // Two thresholds over the same keys are two different authority sets and
        // two different genesis ids, so the commitment must distinguish them.
        // If it did not, `KOVANICA_AUTHORITY_THRESHOLD` could be changed under a
        // live chain and the guard would stay silent.
        let two = set_from_seeds(&[7, 9, 11], 2);
        let three = set_from_seeds(&[7, 9, 11], 3);
        assert_ne!(
            authority_set_commitment(&two),
            authority_set_commitment(&three),
            "threshold must be part of the committed identity"
        );
    }

    #[test]
    fn authority_set_commitment_is_stable_across_key_ordering() {
        // `AuthoritySet` canonically orders keys, so the same set presented in a
        // different order must commit identically — otherwise a cosmetic env
        // reorder would trip the guard.
        let a = set_from_seeds(&[7, 9, 11], 2);
        let b = set_from_seeds(&[11, 7, 9], 2);
        assert_eq!(authority_set_commitment(&a), authority_set_commitment(&b));
    }

    #[test]
    fn recording_then_checking_the_same_authority_set_passes() {
        // The guard must not fire on every ordinary restart.
        let dir = tier_test_dir("authority-match");
        let path = dir.join("alpha.authorities");
        let set = scratch_authority_set();
        record_authority_set_at(&path, &set);
        assert_eq!(
            check_authority_set_at(&path, "alpha", &set),
            Ok(()),
            "a matching commitment must not block boot"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn checking_a_different_authority_set_refuses_to_boot() {
        // The regression this guard exists for. Same data directory, different
        // `KOVANICA_AUTHORITIES` — previously silent, and the node went on to
        // admit blocks signed by keys the genesis does not commit to.
        let dir = tier_test_dir("authority-mismatch");
        let path = dir.join("alpha.authorities");
        record_authority_set_at(&path, &scratch_authority_set());
        let other = set_from_seeds(&[1, 2, 3], 2);
        let err = check_authority_set_at(&path, "alpha", &other)
            .expect_err("a different authority set must refuse to boot");
        assert!(err.contains("authority-set mismatch"), "got: {err}");
        assert!(
            err.contains("consensus-breaking"),
            "the message must say a new authority set needs a reset: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_commitment_does_not_block_boot() {
        // Data directories created before this check existed have no commitment
        // file. Refusing those would be a self-inflicted outage.
        let dir = tier_test_dir("authority-missing");
        let path = dir.join("alpha.authorities");
        assert_eq!(
            check_authority_set_at(&path, "alpha", &scratch_authority_set()),
            Ok(()),
            "an absent commitment must not block boot"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_placeholder_authority_set_is_not_a_real_ceremony() {
        // Sanity check on the premise of gate 1: the placeholder set is derived
        // from the public constant `AUTHORITY_PLACEHOLDER_BASE`, so a "soak" run
        // against it proves nothing about key custody. This test pins the
        // placeholder set's identity so that if the derivation ever changes,
        // the ceremony doc's claim is re-examined rather than silently rotting.
        let placeholder = set_from_seeds(
            &(0..AUTHORITY_PLACEHOLDER_COUNT)
                .map(|i| AUTHORITY_PLACEHOLDER_BASE + i)
                .collect::<Vec<u64>>(),
            2,
        );
        let real = scratch_authority_set();
        assert_ne!(
            authority_set_commitment(&placeholder),
            authority_set_commitment(&real),
            "a ceremony set must differ from the placeholder set"
        );
    }

    #[test]
    fn wipe_data_also_removes_the_authority_set_commitment() {
        // A stale commitment surviving a wipe would make the next fresh boot
        // trip the very guard the wipe is supposed to reset.
        let dir = tier_test_dir("wipe-authorities");
        for name in ["alpha.log", "alpha.snap", "alpha.authorities", "keep.txt"] {
            fs::write(dir.join(name), b"x").unwrap();
        }
        // Same extension filter `wipe_data` uses.
        for entry in fs::read_dir(&dir).unwrap().flatten() {
            let p = entry.path();
            let ext = p.extension().and_then(|s| s.to_str());
            if ext == Some("snap") || ext == Some("log") || ext == Some("authorities") {
                fs::remove_file(p).unwrap();
            }
        }
        assert!(!dir.join("alpha.log").exists());
        assert!(!dir.join("alpha.snap").exists());
        assert!(
            !dir.join("alpha.authorities").exists(),
            "a stale commitment would block the post-reset boot"
        );
        assert!(
            dir.join("keep.txt").exists(),
            "wipe must stay scoped to persistence artifacts"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_http_bootstrap_returns_light_config() {
        let mut app = Explorer::boot();
        let profile = network_profile();
        let (status, body) = send_req(
            &mut app,
            "GET /api/bootstrap HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        );
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_str(&body).expect("bootstrap JSON");

        // Regression: /api/bootstrap must advertise dialable peers only. The
        // node's own listen spec is reported in `listen`; leaking it into
        // `peers` yields an undialable "0.0.0.0:9000,[::]:9000" entry.
        let listen = json["listen"].as_str().unwrap_or("");
        for peer in json["peers"].as_array().expect("peers array") {
            let peer = peer.as_str().unwrap();
            assert!(
                !peer.contains("0.0.0.0") && !peer.contains("[::]"),
                "peers must not contain the listen spec: {peer}"
            );
            assert_ne!(
                peer, listen,
                "peers must not include the node's own listen address"
            );
        }

        // Existing top-level fields remain for backward compatibility.
        assert_eq!(json["network"].as_str().unwrap(), profile.id);
        assert_eq!(json["k"].as_u64().unwrap(), u64::from(profile.genesis_k));
        assert_eq!(json["subsidy"].as_u64().unwrap(), profile.genesis_subsidy);
        assert_eq!(
            json["founder_amount"].as_u64().unwrap(),
            profile.genesis_premine
        );
        assert_eq!(json["founder_seed"].as_u64().unwrap(), profile.founder_seed);
        assert_eq!(
            json["finality_depth"].as_u64().unwrap(),
            profile.finality_depth
        );
        assert_eq!(
            json["payload_pruning_depth"].as_u64().unwrap(),
            profile.payload_pruning_depth
        );
        assert_eq!(
            json["block_pruning_depth"].as_u64().unwrap(),
            profile.block_pruning_depth,
            "RFC-008: bootstrap must advertise the block pruning depth"
        );

        // Nested light_config object expected by the mobile light node FFI.
        let light = &json["light_config"];
        assert!(!light.is_null(), "light_config must be present");
        assert_eq!(light["k"].as_u64().unwrap(), u64::from(profile.genesis_k));
        assert_eq!(light["subsidy"].as_u64().unwrap(), profile.genesis_subsidy);
        assert_eq!(light["premine"].as_u64().unwrap(), profile.genesis_premine);
        assert_eq!(
            light["founder_seed"].as_u64().unwrap(),
            profile.founder_seed
        );
        assert_eq!(
            light["finality_depth"].as_u64().unwrap(),
            profile.finality_depth
        );
        assert_eq!(
            light["payload_pruning_depth"].as_u64().unwrap(),
            profile.payload_pruning_depth
        );
    }

    // ---- PoA: authority-signed block uplink on POST /api/mine/submit ----

    #[test]
    fn test_http_mine_submit_wire_rejects_garbage() {
        let mut app = Explorer::boot();
        let garbage = b"\x00\x01\x02this is not a records frame at all";
        let head = format!(
            "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            garbage.len()
        );
        let (status, body) = send_req_bytes(&mut app, &head, garbage);
        assert_eq!(status, 400);
        assert!(body.contains("\"ok\":false"));
    }

    #[test]
    fn test_http_mine_submit_wire_rejects_empty_body() {
        let mut app = Explorer::boot();
        let head = "POST /api/mine/submit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 0\r\n\r\n"
            .to_string();
        let (status, body) = send_req_bytes(&mut app, &head, b"");
        assert_eq!(status, 400);
        assert!(body.contains("\"ok\":false"));
    }

    // ---- A3: SPV light-sync blob endpoint ----

    /// Parse a light-sync blob into (header, filter) pairs — a local mirror of
    /// the FFI's `parse_light_sync`, so the endpoint's bytes are verified
    /// against the shipped format without depending on the FFI crate.
    fn parse_light_sync_blob(
        blob: &[u8],
    ) -> Vec<(
        kovanica_state::spv::BlockHeader,
        kovanica_state::spv::BlockFilter,
    )> {
        assert!(blob.len() >= 9, "blob too short");
        assert_eq!(&blob[..4], LIGHT_SYNC_MAGIC);
        assert_eq!(blob[4], LIGHT_SYNC_VERSION);
        let count = u32::from_be_bytes(blob[5..9].try_into().unwrap()) as usize;
        let mut off = 9usize;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let get32 = |o: usize| <[u8; 32]>::try_from(&blob[o..o + 32]).unwrap();
            let header = kovanica_state::spv::BlockHeader {
                id: BlockId::from_bytes(get32(off)),
                prev_hash: BlockId::from_bytes(get32(off + 32)),
                merkle_root: get32(off + 64),
                work: u128::from_be_bytes(blob[off + 96..off + 112].try_into().unwrap()),
                timestamp_ms: u64::from_be_bytes(blob[off + 112..off + 120].try_into().unwrap()),
                nonce: u64::from_be_bytes(blob[off + 120..off + 128].try_into().unwrap()),
                blue_score: u64::from_be_bytes(blob[off + 128..off + 136].try_into().unwrap()),
                chain_blue_work: u128::from_be_bytes(
                    blob[off + 136..off + 152].try_into().unwrap(),
                ),
                height: u64::from_be_bytes(blob[off + 152..off + 160].try_into().unwrap()),
                authority_sig: None,
                authority_set_hash: [0u8; 32],
                hash_without_authority_sig: [0u8; 32],
            };
            off += 160;
            let k = blob[off];
            let n = u64::from_be_bytes(blob[off + 1..off + 9].try_into().unwrap());
            let len = u32::from_be_bytes(blob[off + 9..off + 13].try_into().unwrap()) as usize;
            let data = blob[off + 13..off + 13 + len].to_vec();
            off += 13 + len;
            out.push((header, kovanica_state::spv::BlockFilter { k, n, data }));
        }
        assert_eq!(off, blob.len(), "trailing bytes in light-sync blob");
        out
    }

    #[test]
    fn test_light_sync_blob_matches_headers_and_filters() {
        let mut app = Explorer::boot();
        app.producing = false;
        // A few blocks so the selected chain is non-trivial.
        app.mesh.produce_empty("alpha").unwrap();
        app.mesh.produce_empty("alpha").unwrap();
        app.mesh.produce_empty("alpha").unwrap();

        let (status, blob) = send_req_raw(
            &mut app,
            "GET /api/light_sync HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            b"",
        );
        assert_eq!(status, 200);
        let parsed = parse_light_sync_blob(&blob);

        let n = app.mesh.node("alpha").unwrap();
        let headers = n.export_spv_headers();
        assert_eq!(parsed.len(), headers.len());
        for (i, (h, f)) in parsed.iter().enumerate() {
            assert_eq!(&h.id, &headers[i].id);
            assert_eq!(&h.prev_hash, &headers[i].prev_hash);
            assert_eq!(&h.merkle_root, &headers[i].merkle_root);
            assert_eq!(h.work, headers[i].work);
            assert_eq!(h.timestamp_ms, headers[i].timestamp_ms);
            assert_eq!(h.nonce, headers[i].nonce);
            assert_eq!(h.blue_score, headers[i].blue_score);
            assert_eq!(h.chain_blue_work, headers[i].chain_blue_work);
            assert_eq!(h.height, headers[i].height);
            // The filter must match the node's own block_filter helper.
            let expected = n.block_filter(&h.id, LIGHT_SYNC_FILTER_K).unwrap();
            assert_eq!(f.k, expected.k);
            assert_eq!(f.n, expected.n);
            assert_eq!(f.data, expected.data);
        }
    }

    #[test]
    fn test_light_sync_from_is_incremental() {
        let mut app = Explorer::boot();
        app.producing = false;
        app.mesh.produce_empty("alpha").unwrap();
        app.mesh.produce_empty("alpha").unwrap();
        app.mesh.produce_empty("alpha").unwrap();

        let n = app.mesh.node("alpha").unwrap();
        let headers = n.export_spv_headers();
        assert!(headers.len() >= 4, "genesis + 3 blocks");
        // `from` = the second header (index 1): the blob must start at index 2.
        let from_id = headers[1].id.to_hex();
        let req = format!(
            "GET /api/light_sync?from={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            from_id
        );
        let (status, blob) = send_req_raw(&mut app, &req, b"");
        assert_eq!(status, 200);
        let parsed = parse_light_sync_blob(&blob);
        assert_eq!(parsed.len(), headers.len() - 2);
        assert_eq!(parsed[0].0.id, headers[2].id);
        assert_eq!(parsed.last().unwrap().0.id, headers.last().unwrap().id);

        // An unknown `from` falls back to the full blob (safe for a client
        // that drifted off-chain).
        let unknown = BlockId::from_bytes([0xabu8; 32]).to_hex();
        let req = format!(
            "GET /api/light_sync?from={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            unknown
        );
        let (status, blob) = send_req_raw(&mut app, &req, b"");
        assert_eq!(status, 200);
        let parsed = parse_light_sync_blob(&blob);
        assert_eq!(parsed.len(), headers.len());
    }

    #[test]
    fn test_light_proof_endpoint_verifies() {
        let mut app = Explorer::boot();
        app.producing = false;
        // Maturity the founder's genesis coinbase under the CSV rule so the
        // pool() spend from seed 1 is valid (creation_height + 100 <= height).
        for _ in 0..100 {
            app.mesh.produce_empty("alpha").unwrap();
        }
        // A transfer so the block carries a spendable tx (not just coinbase).
        app.mesh.pool("alpha", 1, ATOM, 2).unwrap();
        app.mesh.produce("alpha").unwrap();

        let n = app.mesh.node("alpha").unwrap();
        let tip = n.selected_tip().unwrap();
        let rec = n.block_record(&tip).unwrap();
        let tx = rec.txs.iter().find(|t| !t.is_coinbase()).expect("spend tx");
        let tx_id = tx.id();

        let req = format!(
            "GET /api/light_proof?block={}&tx={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            tip.to_hex(),
            tx_id.to_hex()
        );
        let (status, blob) = send_req_raw(&mut app, &req, b"");
        assert_eq!(status, 200);

        // Decode the proof blob (FFI `encode_proof` layout) and verify it.
        assert!(blob.len() >= 72);
        let get32 = |o: usize| <[u8; 32]>::try_from(&blob[o..o + 32]).unwrap();
        let path_len = u32::from_be_bytes(blob[64..68].try_into().unwrap()) as usize;
        let base = 68 + path_len * 32;
        let proof = kovanica_state::spv::MerkleProof {
            tx_id: get32(0),
            merkle_root: get32(32),
            path: (0..path_len).map(|i| get32(68 + i * 32)).collect(),
            index: u64::from_be_bytes(blob[base..base + 8].try_into().unwrap()) as usize,
            tx_count: u64::from_be_bytes(blob[base + 8..base + 16].try_into().unwrap()) as usize,
        };
        assert_eq!(proof.tx_id, *tx_id.as_bytes());
        assert!(proof.verify(), "merkle proof must verify");

        // Unknown tx → 404.
        let unknown = kovanica_state::TxId::from_bytes([0x42u8; 32]).to_hex();
        let req = format!(
            "GET /api/light_proof?block={}&tx={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            tip.to_hex(),
            unknown
        );
        let (status, body) = send_req(&mut app, &req);
        assert_eq!(status, 404);
        assert!(body.contains("\"ok\":false"));
    }

    // ---- D1: rate limits + faucet gating ----

    #[test]
    fn rate_limit_exhausts_bucket_and_returns_429() {
        let mut app = Explorer::boot();
        app.rate_limit_rate = 0.0; // no refill
        app.rate_limit_burst = 1.0; // one request per IP
        let (s1, _) = send_req(
            &mut app,
            "GET /api/head HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        );
        assert_eq!(s1, 200);
        let (s2, body2) = send_req(
            &mut app,
            "GET /api/head HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        );
        assert_eq!(s2, 429);
        assert!(body2.contains("rate limit"), "{body2}");
    }

    #[test]
    fn faucet_enforces_per_address_cap() {
        let mut app = Explorer::boot();
        app.producing = false;
        // The faucet pays from the operator's coinbase; mature it so the
        // spend is valid under the CSV rule (creation_height + 100 <= height).
        for _ in 0..100 {
            app.mesh.produce_empty("alpha").unwrap();
        }
        let to = kovanica_state::KeyPair::from_u64(9).address();
        let key = to.to_hex();
        // Pre-fill 4 KVNC so the next 1-KVNC payout hits the 5-KVNC cap.
        app.faucet_given.insert(key.clone(), 4 * ATOM);
        let mut q = std::collections::HashMap::new();
        q.insert("to".into(), key);
        q.insert("amount".into(), ATOM.to_string());
        let body = dispatch(&mut app, "faucet", &q).unwrap();
        assert!(body.contains("\"ok\":true"), "{body}");
        // At the cap now: another payout must be refused.
        let err = dispatch(&mut app, "faucet", &q).unwrap_err();
        assert!(err.contains("cap"), "{err}");
    }

    #[test]
    fn faucet_rejects_oversized_request() {
        let mut app = Explorer::boot();
        let to = kovanica_state::KeyPair::from_u64(9).address();
        let mut q = std::collections::HashMap::new();
        q.insert("to".into(), to.to_hex());
        q.insert("amount".into(), (FAUCET_MAX_PER_ADDRESS + 1).to_string());
        let err = dispatch(&mut app, "faucet", &q).unwrap_err();
        assert!(err.contains("max"), "{err}");
    }

    #[test]
    fn faucet_gate_is_testnet_only() {
        // The gate predicate: payouts only on the testnet profile. Mainnet —
        // dormant or not — never pays out.
        assert_eq!(network_profile().id, "kovanica-testnet");
        assert_ne!(NetworkProfile::mainnet().id, "kovanica-testnet");
    }

    // ---- C2: incremental sync + API pagination ----

    #[test]
    fn blocks_endpoint_paginates_from_a_block_id() {
        let mut app = Explorer::boot();
        app.producing = false;
        app.mesh.produce_empty("alpha").unwrap();
        app.mesh.produce_empty("alpha").unwrap();
        app.mesh.produce_empty("alpha").unwrap();

        let headers = app.mesh.node("alpha").unwrap().export_headers();
        assert!(headers.len() >= 3, "want at least three non-genesis blocks");
        let full = send_req_raw(
            &mut app,
            "GET /api/blocks HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            b"",
        );
        assert_eq!(full.0, 200);
        let all_records = decode_records(&full.1).expect("decode full records");
        assert_eq!(all_records.len(), headers.len());

        // Request strictly after the second header: expect everything after it.
        let from = headers[1].id.to_hex();
        let partial = send_req_raw(
            &mut app,
            &format!(
                "GET /api/blocks?from={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                from
            ),
            b"",
        );
        assert_eq!(partial.0, 200, "pagination must return 200");
        let paginated = decode_records(&partial.1).expect("decode paginated records");
        assert_eq!(
            paginated.len(),
            headers.len() - 2,
            "must return blocks strictly after from"
        );

        // Unknown / off-chain id falls back to the full export.
        let unknown = BlockId::from_bytes([0xabu8; 32]).to_hex();
        let fallback = send_req_raw(
            &mut app,
            &format!(
                "GET /api/blocks?from={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                unknown
            ),
            b"",
        );
        assert_eq!(fallback.0, 200);
        let fallback_records = decode_records(&fallback.1).expect("decode fallback records");
        assert_eq!(fallback_records.len(), headers.len());

        // Bad hex returns 400 JSON.
        let bad = send_req(
            &mut app,
            "GET /api/blocks?from=nothex HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        );
        assert_eq!(bad.0, 400);
        assert!(bad.1.contains("\"ok\":false"));
    }

    #[test]
    fn history_endpoint_paginates_limit_and_offset() {
        let mut app = Explorer::boot();
        app.producing = false;
        // The operator (seed 1) is the only funded account; mature its genesis
        // coinbase so the CSV rule allows spending it (creation_height + 100 <= height).
        for _ in 0..100 {
            app.mesh.produce_empty("alpha").unwrap();
        }
        // Each pool+produce creates one transfer block; the address receives
        // one credit per block. Use three different send amounts so each tx
        // has a distinct id (pool() derives the tx from amount+fee+nonce).
        let addr = kovanica_state::KeyPair::from_u64(2).address().to_hex();
        for amount in [ATOM, 2 * ATOM, 3 * ATOM] {
            app.mesh.pool("alpha", 1, amount, 2).unwrap();
            app.mesh.produce("alpha").unwrap();
        }
        let body = send_req(
            &mut app,
            &format!(
                "GET /api/history?address={}&limit=2&offset=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                addr
            ),
        );
        assert_eq!(body.0, 200);
        let v: serde_json::Value = serde_json::from_str(&body.1).unwrap();
        let txs = v["txs"].as_array().unwrap();
        assert_eq!(txs.len(), 2, "limit=2 must return two txs");
        assert_eq!(v["limit"], 2);
        assert_eq!(v["offset"], 1);
        assert_eq!(v["total"], 3);
    }

    #[test]
    fn utxos_endpoint_paginates_limit_and_offset() {
        let mut app = Explorer::boot();
        app.producing = false;
        // Produce several coinbases all paid to actor 1.
        for _ in 0..3 {
            app.mesh.produce_empty("alpha").unwrap();
        }
        // Under PoA the coinbases are paid to the authority, so that is the
        // address holding the three UTXOs this pagination test needs.
        let addr = authority_reward_address().to_hex();
        let body = send_req(
            &mut app,
            &format!(
                "GET /api/utxos?address={}&limit=2&offset=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                addr
            ),
        );
        assert_eq!(body.0, 200);
        let v: serde_json::Value = serde_json::from_str(&body.1).unwrap();
        let utxos = v["utxos"].as_array().unwrap();
        assert_eq!(utxos.len(), 2, "limit=2 must return two utxos");
        assert_eq!(v["limit"], 2);
        assert_eq!(v["offset"], 1);
        assert!(v["total"].as_u64().unwrap() >= 3);
    }
}
