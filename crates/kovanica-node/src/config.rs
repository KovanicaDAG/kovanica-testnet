//! Node configuration.
//!
//! Configuration is loaded from a TOML file (path supplied on the command line)
//! and can be overridden per-field by `KOVANICA_*` environment variables, which is
//! the recommended way to configure containerised deployments.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result};
use serde::Deserialize;

fn default_enabled() -> bool {
    true
}

/// Runtime configuration for a Kovanica node.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NodeConfig {
    /// Directory where chain data (consensus + state databases) is stored.
    pub data_dir: PathBuf,
    /// P2P listen address, either `host:port` or a full libp2p multiaddr.
    pub listen_addr: String,
    /// JSON-RPC bind address (IP or hostname).
    pub rpc_addr: String,
    /// JSON-RPC port.
    pub rpc_port: u16,
    /// Bootstrap peers, each `host:port` or a libp2p multiaddr.
    pub bootnodes: Vec<String>,
    /// Path to a validator signing key file (32-byte hex seed).
    pub validator_key: Option<String>,
    /// Target consensus round duration in milliseconds.
    pub round_duration_ms: u64,
    /// Maximum number of connected peers.
    pub max_peers: usize,
    /// Genesis treasury address (32-byte hex). Defaults to the zero address.
    pub treasury_address: Option<String>,
    /// Order committed waves with scoped GHOSTDAG.
    ///
    /// Default on. `KOVANICA_MYSTICGHOST=false` selects the linearizer path.
    /// A live mesh must take this change together: colouring changes which
    /// blocks a commit executes.
    #[serde(default = "default_enabled")]
    pub use_mysticghost: bool,
    /// Stake-weighted VRF leader election.
    ///
    /// Default on. The leader of round R is the VRF winner over verified
    /// outputs from the previous decide round, and only when every authority
    /// that has a VRF key published one. Otherwise the leader stays
    /// round-robin. `KOVANICA_VRF_LEADER=false` forces round-robin.
    #[serde(default = "default_enabled")]
    pub use_vrf_leader: bool,
    /// Run as a validator (produce blocks, participate in consensus).
    /// When false, the node runs as an RPC/read-only node without consensus participation.
    pub run_validator: bool,
    /// Enforce MIN_ACTIVE_VALIDATORS (15) as a hard floor for committee size.
    ///
    /// Default OFF. When enabled, `build_committee` will fail if fewer than
    /// 15 active validators with sufficient stake exist. It will NOT
    /// automatically fill the committee from offline/spare validators, and
    /// NEVER returns offline/slashed validators automatically. Explicit
    /// `reactivate_validator` stake tx is the only allowed re-entry path.
    /// Overridable with `KOVANICA_ENFORCE_MIN_ACTIVE_VALIDATORS`.
    #[serde(default)]
    pub enforce_min_active_validators: bool,
    /// JSON-RPC rate limit, in requests per minute per client IP. `0` disables
    /// rate limiting. Overridable with `KOVANICA_RPC_RATE_LIMIT_PER_MIN`.
    pub rpc_rate_limit_per_min: u32,
    /// Seconds without a new committed leader after which `/health` reports
    /// `degraded` (HTTP 503). Prevents a *false green*: consensus keeps
    /// advancing rounds and gossip while the commit rule has stalled, so
    /// component state alone cannot detect a chain that never advances.
    /// `0` disables the check. Overridable with
    /// `KOVANICA_HEALTH_COMMIT_STALL_SECS`.
    pub health_commit_stall_secs: u64,
    /// Chain id bound into every v1 signature (see `docs/SIGNATURE_FORMAT.md`):
    /// 1 mainnet, 2 testnet, 3 devnet, 1337 local. Must match the genesis
    /// chain id; the node refuses to start otherwise. For mainnet and testnet
    /// `genesis_validators.toml` must declare `chain_id` explicitly; for
    /// devnet and local it is optional. Overridable with `KOVANICA_CHAIN_ID`.
    pub chain_id: u64,
    /// Gossipsub peer scoring (`[peer_scoring]` table). Defaults are safe for
    /// a small validator network; see `kovanica_network::PeerScoringConfig`.
    pub peer_scoring: kovanica_network::PeerScoringConfig,

    // ------------------------------------------------------------------
    // Retention / pruning (opt-in: with every window unset the node never
    // deletes chain data). Each window is relative to the current tip and is
    // further clamped by the node's built-in safety margin, so an operator can
    // only ever tighten history, never cross the light-client floor.
    // ------------------------------------------------------------------
    /// Keep this many rounds of block history below the block-store tip.
    /// `None` (default) or `Some(0)` disables block pruning. Overridable with
    /// `KOVANICA_RETENTION_BLOCKS_BELOW_TIP`.
    #[serde(default)]
    pub retain_blocks_below_tip: Option<u64>,
    /// Keep state roots for this many committed heights below the tip.
    /// `None` (default) or `Some(0)` disables state-root pruning. Overridable
    /// with `KOVANICA_RETENTION_STATE_ROOTS_BELOW_HEIGHT`.
    #[serde(default)]
    pub retain_state_roots_below_height: Option<u64>,
    /// Keep transaction receipts for this many committed heights below the
    /// tip. `None` (default) or `Some(0)` disables receipt pruning.
    /// Overridable with `KOVANICA_RETENTION_RECEIPTS_BELOW_HEIGHT`.
    #[serde(default)]
    pub retain_receipts_below_height: Option<u64>,
    /// Seconds between retention maintenance passes. Only read when at least
    /// one window above is enabled. Overridable with
    /// `KOVANICA_RETENTION_INTERVAL_SECS`.
    #[serde(default = "default_retention_interval")]
    pub retention_interval_secs: u64,
    /// Maximum rows removed per store per retention pass, so a single pass over
    /// a long chain stays bounded. Overridable with `KOVANICA_RETENTION_BATCH`.
    #[serde(default = "default_retention_batch")]
    pub retention_batch: usize,
    /// A consensus-parameter environment override that the final `chain_id`
    /// forbids, recorded by [`NodeConfig::apply_env_overrides`] and rejected by
    /// [`NodeConfig::validate`].
    ///
    /// This lives on the struct rather than being read from the environment
    /// inside `validate`, so validation stays a pure function of the config and
    /// tests do not have to mutate process-global state. Never loaded from TOML.
    #[serde(skip)]
    pub forbidden_override: Option<&'static str>,
    /// `KOVANICA_ALLOW_GENESIS_MISMATCH` was set to an enabling value.
    ///
    /// Recorded by [`NodeConfig::apply_env_overrides`] and rejected by
    /// [`NodeConfig::validate`] on every chain that is not devnet (3) or local
    /// (1337). Checked before the data directory is created. Never loaded from
    /// TOML.
    #[serde(skip)]
    pub allow_genesis_mismatch: bool,
}

/// Env override that disables the genesis fork/contamination guard.
///
/// Enabling values are `1`, `true`, `yes` and `on`. Only dev chains may set
/// it; [`NodeConfig::validate`] refuses it on every other chain before the
/// data directory is created.
pub const ALLOW_GENESIS_MISMATCH_ENV: &str = "KOVANICA_ALLOW_GENESIS_MISMATCH";

/// True when `value` enables [`ALLOW_GENESIS_MISMATCH_ENV`].
///
/// Pure so the accepted spellings can be tested without the process environment.
pub fn genesis_mismatch_override_enabled(value: Option<&str>) -> bool {
    matches!(
        value
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn default_retention_interval() -> u64 {
    300
}

fn default_retention_batch() -> usize {
    10_000
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            listen_addr: "0.0.0.0:8000".to_string(),
            rpc_addr: "127.0.0.1".to_string(),
            rpc_port: 8545,
            // No hard-coded seeds: kovanica must never dial another project's
            // infrastructure. Populate via `KOVANICA_BOOTNODES` or `[node] bootnodes`.
            bootnodes: Vec::new(),
            validator_key: None,
            // 4 s round → 12 s per committed leader (wave = 3 rounds).
            round_duration_ms: 4000,
            max_peers: 50,
            treasury_address: None,
            use_mysticghost: true,
            use_vrf_leader: true,
            run_validator: true,
            enforce_min_active_validators: false,
            rpc_rate_limit_per_min: 60,
            health_commit_stall_secs: kovanica_rpc::health::DEFAULT_COMMIT_STALL_SECS,
            peer_scoring: kovanica_network::PeerScoringConfig::default(),
            chain_id: kovanica_types::signing::chain_id::LOCAL,
            // Pruning is opt-in: every retention window defaults to "keep
            // everything" so an unconfigured node never deletes data.
            retain_blocks_below_tip: None,
            retain_state_roots_below_height: None,
            retain_receipts_below_height: None,
            retention_interval_secs: 300,
            retention_batch: 10_000,
            forbidden_override: None,
            allow_genesis_mismatch: false,
        }
    }
}

/// Parse a `KOVANICA_*` retention window: unset or empty means "leave as is",
/// a valid integer overrides, and an invalid value is warned about and ignored.
fn env_retention_window(var: &str) -> Option<u64> {
    let Ok(raw) = std::env::var(var) else {
        return None;
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    match raw.parse() {
        Ok(value) => Some(value),
        Err(_) => {
            tracing::warn!(value = %raw, var, "ignoring invalid retention window");
            None
        }
    }
}

/// Environment variables that change consensus behavior and therefore may
/// only be set on a local development chain.
///
/// Round duration sets how often a validator proposes; VRF leader election and
/// MysticGhost change which block counts as the leader and how history is
/// ordered. Two nodes that disagree on any of them cannot commit together, so a
/// per-node override on a shared chain is a fork waiting to happen rather than a
/// tuning knob. `KOVANICA_CHAIN_ID` is deliberately not on this list: it selects
/// the network, and the genesis/config pin rejects a mismatch separately.
pub const FROZEN_CONSENSUS_ENV_VARS: [&str; 3] = [
    "KOVANICA_ROUND_DURATION_MS",
    "KOVANICA_MYSTICGHOST",
    "KOVANICA_VRF_LEADER",
];

/// First frozen consensus variable present in `present`, if any.
///
/// Presence is what matters, not the parsed value: `apply_env_overrides` only
/// warns about an unparseable value, and a value that happens to equal the
/// default is still a deployment mistake worth surfacing before it drifts.
fn first_frozen_override<'a, I>(present: I) -> Option<&'a str>
where
    I: IntoIterator<Item = &'a str>,
{
    present
        .into_iter()
        .find(|var| FROZEN_CONSENSUS_ENV_VARS.contains(var))
}

impl NodeConfig {
    /// Load configuration from a TOML file (if present) and apply environment
    /// overrides.
    ///
    /// A missing file is not an error: the built-in defaults are used and a
    /// warning is emitted. This lets a node boot from environment variables
    /// alone.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let mut config = if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read config file {}", path.display()))?;
            Self::from_toml_str(&text)
                .with_context(|| format!("failed to parse config file {}", path.display()))?
        } else {
            tracing::warn!(path = %path.display(), "config file not found; using defaults");
            Self::default()
        };
        config.apply_env_overrides();
        Ok(config)
    }

    /// Parse configuration from a TOML string (no environment overrides).
    pub fn from_toml_str(text: &str) -> Result<Self> {
        Ok(toml::from_str(text)?)
    }

    /// Apply `KOVANICA_*` environment variable overrides on top of the file values.
    pub fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("KOVANICA_DATA_DIR") {
            self.data_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("KOVANICA_LISTEN_ADDR") {
            self.listen_addr = v;
        }
        if let Ok(v) = std::env::var("KOVANICA_RPC_ADDR") {
            self.rpc_addr = v;
        }
        if let Ok(v) = std::env::var("KOVANICA_RPC_PORT") {
            match v.parse() {
                Ok(port) => self.rpc_port = port,
                Err(_) => tracing::warn!(value = %v, "ignoring invalid KOVANICA_RPC_PORT"),
            }
        }
        if let Ok(v) = std::env::var("KOVANICA_BOOTNODES") {
            self.bootnodes = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(v) = std::env::var("KOVANICA_VALIDATOR_KEY") {
            self.validator_key = Some(v);
        }
        if let Ok(v) = std::env::var("KOVANICA_ROUND_DURATION_MS") {
            match v.parse() {
                Ok(ms) => self.round_duration_ms = ms,
                Err(_) => tracing::warn!(value = %v, "ignoring invalid KOVANICA_ROUND_DURATION_MS"),
            }
        }
        if let Ok(v) = std::env::var("KOVANICA_MAX_PEERS") {
            match v.parse() {
                Ok(n) => self.max_peers = n,
                Err(_) => tracing::warn!(value = %v, "ignoring invalid KOVANICA_MAX_PEERS"),
            }
        }
        if let Ok(v) = std::env::var("KOVANICA_TREASURY_ADDRESS") {
            self.treasury_address = Some(v);
        }
        if let Ok(v) = std::env::var("KOVANICA_MYSTICGHOST") {
            match v.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => self.use_mysticghost = true,
                "0" | "false" | "no" | "off" => self.use_mysticghost = false,
                _ => tracing::warn!(value = %v, "ignoring invalid KOVANICA_MYSTICGHOST"),
            }
        }
        if let Ok(v) = std::env::var("KOVANICA_VRF_LEADER") {
            match v.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => self.use_vrf_leader = true,
                "0" | "false" | "no" | "off" => self.use_vrf_leader = false,
                _ => tracing::warn!(value = %v, "ignoring invalid KOVANICA_VRF_LEADER"),
            }
        }
        if let Ok(v) = std::env::var("KOVANICA_RUN_VALIDATOR") {
            match v.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => self.run_validator = true,
                "0" | "false" | "no" | "off" => self.run_validator = false,
                _ => tracing::warn!(value = %v, "ignoring invalid KOVANICA_RUN_VALIDATOR"),
            }
        }
        if let Ok(v) = std::env::var("KOVANICA_CHAIN_ID") {
            match v.trim().parse() {
                Ok(id) => self.chain_id = id,
                Err(_) => tracing::warn!(value = %v, "ignoring invalid KOVANICA_CHAIN_ID"),
            }
        }
        if let Ok(v) = std::env::var("KOVANICA_HEALTH_COMMIT_STALL_SECS") {
            match v.trim().parse() {
                Ok(secs) => self.health_commit_stall_secs = secs,
                Err(_) => tracing::warn!(
                    value = %v,
                    "ignoring invalid KOVANICA_HEALTH_COMMIT_STALL_SECS"
                ),
            }
        }
        if let Ok(v) = std::env::var("KOVANICA_RPC_RATE_LIMIT_PER_MIN") {
            match v.parse() {
                Ok(rate) => self.rpc_rate_limit_per_min = rate,
                Err(_) => {
                    tracing::warn!(value = %v, "ignoring invalid KOVANICA_RPC_RATE_LIMIT_PER_MIN")
                }
            }
        }
        if let Ok(v) = std::env::var("KOVANICA_ENFORCE_MIN_ACTIVE_VALIDATORS") {
            match v.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => self.enforce_min_active_validators = true,
                "0" | "false" | "no" | "off" => self.enforce_min_active_validators = false,
                _ => {
                    tracing::warn!(value = %v, "ignoring invalid KOVANICA_ENFORCE_MIN_ACTIVE_VALIDATORS")
                }
            }
        }
        // Retention / pruning windows. Unset or empty leaves the file/default
        // value untouched; `0` is accepted and means "keep everything".
        if let Some(v) = env_retention_window("KOVANICA_RETENTION_BLOCKS_BELOW_TIP") {
            self.retain_blocks_below_tip = Some(v);
        }
        if let Some(v) = env_retention_window("KOVANICA_RETENTION_STATE_ROOTS_BELOW_HEIGHT") {
            self.retain_state_roots_below_height = Some(v);
        }
        if let Some(v) = env_retention_window("KOVANICA_RETENTION_RECEIPTS_BELOW_HEIGHT") {
            self.retain_receipts_below_height = Some(v);
        }
        if let Ok(v) = std::env::var("KOVANICA_RETENTION_INTERVAL_SECS") {
            match v.trim().parse() {
                Ok(secs) => self.retention_interval_secs = secs,
                Err(_) => tracing::warn!(
                    value = %v,
                    "ignoring invalid KOVANICA_RETENTION_INTERVAL_SECS"
                ),
            }
        }
        if let Ok(v) = std::env::var("KOVANICA_RETENTION_BATCH") {
            match v.trim().parse() {
                Ok(batch) => self.retention_batch = batch,
                Err(_) => tracing::warn!(value = %v, "ignoring invalid KOVANICA_RETENTION_BATCH"),
            }
        }
        // Recorded here and rejected in `validate` so a non-dev chain fails
        // before `run_node` creates the data directory. Dev chains (3, 1337)
        // keep the override; every other chain must not set it.
        self.allow_genesis_mismatch = genesis_mismatch_override_enabled(
            std::env::var(ALLOW_GENESIS_MISMATCH_ENV).ok().as_deref(),
        );
        // Record (do not yet reject) a consensus-parameter override that the
        // final chain_id forbids. This runs last because `chain_id` is itself an
        // override; validation then turns the record into a hard error, so the
        // rule is shared by `--check-config` and the boot path.
        self.forbidden_override = if kovanica_types::signing::chain_id::is_dev(self.chain_id) {
            None
        } else {
            first_frozen_override(
                FROZEN_CONSENSUS_ENV_VARS
                    .iter()
                    .copied()
                    .filter(|var| std::env::var_os(var).is_some()),
            )
        };
    }

    /// True when at least one retention window is configured.
    ///
    /// Pruning is opt-in: a window of `None` or `Some(0)` keeps everything, and
    /// a node with no enabled window never runs the retention maintenance task.
    pub fn retention_enabled(&self) -> bool {
        self.retain_blocks_below_tip.is_some_and(|v| v > 0)
            || self.retain_state_roots_below_height.is_some_and(|v| v > 0)
            || self.retain_receipts_below_height.is_some_and(|v| v > 0)
    }

    /// Reject configurations the node cannot run safely with.
    ///
    /// Called at startup, after environment overrides are applied, so a
    /// misconfigured node fails fast instead of limping along on defaults.
    pub fn validate(&self) -> Result<()> {
        if self.run_validator
            && self
                .validator_key
                .as_deref()
                .is_none_or(|k| k.trim().is_empty())
        {
            anyhow::bail!(
                "run_validator=true requires validator_key (or KOVANICA_VALIDATOR_KEY) pointing at a 0600 seed file"
            );
        }
        if self.listen_addr.trim().is_empty() {
            anyhow::bail!("listen_addr must not be empty");
        }
        if self.round_duration_ms == 0 {
            anyhow::bail!("round_duration_ms must be greater than 0");
        }
        if self.max_peers == 0 {
            anyhow::bail!("max_peers must be greater than 0");
        }
        self.peer_scoring
            .validate()
            .map_err(|e| anyhow::anyhow!("peer_scoring: {e}"))?;
        if !kovanica_types::signing::chain_id::is_registered(self.chain_id) {
            anyhow::bail!(
                "chain_id {} is not registered (expected 1 mainnet, 2 testnet, 3 devnet, 4 testnet v2 or 1337 local)",
                self.chain_id
            );
        }
        // Before any data directory is created: the override is dev-only.
        // `!is_dev` covers chain 2 and every other non-dev chain, not only 1 and 4.
        if self.allow_genesis_mismatch && !kovanica_types::signing::chain_id::is_dev(self.chain_id)
        {
            anyhow::bail!(
                "{ALLOW_GENESIS_MISMATCH_ENV} must not be set on chain_id {}: it is only \
                 available on dev chains (3 devnet, 1337 local). Unset \
                 {ALLOW_GENESIS_MISMATCH_ENV}. On a shared chain a mismatched data dir \
                 is fixed by a wipe",
                self.chain_id
            );
        }
        // Consensus parameters must be identical on every node of a shared
        // chain; only devnet (3) and local (1337) may differ. The offending
        // variable was recorded when the environment was applied, so this check
        // is a pure function of the config.
        if let Some(var) = self.forbidden_override {
            anyhow::bail!(
                "{var} must not be set on chain_id {}: round duration, VRF leader election and \
                 MysticGhost mode are consensus parameters and must match every node. Unset \
                 {var}, or use chain_id 3 (devnet) or 1337 (local) for an experimental build",
                self.chain_id
            );
        }
        // Retention sanity: only meaningful when a window is enabled, and only
        // guards against a pass that could never make progress or would spin.
        if self.retention_enabled() {
            if self.retention_interval_secs == 0 {
                anyhow::bail!(
                    "retention_interval_secs must be greater than 0 when retention is enabled"
                );
            }
            if self.retention_batch == 0 {
                anyhow::bail!("retention_batch must be greater than 0 when retention is enabled");
            }
        }
        self.rpc_socket_addr()?;
        Ok(())
    }

    /// Resolve the JSON-RPC socket address.
    pub fn rpc_socket_addr(&self) -> Result<SocketAddr> {
        let raw = format!("{}:{}", self.rpc_addr, self.rpc_port);
        SocketAddr::from_str(&raw).with_context(|| format!("invalid rpc address `{raw}`"))
    }

    /// Path to the consensus (DAG) database file.
    pub fn consensus_db_path(&self) -> PathBuf {
        self.data_dir.join("consensus.redb")
    }

    /// Path to the state (accounts + staking) database file.
    pub fn state_db_path(&self) -> PathBuf {
        self.data_dir.join("state.redb")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Tests that touch `KOVANICA_*` environment variables must be serialised: the
    /// environment is process-global.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn config_loads_from_toml() {
        let _guard = env_guard();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node.toml");
        let mut file = std::fs::File::create(&path).expect("create config");
        write!(
            file,
            r#"
data_dir = "/tmp/kovanica-test-data"
listen_addr = "127.0.0.1:7000"
rpc_addr = "0.0.0.0"
rpc_port = 9999
bootnodes = ["seed1.kovanica.invalid:8000", "seed2.kovanica.invalid:8000", "127.0.0.1:7001"]
round_duration_ms = 500
max_peers = 7
treasury_address = "treasury-address-placeholder"
"#
        )
        .expect("write config");

        let config = NodeConfig::load(&path).expect("load config");
        assert_eq!(config.data_dir, PathBuf::from("/tmp/kovanica-test-data"));
        assert_eq!(config.listen_addr, "127.0.0.1:7000");
        assert_eq!(config.rpc_addr, "0.0.0.0");
        assert_eq!(config.rpc_port, 9999);
        assert_eq!(config.bootnodes.len(), 3);
        assert_eq!(config.round_duration_ms, 500);
        assert_eq!(config.max_peers, 7);
        assert!(config.validator_key.is_none());
        assert!(config.treasury_address.is_some());
        assert_eq!(config.rpc_socket_addr().expect("socket addr").port(), 9999);
        assert_eq!(
            config.consensus_db_path(),
            PathBuf::from("/tmp/kovanica-test-data/consensus.redb")
        );
    }

    #[test]
    fn missing_file_uses_defaults() {
        let _guard = env_guard();
        let dir = tempfile::tempdir().expect("tempdir");
        let config = NodeConfig::load(dir.path().join("does-not-exist.toml")).expect("defaults");
        assert_eq!(config.rpc_port, 8545);
        assert_eq!(config.max_peers, 50);
        assert_eq!(config.round_duration_ms, 4000);
        assert!(config.use_mysticghost);
        assert!(config.use_vrf_leader);
        assert!(
            config.bootnodes.is_empty(),
            "defaults must not hard-code third-party seed hosts"
        );
    }

    #[test]
    fn omitted_toml_flags_stay_on_and_env_can_turn_them_off() {
        let _guard = env_guard();
        let config = NodeConfig::from_toml_str("rpc_port = 8545").expect("parse");
        assert!(config.use_mysticghost);
        assert!(config.use_vrf_leader);

        std::env::set_var("KOVANICA_MYSTICGHOST", "false");
        std::env::set_var("KOVANICA_VRF_LEADER", "off");
        let mut config = NodeConfig::default();
        config.apply_env_overrides();
        std::env::remove_var("KOVANICA_MYSTICGHOST");
        std::env::remove_var("KOVANICA_VRF_LEADER");
        assert!(!config.use_mysticghost);
        assert!(!config.use_vrf_leader);
    }

    #[test]
    fn env_overrides_config() {
        let _guard = env_guard();
        let mut config = NodeConfig::default();
        std::env::set_var("KOVANICA_RPC_PORT", "1234");
        std::env::set_var("KOVANICA_MAX_PEERS", "3");
        config.apply_env_overrides();
        std::env::remove_var("KOVANICA_RPC_PORT");
        std::env::remove_var("KOVANICA_MAX_PEERS");
        assert_eq!(config.rpc_port, 1234);
        assert_eq!(config.max_peers, 3);
    }

    #[test]
    fn validate_requires_key_for_validators() {
        let mut config = NodeConfig::default();
        assert!(config.run_validator);
        assert!(
            config.validate().is_err(),
            "validator without key must fail"
        );

        config.validator_key = Some("   ".into());
        assert!(config.validate().is_err(), "blank key path must fail");

        config.validator_key = Some("/etc/kovanica/validator.key".into());
        config.validate().expect("validator with key path is valid");

        config.validator_key = None;
        config.run_validator = false;
        config
            .validate()
            .expect("non-validator may run without a key");
    }

    #[test]
    fn validate_rejects_nonsense_values() {
        let base = NodeConfig {
            run_validator: false,
            ..NodeConfig::default()
        };
        base.validate().expect("base is valid");

        let mut c = base.clone();
        c.round_duration_ms = 0;
        assert!(c.validate().is_err());

        let mut c = base.clone();
        c.max_peers = 0;
        assert!(c.validate().is_err());

        let mut c = base.clone();
        c.listen_addr = " ".into();
        assert!(c.validate().is_err());

        let mut c = base;
        c.rpc_addr = "not an ip".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn genesis_mismatch_override_is_refused_on_non_dev_chains() {
        let _guard = env_guard();
        std::env::set_var(ALLOW_GENESIS_MISMATCH_ENV, "1");
        let mut config = NodeConfig {
            run_validator: false,
            chain_id: 1,
            ..NodeConfig::default()
        };
        config.apply_env_overrides();
        std::env::remove_var(ALLOW_GENESIS_MISMATCH_ENV);
        assert!(config.allow_genesis_mismatch);

        for chain_id in [1, 2, 4] {
            config.chain_id = chain_id;
            let err = config
                .validate()
                .expect_err("non-dev chain must refuse the override");
            let msg = err.to_string();
            assert!(
                msg.contains(ALLOW_GENESIS_MISMATCH_ENV),
                "{chain_id}: {msg}"
            );
            assert!(msg.contains("must not be set"), "{chain_id}: {msg}");
            assert!(msg.contains("dev chains"), "{chain_id}: {msg}");
        }
        for chain_id in [3, 1337] {
            config.chain_id = chain_id;
            config
                .validate()
                .unwrap_or_else(|e| panic!("chain {chain_id} may set the override: {e}"));
        }

        // A disabling spelling does not request the override.
        std::env::set_var(ALLOW_GENESIS_MISMATCH_ENV, "false");
        config.chain_id = 2;
        config.apply_env_overrides();
        std::env::remove_var(ALLOW_GENESIS_MISMATCH_ENV);
        assert!(!config.allow_genesis_mismatch);
        config
            .validate()
            .expect("chain 2 without the override is valid");
    }

    #[test]
    fn validate_accepts_only_registered_chain_ids() {
        let base = NodeConfig {
            run_validator: false,
            ..NodeConfig::default()
        };
        assert_eq!(base.chain_id, 1337, "default is the local chain");
        for id in [1, 2, 3, 4, 1337] {
            let c = NodeConfig {
                chain_id: id,
                ..base.clone()
            };
            c.validate().expect("registered chain id is valid");
        }
        for id in [0, 42, u64::MAX] {
            let c = NodeConfig {
                chain_id: id,
                ..base.clone()
            };
            assert!(c.validate().is_err(), "chain id {id} must be rejected");
        }
    }

    #[test]
    fn peer_scoring_section_overrides_defaults_and_is_validated() {
        let config: NodeConfig =
            toml::from_str("run_validator = false\n[peer_scoring]\nban_threshold = -500.0\ngraylist_threshold = -200.0\n")
                .expect("parse");
        assert!(config.peer_scoring.enabled);
        assert_eq!(config.peer_scoring.ban_threshold, -500.0);
        assert_eq!(config.peer_scoring.graylist_threshold, -200.0);
        assert_eq!(config.peer_scoring.gossip_threshold, -10.0);
        config.validate().expect("valid");

        let bad: NodeConfig =
            toml::from_str("run_validator = false\n[peer_scoring]\nban_threshold = 5.0\n")
                .expect("parse");
        let err = bad.validate().expect_err("positive ban threshold");
        assert!(err.to_string().contains("peer_scoring"), "{err}");
    }

    #[test]
    fn retention_defaults_to_keeping_everything() {
        let config = NodeConfig::default();
        assert_eq!(config.retain_blocks_below_tip, None);
        assert_eq!(config.retain_state_roots_below_height, None);
        assert_eq!(config.retain_receipts_below_height, None);
        assert!(
            !config.retention_enabled(),
            "an unconfigured node must never prune"
        );

        // An explicit zero is accepted and still means "keep everything".
        let zeroed = NodeConfig {
            retain_blocks_below_tip: Some(0),
            retain_state_roots_below_height: Some(0),
            retain_receipts_below_height: Some(0),
            ..NodeConfig::default()
        };
        assert!(!zeroed.retention_enabled());
    }

    #[test]
    fn retention_windows_parse_from_toml() {
        let config: NodeConfig = toml::from_str(
            "run_validator = false\n\
             retain_blocks_below_tip = 10\n\
             retain_state_roots_below_height = 20\n\
             retain_receipts_below_height = 30\n\
             retention_interval_secs = 60\n\
             retention_batch = 5\n",
        )
        .expect("parse");
        assert_eq!(config.retain_blocks_below_tip, Some(10));
        assert_eq!(config.retain_state_roots_below_height, Some(20));
        assert_eq!(config.retain_receipts_below_height, Some(30));
        assert_eq!(config.retention_interval_secs, 60);
        assert_eq!(config.retention_batch, 5);
        assert!(config.retention_enabled());
        config.validate().expect("valid");
    }

    #[test]
    fn retention_env_overrides_parse() {
        let _guard = env_guard();
        std::env::set_var("KOVANICA_RETENTION_BLOCKS_BELOW_TIP", "10");
        std::env::set_var("KOVANICA_RETENTION_STATE_ROOTS_BELOW_HEIGHT", "20");
        std::env::set_var("KOVANICA_RETENTION_RECEIPTS_BELOW_HEIGHT", "30");
        std::env::set_var("KOVANICA_RETENTION_INTERVAL_SECS", "60");
        std::env::set_var("KOVANICA_RETENTION_BATCH", "7");
        let mut config = NodeConfig::default();
        config.apply_env_overrides();
        for var in [
            "KOVANICA_RETENTION_BLOCKS_BELOW_TIP",
            "KOVANICA_RETENTION_STATE_ROOTS_BELOW_HEIGHT",
            "KOVANICA_RETENTION_RECEIPTS_BELOW_HEIGHT",
            "KOVANICA_RETENTION_INTERVAL_SECS",
            "KOVANICA_RETENTION_BATCH",
        ] {
            std::env::remove_var(var);
        }
        assert_eq!(config.retain_blocks_below_tip, Some(10));
        assert_eq!(config.retain_state_roots_below_height, Some(20));
        assert_eq!(config.retain_receipts_below_height, Some(30));
        assert_eq!(config.retention_interval_secs, 60);
        assert_eq!(config.retention_batch, 7);
        assert!(config.retention_enabled());
    }

    #[test]
    fn invalid_retention_env_is_ignored() {
        let _guard = env_guard();
        let mut config = NodeConfig {
            retain_blocks_below_tip: Some(99),
            ..NodeConfig::default()
        };
        std::env::set_var("KOVANICA_RETENTION_BLOCKS_BELOW_TIP", "not-a-number");
        config.apply_env_overrides();
        std::env::remove_var("KOVANICA_RETENTION_BLOCKS_BELOW_TIP");
        assert_eq!(
            config.retain_blocks_below_tip,
            Some(99),
            "an invalid override must not clobber the configured value"
        );
    }

    #[test]
    fn validate_rejects_zero_retention_interval_when_enabled() {
        let mut config = NodeConfig {
            run_validator: false,
            retain_blocks_below_tip: Some(10),
            retention_interval_secs: 0,
            ..NodeConfig::default()
        };
        assert!(config.validate().is_err());

        config.retention_interval_secs = 300;
        config.retention_batch = 0;
        assert!(config.validate().is_err());

        config.retention_batch = 10_000;
        config.validate().expect("sane retention config");
    }
    /// The frozen list is exactly the consensus-shaping variables, and detection
    /// does not depend on ordering or on unrelated variables.
    #[test]
    fn frozen_override_detection_uses_the_declared_list() {
        assert_eq!(
            first_frozen_override(["KOVANICA_RPC_PORT", "KOVANICA_MYSTICGHOST"]),
            Some("KOVANICA_MYSTICGHOST")
        );
        assert_eq!(
            first_frozen_override(["KOVANICA_ROUND_DURATION_MS"]),
            Some("KOVANICA_ROUND_DURATION_MS")
        );
        assert_eq!(
            first_frozen_override(["KOVANICA_MAX_PEERS", "KOVANICA_DATA_DIR"]),
            None
        );
        // `chain_id` selects the network and is frozen a different way (the
        // genesis pin), so it must not appear in this list.
        assert!(!FROZEN_CONSENSUS_ENV_VARS.contains(&"KOVANICA_CHAIN_ID"));
        assert_eq!(FROZEN_CONSENSUS_ENV_VARS.len(), 3);
    }

    /// A public chain rejects a consensus override at validation time, naming
    /// the variable; a dev chain accepts the same environment.
    #[test]
    fn public_chain_rejects_consensus_env_overrides() {
        let _guard = env_guard();
        std::env::set_var("KOVANICA_ROUND_DURATION_MS", "250");

        let mut public = NodeConfig {
            run_validator: false,
            chain_id: kovanica_types::signing::chain_id::TESTNET_V2,
            ..NodeConfig::default()
        };
        public.apply_env_overrides();
        let err = public
            .validate()
            .expect_err("chain 4 must reject a round-duration override");
        let msg = err.to_string();
        assert!(
            msg.contains("KOVANICA_ROUND_DURATION_MS") && msg.contains("chain_id 4"),
            "error must name the variable and the chain, got: {msg}"
        );

        // Presence, not value, is what is rejected: an unparseable value is
        // ignored by `apply_env_overrides` but must still be flagged rather
        // than silently leaving an operator believing they changed something.
        std::env::set_var("KOVANICA_ROUND_DURATION_MS", "not-a-number");
        let mut bogus = NodeConfig {
            run_validator: false,
            chain_id: kovanica_types::signing::chain_id::MAINNET,
            ..NodeConfig::default()
        };
        bogus.apply_env_overrides();
        assert!(
            bogus.validate().is_err(),
            "a bogus override is still an override"
        );

        std::env::remove_var("KOVANICA_ROUND_DURATION_MS");

        // Same environment, dev chains: allowed.
        for chain in [
            kovanica_types::signing::chain_id::DEVNET,
            kovanica_types::signing::chain_id::LOCAL,
        ] {
            let mut dev = NodeConfig {
                run_validator: false,
                chain_id: chain,
                ..NodeConfig::default()
            };
            std::env::set_var("KOVANICA_VRF_LEADER", "false");
            dev.apply_env_overrides();
            std::env::remove_var("KOVANICA_VRF_LEADER");
            assert!(dev.validate().is_ok(), "chain {chain} must allow overrides");
            assert!(!dev.use_vrf_leader, "the override must still apply");
        }
    }

    /// Every frozen variable is covered, not just the first one tested.
    #[test]
    fn each_frozen_variable_is_rejected_on_a_public_chain() {
        let _guard = env_guard();
        for var in FROZEN_CONSENSUS_ENV_VARS {
            std::env::set_var(
                var,
                if var == "KOVANICA_ROUND_DURATION_MS" {
                    "250"
                } else {
                    "false"
                },
            );
            let mut config = NodeConfig {
                run_validator: false,
                chain_id: kovanica_types::signing::chain_id::TESTNET_V2,
                ..NodeConfig::default()
            };
            config.apply_env_overrides();
            let err = config.validate().expect_err(var);
            assert!(err.to_string().contains(var), "{var}: {err}");
            std::env::remove_var(var);
        }
    }
}
