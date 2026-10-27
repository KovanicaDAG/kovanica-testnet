//! Kovanica (KUNA) Faucet Service
//!
//! Rate-limited faucet that dispenses test KUNA to addresses.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use clap::Parser;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use zeroize::Zeroizing;

use ed25519_dalek::{Signer, SigningKey};
use kovanica_cli::wallet;
use kovanica_types::signing::chain_id;
use kovanica_types::{hash::Hash, Address, PublicKey, Signature, Transaction, TransactionKind};

mod cors;
mod proxy;

/// Faucet configuration
#[derive(Clone)]
struct FaucetConfig {
    /// Amount to dispense per request (in atoms)
    dispense_amount: u64,
    /// Rate limit window (seconds)
    rate_limit_window: u64,
    /// Max requests per window per IP
    max_requests_per_window: usize,
    /// RPC endpoint of the node
    rpc_url: String,
    /// Network signing context (signature format v1): every dispensed
    /// transaction commits to this `chain_id`.
    signing_ctx: kovanica_types::SigningContext,
    /// Reverse proxies whose `X-Forwarded-For` header may be trusted for
    /// rate-limit keying. Empty means every request keys on the socket peer.
    trusted_proxies: proxy::TrustedProxies,
    /// Refuse to dispense when the faucet's own balance (in atoms) is below
    /// this. `0` disables the check.
    min_balance_atoms: u64,
}

/// Rate limiter state
#[derive(Default)]
struct RateLimiter {
    requests: Mutex<std::collections::HashMap<String, Vec<std::time::Instant>>>,
}

impl RateLimiter {
    fn check_and_record(&self, ip: &str, window_secs: u64, max_requests: usize) -> bool {
        let mut requests = self.requests.lock();
        let now = std::time::Instant::now();
        let window_start = now - Duration::from_secs(window_secs);

        let entry = requests.entry(ip.to_string()).or_default();
        entry.retain(|t| *t > window_start);

        if entry.len() >= max_requests {
            return false;
        }

        entry.push(now);
        true
    }
}

/// Faucet state
struct FaucetState {
    config: FaucetConfig,
    signer: SigningKey,
    faucet_address: Address,
    rate_limiter: RateLimiter,
    client: reqwest::Client,
}

/// Request payload
#[derive(Deserialize)]
struct FaucetRequest {
    address: String,
}

/// Response payload
#[derive(Serialize)]
struct FaucetResponse {
    success: bool,
    message: String,
    tx_hash: Option<String>,
}

#[derive(Parser)]
#[command(name = "kovanica-faucet")]
#[command(about = "Kovanica (KUNA) Faucet Service")]
struct Cli {
    /// Faucet keystore path
    #[arg(long, default_value = "faucet.keystore")]
    keystore: String,
    /// File containing the keystore passphrase (unix: must be 0600 or 0400).
    /// Alternatives: env KOVANICA_FAUCET_PASSPHRASE, or an interactive prompt on a TTY.
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
    /// Amount to dispense per request (in KUNA)
    #[arg(long, default_value = "10")]
    dispense_kovanica: u64,
    /// Rate limit window (seconds)
    #[arg(long, default_value = "3600")]
    rate_limit_window: u64,
    /// Max requests per window per IP
    #[arg(long, default_value = "3")]
    max_requests: usize,
    /// Network chain_id committed to by every transaction signature
    /// (1 mainnet, 2 testnet, 3 devnet, 1337 local). No default on purpose.
    #[arg(long)]
    chain_id: u64,
    /// Loud override required to run the faucet on MAINNET (chain_id 1).
    /// Default behaviour is to refuse mainnet outright.
    ///
    /// Equivalent to setting `KOVANICA_FAUCET_ALLOW_MAINNET=1`.
    #[arg(long)]
    allow_mainnet: bool,
    /// Comma-separated list of reverse-proxy IPs/CIDRs whose `X-Forwarded-For`
    /// header is trusted for rate-limit keying (e.g. `10.0.0.0/8,127.0.0.1`).
    ///
    /// When unset (or the socket peer is not in the list) the socket peer IP is
    /// used and `X-Forwarded-For` is ignored. Equivalent to
    /// `KOVANICA_FAUCET_TRUSTED_PROXIES`.
    #[arg(long)]
    trusted_proxies: Option<String>,
    /// Refuse requests when the faucet balance (in KUNA) is below this floor.
    /// `0` (default) disables the low-balance guard.
    #[arg(long, default_value = "0")]
    min_balance_ku: u64,
    /// Node RPC URL
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc_url: String,
    /// Listen address
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // MAINNET GUARD: never dispense real KUNA by accident. Running on chain_id 1
    // requires an explicit, loudly-named override.
    let allow_mainnet = cli.allow_mainnet || env_truthy(ALLOW_MAINNET_ENV);
    ensure_chain_allowed(cli.chain_id, allow_mainnet)?;
    if cli.chain_id == chain_id::MAINNET {
        warn!(
            chain_id = cli.chain_id,
            "running the faucet on MAINNET with the explicit --allow-mainnet override: \
             it will dispense REAL KUNA"
        );
    }

    // Trusted reverse proxies for X-Forwarded-For handling. A malformed entry
    // fails startup rather than silently trusting (or not trusting) the wrong hosts.
    let trusted_proxies_raw = cli
        .trusted_proxies
        .clone()
        .or_else(|| std::env::var(TRUSTED_PROXIES_ENV).ok());
    let trusted_proxies = match trusted_proxies_raw.as_deref() {
        Some(list) => proxy::TrustedProxies::parse_list(list)
            .with_context(|| format!("parsing trusted proxies `{list}`"))?,
        None => proxy::TrustedProxies::default(),
    };
    if !trusted_proxies.is_empty() {
        info!("trusting X-Forwarded-For from configured reverse proxies");
    }

    // Load faucet keystore
    let keystore = wallet::load(std::path::Path::new(&cli.keystore))
        .with_context(|| format!("loading faucet keystore {}", cli.keystore))?;
    // The passphrase is only needed to decrypt the seed; it is wiped right
    // after and never stored in config/state or logged.
    let cli_passphrase = if keystore.encrypted {
        Some(resolve_passphrase(cli.passphrase_file.as_deref())?)
    } else {
        None
    };
    let passphrase = cli_passphrase.as_ref().map(|p| p.as_str());
    let seed =
        wallet::secret_seed(&keystore, passphrase).with_context(|| "decrypting faucet keystore")?;
    let signer = SigningKey::from_bytes(&seed);
    drop(cli_passphrase);
    let faucet_address = Address::from_public_key(&PublicKey::from(signer.verifying_key()));

    info!(faucet_address = %faucet_address, "faucet identity loaded");

    let config = FaucetConfig {
        dispense_amount: cli.dispense_kovanica * 1_000_000_000, // KUNA to atoms
        rate_limit_window: cli.rate_limit_window,
        max_requests_per_window: cli.max_requests,
        rpc_url: normalize_rpc_url(&cli.rpc_url),
        signing_ctx: kovanica_types::SigningContext::new(cli.chain_id),
        trusted_proxies,
        min_balance_atoms: cli.min_balance_ku * 1_000_000_000, // KUNA to atoms
    };

    let state = Arc::new(FaucetState {
        config,
        signer,
        faucet_address,
        rate_limiter: RateLimiter::default(),
        client: reqwest::Client::new(),
    });

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/faucet", post(faucet_handler))
        .with_state(state)
        .layer(axum::middleware::from_fn(cors::faucet_cors));

    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    info!(addr = %cli.listen, "faucet server listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Env override that permits running the faucet on mainnet.
const ALLOW_MAINNET_ENV: &str = "KOVANICA_FAUCET_ALLOW_MAINNET";

/// Env override with the comma-separated trusted-proxy IP/CIDR list.
const TRUSTED_PROXIES_ENV: &str = "KOVANICA_FAUCET_TRUSTED_PROXIES";

/// Whether an environment variable holds an affirmative boolean value
/// (`1`, `true`, `yes` or `on`, case-insensitive).
fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Validate the configured `chain_id`.
///
/// * unregistered ids are always refused;
/// * `chain_id 1` (mainnet) is refused unless `allow_mainnet` was given
///   explicitly — the faucet would otherwise dispense real KUNA.
fn ensure_chain_allowed(chain_id: u64, allow_mainnet: bool) -> Result<()> {
    if !kovanica_types::signing::chain_id::is_registered(chain_id) {
        bail!(
            "unknown chain id {}: expected 1 (mainnet), 2 (testnet), 3 (devnet), 4 (testnet v2) or 1337 (local)",
            chain_id
        );
    }
    if chain_id == chain_id::MAINNET && !allow_mainnet {
        bail!(
            "refusing to run the faucet on MAINNET (chain_id 1): it would dispense REAL KUNA. \
             If this is intentional, pass --allow-mainnet or set {ALLOW_MAINNET_ENV}=1."
        );
    }
    Ok(())
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

async fn faucet_handler(
    State(state): State<Arc<FaucetState>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<FaucetRequest>,
) -> impl IntoResponse {
    // Resolve the client IP for rate limiting. `X-Forwarded-For` is only
    // honoured when the socket peer is a configured trusted proxy.
    let forwarded_for = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let ip = proxy::client_ip(peer.ip(), forwarded_for, &state.config.trusted_proxies);
    let ip_str = ip.to_string();

    // Check rate limit
    if !state.rate_limiter.check_and_record(
        &ip_str,
        state.config.rate_limit_window,
        state.config.max_requests_per_window,
    ) {
        warn!(ip = %ip_str, "rate limit exceeded");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(FaucetResponse {
                success: false,
                message: format!(
                    "Rate limit exceeded. Max {} requests per {} seconds.",
                    state.config.max_requests_per_window, state.config.rate_limit_window
                ),
                tx_hash: None,
            }),
        )
            .into_response();
    }

    // Parse destination address
    let to_address = match parse_address(&req.address, state.config.signing_ctx.chain_id) {
        Ok(addr) => addr,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(FaucetResponse {
                    success: false,
                    message: format!("Invalid address: {}", e),
                    tx_hash: None,
                }),
            )
                .into_response();
        }
    };

    // Prevent faucet from sending to itself
    if to_address == state.faucet_address {
        return (
            StatusCode::BAD_REQUEST,
            Json(FaucetResponse {
                success: false,
                message: "Faucet cannot send to itself".to_string(),
                tx_hash: None,
            }),
        )
            .into_response();
    }

    // Low-balance guard: refuse early when the faucet is running dry, so callers
    // get a clear error instead of a transaction that fails on-chain.
    if state.config.min_balance_atoms > 0 {
        match get_balance(&state.client, &state.config.rpc_url, &state.faucet_address).await {
            Ok(balance) if balance < state.config.min_balance_atoms => {
                warn!(
                    balance,
                    threshold = state.config.min_balance_atoms,
                    "faucet balance below minimum; refusing to dispense"
                );
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(FaucetResponse {
                        success: false,
                        message: "Faucet is low on funds; try again later.".to_string(),
                        tx_hash: None,
                    }),
                )
                    .into_response();
            }
            Ok(balance) => {
                tracing::debug!(balance, "faucet balance above minimum");
            }
            Err(e) => {
                // A transient balance-read error must not take the faucet down;
                // the nonce fetch below will surface a hard RPC outage anyway.
                warn!("Failed to read faucet balance: {}", e);
            }
        }
    }

    // Get faucet nonce from RPC
    let nonce = match get_nonce(&state.client, &state.config.rpc_url, &state.faucet_address).await {
        Ok(n) => n,
        Err(e) => {
            warn!("Failed to get faucet nonce: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(FaucetResponse {
                    success: false,
                    message: "Failed to get faucet nonce".to_string(),
                    tx_hash: None,
                }),
            )
                .into_response();
        }
    };

    // Build transaction
    let tx = Transaction {
        sender: state.faucet_address,
        nonce,
        fee: 1_000_000, // 0.001 KUNA fee
        kind: TransactionKind::Transfer {
            to: to_address,
            amount: state.config.dispense_amount,
        },
        signature: Signature([0; 64]),
        hash: Hash::zero(),
    };

    // Sign transaction
    let signed_tx = match sign_transaction(tx, &state.signer, &state.config.signing_ctx) {
        Ok(tx) => tx,
        Err(e) => {
            warn!("Failed to sign transaction: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(FaucetResponse {
                    success: false,
                    message: "Failed to sign transaction".to_string(),
                    tx_hash: None,
                }),
            )
                .into_response();
        }
    };

    // Submit transaction
    match submit_transaction(&state.client, &state.config.rpc_url, &signed_tx).await {
        Ok(tx_hash) => {
            info!(to = %to_address, amount = state.config.dispense_amount, tx_hash = %tx_hash, "faucet dispensed");
            (
                StatusCode::OK,
                Json(FaucetResponse {
                    success: true,
                    message: format!(
                        "Dispensed {} KUNA",
                        state.config.dispense_amount / 1_000_000_000
                    ),
                    tx_hash: Some(tx_hash),
                }),
            )
                .into_response()
        }
        Err(e) => {
            warn!("Failed to submit transaction: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(FaucetResponse {
                    success: false,
                    message: format!("Failed to submit transaction: {e}"),
                    tx_hash: None,
                }),
            )
                .into_response()
        }
    }
}

/// Parse a dispense destination for the faucet's chain.
///
/// Canonical base32 is accepted on every chain. Legacy hex is accepted only
/// where [`kovanica_types::address::legacy_address_allowed`] is true, so
/// chain 1 refuses it.
fn parse_address(s: &str, chain_id: u64) -> Result<Address> {
    Address::parse_for_chain(s, chain_id).context("invalid address")
}

fn normalize_rpc_url(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    if trimmed.ends_with("/rpc") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/rpc")
    }
}

async fn get_nonce(client: &reqwest::Client, rpc_url: &str, address: &Address) -> Result<u64> {
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "kovanica_getNonce",
        "params": [address.to_string()],
        "id": 1
    });
    let resp: serde_json::Value = client.post(rpc_url).json(&req).send().await?.json().await?;
    if let Some(err) = resp.get("error") {
        anyhow::bail!("rpc error: {err}");
    }
    let result = resp
        .get("result")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("invalid nonce response: {resp}"))?;
    let nonce = u64::from_str_radix(result.strip_prefix("0x").unwrap_or(result), 16)?;
    Ok(nonce)
}

async fn get_balance(client: &reqwest::Client, rpc_url: &str, address: &Address) -> Result<u64> {
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "kovanica_getBalance",
        "params": [address.to_string()],
        "id": 1
    });
    let resp: serde_json::Value = client.post(rpc_url).json(&req).send().await?.json().await?;
    if let Some(err) = resp.get("error") {
        anyhow::bail!("rpc error: {err}");
    }
    let result = resp
        .get("result")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("invalid balance response: {resp}"))?;
    let balance = u64::from_str_radix(result.strip_prefix("0x").unwrap_or(result), 16)?;
    Ok(balance)
}

fn sign_transaction(
    mut tx: Transaction,
    signer: &SigningKey,
    ctx: &kovanica_types::SigningContext,
) -> Result<Transaction> {
    let msg = tx.signing_hash(ctx);
    let sig = signer.sign(&msg.0);
    tx.signature = Signature(sig.to_bytes());
    tx.hash = msg; // signing_hash(ctx) is the v1 domain- and chain-separated hash
    Ok(tx)
}

async fn submit_transaction(
    client: &reqwest::Client,
    rpc_url: &str,
    tx: &Transaction,
) -> Result<String> {
    let raw = bincode::serialize(tx)?;
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "kovanica_sendRawTransaction",
        "params": [hex::encode(raw)],
        "id": 1
    });
    let resp: serde_json::Value = client.post(rpc_url).json(&req).send().await?.json().await?;
    if let Some(err) = resp.get("error") {
        anyhow::bail!("rpc error: {err}");
    }
    let result = resp
        .get("result")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("invalid tx submit response: {resp}"))?;
    Ok(result.to_string())
}

/// Environment variable holding the faucet keystore passphrase.
const PASSPHRASE_ENV: &str = "KOVANICA_FAUCET_PASSPHRASE";

/// Resolve the keystore passphrase without ever taking it from argv.
///
/// Order: `--passphrase-file`, then `KOVANICA_FAUCET_PASSPHRASE`, then an
/// interactive no-echo prompt if stdin is a TTY. Errors if none is available.
fn resolve_passphrase(file: Option<&Path>) -> Result<Zeroizing<String>> {
    let env = std::env::var(PASSPHRASE_ENV).ok().map(Zeroizing::new);
    resolve_passphrase_from(file, env, || {
        if std::io::stdin().is_terminal() {
            let p = rpassword::prompt_password("Faucet keystore passphrase: ")
                .context("reading passphrase from TTY")?;
            Ok(Some(Zeroizing::new(p)))
        } else {
            Ok(None)
        }
    })
}

fn resolve_passphrase_from<F>(
    file: Option<&Path>,
    env: Option<Zeroizing<String>>,
    prompt: F,
) -> Result<Zeroizing<String>>
where
    F: FnOnce() -> Result<Option<Zeroizing<String>>>,
{
    if let Some(path) = file {
        return read_passphrase_file(path);
    }
    if let Some(p) = env {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    if let Some(p) = prompt()? {
        return Ok(p);
    }
    bail!(
        "keystore is encrypted but no passphrase source is available: \
         use --passphrase-file <path>, set {PASSPHRASE_ENV}, or run on a TTY"
    )
}

fn read_passphrase_file(path: &Path) -> Result<Zeroizing<String>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .with_context(|| format!("reading metadata of passphrase file {}", path.display()))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "refusing passphrase file {}: permissions {:o} are too broad (use 0600 or 0400)",
                path.display(),
                mode
            );
        }
    }
    let mut raw = Zeroizing::new(
        std::fs::read_to_string(path)
            .with_context(|| format!("reading passphrase file {}", path.display()))?,
    );
    while raw.ends_with('\n') || raw.ends_with('\r') {
        raw.pop();
    }
    if raw.is_empty() {
        bail!("passphrase file {} is empty", path.display());
    }
    Ok(raw)
}

#[cfg(test)]
mod passphrase_tests {
    use super::*;
    use std::io::Write;

    fn write_file(contents: &str, mode: u32) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        f
    }

    fn no_prompt() -> Result<Option<Zeroizing<String>>> {
        Ok(None)
    }

    #[test]
    fn file_trims_trailing_newline_and_wins_over_env() {
        let f = write_file("s3cret\r\n", 0o600);
        let env = Some(Zeroizing::new("from-env".to_string()));
        let p = resolve_passphrase_from(Some(f.path()), env, no_prompt).unwrap();
        assert_eq!(p.as_str(), "s3cret");
    }

    #[test]
    fn file_0400_is_accepted() {
        let f = write_file("pw\n", 0o400);
        assert_eq!(read_passphrase_file(f.path()).unwrap().as_str(), "pw");
    }

    #[cfg(unix)]
    #[test]
    fn file_with_broad_permissions_is_refused() {
        let f = write_file("pw\n", 0o644);
        let err = read_passphrase_file(f.path()).unwrap_err().to_string();
        assert!(err.contains("too broad"), "{err}");
        assert!(!err.contains("pw\n"));
    }

    #[test]
    fn env_used_when_no_file() {
        let env = Some(Zeroizing::new("from-env".to_string()));
        let p = resolve_passphrase_from(None, env, no_prompt).unwrap();
        assert_eq!(p.as_str(), "from-env");
    }

    #[test]
    fn prompt_used_as_last_resort() {
        let p =
            resolve_passphrase_from(None, None, || Ok(Some(Zeroizing::new("typed".to_string()))))
                .unwrap();
        assert_eq!(p.as_str(), "typed");
    }

    #[test]
    fn errors_clearly_when_no_source() {
        let err = resolve_passphrase_from(None, Some(Zeroizing::new(String::new())), no_prompt)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("--passphrase-file") && err.contains(PASSPHRASE_ENV),
            "{err}"
        );
    }
}

#[cfg(test)]
mod guard_tests {
    use super::*;

    #[test]
    fn unknown_chain_ids_are_always_refused() {
        for id in [0, 42, u64::MAX] {
            let err = ensure_chain_allowed(id, true).unwrap_err().to_string();
            assert!(err.contains("unknown chain id"), "{err}");
        }
    }

    #[test]
    fn mainnet_is_refused_without_the_explicit_override() {
        let err = ensure_chain_allowed(chain_id::MAINNET, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("MAINNET"), "{err}");
        assert!(err.contains("--allow-mainnet"), "{err}");
        assert!(err.contains(ALLOW_MAINNET_ENV), "{err}");
    }

    #[test]
    fn mainnet_is_allowed_with_the_explicit_override() {
        ensure_chain_allowed(chain_id::MAINNET, true).expect("explicit override permits mainnet");
    }

    #[test]
    fn non_mainnet_networks_do_not_need_the_override() {
        for id in [
            chain_id::TESTNET,
            chain_id::DEVNET,
            chain_id::TESTNET_V2,
            chain_id::LOCAL,
        ] {
            ensure_chain_allowed(id, false).expect("non-mainnet chain is allowed");
        }
    }

    #[test]
    fn env_truthy_accepts_common_affirmatives() {
        let name = "KOVANICA_FAUCET_TEST_TRUTHY_FLAG";
        for truthy in ["1", "true", "TRUE", " yes ", "on"] {
            std::env::set_var(name, truthy);
            assert!(env_truthy(name), "{truthy:?} should be truthy");
        }
        for falsy in ["0", "false", "off", "", "maybe"] {
            std::env::set_var(name, falsy);
            assert!(!env_truthy(name), "{falsy:?} should not be truthy");
        }
        std::env::remove_var(name);
        assert!(!env_truthy(name), "unset variable is falsy");
    }

    #[test]
    fn parse_address_accepts_canonical_kvnc_dag_format() {
        let pk_bytes = [1u8; 32];
        let address = Address(pk_bytes);
        let canonical = address.encode();
        let parsed = parse_address(&canonical, chain_id::MAINNET).expect("canonical format parses");
        assert_eq!(parsed.to_hex(), address.to_hex());
    }

    #[test]
    fn parse_address_rejects_invalid_canonical_checksum() {
        let pk_bytes = [2u8; 32];
        let address = Address(pk_bytes);
        let canonical = address.encode();
        let mut bad_canonical = canonical.clone();
        let checksum_start = bad_canonical.len() - "dag".len() - 8;
        bad_canonical.replace_range(checksum_start..checksum_start + 2, "ff");
        let err = parse_address(&bad_canonical, chain_id::MAINNET).unwrap_err();
        assert!(
            err.to_string().contains("invalid address"),
            "got error: {}",
            err
        );
    }

    /// Chain 1 refuses legacy hex. Devnet, chain 4, and local still accept it.
    #[test]
    fn parse_address_follows_the_chain_policy() {
        let pk_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let address = Address(hex::decode(pk_hex).unwrap().try_into().expect("32 bytes"));
        let forms = [
            pk_hex.to_string(),
            format!("0x{pk_hex}"),
            address.encode_legacy_hex(),
        ];
        for form in &forms {
            let err = parse_address(form, chain_id::MAINNET).unwrap_err();
            assert!(
                format!("{err:#}").contains("not accepted"),
                "{form} on chain 1: {err:#}"
            );
            for chain in [chain_id::DEVNET, chain_id::LOCAL, chain_id::TESTNET_V2] {
                let parsed = parse_address(form, chain)
                    .unwrap_or_else(|e| panic!("{form} on chain {chain}: {e:#}"));
                assert_eq!(parsed, address);
            }
        }
    }
}
