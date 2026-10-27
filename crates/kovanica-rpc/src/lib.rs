//! JSON-RPC server for Kovanica nodes.

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use axum::{
    extract::{ws::WebSocketUpgrade, Extension, Json},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use kovanica_consensus::{
    metrics::{metrics_text, observe_rpc_request, record_rpc_error},
    CommitteeInfo,
};
use kovanica_mempool::Mempool;
use kovanica_staking::StakingState;
use kovanica_storage::Storage;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

mod chain_methods;
pub mod health;
mod openapi;
mod rpc_methods;
mod rpc_middleware;
mod subscriptions;
pub use chain_methods::*;
pub use health::{ComponentState, HealthSnapshot, NodeHealth};
pub use openapi::{generate_openapi_spec, write_openapi_json, write_openapi_yaml};
pub use rpc_methods::*;
pub use rpc_middleware::{
    console_cors, console_origin, rate_limit_middleware, AuthConfig, AuthError, RateLimitConfig,
    RateLimiterState, CONSOLE_ALLOWED_ORIGINS, WRITE_METHODS,
};

/// Upper bound on how long one JSON-RPC call may run. A handler stuck on a
/// lock or a wedged subsystem returns a timeout error instead of holding the
/// client connection (and a server task) forever.
pub const RPC_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub use subscriptions::{EventBus, SubscriptionKind};

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("Method not found: {0}")]
    MethodNotFound(String),
    #[error("Invalid params: {0}")]
    InvalidParams(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Execution error: {0}")]
    ExecutionError(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    #[error("Request timed out after {0:?}")]
    Timeout(std::time::Duration),
}

impl RpcError {
    fn code(&self) -> i32 {
        match self {
            RpcError::ParseError(_) => -32700,
            RpcError::InvalidRequest(_) => -32600,
            RpcError::MethodNotFound(_) => -32601,
            RpcError::InvalidParams(_) => -32602,
            RpcError::InternalError(_) => -32603,
            RpcError::ExecutionError(_) => -32000,
            RpcError::Unauthorized(_) => -32001,
            RpcError::NotImplemented(_) => -32004,
            RpcError::Timeout(_) => -32003,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<Value>,
    pub id: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcErrorObject>,
    pub id: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcErrorObject {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

type RpcHandler = Arc<
    dyn Fn(Value) -> Pin<Box<dyn std::future::Future<Output = Result<Value, RpcError>> + Send>>
        + Send
        + Sync,
>;

/// Shared state for RPC handlers providing access to node internals.
#[derive(Clone)]
pub struct RpcState {
    pub storage: Arc<Storage>,
    /// Consensus store (dag_store's consensus store) for block height, etc.
    pub consensus_store: Arc<kovanica_dag::DagStore>,
    pub mempool: Arc<Mempool>,
    pub staking: Arc<RwLock<StakingState>>,
    pub committee: Arc<RwLock<CommitteeInfo>>,
    /// Shared distinct connected-peer count maintained by the network service.
    pub peer_count: Arc<AtomicUsize>,
    /// Execution / consensus liveness reported by the node's background tasks.
    pub health: NodeHealth,
    /// Fan-out bus for WebSocket subscription events.
    pub events: EventBus,
    /// Rate limiter state
    pub rate_limiter: Arc<RateLimiterState>,
    /// Authentication config
    pub auth_config: Arc<AuthConfig>,
    /// Outbound gossip for transactions accepted via `kovanica_sendRawTransaction`.
    /// `None` disables publishing (tests, RPC-only setups).
    pub tx_gossip: Option<TxGossipSender>,
    /// Live sync / catch-up status source for the read-only `kovanica_syncStatus`
    /// method. `None` disables it beyond a bare peer count (tests, RPC-only
    /// setups).
    pub sync_status: Option<SyncStatusSource>,
}

/// Channel the node drains to publish RPC-submitted transactions on gossip,
/// through the same path as re-gossip of accepted transactions.
pub type TxGossipSender = tokio::sync::mpsc::UnboundedSender<kovanica_types::Transaction>;

#[derive(Clone)]
pub struct RpcServer {
    methods: Arc<RwLock<HashMap<String, RpcHandler>>>,
    addr: SocketAddr,
    state: RpcState,
}

impl RpcServer {
    pub async fn new(
        addr: SocketAddr,
        state: RpcState,
        rate_limit_config: Option<RateLimitConfig>,
        auth_config: Option<AuthConfig>,
    ) -> Self {
        let rate_limiter = Arc::new(RateLimiterState::new(rate_limit_config.unwrap_or_default()));
        let auth_config = Arc::new(auth_config.unwrap_or_default());

        let state = RpcState {
            rate_limiter,
            auth_config,
            ..state
        };

        let mut server = Self {
            methods: Arc::new(RwLock::new(HashMap::new())),
            addr,
            state,
        };
        server.register_default_methods().await;
        server
    }

    async fn register_default_methods(&mut self) {
        // Built-in contract methods (separate namespace).
        self.register_stateful("htlc_create", handle_htlc_create)
            .await;
        self.register_stateful("htlc_claim", handle_htlc_claim)
            .await;
        self.register_stateful("htlc_refund", handle_htlc_refund)
            .await;

        self.register_stateful("vault_create", handle_vault_create)
            .await;
        self.register_stateful("vault_claim", handle_vault_claim)
            .await;
        self.register_stateful("vault_cancel", handle_vault_cancel)
            .await;

        self.register_stateful("multisig_create", handle_multisig_create)
            .await;
        self.register_stateful("multisig_propose", handle_multisig_propose)
            .await;
        self.register_stateful("multisig_confirm", handle_multisig_confirm)
            .await;
        self.register_stateful("multisig_execute", handle_multisig_execute)
            .await;

        self.register_stateful("token_create", handle_token_create)
            .await;
        self.register_stateful("token_transfer", handle_token_transfer)
            .await;
        self.register_stateful("token_mint", handle_token_mint)
            .await;
        self.register_stateful("token_burn", handle_token_burn)
            .await;
        self.register_stateful("token_balance", handle_token_balance)
            .await;

        // Chain methods.
        self.register_stateful("kovanica_blockNumber", handle_block_number)
            .await;
        self.register_stateful("kovanica_getBlockByHash", handle_get_block_by_hash)
            .await;
        self.register_stateful("kovanica_getBlockByNumber", handle_get_block_by_number)
            .await;

        // Transaction methods.
        self.register_stateful("kovanica_sendRawTransaction", handle_send_raw_transaction)
            .await;
        self.register_stateful(
            "kovanica_getTransactionReceipt",
            handle_get_transaction_receipt,
        )
        .await;
        self.register_stateful(
            "kovanica_getTransactionByHash",
            handle_get_transaction_by_hash,
        )
        .await;
        self.register_stateful(
            "kovanica_getTransactionHistory",
            handle_get_transaction_history,
        )
        .await;
        self.register_stateful("kovanica_getLogs", handle_get_logs)
            .await;

        // Account methods.
        self.register_stateful("kovanica_getBalance", handle_get_balance)
            .await;
        self.register_stateful("kovanica_getNonce", handle_get_nonce)
            .await;
        self.register_stateful("kovanica_getCode", handle_get_code)
            .await;
        self.register_stateful("kovanica_getStorageAt", handle_get_storage_at)
            .await;

        // Staking methods.
        self.register_stateful("kovanica_getValidators", handle_get_validators)
            .await;
        self.register_stateful("kovanica_getStake", handle_get_stake)
            .await;
        self.register_stateful("kovanica_getRewards", handle_get_rewards)
            .await;

        // Mempool methods.
        self.register_stateful(
            "kovanica_getPendingTransactions",
            handle_get_pending_transactions,
        )
        .await;
        self.register_stateful("kovanica_estimateFee", handle_estimate_fee)
            .await;

        // Consensus methods.
        self.register_stateful("kovanica_getLeaderSchedule", handle_get_leader_schedule)
            .await;
        self.register_stateful("kovanica_getCommittee", handle_get_committee)
            .await;
        self.register_stateful("kovanica_getCommitteeInfo", handle_get_committee_info)
            .await;
        self.register_stateful("kovanica_getLeaderHeader", handle_get_leader_header)
            .await;
        self.register_stateful("kovanica_getCommitSeals", handle_get_commit_seals)
            .await;
        self.register_stateful("kovanica_getTxProof", handle_get_tx_proof)
            .await;
        self.register_stateful("kovanica_getAccountProof", handle_get_account_proof)
            .await;
        self.register_stateful("kovanica_getLightSet", handle_get_light_set)
            .await;
        self.register_stateful(
            "kovanica_lightClientCheckpoint",
            handle_light_client_checkpoint,
        )
        .await;

        // Node sync / catch-up status (read-only).
        self.register_stateful("kovanica_syncStatus", handle_sync_status)
            .await;
    }

    /// Register a handler that needs access to the shared [`RpcState`].
    async fn register_stateful<F, Fut>(&mut self, name: &str, handler: F)
    where
        F: Fn(Value, RpcState) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<Value, RpcError>> + Send + 'static,
    {
        let state = self.state.clone();
        self.register_method(name, move |params| {
            let state = state.clone();
            handler(params, state)
        })
        .await;
    }

    pub async fn register_method<F, Fut>(&mut self, name: &str, handler: F)
    where
        F: Fn(Value) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<Value, RpcError>> + Send + 'static,
    {
        self.methods.write().await.insert(
            name.to_string(),
            Arc::new(move |params: Value| Box::pin(handler(params))),
        );
    }

    /// Build the HTTP router (exposed for tests).
    pub fn router(&self) -> Router {
        // /rpc and /ws are rate limited per client IP; /health and /metrics
        // are not, so monitoring keeps working under load.
        let limited = Router::new()
            .route("/rpc", post(rpc_handler))
            .route("/ws", get(ws_handler))
            .layer(axum::middleware::from_fn(rate_limit_middleware));

        Router::new()
            .merge(limited)
            .route("/health", get(health_check))
            .route("/metrics", get(metrics_handler))
            .layer(Extension(self.methods.clone()))
            .layer(Extension(self.state.rate_limiter.clone()))
            .layer(Extension(self.state.auth_config.clone()))
            .layer(Extension(self.state.peer_count.clone()))
            .layer(Extension(self.state.clone()))
            // Outermost, so a browser preflight is answered before the
            // rate limiter and before routing.
            .layer(axum::middleware::from_fn(console_cors))
    }

    pub async fn start(self) -> Result<tokio::task::JoinHandle<()>, std::io::Error> {
        let app = self.router();
        let listener = TcpListener::bind(self.addr).await?;
        let actual_addr = listener.local_addr()?;
        info!("JSON-RPC server listening on http://{}", actual_addr);

        let handle = tokio::spawn(async move {
            // Connect info gives the rate limiter the client IP.
            if let Err(e) = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal())
            .await
            {
                error!(error = %e, "JSON-RPC server stopped with an error");
            }
        });

        Ok(handle)
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// Upgrades an HTTP request to a WebSocket and drives the subscription loop.
async fn ws_handler(ws: WebSocketUpgrade, Extension(state): Extension<RpcState>) -> Response {
    ws.on_upgrade(move |socket| subscriptions::serve_connection(socket, state))
}

/// Fixed set of JSON-RPC method names the default server registers.
///
/// It exists purely to keep the `method` label on the RPC metrics bounded: any
/// name not listed here (an unknown method, or a handler registered only in a
/// test) is reported under `"other"`, so a caller cannot grow metric
/// cardinality by inventing method names. Adding a method to
/// [`RpcServer::register_default_methods`] should add it here too; until it
/// does, it is counted under `"other"`.
const KNOWN_RPC_METHODS: &[&str] = &[
    "htlc_create",
    "htlc_claim",
    "htlc_refund",
    "vault_create",
    "vault_claim",
    "vault_cancel",
    "multisig_create",
    "multisig_propose",
    "multisig_confirm",
    "multisig_execute",
    "token_create",
    "token_transfer",
    "token_mint",
    "token_burn",
    "token_balance",
    "kovanica_blockNumber",
    "kovanica_getBlockByHash",
    "kovanica_getBlockByNumber",
    "kovanica_sendRawTransaction",
    "kovanica_getTransactionReceipt",
    "kovanica_getTransactionByHash",
    "kovanica_getTransactionHistory",
    "kovanica_getLogs",
    "kovanica_getBalance",
    "kovanica_getNonce",
    "kovanica_getCode",
    "kovanica_getStorageAt",
    "kovanica_getValidators",
    "kovanica_getStake",
    "kovanica_getRewards",
    "kovanica_getPendingTransactions",
    "kovanica_estimateFee",
    "kovanica_getLeaderSchedule",
    "kovanica_getCommittee",
    "kovanica_getCommitteeInfo",
    "kovanica_getLeaderHeader",
    "kovanica_getCommitSeals",
    "kovanica_getTxProof",
    "kovanica_getAccountProof",
    "kovanica_getLightSet",
    "kovanica_lightClientCheckpoint",
    "kovanica_syncStatus",
];

/// Map a caller-supplied method name to a bounded metric label.
///
/// Returns the matching `&'static str` from [`KNOWN_RPC_METHODS`], or `"other"`
/// for anything unrecognised, so the number of metric series stays fixed.
fn bounded_method_label(method: &str) -> &'static str {
    KNOWN_RPC_METHODS
        .iter()
        .copied()
        .find(|known| *known == method)
        .unwrap_or("other")
}

/// Dispatch a single JSON-RPC request and record its latency / outcome.
///
/// A thin metrics wrapper around [`dispatch_rpc`]: it timestamps the call,
/// records the request (counter + latency histogram) with a bounded method
/// label, and records an error under the same label whenever the response is a
/// JSON-RPC error (bad version, unauthorized, unknown method, handler error or
/// timeout). The metrics are additive and non-consensus.
async fn rpc_handler(
    Extension(methods): Extension<Arc<RwLock<HashMap<String, RpcHandler>>>>,
    Extension(auth): Extension<Arc<AuthConfig>>,
    headers: HeaderMap,
    Json(request): Json<JsonRpcRequest>,
) -> Response {
    let method_label = bounded_method_label(&request.method);
    let started = std::time::Instant::now();

    let (response, failed) = dispatch_rpc(methods, auth, headers, request).await;

    observe_rpc_request(method_label, started.elapsed().as_secs_f64());
    if failed {
        record_rpc_error(method_label);
    }
    response
}

/// The body of [`rpc_handler`]: validate, authorize, look up the handler and
/// run it under [`RPC_REQUEST_TIMEOUT`]. Returns the response plus whether it
/// is a JSON-RPC error, so the caller can update the metrics.
async fn dispatch_rpc(
    methods: Arc<RwLock<HashMap<String, RpcHandler>>>,
    auth: Arc<AuthConfig>,
    headers: HeaderMap,
    request: JsonRpcRequest,
) -> (Response, bool) {
    let id = request.id.clone();

    // Validate JSON-RPC version
    if request.jsonrpc != "2.0" {
        return (
            build_error_response(
                id,
                RpcError::InvalidRequest("Invalid JSON-RPC version".into()),
            ),
            true,
        );
    }

    // Write authorisation is per JSON-RPC method, checked before dispatch.
    if let Err(e) = auth.authorize(&request.method, &headers) {
        warn!(method = %request.method, error = %e, "unauthorized RPC write");
        let mut response = build_error_response(id, RpcError::Unauthorized(e.to_string()));
        *response.status_mut() = StatusCode::UNAUTHORIZED;
        return (response, true);
    }

    // Get the method handler
    let handler = {
        let methods = methods.read().await;
        methods.get(&request.method).cloned()
    };

    let handler = match handler {
        Some(h) => h,
        None => {
            return (
                build_error_response(id, RpcError::MethodNotFound(request.method)),
                true,
            );
        }
    };

    // Execute the handler, bounded in time.
    let params = request.params.unwrap_or(Value::Null);
    match tokio::time::timeout(RPC_REQUEST_TIMEOUT, handler(params)).await {
        Ok(Ok(result)) => (build_success_response(id, result), false),
        Ok(Err(e)) => (build_error_response(id, e), true),
        Err(_) => {
            warn!(method = %request.method, "RPC call timed out");
            (
                build_error_response(id, RpcError::Timeout(RPC_REQUEST_TIMEOUT)),
                true,
            )
        }
    }
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    /// `ok`, or `degraded` once execution or consensus has stopped.
    status: &'static str,
    peer_count: usize,
    #[serde(flatten)]
    detail: HealthSnapshot,
}

/// `/health`: HTTP 200 while the node is healthy, 503 once the execution
/// worker or the consensus engine has stopped, so health checks fail loudly.
async fn health_check(Extension(state): Extension<RpcState>) -> (StatusCode, Json<HealthResponse>) {
    let detail = state.health.snapshot();
    let (code, status) = if detail.healthy {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "degraded")
    };
    (
        code,
        Json(HealthResponse {
            status,
            peer_count: state.peer_count.load(Ordering::Relaxed),
            detail,
        }),
    )
}

/// Prometheus /metrics endpoint (text format).
async fn metrics_handler() -> (StatusCode, String) {
    (StatusCode::OK, metrics_text())
}

fn build_success_response(id: Option<Value>, result: Value) -> Response {
    let response = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: Some(result),
        error: None,
        id,
    };
    (StatusCode::OK, Json(response)).into_response()
}

fn build_error_response(id: Option<Value>, error: RpcError) -> Response {
    let response = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: None,
        error: Some(JsonRpcErrorObject {
            code: error.code(),
            message: error.to_string(),
            data: None,
        }),
        id,
    };
    (StatusCode::OK, Json(response)).into_response()
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("Shutdown signal received, stopping server...");
}

/// Contract entry points over RPC are not wired to the node yet.
///
/// This used to return a placeholder *success*, so `htlc_*`, `vault_*`,
/// `multisig_*` and `token_*` calls answered `ok: true` (or a fake id)
/// without doing anything. They now fail explicitly with
/// [`RpcError::NotImplemented`] until a real `ContractHost` backed by the
/// node's storage is connected (contract transactions should go through
/// `kovanica_sendRawTransaction` instead).
async fn execute_contract_call(
    entry: &str,
    _contract: [u8; 32],
    _caller: [u8; 32],
    _height: u64,
    _timestamp: u64,
    _args: &[u8],
) -> Result<Vec<u8>, RpcError> {
    Err(RpcError::NotImplemented(format!(
        "{entry}: contract calls over RPC are not wired to the node; submit a signed \
         transaction with kovanica_sendRawTransaction"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health_state(peers: usize) -> (tempfile::TempDir, RpcState) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(Storage::new(dir.path().join("state.redb")).expect("storage"));
        let authority = kovanica_consensus::AuthorityInfo {
            index: 0,
            stake: kovanica_staking::MIN_VALIDATOR_STAKE,
            public_key: kovanica_types::PublicKey([7u8; 32]),
            vrf_public_key: None,
            address: kovanica_types::Address([9u8; 32]),
            network_address: "127.0.0.1:9000".to_string(),
        };
        let state = RpcState {
            health: NodeHealth::new(),
            consensus_store: Arc::new(kovanica_dag::DagStore::from_storage(storage.clone())),
            mempool: Arc::new(Mempool::new(
                kovanica_mempool::MempoolConfig::default(),
                storage.clone(),
                kovanica_types::SigningContext::new(kovanica_types::signing::chain_id::LOCAL),
            )),
            storage,
            staking: Arc::new(RwLock::new(StakingState::new())),
            committee: Arc::new(RwLock::new(
                CommitteeInfo::try_new(0, vec![authority]).expect("committee"),
            )),
            peer_count: Arc::new(AtomicUsize::new(peers)),
            events: EventBus::new(),
            rate_limiter: Arc::new(RateLimiterState::new(RateLimitConfig::default())),
            auth_config: Arc::new(AuthConfig::default()),
            tx_gossip: None,
            sync_status: None,
        };
        (dir, state)
    }

    #[tokio::test]
    async fn health_is_ok_with_zero_peers() {
        let (_dir, state) = health_state(0);
        let (code, Json(response)) = health_check(Extension(state)).await;
        let response = serde_json::to_value(response).expect("health response serializes");

        assert_eq!(code, StatusCode::OK);
        assert_eq!(response["status"], "ok");
        assert_eq!(response["peer_count"], 0);
    }

    #[tokio::test]
    async fn health_reports_nonzero_peer_count() {
        let (_dir, state) = health_state(3);
        let (_, Json(response)) = health_check(Extension(state)).await;
        let response = serde_json::to_value(response).expect("health response serializes");

        assert_eq!(response["status"], "ok");
        assert_eq!(response["peer_count"], 3);
    }

    #[tokio::test]
    async fn health_degrades_when_execution_fails() {
        let (_dir, state) = health_state(2);
        state.health.execution_progress(41);
        state.health.execution_failed("state root mismatch");
        let (code, Json(response)) = health_check(Extension(state)).await;
        let response = serde_json::to_value(response).expect("health response serializes");

        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response["status"], "degraded");
        assert_eq!(response["healthy"], false);
        assert_eq!(response["execution"]["state"], "failed");
        assert_eq!(response["execution"]["last_executed_round"], 41);
        assert_eq!(response["last_error"], "execution: state root mismatch");
    }

    #[tokio::test]
    async fn health_degrades_when_consensus_stops() {
        let (_dir, state) = health_state(2);
        state.health.consensus_stopped();
        let (code, Json(response)) = health_check(Extension(state)).await;
        let response = serde_json::to_value(response).expect("health response serializes");
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response["consensus"]["state"], "stopped");
    }

    // ------------------------------------------------------------------
    // Router-level tests: auth per method, stubs, rate limit, timeouts,
    // key surface.
    // ------------------------------------------------------------------

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use kovanica_consensus::AuthorityInfo;
    use kovanica_mempool::MempoolConfig;
    use kovanica_types::{Address, PublicKey};
    use serde_json::json;
    use tower::ServiceExt;

    fn state(dir: &tempfile::TempDir, rate: RateLimitConfig, auth: AuthConfig) -> RpcState {
        let storage = Arc::new(Storage::new(dir.path().join("state.db")).expect("storage"));
        let authority = AuthorityInfo {
            index: 0,
            stake: kovanica_staking::MIN_VALIDATOR_STAKE,
            public_key: PublicKey([7u8; 32]),
            vrf_public_key: None,
            address: Address([9u8; 32]),
            network_address: "127.0.0.1:9000".to_string(),
        };
        RpcState {
            consensus_store: Arc::new(kovanica_dag::DagStore::from_storage(storage.clone())),
            mempool: Arc::new(Mempool::new(
                MempoolConfig::default(),
                storage.clone(),
                kovanica_types::SigningContext::new(kovanica_types::signing::chain_id::LOCAL),
            )),
            storage,
            staking: Arc::new(RwLock::new(StakingState::new())),
            committee: Arc::new(RwLock::new(
                CommitteeInfo::try_new(0, vec![authority]).expect("committee"),
            )),
            peer_count: Arc::new(AtomicUsize::new(0)),
            events: EventBus::new(),
            rate_limiter: Arc::new(RateLimiterState::new(rate.clone())),
            auth_config: Arc::new(auth.clone()),
            health: NodeHealth::new(),
            tx_gossip: None,
            sync_status: None,
        }
    }

    async fn server(rate: RateLimitConfig, auth: AuthConfig) -> (tempfile::TempDir, RpcServer) {
        let dir = tempfile::tempdir().expect("tempdir");
        let st = state(&dir, rate.clone(), auth.clone());
        let server =
            RpcServer::new("127.0.0.1:0".parse().unwrap(), st, Some(rate), Some(auth)).await;
        (dir, server)
    }

    fn open_auth() -> AuthConfig {
        AuthConfig {
            write_tokens: Vec::new(),
            require_auth_for_writes: false,
        }
    }

    fn unlimited() -> RateLimitConfig {
        RateLimitConfig::from_requests_per_minute(0)
    }

    async fn call(
        router: Router,
        method: &str,
        params: Value,
        token: Option<&str>,
    ) -> (StatusCode, Value) {
        let body =
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let mut req = Request::post("/rpc").header("content-type", "application/json");
        if let Some(token) = token {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        let response = router
            .oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .expect("router responds");
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    #[tokio::test]
    async fn write_method_requires_token_by_json_rpc_method() {
        let auth = AuthConfig {
            write_tokens: vec!["tok".into()],
            require_auth_for_writes: true,
        };
        let (_dir, server) = server(unlimited(), auth).await;
        let (status, body) = call(
            server.router(),
            "kovanica_sendRawTransaction",
            json!(["0x00"]),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], -32001);

        let (status, body) = call(
            server.router(),
            "kovanica_sendRawTransaction",
            json!(["0x00"]),
            Some("nope"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], -32001);

        // With the token the call reaches the handler (and fails on the bogus payload).
        let (status, body) = call(
            server.router(),
            "kovanica_sendRawTransaction",
            json!(["0x00"]),
            Some("tok"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"]["code"], -32602);

        // Reads need no token.
        let (status, body) = call(server.router(), "kovanica_blockNumber", Value::Null, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["error"].is_null(), "{body}");
    }

    #[tokio::test]
    async fn contract_stubs_fail_instead_of_reporting_success() {
        let (_dir, server) = server(unlimited(), open_auth()).await;
        let zero = format!("{:?}", [0u8; 32]);
        let id: Value = serde_json::from_str(&zero).unwrap();
        let cases = [
            ("htlc_claim", json!({"id": id, "preimage": []})),
            ("htlc_refund", json!({"id": id})),
            ("token_balance", json!({"address": id})),
        ];
        for (method, params) in cases {
            let (_, body) = call(server.router(), method, params, None).await;
            assert!(
                body["result"].is_null(),
                "{method} must not succeed: {body}"
            );
            let code = body["error"]["code"].as_i64().unwrap();
            assert!(
                code == -32004 || code == -32602,
                "{method}: unexpected code {code}: {body}"
            );
        }
        // A well-formed htlc_claim specifically hits NotImplemented.
        let (_, body) = call(
            server.router(),
            "htlc_claim",
            json!({"id": id, "preimage": [1, 2]}),
            None,
        )
        .await;
        assert_eq!(body["error"]["code"], -32004, "{body}");
    }

    #[tokio::test]
    async fn rpc_is_rate_limited_but_health_is_not() {
        let rate = RateLimitConfig {
            requests_per_minute: 1,
            burst: 1,
        };
        let (_dir, server) = server(rate, open_auth()).await;
        let (status, _) = call(server.router(), "kovanica_blockNumber", Value::Null, None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(server.router(), "kovanica_blockNumber", Value::Null, None).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        let health = server
            .router()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);
    }

    const CONSOLE_ORIGIN: &str = "https://console.kovanica.online";

    async fn send_origin(
        router: Router,
        method: &str,
        path: &str,
        origin: Option<&str>,
        body: Option<&str>,
    ) -> axum::response::Response {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(origin) = origin {
            req = req.header("origin", origin);
        }
        if body.is_some() {
            req = req.header("content-type", "application/json");
        }
        router
            .oneshot(
                req.body(Body::from(body.unwrap_or("").to_string()))
                    .unwrap(),
            )
            .await
            .expect("router responds")
    }

    #[tokio::test]
    async fn console_origin_is_accepted_for_rpc_ws_and_health() {
        let (_dir, server) = server(unlimited(), open_auth()).await;
        let preflight = send_origin(
            server.router(),
            "OPTIONS",
            "/rpc",
            Some(CONSOLE_ORIGIN),
            None,
        )
        .await;
        assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            preflight
                .headers()
                .get("access-control-allow-origin")
                .unwrap(),
            CONSOLE_ORIGIN
        );
        assert_eq!(
            preflight
                .headers()
                .get("access-control-allow-headers")
                .unwrap(),
            "content-type"
        );
        assert_eq!(
            preflight
                .headers()
                .get("access-control-allow-methods")
                .unwrap(),
            "GET, POST, OPTIONS"
        );

        let body = r#"{"jsonrpc":"2.0","id":1,"method":"kovanica_blockNumber","params":[]}"#;
        let response = send_origin(
            server.router(),
            "POST",
            "/rpc",
            Some("http://127.0.0.1:5173"),
            Some(body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .unwrap(),
            "http://127.0.0.1:5173"
        );

        let health = send_origin(
            server.router(),
            "GET",
            "/health",
            Some("http://localhost:5173"),
            None,
        )
        .await;
        assert_eq!(health.status(), StatusCode::OK);
        assert_eq!(
            health.headers().get("access-control-allow-origin").unwrap(),
            "http://localhost:5173"
        );

        // Not a real upgrade. The origin is allowed, so the request reaches
        // the websocket handler instead of being rejected as a foreign page.
        let ws = send_origin(server.router(), "GET", "/ws", Some(CONSOLE_ORIGIN), None).await;
        assert_ne!(ws.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            ws.headers().get("access-control-allow-origin").unwrap(),
            CONSOLE_ORIGIN
        );
    }

    #[tokio::test]
    async fn foreign_origin_is_rejected_and_metrics_stay_unshared() {
        let (_dir, server) = server(unlimited(), open_auth()).await;
        let denied = send_origin(
            server.router(),
            "POST",
            "/rpc",
            Some("https://evil.example"),
            Some(r#"{"jsonrpc":"2.0","id":1,"method":"kovanica_blockNumber","params":[]}"#),
        )
        .await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert!(denied
            .headers()
            .get("access-control-allow-origin")
            .is_none());
        let bytes = denied.into_body().collect().await.unwrap().to_bytes();
        assert!(!bytes.windows(7).any(|w| w == b"jsonrpc"));

        let ws = send_origin(
            server.router(),
            "GET",
            "/ws",
            Some("https://evil.example"),
            None,
        )
        .await;
        assert_eq!(ws.status(), StatusCode::FORBIDDEN);

        let metrics = send_origin(
            server.router(),
            "GET",
            "/metrics",
            Some(CONSOLE_ORIGIN),
            None,
        )
        .await;
        assert_eq!(metrics.status(), StatusCode::OK);
        assert!(metrics
            .headers()
            .get("access-control-allow-origin")
            .is_none());
    }

    #[tokio::test]
    async fn preflight_does_not_spend_a_rate_limit_token() {
        let rate = RateLimitConfig {
            requests_per_minute: 1,
            burst: 1,
        };
        let (_dir, server) = server(rate, open_auth()).await;
        let first = send_origin(
            server.router(),
            "OPTIONS",
            "/rpc",
            Some(CONSOLE_ORIGIN),
            None,
        )
        .await;
        assert_eq!(first.status(), StatusCode::NO_CONTENT);
        let second = send_origin(
            server.router(),
            "OPTIONS",
            "/rpc",
            Some(CONSOLE_ORIGIN),
            None,
        )
        .await;
        assert_eq!(second.status(), StatusCode::NO_CONTENT);
        let (status, _) = call(server.router(), "kovanica_blockNumber", Value::Null, None).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test(start_paused = true)]
    async fn hung_handler_times_out() {
        let (_dir, mut server) = server(unlimited(), open_auth()).await;
        server
            .register_method("test_hang", |_params| async {
                std::future::pending::<()>().await;
                Ok(Value::Null)
            })
            .await;
        let (status, body) = call(server.router(), "test_hang", Value::Null, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"]["code"], -32003, "{body}");
    }

    #[tokio::test]
    async fn rpc_handler_records_per_method_metrics() {
        let (_dir, server) = server(unlimited(), open_auth()).await;

        // A known method increments its own request counter and is not an error.
        let before = kovanica_consensus::metrics::rpc_request_count("kovanica_blockNumber");
        let (status, body) = call(server.router(), "kovanica_blockNumber", Value::Null, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["error"].is_null(), "{body}");
        let after = kovanica_consensus::metrics::rpc_request_count("kovanica_blockNumber");
        assert!(
            after > before,
            "request counter must increment on a handled call ({before} -> {after})"
        );

        // An unknown method is labelled with the bounded `other` label and
        // counted as an error. Counter reads only ever grow, so a concurrently
        // running test cannot make this assertion flake in the wrong direction.
        let before_err = kovanica_consensus::metrics::rpc_error_count("other");
        let (_, body) = call(
            server.router(),
            "definitely_not_a_method",
            Value::Null,
            None,
        )
        .await;
        assert_eq!(body["error"]["code"], -32601, "{body}");
        let after_err = kovanica_consensus::metrics::rpc_error_count("other");
        assert!(
            after_err > before_err,
            "an unknown method must be counted as an error ({before_err} -> {after_err})"
        );
    }

    #[tokio::test]
    async fn no_rpc_method_exposes_key_material() {
        let (_dir, server) = server(unlimited(), open_auth()).await;
        let methods = server.methods.read().await;
        for name in methods.keys() {
            let lower = name.to_ascii_lowercase();
            for needle in [
                "private", "secret", "seed", "mnemonic", "sign", "keystore", "export",
            ] {
                assert!(
                    !lower.contains(needle),
                    "RPC method {name} looks like it handles key material"
                );
            }
        }
        // RpcState carries no signing key: this would not compile otherwise.
        let _: fn(&RpcState) = |s| {
            let RpcState {
                storage: _,
                consensus_store: _,
                mempool: _,
                staking: _,
                committee: _,
                peer_count: _,
                events: _,
                rate_limiter: _,
                auth_config: _,
                health: _,
                tx_gossip: _,
                sync_status: _,
            } = s;
        };
    }
}
