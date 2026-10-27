//! Relay HTTP API v1 — `docs/COMMS-M1-INTERFACES.md` §4.
//!
//! axum 0.7 server exposing exactly:
//!
//! | Method | Path | Success | Errors |
//! |---|---|---|---|
//! | POST | `/v1/envelope` | `201 {"ok":true,"id":"<hex>"}` | `400`,`413`,`429` |
//! | GET  | `/v1/inbox/{comms_id}` | `200 {"envelopes":[…]}` | `400` |
//! | POST | `/v1/ack` | `200 {"ok":true,"deleted":<n>}` | `400` |
//! | GET  | `/v1/health` | `200 {"ok":true,"version":…,"envelopes":<n>}` | — |
//!
//! Errors are `{"error":{"code":"<slug>","message":"…"}}` with slugs
//! `bad_request`, `too_large`, `not_found`, `rate_limited`, `internal`.
//! **GET never deletes** — deletion is only via `/v1/ack`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::envelope::{Envelope, MAX_CT, MAX_ENVELOPE_JSON};
use crate::store::{Store, StoreError, DEFAULT_INBOX_LIMIT, MAX_INBOX_LIMIT};
use crate::{comms_id_from_hex, now_ms, pow_verify, SubmissionWrapper};

/// How often the background task sweeps expired envelopes.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Error slugs (`error.code`) used by §4.
pub mod slug {
    pub const BAD_REQUEST: &str = "bad_request";
    pub const TOO_LARGE: &str = "too_large";
    pub const NOT_FOUND: &str = "not_found";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const INTERNAL: &str = "internal";
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

fn error_response(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorEnvelope {
            error: ErrorBody {
                code,
                message: message.into(),
            },
        }),
    )
        .into_response()
}

fn bad_request(message: impl Into<String>) -> Response {
    error_response(StatusCode::BAD_REQUEST, slug::BAD_REQUEST, message)
}

fn too_large(message: impl Into<String>) -> Response {
    error_response(StatusCode::PAYLOAD_TOO_LARGE, slug::TOO_LARGE, message)
}

fn rate_limited() -> Response {
    error_response(
        StatusCode::TOO_MANY_REQUESTS,
        slug::RATE_LIMITED,
        "recipient quota exceeded",
    )
}

#[derive(Debug, Serialize)]
struct PostEnvelopeResponse {
    ok: bool,
    id: String,
}

/// LRU entry for PoW replay (id, nonce)
#[derive(Clone, Debug)]
struct PowSeen {
    id: String,
    nonce: String,
    expires_at: u64,
}

#[derive(Clone, Debug)]
struct AppState {
    store: Arc<Store>,
    pow_seen: Arc<Mutex<VecDeque<PowSeen>>>,
}

fn pow_ttl_ms() -> u64 {
    std::env::var("KOVANICA_RELAY_POW_TTL_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(600_000)
}

fn pow_bits_required() -> u8 {
    std::env::var("KOVANICA_RELAY_POW_BITS")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(20)
}

fn allow_unpaid() -> bool {
    std::env::var("KOVANICA_RELAY_ALLOW_UNPAID")
        .ok()
        .and_then(|v| {
            let s = v.trim().to_ascii_lowercase();
            match s.as_str() {
                "true" | "1" | "yes" | "y" => Some(true),
                "false" | "0" | "no" | "n" => Some(false),
                _ => None,
            }
        })
        .unwrap_or(true)
}

fn relay_claimer_addr() -> Option<String> {
    std::env::var("KOVANICA_RELAY_CLAIMER_ADDR").ok()
}

fn now_ms_u64() -> u64 {
    now_ms()
}

/// `POST /v1/envelope` — validate and store an opaque envelope.
async fn post_envelope(State(state): State<AppState>, body: Bytes) -> Response {
    if body.len() > MAX_ENVELOPE_JSON {
        return too_large(format!("envelope json exceeds {MAX_ENVELOPE_JSON} bytes"));
    }

    // Try to deserialize wrapper first, else bare envelope
    let (envelope, pow_opt, payment_opt) = match serde_json::from_slice::<SubmissionWrapper>(&body)
    {
        Ok(w) => (w.envelope, w.pow, w.payment),
        Err(_) => match Envelope::from_json(&body) {
            Ok(envelope) => (envelope, None, None),
            Err(e) => return bad_request(format!("malformed envelope: {e}")),
        },
    };

    if let Err(e) = envelope.validate_shape() {
        return bad_request(format!("invalid envelope: {e}"));
    }
    if envelope.ct.len() > MAX_CT {
        return too_large(format!("ct exceeds {MAX_CT} bytes"));
    }
    let env_id = match envelope.compute_id() {
        Ok(id) => id,
        Err(e) => return bad_request(format!("invalid envelope: {e}")),
    };
    if env_id != envelope.id {
        return bad_request("envelope id does not match its contents");
    }

    let now = now_ms_u64();
    let mut admitted = false;

    // PoW handling
    let pow_ttl = pow_ttl_ms();
    let req_bits = pow_bits_required();
    if let Some(ref p) = pow_opt {
        if p.bits < req_bits {
            return bad_request(format!(
                "insufficient pow bits: required {req_bits}, got {}",
                p.bits
            ));
        }
        {
            let mut seen = state.pow_seen.lock();
            seen.retain(|s| s.expires_at > now);
            // check replay
            let mut replay = false;
            for s in seen.iter() {
                if s.id == env_id && s.nonce == p.nonce {
                    replay = true;
                    break;
                }
            }
            if replay {
                return rate_limited();
            }
            if pow_verify(&env_id, &p.nonce, p.bits) {
                seen.push_back(PowSeen {
                    id: env_id.clone(),
                    nonce: p.nonce.clone(),
                    expires_at: now + pow_ttl,
                });
                if seen.len() > 10000 {
                    seen.pop_front();
                }
                admitted = true;
            } else {
                return bad_request("invalid pow");
            }
        }
    }

    // Payment handling
    if !admitted {
        if let Some(ref pay) = payment_opt {
            let preimg_bytes = crate::b64_decode(&pay.preimage).unwrap_or_default();
            let hash_lock = kovanica_common::hash(&preimg_bytes);
            if let Some(req_claimer) = relay_claimer_addr() {
                if pay.claimer_addr != req_claimer {
                    return bad_request("invalid claimer");
                }
            }
            if pay.expiry <= now + 1000 {
                return bad_request("payment expired");
            }
            let min_fee = std::env::var("KOVANICA_RELAY_MIN_FEE_ATOMS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(1000);
            if pay.amount_atoms < min_fee {
                return bad_request("insufficient payment amount");
            }
            // recompute htlc id
            let sender_bytes = if let Some(ref s) = pay.sender_addr {
                if let Ok(b) = hex::decode(s) {
                    let mut v = [0u8; 32];
                    let take = b.len().min(32);
                    v[0..take].copy_from_slice(&b[0..take]);
                    v
                } else {
                    [0u8; 32]
                }
            } else {
                [0u8; 32]
            };
            let claimer_bytes = if let Ok(b) = hex::decode(&pay.claimer_addr) {
                let mut v = [0u8; 32];
                let take = b.len().min(32);
                v[0..take].copy_from_slice(&b[0..take]);
                v
            } else {
                [0u8; 32]
            };
            let mut htlc_input = Vec::with_capacity(6 + 32 + 32 + 16 + 32 + 8);
            htlc_input.extend_from_slice(b"htlc/id");
            htlc_input.extend_from_slice(&sender_bytes);
            htlc_input.extend_from_slice(&claimer_bytes);
            htlc_input.extend_from_slice(&pay.amount_atoms.to_le_bytes());
            htlc_input.extend_from_slice(&hash_lock);
            htlc_input.extend_from_slice(&pay.expiry.to_le_bytes());
            let htlc_id_comp = hex::encode(kovanica_common::hash(&htlc_input));
            if htlc_id_comp != pay.htlc_id {
                return bad_request("invalid htlc id");
            }
            let _ = state.store.credit_add(&envelope.to, pay.amount_atoms, now);
            if state.store.credit_deduct(&envelope.to, 1, now) {
                admitted = true;
            } else {
                return bad_request("insufficient credit");
            }
        }
    }

    // If no wrapper/pow/payment provided, check allow_unpaid
    if !admitted {
        if !allow_unpaid() {
            return rate_limited();
        }
        // bare envelope allowed (M1 back-compat)
        let _ = admitted; // already true
    }

    let id_res = envelope.id.clone();
    match state.store.insert(envelope, now) {
        Ok(_outcome) => (
            StatusCode::CREATED,
            Json(PostEnvelopeResponse {
                ok: true,
                id: id_res,
            }),
        )
            .into_response(),
        Err(StoreError::RateLimited) => rate_limited(),
    }
}

#[derive(Debug, Deserialize)]
struct InboxQuery {
    limit: Option<usize>,
    since: Option<u64>,
}

#[derive(Debug, Serialize)]
struct InboxResponse {
    envelopes: Vec<Envelope>,
}

/// `GET /v1/inbox/{comms_id}` — undelivered envelopes, oldest first. Never deletes.
async fn get_inbox(
    State(state): State<AppState>,
    Path(comms_id): Path<String>,
    Query(query): Query<InboxQuery>,
) -> Response {
    if comms_id_from_hex(&comms_id).is_err() {
        return bad_request("invalid comms id");
    }
    let limit = query
        .limit
        .unwrap_or(DEFAULT_INBOX_LIMIT)
        .min(MAX_INBOX_LIMIT);
    let envelopes = state.store.inbox(&comms_id, limit, query.since, now_ms());
    (StatusCode::OK, Json(InboxResponse { envelopes })).into_response()
}

#[derive(Debug, Deserialize)]
struct AckRequest {
    to: String,
    ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AckResponse {
    ok: bool,
    deleted: usize,
}

/// `POST /v1/ack` — the only delete path.
async fn post_ack(State(state): State<AppState>, Json(req): Json<AckRequest>) -> Response {
    if comms_id_from_hex(&req.to).is_err() {
        return bad_request("invalid comms id");
    }
    for id in &req.ids {
        if !is_lower_hex64(id) {
            return bad_request("invalid envelope id");
        }
    }
    let deleted = state.store.ack(&req.to, &req.ids);
    (StatusCode::OK, Json(AckResponse { ok: true, deleted })).into_response()
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
    version: &'static str,
    envelopes: usize,
}

/// `GET /v1/health`.
async fn get_health(State(state): State<AppState>) -> Response {
    (
        StatusCode::OK,
        Json(HealthResponse {
            ok: true,
            version: env!("CARGO_PKG_VERSION"),
            envelopes: state.store.len(),
        }),
    )
        .into_response()
}

fn is_lower_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Build the §4 router around a shared [`Store`].
pub fn router(store: Arc<Store>) -> Router {
    let state = AppState {
        store,
        pow_seen: Arc::new(Mutex::new(VecDeque::new())),
    };
    Router::new()
        .route("/v1/envelope", post(post_envelope))
        .route("/v1/inbox/:comms_id", get(get_inbox))
        .route("/v1/ack", post(post_ack))
        .route("/v1/health", get(get_health))
        .with_state(state)
}

/// The relay HTTP server. Mirrors the `kovanica-rpc` [`RpcServer`] shape
/// (`router()` / `start()`).
///
/// [`RpcServer`]: https://docs.rs/kovanica-rpc
#[derive(Clone)]
pub struct RelayServer {
    addr: SocketAddr,
    store: Arc<Store>,
}

impl RelayServer {
    /// Create a server with a fresh, empty store.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            store: Arc::new(Store::new()),
        }
    }

    /// Create a server sharing an existing store (tests, embedding).
    pub fn with_store(addr: SocketAddr, store: Arc<Store>) -> Self {
        Self { addr, store }
    }

    /// The shared store backing this server.
    pub fn store(&self) -> Arc<Store> {
        self.store.clone()
    }

    /// The configured bind address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Build the §4 router (exposed for tests and embedded use).
    pub fn router(&self) -> Router {
        router(self.store.clone())
    }

    /// Bind, serve, and return the background task handle.
    ///
    /// Shuts down gracefully on `SIGINT`/`SIGTERM`. Also spawns the periodic
    /// expiry sweep for the lifetime of the store.
    pub async fn start(self) -> Result<JoinHandle<()>, std::io::Error> {
        let app = self.router();
        let listener = TcpListener::bind(self.addr).await?;
        let actual_addr = listener.local_addr()?;
        info!("kovanica-comms-relay listening on http://{}", actual_addr);

        spawn_sweeper(self.store.clone());

        let handle = tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await
            {
                error!(error = %e, "relay server stopped with an error");
            }
        });

        Ok(handle)
    }
}

/// Spawn the background expiry sweep (drops envelopes past `expiresAt`).
///
/// Returns the task handle; the task runs until the process exits.
pub fn spawn_sweeper(store: Arc<Store>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let dropped = store.sweep(now_ms());
            if dropped > 0 {
                info!(dropped, "relay sweep dropped expired envelopes");
            }
        }
    })
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
    warn!("relay shutdown signal received");
}
