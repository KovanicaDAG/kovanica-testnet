//! Rate limiting and authentication middleware for the RPC server.

//!
//! * Rate limiting is per client IP (from axum's `ConnectInfo`), not per
//!   socket address: a fresh TCP connection (new source port) does not get a
//!   fresh bucket, and all clients no longer share one bucket.
//! * Write authorisation is decided per JSON-RPC *method* (see
//!   [`AuthConfig::authorize`]), called by the RPC handler once the request
//!   body has been parsed. The old middleware looked at the URL path, which
//!   is always `/rpc`, so it never matched a write method.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{ConnectInfo, Extension, Request},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use parking_lot::{Mutex, RwLock};

/// Rate limiter configuration
///
/// A `requests_per_minute` of `0` disables rate limiting entirely (every
/// request is admitted); this is the documented `KOVANICA_RPC_RATE_LIMIT_PER_MIN=0`
/// escape hatch for tests and trusted local tooling.
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Requests per minute per client IP. `0` disables rate limiting.
    pub requests_per_minute: u32,
    /// Burst allowance (token-bucket capacity)
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60, // 1 req/sec
            burst: 10,
        }
    }
}

impl RateLimitConfig {
    /// Build a config from a requests-per-minute figure, deriving the burst.
    ///
    /// Burst rule: `burst = max(1, requests_per_minute / 6)`, preserving the
    /// historical default (`60` rpm -> `10` burst). `requests_per_minute == 0`
    /// disables rate limiting (burst is irrelevant and set to `0`).
    pub fn from_requests_per_minute(requests_per_minute: u32) -> Self {
        if requests_per_minute == 0 {
            return Self {
                requests_per_minute: 0,
                burst: 0,
            };
        }
        Self {
            requests_per_minute,
            burst: (requests_per_minute / 6).max(1),
        }
    }

    /// Whether rate limiting is disabled (`requests_per_minute == 0`).
    pub fn is_disabled(&self) -> bool {
        self.requests_per_minute == 0
    }
}

/// Token bucket for rate limiting
struct TokenBucket {
    capacity: u32,
    tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    fn consume(&mut self, tokens: u32) -> bool {
        self.refill();
        if self.tokens >= tokens as f64 {
            self.tokens -= tokens as f64;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity as f64);
        self.last_refill = now;
    }

    fn retry_after(&self) -> Option<u64> {
        if self.tokens >= 1.0 {
            return None;
        }
        let needed = 1.0 - self.tokens;
        let seconds = (needed / self.refill_rate).ceil() as u64;
        Some(seconds.max(1))
    }
}

/// Per-client rate limiter state
struct ClientRateLimiter {
    bucket: TokenBucket,
    last_seen: Instant,
}

/// How often idle client buckets are swept.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(300);
/// A client bucket idle this long is dropped.
const IDLE_EXPIRY: Duration = Duration::from_secs(600);
/// Hard cap on tracked clients; beyond it idle buckets are swept early.
const MAX_TRACKED_CLIENTS: usize = 100_000;

/// Global rate limiter state: one token bucket per client IP.
pub struct RateLimiterState {
    limiters: RwLock<HashMap<IpAddr, ClientRateLimiter>>,
    config: RateLimitConfig,
    last_cleanup: Mutex<Instant>,
}

impl RateLimiterState {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            limiters: RwLock::new(HashMap::new()),
            config,
            last_cleanup: Mutex::new(Instant::now()),
        }
    }

    /// Check if a request from `client` is allowed; returns
    /// `(allowed, retry_after_secs)`.
    pub fn check_limit(&self, client: IpAddr) -> (bool, Option<u64>) {
        // A configured rate of 0 disables rate limiting (admit everything).
        if self.config.is_disabled() {
            return (true, None);
        }

        let mut limiters = self.limiters.write();

        let now = Instant::now();
        let mut last_cleanup = self.last_cleanup.lock();
        if now.duration_since(*last_cleanup) > CLEANUP_INTERVAL
            || limiters.len() >= MAX_TRACKED_CLIENTS
        {
            limiters.retain(|_, v| now.duration_since(v.last_seen) < IDLE_EXPIRY);
            *last_cleanup = now;
        }
        drop(last_cleanup);

        let refill_rate = self.config.requests_per_minute as f64 / 60.0;
        let limiter = limiters.entry(client).or_insert_with(|| ClientRateLimiter {
            bucket: TokenBucket::new(self.config.burst, refill_rate),
            last_seen: now,
        });

        limiter.last_seen = now;
        let allowed = limiter.bucket.consume(1);
        let retry_after = limiter.bucket.retry_after();
        (allowed, retry_after)
    }

    /// Number of client buckets currently tracked.
    pub fn tracked_clients(&self) -> usize {
        self.limiters.read().len()
    }
}

/// JSON-RPC methods that require a bearer token when
/// [`AuthConfig::require_auth_for_writes`] is set (see `docs/SECURITY.md`).
pub const WRITE_METHODS: &[&str] = &[
    "kovanica_sendRawTransaction",
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
];

/// Authentication configuration
#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// Bearer tokens for write operations
    pub write_tokens: Vec<String>,
    /// Whether auth is required for write methods
    pub require_auth_for_writes: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            write_tokens: Vec::new(),
            require_auth_for_writes: true,
        }
    }
}

/// Why a request was not authorised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Write method called without an `Authorization: Bearer` header.
    MissingToken,
    /// The bearer token is not one of the configured write tokens.
    InvalidToken,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::MissingToken => write!(f, "authentication required for write method"),
            AuthError::InvalidToken => write!(f, "invalid authentication token"),
        }
    }
}

/// Constant-time byte comparison, so token checks do not leak how many
/// leading bytes matched.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl AuthConfig {
    /// Whether `method` is a write method.
    pub fn is_write_method(method: &str) -> bool {
        WRITE_METHODS.contains(&method)
    }

    /// Authorise a JSON-RPC call to `method` given the request headers.
    pub fn authorize(&self, method: &str, headers: &HeaderMap) -> Result<(), AuthError> {
        if !self.require_auth_for_writes || !Self::is_write_method(method) {
            return Ok(());
        }
        let token = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(AuthError::MissingToken)?;
        let mut ok = false;
        for candidate in &self.write_tokens {
            // No early exit: every configured token is compared.
            ok |= constant_time_eq(candidate.as_bytes(), token.as_bytes());
        }
        if ok && !token.is_empty() {
            Ok(())
        } else {
            Err(AuthError::InvalidToken)
        }
    }
}

/// Client IP for rate limiting. Falls back to `0.0.0.0` (one shared bucket)
/// when the server was not started with connect info, e.g. in unit tests.
fn client_ip(request: &Request) -> IpAddr {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

/// Per-client-IP rate limiting middleware.
pub async fn rate_limit_middleware(
    Extension(rate_limiter): Extension<Arc<RateLimiterState>>,
    request: Request,
    next: Next,
) -> Response {
    let (allowed, retry_after) = rate_limiter.check_limit(client_ip(&request));
    if !allowed {
        let mut response = Response::new("Rate limit exceeded".into());
        *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        if let Some(seconds) = retry_after {
            if let Ok(value) = seconds.to_string().parse() {
                response.headers_mut().insert("Retry-After", value);
            }
        }
        return response;
    }
    next.run(request).await
}

/// Browser origins allowed to call the public RPC from Kovanica Console.
///
/// The same three strings are the faucet allowlist (`kovanica-faucet`). A request
/// with no `Origin` (CLI, curl, node-to-node) is unchanged. Any other origin
/// is rejected. There is no wildcard.
pub const CONSOLE_ALLOWED_ORIGINS: &[&str] = &[
    "https://console.kovanica.online",
    "https://dash.kovanica.online",
    "https://faucet.kovanica.online",
    "https://kovanica.online",
    "https://wallet.kovanica.online",
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
];

/// Routes a browser on the console is allowed to read. `/metrics` is left
/// alone so a page cannot scrape it.
const RPC_CORS_PATHS: &[&str] = &["/rpc", "/ws", "/health"];

/// Return the canonical allowlist entry when `origin` matches one of them.
pub fn console_origin(origin: &str) -> Option<&'static str> {
    CONSOLE_ALLOWED_ORIGINS
        .iter()
        .copied()
        .find(|allowed| *allowed == origin)
}

/// CORS for `POST /rpc`, `GET /ws`, `GET /health`, and their preflight.
///
/// Layer this outside the rate limiter so an `OPTIONS` preflight does not
/// spend a token.
pub async fn console_cors(request: Request, next: Next) -> Response {
    apply_console_cors(RPC_CORS_PATHS, request, next).await
}

/// Shared CORS decision used by [`console_cors`]. `paths` are exact URI paths.
pub async fn apply_console_cors(paths: &[&str], request: Request, next: Next) -> Response {
    if !paths.contains(&request.uri().path()) {
        return next.run(request).await;
    }
    let origin = request
        .headers()
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    let Some(origin) = origin else {
        return next.run(request).await;
    };
    let Some(origin) = console_origin(origin) else {
        let mut response = Response::new("origin not allowed".into());
        *response.status_mut() = StatusCode::FORBIDDEN;
        return response;
    };
    if request.method() == axum::http::Method::OPTIONS {
        return preflight(origin);
    }
    let mut response = next.run(request).await;
    allow_origin(response.headers_mut(), origin);
    response
}

fn allow_origin(headers: &mut HeaderMap, origin: &'static str) {
    headers.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        axum::http::HeaderValue::from_static(origin),
    );
    headers.insert(
        axum::http::header::VARY,
        axum::http::HeaderValue::from_static("Origin"),
    );
}

fn preflight(origin: &'static str) -> Response {
    let mut response = Response::new("".into());
    *response.status_mut() = StatusCode::NO_CONTENT;
    allow_origin(response.headers_mut(), origin);
    response.headers_mut().insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
        axum::http::HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    response.headers_mut().insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
        axum::http::HeaderValue::from_static("content-type"),
    );
    response.headers_mut().insert(
        axum::http::header::ACCESS_CONTROL_MAX_AGE,
        axum::http::HeaderValue::from_static("600"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers
    }

    #[test]
    fn write_methods_need_a_valid_token_reads_do_not() {
        let auth = AuthConfig {
            write_tokens: vec!["s3cret".into()],
            require_auth_for_writes: true,
        };
        assert_eq!(
            auth.authorize("kovanica_sendRawTransaction", &HeaderMap::new()),
            Err(AuthError::MissingToken)
        );
        assert_eq!(
            auth.authorize("kovanica_sendRawTransaction", &bearer("wrong")),
            Err(AuthError::InvalidToken)
        );
        assert_eq!(
            auth.authorize("kovanica_sendRawTransaction", &bearer("s3cret")),
            Ok(())
        );
        assert_eq!(
            auth.authorize("kovanica_getBalance", &HeaderMap::new()),
            Ok(())
        );
        assert_eq!(
            auth.authorize("kovanica_getTransactionHistory", &HeaderMap::new()),
            Ok(())
        );
    }

    #[test]
    fn default_config_rejects_every_write_and_empty_token() {
        let auth = AuthConfig::default();
        assert_eq!(
            auth.authorize("token_mint", &bearer("")),
            Err(AuthError::InvalidToken)
        );
        let auth = AuthConfig {
            write_tokens: vec![String::new()],
            require_auth_for_writes: true,
        };
        assert_eq!(
            auth.authorize("token_mint", &bearer("")),
            Err(AuthError::InvalidToken)
        );
    }

    #[test]
    fn disabled_auth_admits_writes() {
        let auth = AuthConfig {
            write_tokens: Vec::new(),
            require_auth_for_writes: false,
        };
        assert_eq!(auth.authorize("htlc_create", &HeaderMap::new()), Ok(()));
    }

    #[test]
    fn rate_limit_is_per_client_ip() {
        let limiter = RateLimiterState::new(RateLimitConfig {
            requests_per_minute: 60,
            burst: 2,
        });
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(limiter.check_limit(a).0);
        assert!(limiter.check_limit(a).0);
        let (allowed, retry) = limiter.check_limit(a);
        assert!(!allowed, "a exhausted its own burst");
        assert!(retry.is_some());
        assert!(limiter.check_limit(b).0, "b has its own bucket");
        assert_eq!(limiter.tracked_clients(), 2);
    }

    #[test]
    fn zero_rate_disables_limiting() {
        let limiter = RateLimiterState::new(RateLimitConfig::from_requests_per_minute(0));
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..1000 {
            assert!(limiter.check_limit(a).0);
        }
    }
}
