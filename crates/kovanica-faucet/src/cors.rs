//! Browser access for the testnet faucet from Kovanica Console.
//!
//! The allowlist matches `kovanica_rpc::CONSOLE_ALLOWED_ORIGINS`. The faucet does
//! not depend on `kovanica-rpc` (that crate pulls in the node), so the strings
//! are repeated here and locked by a test.

use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

/// Same origins as the RPC server. No wildcard.
pub const FAUCET_ALLOWED_ORIGINS: &[&str] = &[
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

const FAUCET_CORS_PATHS: &[&str] = &["/faucet", "/health"];

fn allowed(origin: &str) -> Option<&'static str> {
    FAUCET_ALLOWED_ORIGINS
        .iter()
        .copied()
        .find(|candidate| *candidate == origin)
}

/// CORS for `POST /faucet` and `GET /health`.
pub async fn faucet_cors(request: Request, next: Next) -> Response {
    if !FAUCET_CORS_PATHS.contains(&request.uri().path()) {
        return next.run(request).await;
    }
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    let Some(origin) = origin else {
        return next.run(request).await;
    };
    let Some(origin) = allowed(origin) else {
        let mut response = Response::new("origin not allowed".into());
        *response.status_mut() = StatusCode::FORBIDDEN;
        return response;
    };
    if request.method() == Method::OPTIONS {
        return preflight(origin);
    }
    let mut response = next.run(request).await;
    allow_origin(response.headers_mut(), origin);
    response
}

fn allow_origin(headers: &mut HeaderMap, origin: &'static str) {
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static(origin),
    );
    headers.insert(header::VARY, HeaderValue::from_static("Origin"));
}

fn preflight(origin: &'static str) -> Response {
    let mut response = Response::new("".into());
    *response.status_mut() = StatusCode::NO_CONTENT;
    allow_origin(response.headers_mut(), origin);
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type"),
    );
    response.headers_mut().insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("600"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::middleware::from_fn;
    use axum::routing::{get, post};
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new()
            .route("/faucet", post(|| async { "dispensed" }))
            .route("/health", get(|| async { "ok" }))
            .route("/metrics", get(|| async { "secret" }))
            .layer(from_fn(faucet_cors))
    }

    async fn send(origin: Option<&str>, method: &str, path: &str) -> axum::response::Response {
        let mut builder = axum::http::Request::builder().method(method).uri(path);
        if let Some(origin) = origin {
            builder = builder.header("origin", origin);
        }
        app()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[test]
    fn allowlist_matches_the_rpc_server() {
        assert_eq!(
            FAUCET_ALLOWED_ORIGINS,
            [
                "https://console.kovanica.online",
                "https://dash.kovanica.online",
                "https://faucet.kovanica.online",
                "https://kovanica.online",
                "https://wallet.kovanica.online",
                "http://127.0.0.1:5173",
                "http://localhost:5173",
                "http://127.0.0.1:3000",
                "http://localhost:3000",
            ]
        );
    }

    #[tokio::test]
    async fn console_origin_can_preflight_and_call_the_faucet() {
        let preflight = send(
            Some("https://console.kovanica.online"),
            "OPTIONS",
            "/faucet",
        )
        .await;
        assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            preflight
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://console.kovanica.online"
        );
        assert_eq!(
            preflight
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
                .unwrap(),
            "content-type"
        );

        let call = send(Some("http://localhost:5173"), "POST", "/faucet").await;
        assert_eq!(call.status(), StatusCode::OK);
        assert_eq!(
            call.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "http://localhost:5173"
        );
        let body = call.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"dispensed");
    }

    #[tokio::test]
    async fn foreign_origin_is_rejected_and_health_is_readable() {
        let denied = send(Some("https://evil.example"), "POST", "/faucet").await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert!(denied
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());

        let health = send(Some("https://console.kovanica.online"), "GET", "/health").await;
        assert_eq!(health.status(), StatusCode::OK);
        assert_eq!(
            health
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://console.kovanica.online"
        );
    }

    #[tokio::test]
    async fn requests_without_origin_and_other_paths_are_unchanged() {
        let call = send(None, "POST", "/faucet").await;
        assert_eq!(call.status(), StatusCode::OK);
        assert!(call
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());

        let metrics = send(Some("https://console.kovanica.online"), "GET", "/metrics").await;
        assert_eq!(metrics.status(), StatusCode::OK);
        assert!(metrics
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());
        let body = metrics.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"secret");
    }
}
