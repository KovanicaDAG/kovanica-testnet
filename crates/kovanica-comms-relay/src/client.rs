//! reqwest client for the relay HTTP API v1 (`docs/COMMS-M1-INTERFACES.md` §4).
//!
//! Small, typed wrapper so the CLI / desktop client never hand-builds URLs or
//! re-parses §4 error bodies.

use serde::{Deserialize, Serialize};

use crate::Envelope;

/// Errors raised by [`RelayClient`].
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The transport failed.
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    /// The relay answered with a §4 error object.
    #[error("relay error {status} ({code}): {message}")]
    Status {
        status: u16,
        code: String,
        message: String,
    },
    /// A response body could not be parsed.
    #[error("invalid response: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthResponse {
    pub ok: bool,
    pub version: String,
    pub envelopes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct PostEnvelopeResponse {
    ok: bool,
    id: String,
}

#[derive(Debug, Deserialize)]
struct InboxResponse {
    envelopes: Vec<Envelope>,
}

#[derive(Debug, Deserialize)]
struct AckResponse {
    ok: bool,
    deleted: usize,
}

#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    code: String,
    message: String,
}

/// Typed client for a relay base URL (e.g. `http://127.0.0.1:8787`).
#[derive(Debug, Clone)]
pub struct RelayClient {
    base: String,
    http: reqwest::Client,
}

impl RelayClient {
    /// Create a client for `base_url`. Trailing `/` is trimmed.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Create a client reusing an existing `reqwest::Client`.
    pub fn with_http(base_url: impl Into<String>, http: reqwest::Client) -> Self {
        Self {
            base: base_url.into().trim_end_matches('/').to_string(),
            http,
        }
    }

    /// `POST /v1/envelope`; returns the stored envelope `id`.
    pub async fn post_envelope(&self, envelope: &Envelope) -> Result<String, ClientError> {
        let body = envelope.to_json_bytes().map_err(|e| ClientError::Status {
            status: 0,
            code: "local".to_string(),
            message: e.to_string(),
        })?;
        let response = self
            .http
            .post(format!("{}/v1/envelope", self.base))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await?;
        let response = check_status(response).await?;
        let parsed: PostEnvelopeResponse = response.json().await?;
        Ok(parsed.id)
    }

    /// `GET /v1/inbox/{comms_id}` (does not delete server-side).
    pub async fn get_inbox(
        &self,
        comms_id: &str,
        limit: Option<usize>,
        since: Option<u64>,
    ) -> Result<Vec<Envelope>, ClientError> {
        let mut request = self.http.get(format!("{}/v1/inbox/{comms_id}", self.base));
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(limit) = limit {
            params.push(("limit", limit.to_string()));
        }
        if let Some(since) = since {
            params.push(("since", since.to_string()));
        }
        if !params.is_empty() {
            request = request.query(&params);
        }
        let response = check_status(request.send().await?).await?;
        let parsed: InboxResponse = response.json().await?;
        Ok(parsed.envelopes)
    }

    /// `POST /v1/ack`; returns the number of deleted envelopes.
    pub async fn ack(&self, to: &str, ids: &[String]) -> Result<usize, ClientError> {
        #[derive(Serialize)]
        struct AckBody<'a> {
            to: &'a str,
            ids: &'a [String],
        }
        let body = serde_json::to_vec(&AckBody { to, ids })?;
        let response = self
            .http
            .post(format!("{}/v1/ack", self.base))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await?;
        let response = check_status(response).await?;
        let parsed: AckResponse = response.json().await?;
        if !parsed.ok {
            return Err(ClientError::Status {
                status: 200,
                code: "internal".to_string(),
                message: "relay ack returned ok:false".to_string(),
            });
        }
        Ok(parsed.deleted)
    }

    /// `GET /v1/health`.
    pub async fn health(&self) -> Result<HealthResponse, ClientError> {
        let response = check_status(
            self.http
                .get(format!("{}/v1/health", self.base))
                .send()
                .await?,
        )
        .await?;
        Ok(response.json().await?)
    }
}

/// Turn a non-success §4 response into [`ClientError::Status`].
async fn check_status(response: reqwest::Response) -> Result<reqwest::Response, ClientError> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status().as_u16();
    let bytes = response.bytes().await?;
    match serde_json::from_slice::<ErrorEnvelope>(&bytes) {
        Ok(parsed) => Err(ClientError::Status {
            status,
            code: parsed.error.code,
            message: parsed.error.message,
        }),
        Err(_) => Err(ClientError::Status {
            status,
            code: "internal".to_string(),
            message: String::from_utf8_lossy(&bytes).into_owned(),
        }),
    }
}
