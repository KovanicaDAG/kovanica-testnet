//! Blocking JSON-RPC client for light-node reads and `kovanica_sendRawTransaction`.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use kovanica_types::{Address, CommitSeal, Committee, Hash, LeaderHeader, StateProof};
use serde_json::{json, Value};

use crate::decode::{
    account_proof_from_json, committee_from_json, leader_header_from_json, seals_from_json,
};

/// Client bound to one full node.
pub struct RpcClient {
    url: String,
    http: reqwest::blocking::Client,
}

impl RpcClient {
    /// `url` is the node base (`http://127.0.0.1:8545`) or an `/rpc` URL.
    pub fn new(url: impl Into<String>) -> Result<Self> {
        let mut url = url.into();
        if !url.ends_with("/rpc") {
            url = format!("{}/rpc", url.trim_end_matches('/'));
        }
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .context("building HTTP client")?;
        Ok(Self { url, http })
    }

    /// Endpoint this client posts to.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Invoke `method` and return the JSON `result`.
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        });
        let response = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .with_context(|| format!("POST {}", self.url))?;
        let status = response.status();
        let value: Value = response
            .json()
            .with_context(|| format!("decoding JSON-RPC response from {}", self.url))?;
        if let Some(error) = value.get("error").filter(|err| !err.is_null()) {
            return Err(anyhow!("RPC `{method}` failed: {error}"));
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow!("RPC `{method}`: response had no `result` (HTTP {status})"))
    }

    /// Latest sealed header, or `None` when the node has not stored one.
    pub fn latest_header(&self) -> Result<Option<LeaderHeader>> {
        self.header(None)
    }

    /// Header at `height`, or the latest when `height` is `None`.
    pub fn header(&self, height: Option<u64>) -> Result<Option<LeaderHeader>> {
        let params = match height {
            Some(height) => json!([format!("0x{height:x}")]),
            None => json!([]),
        };
        let value = self.call("kovanica_getLeaderHeader", params)?;
        if value.is_null() {
            return Ok(None);
        }
        Ok(Some(leader_header_from_json(&value)?))
    }

    /// Seals stored at `height`.
    pub fn seals(&self, height: u64) -> Result<Vec<CommitSeal>> {
        let value = self.call("kovanica_getCommitSeals", json!([format!("0x{height:x}")]))?;
        seals_from_json(&value)
    }

    /// Current committee, interpreted at the configured `epoch`.
    pub fn committee(&self, epoch: u64) -> Result<Committee> {
        let value = self.call("kovanica_getCommittee", json!([]))?;
        committee_from_json(epoch, &value)
    }

    /// Account nonce. Missing accounts are 0.
    pub fn nonce(&self, address: &Address) -> Result<u64> {
        let value = self.call("kovanica_getNonce", json!([address.to_string()]))?;
        crate::decode::parse_quantity(&value, "nonce")
    }

    /// Submit a bincode transaction as `0x` hex. Returns the transaction hash hex.
    pub fn send_raw(&self, raw_hex: &str) -> Result<String> {
        let value = self.call("kovanica_sendRawTransaction", json!([raw_hex]))?;
        value.as_str().map(str::to_owned).ok_or_else(|| {
            anyhow!("kovanica_sendRawTransaction: expected a hash string, got {value}")
        })
    }

    /// Latest account proof, or `None` when the node has no committed state root.
    pub fn account_proof(&self, address: &Address) -> Result<Option<(u64, StateProof)>> {
        let value = self.call("kovanica_getAccountProof", json!([address.to_string()]))?;
        if value.is_null() {
            return Ok(None);
        }
        Ok(Some(account_proof_from_json(&value)?))
    }

    /// Light registration set. `rewardBps` is the full node's live split.
    pub fn light_set(&self) -> Result<Value> {
        self.call("kovanica_getLightSet", json!([]))
    }

    /// Transaction hash as returned by the node, for callers that already have [`Hash`].
    pub fn hash_hex(hash: &Hash) -> String {
        format!("0x{}", hex::encode(hash.0))
    }
}
