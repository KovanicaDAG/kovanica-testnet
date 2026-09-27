//! Thin HTTP client for the Kovanica explorer JSON API.
//!
//! Routes and shapes mirror `kovanica-node`'s `explorer.rs`:
//!   * `GET  /api/head`              — chain head summary
//!   * `GET  /api/p2p`               — p2p listen/peers/bootstrap
//!   * `GET  /api/bootstrap`         — network parameters
//!   * `GET  /api/state`             — full snapshot (includes the block DAG)
//!   * `GET  /api/utxos?address=…`   — balance + unspent outputs
//!   * `POST /api/prepare?from&to&amount`  — returns the sighash to sign
//!   * `POST /api/submit?from&to&amount&sig` — broadcasts the signed transfer
//!
//! Note: `/api/blocks` returns a binary record export, not JSON, so the `blocks`
//! command reads the `node.dag` array out of `/api/state` instead.

use anyhow::{anyhow, Result};
use serde_json::Value;

/// A client bound to one explorer base URL (no trailing slash).
#[derive(Clone)]
pub struct Client {
    base: String,
}

/// Parse a Kovanica address (`kvnc…dag` or 64-hex).
pub fn parse_address(s: &str) -> Result<kovanica_state::Address> {
    kovanica_state::Address::parse(s).map_err(|e| anyhow!("invalid address {s:?}: {e}"))
}

impl Client {
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    fn call(resp: ureq::Response) -> Result<Value> {
        let text = resp.into_string()?;
        serde_json::from_str(&text).map_err(|e| anyhow!("response was not valid JSON: {e}\n{text}"))
    }

    fn get(&self, path: &str) -> Result<Value> {
        let resp = ureq::get(&self.url(path)).call()?;
        Self::call(resp)
    }

    fn post_json(&self, path: &str, body: &serde_json::Value) -> Result<Value> {
        let body_str = serde_json::to_string(body)?;
        let resp = ureq::post(&self.url(path))
            .set("Content-Type", "application/json")
            .send_string(&body_str)?;
        Self::call(resp)
    }

    fn post_form(&self, path: &str) -> Result<Value> {
        let resp = ureq::post(&self.url(path)).call()?;
        Self::call(resp)
    }

    pub fn head(&self) -> Result<Value> {
        self.get("/api/head")
    }

    pub fn p2p(&self) -> Result<Value> {
        self.get("/api/p2p")
    }

    pub fn bootstrap(&self) -> Result<Value> {
        self.get("/api/bootstrap")
    }

    pub fn state(&self) -> Result<Value> {
        self.get("/api/state")
    }

    /// The block DAG, pulled out of the full state snapshot.
    pub fn blocks(&self) -> Result<Value> {
        let mut state = self.state()?;
        match state.get_mut("node").and_then(|n| n.get_mut("dag")) {
            Some(dag) => Ok(dag.take()),
            None => Ok(state),
        }
    }

    /// Balance + unspent outputs for an address (hex or `kvnc…dag`).
    pub fn utxos(&self, address: &str) -> Result<Value> {
        self.get(&format!("/api/utxos?address={address}"))
    }

    /// Ask the node to build a transfer and return its signature hash.
    pub fn prepare(&self, from: &str, to: &str, amount: u64) -> Result<Value> {
        self.post_form(&format!("/api/prepare?from={from}&to={to}&amount={amount}"))
    }

    /// Broadcast a signed transfer. `sig` is 128 lowercase hex chars.
    pub fn submit(&self, from: &str, to: &str, amount: u64, sig: &str) -> Result<Value> {
        self.post_form(&format!(
            "/api/submit?from={from}&to={to}&amount={amount}&sig={sig}"
        ))
    }

    /// Ask the node to build an HTLC and return its signature hash.
    pub fn prepare_htlc(
        &self,
        from: &str,
        amount: u64,
        recipient_pk: &[u8; 32],
        preimage_hash: &[u8; 32],
        timeout: u32,
        asset_id: Option<kovanica_state::AssetId>,
    ) -> Result<Value> {
        let mut body = serde_json::json!({
            "from": from,
            "amount": amount,
            "recipient_pk": hex::encode(recipient_pk),
            "preimage_hash": hex::encode(preimage_hash),
            "timeout": timeout,
        });
        if let Some(asset) = asset_id {
            body["asset_id"] = serde_json::Value::String(hex::encode(asset.as_bytes()));
        }
        self.post_json("/api/htlc/prepare", &body)
    }

    /// Submit a signed HTLC creation transaction.
    pub fn submit_htlc(&self, from: &str, sighash: &str, sig: &str) -> Result<Value> {
        let body = serde_json::json!({
            "from": from,
            "sighash": sighash,
            "sig": sig,
        });
        self.post_json("/api/htlc/submit", &body)
    }

    /// Redeem (claim) an HTLC by revealing the preimage.
    pub fn redeem_htlc(
        &self,
        from: &str,
        outpoint: kovanica_state::OutPoint,
        script: kovanica_state::htlc::HtlcScript,
        preimage: [u8; 32],
        to: &str,
    ) -> Result<Value> {
        let body = serde_json::json!({
            "from": from,
            "outpoint_tx": outpoint.tx.to_hex(),
            "outpoint_index": outpoint.index,
            "script": hex::encode(script.bytes()),
            "preimage": hex::encode(preimage),
            "to": to,
        });
        self.post_json("/api/htlc/redeem", &body)
    }

    /// Refund an expired HTLC.
    pub fn refund_htlc(
        &self,
        from: &str,
        outpoint: kovanica_state::OutPoint,
        script: kovanica_state::htlc::HtlcScript,
        to: &str,
    ) -> Result<Value> {
        let body = serde_json::json!({
            "from": from,
            "outpoint_tx": outpoint.tx.to_hex(),
            "outpoint_index": outpoint.index,
            "script": hex::encode(script.bytes()),
            "to": to,
        });
        self.post_json("/api/htlc/refund", &body)
    }

    /// Query the balance of an HTLC script.
    pub fn htlc_balance(&self, script: &kovanica_state::htlc::HtlcScript) -> Result<u64> {
        let script_hex = hex::encode(script.bytes());
        let val = self.get(&format!("/api/htlc/balance?script={script_hex}"))?;
        val.get("balance")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow!("no balance in response"))
    }

    /// Ask the node to build an asset transfer and return its signature hash.
    pub fn prepare_transfer_asset(
        &self,
        from: &str,
        amount: u64,
        to: &str,
        asset_id: Option<kovanica_state::AssetId>,
    ) -> Result<Value> {
        let mut query = format!("/api/prepare?from={from}&to={to}&amount={amount}");
        if let Some(asset) = asset_id {
            query.push_str(&format!("&asset_id={}", hex::encode(asset.as_bytes())));
        }
        self.post_form(&query)
    }

    /// Broadcast a signed asset transfer. `sig` is 128 lowercase hex chars.
    pub fn submit_transfer_asset(
        &self,
        from: &str,
        to: &str,
        amount: u64,
        asset_id: Option<kovanica_state::AssetId>,
        sig: &str,
    ) -> Result<Value> {
        let mut query = format!("/api/submit?from={from}&to={to}&amount={amount}&sig={sig}");
        if let Some(asset) = asset_id {
            query.push_str(&format!("&asset_id={}", hex::encode(asset.as_bytes())));
        }
        self.post_form(&query)
    }

    /// Get NFT detail by asset ID.
    pub fn nft_detail(&self, asset_id: &str) -> Result<Value> {
        self.get(&format!("/api/nft/{asset_id}"))
    }

    /// Get collection detail by collection ID.
    pub fn collection_detail(&self, collection_id: &str) -> Result<Value> {
        self.get(&format!("/api/collection/{collection_id}"))
    }

    /// Get RWA detail by asset ID.
    pub fn rwa_detail(&self, asset_id: &str) -> Result<Value> {
        self.get(&format!("/api/rwa/{asset_id}"))
    }

    /// Derive an RWA asset id from issuer key + parameters.
    pub fn rwa_derive(&self, issuer: &str, class: &str, id: &str, version: u8) -> Result<Value> {
        self.post_form(&format!(
            "/api/rwa/derive?issuer={issuer}&class={class}&id={id}&version={version}"
        ))
    }

    /// Transaction history for an address.
    pub fn history(&self, address: &str, limit: u32) -> Result<Value> {
        self.get(&format!("/api/history?address={address}&limit={limit}"))
    }

    /// Mempool fee estimate for a transfer amount.
    pub fn fee_estimate(&self, amount: u64) -> Result<Value> {
        self.get(&format!("/api/fee_estimate?amount={amount}"))
    }

    /// Block detail by id.
    pub fn block_detail(&self, id: &str) -> Result<Value> {
        self.get(&format!("/api/block/{id}"))
    }

    /// Transaction detail by id.
    pub fn tx_detail(&self, id: &str) -> Result<Value> {
        self.get(&format!("/api/tx/{id}"))
    }

    /// Address detail (balance + history summary).
    pub fn address_detail(&self, addr: &str) -> Result<Value> {
        self.get(&format!("/api/address/{addr}"))
    }

    /// Broadcast a fully-encoded, already-signed transaction blob.
    pub fn submit_tx(&self, tx_hex: &str) -> Result<Value> {
        let body = serde_json::json!({ "tx_hex": tx_hex });
        self.post_json("/api/submit_tx", &body)
    }

    /// Testnet faucet: request KVNC from the operator wallet.
    pub fn faucet(&self, to: &str, amount: u64) -> Result<Value> {
        self.post_form(&format!("/api/faucet?to={to}&amount={amount}"))
    }

    /// Create a multisig (M-of-N P2SH) address from public keys.
    pub fn multisig_create(&self, threshold: u8, pubkeys_hex: &[String]) -> Result<Value> {
        let body = serde_json::json!({
            "threshold": threshold,
            "pubkeys_hex": pubkeys_hex,
        });
        self.post_json("/api/multisig/create", &body)
    }

    /// Build an unsigned multisig spend; returns `tx_blob_hex` + `sighash_hex`.
    pub fn multisig_build(&self, address: &str, outputs: &[(String, u64)]) -> Result<Value> {
        let outputs: Vec<serde_json::Value> = outputs
            .iter()
            .map(|(addr, amount)| serde_json::json!({ "address": addr, "amount_atoms": amount }))
            .collect();
        let body = serde_json::json!({
            "address": address,
            "outputs": outputs,
        });
        self.post_json("/api/multisig/build", &body)
    }

    /// Combine partial signatures into a signed multisig transaction.
    pub fn multisig_combine(
        &self,
        tx_blob_hex: &str,
        partial_sigs_hex: &[String],
    ) -> Result<Value> {
        let body = serde_json::json!({
            "tx_blob_hex": tx_blob_hex,
            "partial_sigs_hex": partial_sigs_hex,
        });
        self.post_json("/api/multisig/combine", &body)
    }

    /// Submit a fully-signed multisig transaction.
    pub fn multisig_submit(&self, signed_tx_blob_hex: &str) -> Result<Value> {
        let body = serde_json::json!({ "signed_tx_blob_hex": signed_tx_blob_hex });
        self.post_json("/api/multisig/submit", &body)
    }
}

/// Pretty-print a JSON value to stdout.
pub fn print_json(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
