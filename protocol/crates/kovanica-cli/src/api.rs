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
    /// Ask the node to build an asset transfer and return its signature hash.
    pub fn prepare_transfer_asset(
        &self,
        from: &str,
        to: &str,
        amount: u64,
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

    /// Ask the node to build an HTLC creation and return its signature hash.
    pub fn prepare_create_htlc(
        &self,
        from: &str,
        amount: u64,
        recipient_pk: &[u8; 32],
        preimage_hash: &[u8; 32],
        timeout: u32,
        asset_id: Option<kovanica_state::AssetId>,
    ) -> Result<Value> {
        let mut query = format!(
            "/api/htlc/prepare?from={}&amount={}&recipient_pk={}&preimage_hash={}&timeout={}",
            from,
            amount,
            hex::encode(recipient_pk),
            hex::encode(preimage_hash),
            timeout
        );
        if let Some(asset) = asset_id {
            query.push_str(&format!("&asset_id={}", hex::encode(asset.as_bytes())));
        }
        self.get(&query)
    }

    /// Submit a signed HTLC creation transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_create_htlc(
        &self,
        from: &str,
        amount: u64,
        recipient_pk: &[u8; 32],
        preimage_hash: &[u8; 32],
        timeout: u32,
        asset_id: Option<kovanica_state::AssetId>,
        sighash: &str,
        sig: &str,
    ) -> Result<Value> {
        let mut query = format!(
            "/api/htlc/submit?from={}&amount={}&recipient_pk={}&preimage_hash={}&timeout={}&sighash={}&sig={}",
            from,
            amount,
            hex::encode(recipient_pk),
            hex::encode(preimage_hash),
            timeout,
            sighash,
            sig
        );
        if let Some(asset) = asset_id {
            query.push_str(&format!("&asset_id={}", hex::encode(asset.as_bytes())));
        }
        self.post_form(&query)
    }

    /// Prepare an unsigned HTLC redeem transaction.
    pub fn prepare_redeem_htlc(
        &self,
        from: &str,
        outpoint: kovanica_state::OutPoint,
        script: kovanica_state::htlc::HtlcScript,
        preimage: [u8; 32],
        to: &str,
    ) -> Result<Value> {
        let query = format!(
            "/api/htlc/redeem/prepare?from={}&outpoint_tx={}&outpoint_index={}&script={}&preimage={}&to={}",
            from,
            outpoint.tx.to_hex(),
            outpoint.index,
            hex::encode(script.bytes()),
            hex::encode(preimage),
            to
        );
        self.get(&query)
    }

    /// Submit a signed HTLC redeem transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_redeem_htlc(
        &self,
        from: &str,
        outpoint: kovanica_state::OutPoint,
        script: kovanica_state::htlc::HtlcScript,
        preimage: [u8; 32],
        to: &str,
        sighash: &str,
        sig: &str,
    ) -> Result<Value> {
        let query = format!(
            "/api/htlc/redeem/submit?from={}&outpoint_tx={}&outpoint_index={}&script={}&preimage={}&to={}&sighash={}&sig={}",
            from,
            outpoint.tx.to_hex(),
            outpoint.index,
            hex::encode(script.bytes()),
            hex::encode(preimage),
            to,
            sighash,
            sig
        );
        self.post_form(&query)
    }

    /// Prepare an unsigned HTLC refund transaction.
    pub fn prepare_refund_htlc(
        &self,
        from: &str,
        outpoint: kovanica_state::OutPoint,
        script: kovanica_state::htlc::HtlcScript,
        to: &str,
    ) -> Result<Value> {
        let query = format!(
            "/api/htlc/refund/prepare?from={}&outpoint_tx={}&outpoint_index={}&script={}&to={}",
            from,
            outpoint.tx.to_hex(),
            outpoint.index,
            hex::encode(script.bytes()),
            to
        );
        self.get(&query)
    }

    /// Submit a signed HTLC refund transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_refund_htlc(
        &self,
        from: &str,
        outpoint: kovanica_state::OutPoint,
        script: kovanica_state::htlc::HtlcScript,
        to: &str,
        sighash: &str,
        sig: &str,
    ) -> Result<Value> {
        let query = format!(
            "/api/htlc/refund/submit?from={}&outpoint_tx={}&outpoint_index={}&script={}&to={}&sighash={}&sig={}",
            from,
            outpoint.tx.to_hex(),
            outpoint.index,
            hex::encode(script.bytes()),
            to,
            sighash,
            sig
        );
        self.post_form(&query)
    }

    /// Query the balance locked to an HTLC script.
    pub fn htlc_balance(&self, script: &kovanica_state::htlc::HtlcScript) -> Result<u64> {
        let script_hex = hex::encode(script.bytes());
        let val = self.get(&format!("/api/htlc/balance?script={script_hex}"))?;
        val.get("balance")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("no balance in response"))
    }

    /// Derive an RWA asset id from issuer key + parameters.
    pub fn rwa_derive(&self, issuer: &str, class: &str, id: &str, version: u8) -> Result<Value> {
        let query = format!(
            "/api/rwa/derive?issuer={}&class={}&id={}&version={}",
            issuer, class, id, version
        );
        self.get(&query)
    }

    /// Get RWA detail by asset ID.
    pub fn rwa_detail(&self, asset_id: &str) -> Result<Value> {
        self.get(&format!("/api/rwa/{asset_id}"))
    }

    /// Get NFT detail by asset ID.
    pub fn nft_detail(&self, asset_id: &str) -> Result<Value> {
        self.get(&format!("/api/nft/{asset_id}"))
    }

    /// Get collection detail by collection ID.
    pub fn collection_detail(&self, collection_id: &str) -> Result<Value> {
        self.get(&format!("/api/collection/{collection_id}"))
    }

    /// Transaction history for an address.
    pub fn history(&self, address: &str, limit: u32) -> Result<Value> {
        self.get(&format!("/api/history?address={address}&limit={limit}"))
    }

    /// Mempool fee estimate for a transfer amount.
    pub fn fee_estimate(&self, amount: u64) -> Result<Value> {
        self.get(&format!("/api/fee_estimate?amount={amount}"))
    }

    /// Block detail by ID.
    pub fn block_detail(&self, id: &str) -> Result<Value> {
        self.get(&format!("/api/block/{id}"))
    }

    /// Transaction detail by ID.
    pub fn tx_detail(&self, id: &str) -> Result<Value> {
        self.get(&format!("/api/tx/{id}"))
    }

    /// Address detail by address.
    pub fn address_detail(&self, addr: &str) -> Result<Value> {
        self.get(&format!("/api/address/{addr}"))
    }

    /// Submit a signed transaction (generic).
    pub fn submit_tx(&self, tx_hex: &str) -> Result<Value> {
        self.post_form(&format!("/api/submit?tx={tx_hex}"))
    }

    /// Faucet request.
    pub fn faucet(&self, address: &str, amount: u64) -> Result<Value> {
        self.post_form(&format!("/api/faucet?to={address}&amount={amount}"))
    }

    /// Multisig create.
    pub fn multisig_create(&self, m: u8, pubkeys: &[[u8; 32]]) -> Result<Value> {
        let pubkeys_hex: Vec<String> = pubkeys.iter().map(hex::encode).collect();
        let body = serde_json::json!({
            "m": m,
            "pubkeys": pubkeys_hex,
        });
        self.post_json("/api/multisig/create", &body)
    }

    /// Multisig build.
    pub fn multisig_build(
        &self,
        from: &str,
        to: &str,
        amount: u64,
        asset_id: Option<kovanica_state::AssetId>,
    ) -> Result<Value> {
        let mut query = format!("/api/multisig/build?from={from}&to={to}&amount={amount}");
        if let Some(asset) = asset_id {
            query.push_str(&format!("&asset_id={}", hex::encode(asset.as_bytes())));
        }
        self.get(&query)
    }

    /// Multisig combine partial signatures.
    pub fn multisig_combine(&self, partials: &[Value]) -> Result<Value> {
        let body = serde_json::json!({ "partials": partials });
        self.post_json("/api/multisig/combine", &body)
    }

    /// Multisig submit.
    pub fn multisig_submit(&self, tx_hex: &str, signatures: &[[u8; 64]]) -> Result<Value> {
        let sigs_hex: Vec<String> = signatures.iter().map(hex::encode).collect();
        let body = serde_json::json!({
            "tx": tx_hex,
            "signatures": sigs_hex,
        });
        self.post_json("/api/multisig/submit", &body)
    }
}

/// Pretty-print a JSON value to stdout.
pub fn print_json(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
