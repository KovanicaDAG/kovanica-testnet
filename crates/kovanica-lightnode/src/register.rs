//! Light-node bond, exit, and VRF witness submission.
//!
//! These transactions pay a fee. Stake and Delegate are the fee-free kinds.
//! A witness is submitted once the full node has accepted the raw transaction
//! for this epoch. The same proof is not rebuilt every round: the VRF proof
//! is not deterministic, and a second witness would pay another fee.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use kovanica_crypto::{derive_vrf_secret_from_seed, vrf_prove, VRFKeyPair};
use kovanica_light::sign_exit_light_node;
use kovanica_light::{sign_light_witness, sign_register_light_node};
use kovanica_types::{light_vrf_input, Address, Hash, PublicKey, SigningKey};
use serde_json::Value;

use crate::decode::{parse_hash, parse_quantity};
use crate::rpc::RpcClient;
use crate::transfer::encode_raw;

/// File that records the epoch whose witness the RPC already accepted.
const WITNESS_EPOCH_FILE: &str = "witness-epoch";

/// Fee in atoms for register, exit, and witness transactions.
pub const LIGHT_TX_FEE: u64 = 1;

/// One `kovanica_getLightSet` response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LightView {
    /// Live reward split in basis points, as reported by the full node.
    pub reward_bps: u64,
    /// `epoch_for_height(committed_height)` (2 400 heights ≈ 8 h) on the full node.
    pub epoch: u64,
    /// Epoch-opening leader digest, when the full node has noted one.
    pub beacon: Option<Hash>,
    /// Registered identities.
    pub nodes: Vec<LightNodeView>,
}

/// One registered light node as the RPC reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LightNodeView {
    /// Bonded account.
    pub address: Address,
    /// Bond in atoms.
    pub stake: u64,
    /// ECVRF public key.
    pub vrf_public_key: PublicKey,
    /// Active in [`LightView::epoch`].
    pub active: bool,
    /// A witness for this epoch is already stored.
    pub witnessed: bool,
    /// Currently inside the 32-slot winner set.
    pub selected: bool,
}

impl LightView {
    /// Decode `kovanica_getLightSet`.
    pub fn from_value(value: &Value) -> Result<Self> {
        let reward_bps = value.get("rewardBps").and_then(Value::as_u64).unwrap_or(0);
        let epoch = match value.get("epoch") {
            Some(epoch) => parse_quantity(epoch, "epoch")?,
            None => bail!("light set is missing `epoch`"),
        };
        let beacon = match value.get("beacon") {
            None | Some(Value::Null) => None,
            Some(raw) => Some(parse_hash(raw, "beacon")?),
        };
        let empty = Vec::new();
        let raw_nodes = value
            .get("nodes")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        let mut nodes = Vec::with_capacity(raw_nodes.len());
        for node in raw_nodes {
            nodes.push(LightNodeView::from_value(node)?);
        }
        Ok(Self {
            reward_bps,
            epoch,
            beacon,
            nodes,
        })
    }

    /// The registration for `address`, if the full node has one.
    pub fn node(&self, address: &Address) -> Option<&LightNodeView> {
        self.nodes.iter().find(|node| node.address == *address)
    }
}

impl LightNodeView {
    fn from_value(value: &Value) -> Result<Self> {
        let address = value
            .get("address")
            .and_then(Value::as_str)
            .context("light node is missing `address`")?
            .parse()
            .map_err(|err| anyhow::anyhow!("light node address: {err}"))?;
        let stake = match value.get("stake") {
            Some(stake) => parse_quantity(stake, "stake")?,
            None => bail!("light node is missing `stake`"),
        };
        let vrf = match value.get("vrfPublicKey") {
            Some(raw) => parse_hash(raw, "vrfPublicKey")?,
            None => bail!("light node is missing `vrfPublicKey`"),
        };
        if let Some(epoch) = value.get("effectiveEpoch") {
            parse_quantity(epoch, "effectiveEpoch")?;
        }
        if let Some(epoch) = value.get("exitEpoch").filter(|epoch| !epoch.is_null()) {
            parse_quantity(epoch, "exitEpoch")?;
        }
        Ok(Self {
            address,
            stake,
            vrf_public_key: PublicKey(vrf.0),
            active: value
                .get("active")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            witnessed: value
                .get("witnessed")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            selected: value
                .get("selected")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }
}

/// Whether this process should build a witness for the current epoch.
///
/// `submitted_epoch` is the epoch whose raw transaction the RPC already
/// accepted. A second proof is not built for that epoch.
pub fn witness_beacon(
    view: &LightView,
    sender: &Address,
    submitted_epoch: Option<u64>,
) -> Option<Hash> {
    let node = view.node(sender)?;
    if !node.active || node.witnessed || submitted_epoch == Some(view.epoch) {
        return None;
    }
    view.beacon
}

/// Status lines for the light set. `None` means the RPC could not be read.
pub fn status_lines(view: Option<&LightView>, address: &Address) -> Vec<String> {
    let Some(view) = view else {
        return vec![
            "bond: light set unavailable".to_owned(),
            "reward basis points: unavailable".to_owned(),
        ];
    };
    let mut lines = vec![
        format!("light epoch: {}", view.epoch),
        format!("reward basis points: {}", view.reward_bps),
    ];
    match view.node(address) {
        Some(node) => {
            lines.push(format!("bond: {} atoms", node.stake));
            lines.push(format!(
                "active: {}",
                if node.active { "yes" } else { "no" }
            ));
            lines.push(format!(
                "witnessed: {}",
                if node.witnessed { "yes" } else { "no" }
            ));
            lines.push(format!(
                "selected: {}",
                if node.selected { "yes" } else { "no" }
            ));
        }
        None => lines.push("bond: not registered".to_owned()),
    }
    lines
}

/// Sign and submit `RegisterLightNode`.
pub fn submit_bond(
    rpc: &RpcClient,
    chain_id: u64,
    signing_key: &SigningKey,
    sender: Address,
    stake: u64,
    fee: u64,
) -> Result<String> {
    let vrf = vrf_keypair(signing_key)?;
    let nonce = rpc.nonce(&sender)?;
    let transaction = sign_register_light_node(
        chain_id,
        signing_key,
        sender,
        vrf.public_key_typed(),
        stake,
        nonce,
        fee,
    );
    let hash = rpc.send_raw(&encode_raw(&transaction)?)?;
    println!(
        "vrf public key: 0x{}",
        hex::encode(vrf.public_key_typed().0)
    );
    Ok(hash)
}

/// Sign and submit `ExitLightNode`.
pub fn submit_exit(
    rpc: &RpcClient,
    chain_id: u64,
    signing_key: &SigningKey,
    sender: Address,
    fee: u64,
) -> Result<String> {
    let nonce = rpc.nonce(&sender)?;
    let transaction = sign_exit_light_node(chain_id, signing_key, sender, nonce, fee);
    rpc.send_raw(&encode_raw(&transaction)?)
}

/// Submit one witness when this key is active and the beacon is known.
///
/// Returns the transaction hash when a new witness was accepted by the RPC.
/// A missing light set, an inactive bond, or an epoch already submitted
/// returns `Ok(None)`.
pub fn submit_witness_if_due(
    dir: &Path,
    rpc: &RpcClient,
    chain_id: u64,
    signing_key: &SigningKey,
    sender: Address,
) -> Result<Option<String>> {
    let value = match rpc.light_set() {
        Ok(value) => value,
        Err(err) => {
            eprintln!("light set unavailable: {err:#}");
            return Ok(None);
        }
    };
    let view = LightView::from_value(&value)?;
    let Some(beacon) = witness_beacon(&view, &sender, submitted_epoch(dir)?) else {
        return Ok(None);
    };
    let vrf = vrf_keypair(signing_key)?;
    let registered = view
        .node(&sender)
        .context("light node disappeared while submitting")?;
    if registered.vrf_public_key != vrf.public_key_typed() {
        bail!("registered VRF key does not match this keystore");
    }
    let input = light_vrf_input(chain_id, view.epoch, &beacon);
    let output = vrf_prove(&vrf, &input);
    let nonce = rpc.nonce(&sender)?;
    let transaction = sign_light_witness(
        chain_id,
        signing_key,
        sender,
        view.epoch,
        output.hash,
        output.proof,
        nonce,
        LIGHT_TX_FEE,
    );
    let hash = match rpc.send_raw(&encode_raw(&transaction)?) {
        Ok(hash) => hash,
        Err(err) if err.to_string().contains("already exists") => {
            remember_epoch(dir, view.epoch)?;
            return Ok(None);
        }
        Err(err) => return Err(err),
    };
    remember_epoch(dir, view.epoch)?;
    Ok(Some(hash))
}

fn vrf_keypair(signing_key: &SigningKey) -> Result<VRFKeyPair> {
    let secret = derive_vrf_secret_from_seed(&signing_key.to_bytes());
    VRFKeyPair::from_secret(secret).context("deriving the light-node VRF key")
}

fn submitted_epoch(dir: &Path) -> Result<Option<u64>> {
    let path = dir.join(WITNESS_EPOCH_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let epoch = text
        .trim()
        .parse()
        .with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(epoch))
}

fn remember_epoch(dir: &Path, epoch: u64) -> Result<()> {
    let path = dir.join(WITNESS_EPOCH_FILE);
    let tmp = dir.join(format!("{WITNESS_EPOCH_FILE}.tmp"));
    fs::write(&tmp, epoch.to_string()).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_types::Address;

    fn address(byte: u8) -> Address {
        Address([byte; 32])
    }

    fn view(active: bool, witnessed: bool, beacon: bool) -> LightView {
        LightView {
            reward_bps: 0,
            epoch: 4,
            beacon: beacon.then_some(Hash([9u8; 32])),
            nodes: vec![LightNodeView {
                address: address(1),
                stake: 100,
                vrf_public_key: PublicKey([2u8; 32]),
                active,
                witnessed,
                selected: false,
            }],
        }
    }

    #[test]
    fn a_witness_is_due_only_when_the_node_is_active_and_unseen() {
        let sender = address(1);
        let beacon = Hash([9u8; 32]);
        assert_eq!(
            witness_beacon(&view(true, false, true), &sender, None),
            Some(beacon)
        );
        assert_eq!(
            witness_beacon(&view(false, false, true), &sender, None),
            None
        );
        assert_eq!(witness_beacon(&view(true, true, true), &sender, None), None);
        assert_eq!(
            witness_beacon(&view(true, false, false), &sender, None),
            None
        );
        assert_eq!(
            witness_beacon(&view(true, false, true), &sender, Some(4)),
            None
        );
        assert_eq!(
            witness_beacon(&view(true, false, true), &address(3), None),
            None
        );
    }

    #[test]
    fn light_set_json_decodes_the_live_shape() {
        let value = serde_json::json!({
            "rewardBps": 0,
            "epoch": "0x4",
            "beacon": null,
            "nodes": [{
                "address": address(1).to_string(),
                "stake": "0x64",
                "vrfPublicKey": format!("0x{}", hex::encode([2u8; 32])),
                "effectiveEpoch": "0x5",
                "exitEpoch": null,
                "active": false,
                "witnessed": false,
                "selected": false
            }]
        });
        let view = LightView::from_value(&value).unwrap();
        assert_eq!(view.reward_bps, 0);
        assert_eq!(view.epoch, 4);
        assert!(view.beacon.is_none());
        assert_eq!(view.nodes[0].stake, 100);
        assert!(!view.nodes[0].active);
        let lines = status_lines(Some(&view), &address(1));
        assert!(lines.iter().any(|line| line == "bond: 100 atoms"));
        assert!(lines.iter().any(|line| line == "reward basis points: 0"));
        let missing = status_lines(None, &address(1));
        assert!(missing
            .iter()
            .any(|line| line == "reward basis points: unavailable"));
    }
}
