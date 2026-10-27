//! Node operations: status, balances, staking and governance.
//!
//! Status, balance, stake, and rewards read the node JSON-RPC. Governance
//! proposal commands are still a TODO: the node has no proposal RPC.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

use crate::amount::{format_kuna, format_kuna_decimal, format_kuna_fixed};
use crate::output::{print_json, print_kv, print_table};
use crate::rpc::{parse_quantity, RpcClient};
use crate::wallet::parse_address;
use kovanica_types::Address;

/// Render a JSON value as a display cell (`-` when absent).
fn cell(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => "-".to_string(),
    }
}

/// One connected peer from `kovanica_syncStatus`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerView {
    /// libp2p peer id. This is a transport identity, not a validator key.
    pub peer_id: String,
    /// Last DAG tip round the peer advertised.
    pub reported_tip_round: Option<u64>,
}

/// Fields read from `kovanica_syncStatus`.
///
/// Counters are plain JSON integers on the wire. Hex quantities are accepted
/// too, because other chain methods use that encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncSnapshot {
    /// Committed leader height, falling back to `localHeight`.
    pub height: Option<u64>,
    /// Local DAG tip round.
    pub round: Option<u64>,
    /// `None` when the payload did not say whether the node is catching up.
    pub catching_up: Option<bool>,
    pub behind_by: Option<u64>,
    pub target: Option<u64>,
    pub peer_count: Option<usize>,
    pub peers: Vec<PeerView>,
    /// Chain id from `networkTag`, `chainId`, or `chain_id`, when the node sent one.
    pub node_chain_id: Option<u64>,
}

/// How far the node is from the peers it can see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncState {
    /// `kovanica_syncStatus` reported `catchingUp: false`.
    InSync,
    /// `kovanica_syncStatus` reported `catchingUp: true`.
    CatchingUp {
        behind_by: Option<u64>,
        target: Option<u64>,
    },
    /// The sync method was missing or did not include `catchingUp`.
    Unknown,
}

/// Operator view of `kovanica status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainStatus {
    pub rpc: String,
    /// `--chain-id` or `KOVANICA_CHAIN_ID`.
    pub signing_chain_id: Option<u64>,
    /// Chain id the node reported, when `kovanica_syncStatus` included one.
    pub node_chain_id: Option<u64>,
    pub height: Option<u64>,
    pub round: Option<u64>,
    pub epoch: Option<u64>,
    pub committee: Vec<Value>,
    pub peer_count: Option<usize>,
    pub peers: Vec<PeerView>,
    pub sync: SyncState,
}

/// Parse `kovanica_syncStatus`.
pub fn parse_sync_status(value: &Value) -> Result<SyncSnapshot> {
    let object = value
        .as_object()
        .context("kovanica_syncStatus: expected an object")?;
    let committed = optional_quantity(object.get("committedHeight"))?;
    let local_height = optional_quantity(object.get("localHeight"))?;
    let peers = object
        .get("peers")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let peer_id = item.get("peerId")?.as_str()?.trim();
                    if peer_id.is_empty() {
                        return None;
                    }
                    let reported_tip_round =
                        optional_quantity(item.get("reportedTipRound")).unwrap_or(None);
                    Some(PeerView {
                        peer_id: peer_id.to_string(),
                        reported_tip_round,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let peer_count = match object.get("peerCount") {
        None | Some(Value::Null) => None,
        Some(count) => Some(
            usize::try_from(parse_quantity(count).context("kovanica_syncStatus peerCount")?)
                .map_err(|_| anyhow!("kovanica_syncStatus peerCount does not fit"))?,
        ),
    };
    Ok(SyncSnapshot {
        height: committed.or(local_height),
        round: optional_quantity(object.get("localTipRound"))?,
        catching_up: match object.get("catchingUp") {
            Some(Value::Bool(flag)) => Some(*flag),
            _ => None,
        },
        behind_by: optional_quantity(object.get("behindBy"))?,
        target: optional_quantity(object.get("catchUpTarget"))?,
        peer_count,
        peers,
        node_chain_id: reported_chain_id(object)?,
    })
}

/// Chain id from a sync-status object.
///
/// `networkTag` is `<chain_id>-<16 hex genesis digest>`. A numeric `chainId`
/// or `chain_id` is used when the tag is absent. Missing fields mean the node
/// did not report a chain.
fn reported_chain_id(object: &serde_json::Map<String, Value>) -> Result<Option<u64>> {
    if let Some(tag) = object.get("networkTag").and_then(Value::as_str) {
        let prefix = tag.split_once('-').map(|(id, _)| id).unwrap_or(tag);
        if prefix.is_empty() {
            return Ok(None);
        }
        let id = prefix.parse::<u64>().map_err(|_| {
            anyhow!("kovanica_syncStatus networkTag does not start with a chain id")
        })?;
        return Ok(Some(id));
    }
    for key in ["chainId", "chain_id"] {
        if let Some(value) = object.get(key) {
            if value.is_null() {
                return Ok(None);
            }
            return Ok(Some(
                parse_quantity(value).with_context(|| format!("kovanica_syncStatus {key}"))?,
            ));
        }
    }
    Ok(None)
}

/// Refuse to sign when `--chain-id` and the node name two different chains.
pub fn refuse_chain_mismatch(local: Option<u64>, reported: Option<u64>) -> Result<()> {
    if let (Some(local), Some(reported)) = (local, reported) {
        if local != reported {
            bail!(
                "--chain-id {local} does not match the node's chain {reported}. Refusing to use a different chain."
            );
        }
    }
    Ok(())
}

/// Query `kovanica_syncStatus` and refuse when the node reports a chain id
/// that differs from `signing_chain_id`.
///
/// When `kovanica_syncStatus` is unavailable or does not report a chain id,
/// this succeeds so signing still works against older or minimal RPC servers.
pub async fn ensure_node_chain_matches(
    client: &RpcClient,
    signing_chain_id: Option<u64>,
) -> Result<()> {
    if signing_chain_id.is_none() {
        return Ok(());
    }
    if let Ok(value) = client.call("kovanica_syncStatus", json!([])).await {
        let snapshot = parse_sync_status(&value)?;
        refuse_chain_mismatch(signing_chain_id, snapshot.node_chain_id)?;
    }
    Ok(())
}

/// Parse `kovanica_getCommitteeInfo` into `(epoch, members)`.
pub fn parse_committee_info(value: &Value) -> Result<(Option<u64>, Vec<Value>)> {
    let object = value
        .as_object()
        .context("kovanica_getCommitteeInfo: expected an object")?;
    let epoch = optional_quantity(object.get("epoch"))?;
    let members = object
        .get("members")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok((epoch, members))
}

/// Combine the RPC pieces `status` managed to read.
///
/// Height prefers the sync snapshot, then `kovanica_blockNumber`. Peer count
/// prefers the sync snapshot, including zero, then `/health`.
pub fn assemble_status(
    rpc: &str,
    signing_chain_id: Option<u64>,
    block_height: Option<u64>,
    sync: Option<&SyncSnapshot>,
    epoch: Option<u64>,
    committee: Vec<Value>,
    health_peers: Option<usize>,
) -> ChainStatus {
    let (height, round, peer_count, peers, sync_state) = match sync {
        Some(sync) => (
            sync.height.or(block_height),
            sync.round,
            sync.peer_count.or(health_peers),
            sync.peers.clone(),
            match sync.catching_up {
                Some(false) => SyncState::InSync,
                Some(true) => SyncState::CatchingUp {
                    behind_by: sync.behind_by,
                    target: sync.target,
                },
                None => SyncState::Unknown,
            },
        ),
        None => (
            block_height,
            None,
            health_peers,
            Vec::new(),
            SyncState::Unknown,
        ),
    };
    ChainStatus {
        rpc: rpc.to_string(),
        signing_chain_id,
        node_chain_id: sync.and_then(|item| item.node_chain_id),
        height,
        round,
        epoch,
        committee,
        peer_count,
        peers,
        sync: sync_state,
    }
}

fn status_json(status: &ChainStatus) -> Value {
    json!({
        "rpc": status.rpc,
        "chainIdReportedByNode": status.node_chain_id.is_some(),
        "signingChainId": status.signing_chain_id,
        "latestBlock": status.height,
        "round": status.round,
        "epoch": status.epoch,
        "committeeSize": status.committee.len(),
        "committee": status.committee,
        "syncing": match &status.sync {
            SyncState::InSync => Value::Bool(false),
            SyncState::CatchingUp { .. } => Value::Bool(true),
            SyncState::Unknown => Value::Null,
        },
        "sync": sync_label(&status.sync),
        "peerCount": status.peer_count,
        "peers": status.peers.iter().map(|peer| json!({
            "peerId": peer.peer_id,
            "reportedTipRound": peer.reported_tip_round,
        })).collect::<Vec<_>>(),
    })
}

fn status_rows(status: &ChainStatus) -> Vec<(&'static str, String)> {
    vec![
        ("RPC", status.rpc.clone()),
        (
            "Signing chain id",
            signing_chain_label(status.signing_chain_id, status.node_chain_id),
        ),
        ("Height", optional_number(status.height)),
        ("Round", optional_number(status.round)),
        ("Epoch", optional_number(status.epoch)),
        ("Sync", sync_label(&status.sync)),
        (
            "Peers",
            optional_number(status.peer_count.map(|count| count as u64)),
        ),
        ("Committee size", status.committee.len().to_string()),
    ]
}

fn signing_chain_label(local: Option<u64>, reported: Option<u64>) -> String {
    match (local, reported) {
        (Some(id), Some(node)) if id == node => format!("{id} (matches the node)"),
        (Some(id), Some(node)) => format!("{id} (local flag; the node reports chain {node})"),
        (Some(id), None) => format!("{id} (local flag; the node does not report chain_id)"),
        (None, Some(id)) => format!("{id} (reported by the node)"),
        (None, None) => "not reported by the node".to_string(),
    }
}

fn optional_number(value: Option<u64>) -> String {
    value
        .map(|number| number.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn sync_label(sync: &SyncState) -> String {
    match sync {
        SyncState::InSync => "in sync".to_string(),
        SyncState::Unknown => "unknown".to_string(),
        SyncState::CatchingUp {
            behind_by: Some(behind),
            target: Some(target),
        } => format!("catching up (behind {behind} rounds, target {target})"),
        SyncState::CatchingUp {
            behind_by: Some(behind),
            target: None,
        } => format!("catching up (behind {behind} rounds)"),
        SyncState::CatchingUp {
            behind_by: None,
            target: Some(target),
        } => format!("catching up (target {target})"),
        SyncState::CatchingUp {
            behind_by: None,
            target: None,
        } => "catching up".to_string(),
    }
}

fn optional_quantity(value: Option<&Value>) -> Result<Option<u64>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(other) => Ok(Some(parse_quantity(other)?)),
    }
}

fn stake_cell(value: Option<&Value>) -> String {
    value
        .and_then(|stake| parse_quantity(stake).ok())
        .map(format_kuna_fixed)
        .unwrap_or_else(|| cell(value))
}

/// `kovanica status` — height, round, epoch, peers, and sync, as the node reports them.
///
/// `signing_chain_id` is the local `--chain-id` / `KOVANICA_CHAIN_ID` value.
/// When `kovanica_syncStatus` includes `networkTag` or `chainId` and that
/// chain differs from the flag, the command refuses. When the node reports
/// nothing, status still says the chain id is a local flag.
pub async fn status(
    client: &RpcClient,
    signing_chain_id: Option<u64>,
    json_output: bool,
) -> Result<()> {
    let mut block_error = None;
    let block_height = match client.call("kovanica_blockNumber", json!([])).await {
        Ok(value) => Some(parse_quantity(&value).context("kovanica_blockNumber")?),
        Err(error) => {
            block_error = Some(error);
            None
        }
    };
    let sync = match client.call("kovanica_syncStatus", json!([])).await {
        Ok(value) => Some(parse_sync_status(&value)?),
        Err(error) => {
            if block_height.is_none() {
                return Err(block_error.unwrap_or(error));
            }
            None
        }
    };
    let (epoch, committee) = match client.call("kovanica_getCommitteeInfo", json!([])).await {
        Ok(value) => parse_committee_info(&value)?,
        Err(_) => match client.call("kovanica_getCommittee", json!([])).await {
            Ok(value) => (None, value.as_array().cloned().unwrap_or_default()),
            Err(_) => (None, Vec::new()),
        },
    };
    if let Some(snapshot) = &sync {
        refuse_chain_mismatch(signing_chain_id, snapshot.node_chain_id)?;
    }
    let health_peers = if sync.as_ref().and_then(|item| item.peer_count).is_none() {
        client.health_peer_count().await
    } else {
        None
    };
    let status = assemble_status(
        client.url(),
        signing_chain_id,
        block_height,
        sync.as_ref(),
        epoch,
        committee,
        health_peers,
    );

    if json_output {
        return print_json(&status_json(&status));
    }

    print_kv(&status_rows(&status));
    if !status.committee.is_empty() {
        println!();
        let rows: Vec<Vec<String>> = status
            .committee
            .iter()
            .map(|member| {
                vec![
                    cell(member.get("index")),
                    cell(member.get("address")),
                    stake_cell(member.get("stake")),
                    cell(member.get("network_address")),
                ]
            })
            .collect();
        print_table(&["INDEX", "ADDRESS", "STAKE", "NETWORK"], &rows);
    }
    if !status.peers.is_empty() {
        println!();
        let rows: Vec<Vec<String>> = status
            .peers
            .iter()
            .map(|peer| {
                vec![
                    peer.peer_id.clone(),
                    peer.reported_tip_round
                        .map(|round| round.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ]
            })
            .collect();
        print_table(&["PEER", "TIP ROUND"], &rows);
    }
    Ok(())
}

/// JSON and human rows for a native balance.
///
/// `balance` stays the atom count. `balanceKuna` is the same value with exactly
/// 9 decimal places, so a JSON number is never asked to hold a fractional KUNA.
pub fn balance_report(address: &Address, atoms: u64) -> Value {
    json!({
        "address": address.to_string(),
        "balance": atoms,
        "balanceKuna": format_kuna_decimal(atoms),
    })
}

/// Human-readable balance rows. The amount always shows 9 decimal places.
pub fn balance_rows(address: &Address, atoms: u64) -> Vec<(&'static str, String)> {
    vec![
        ("Address", address.to_string()),
        ("Balance", format_kuna_fixed(atoms)),
    ]
}

/// Stake, the part of it that is this address's validator bond, and rewards.
///
/// `kovanica_getStake` is one number: own validator stake plus every delegation
/// this address has made. The node does not return one row per delegation.
/// `own` is the sum of matching `kovanica_getValidators` rows. `delegated` is
/// `total - own` when that does not underflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakingReport {
    pub address: Address,
    pub total: u64,
    pub own: u64,
    pub delegated: u64,
    /// `false` when the stake total is smaller than the matching validator rows.
    pub total_covers_own: bool,
    pub rewards: u64,
    pub validator_rows: usize,
    /// Commission from the first matching validator row.
    pub commission_bps: Option<u64>,
    /// Active flag from the first matching validator row.
    pub active: Option<bool>,
    /// Payout address from the first matching validator row.
    pub payout: Option<Address>,
}

/// Split a stake total using validator rows compared as [`Address`] values.
pub fn assemble_staking(
    address: Address,
    total: u64,
    rewards: u64,
    validators: &[Value],
) -> Result<StakingReport> {
    let mut own = 0u64;
    let mut validator_rows = 0usize;
    let mut commission_bps = None;
    let mut active = None;
    let mut payout = None;
    for row in validators {
        let Some(text) = row.get("address").and_then(Value::as_str) else {
            continue;
        };
        let Ok(row_address) =
            Address::parse_for_chain(text.trim(), kovanica_types::signing::chain_id::LOCAL)
        else {
            continue;
        };
        if row_address != address {
            continue;
        }
        validator_rows += 1;
        let stake = match row.get("stake") {
            None | Some(Value::Null) => 0,
            Some(value) => parse_quantity(value).context("validator stake")?,
        };
        own = own.saturating_add(stake);
        if validator_rows == 1 {
            commission_bps = row.get("commission_bps").and_then(Value::as_u64);
            active = row.get("active").and_then(Value::as_bool);
            payout = row
                .get("payout_address")
                .and_then(Value::as_str)
                .and_then(|text| {
                    Address::parse_for_chain(text.trim(), kovanica_types::signing::chain_id::LOCAL)
                        .ok()
                });
        }
    }
    let total_covers_own = total >= own;
    Ok(StakingReport {
        address,
        total,
        own,
        delegated: total.saturating_sub(own),
        total_covers_own,
        rewards,
        validator_rows,
        commission_bps,
        active,
        payout,
    })
}

fn staking_json(report: &StakingReport) -> Value {
    json!({
        "address": report.address.to_string(),
        "total": report.total,
        "totalKuna": format_kuna_decimal(report.total),
        "own": report.own,
        "ownKuna": format_kuna_decimal(report.own),
        "delegated": report.delegated,
        "delegatedKuna": format_kuna_decimal(report.delegated),
        "rewards": report.rewards,
        "rewardsKuna": format_kuna_decimal(report.rewards),
        "totalCoversOwn": report.total_covers_own,
        "validatorRows": report.validator_rows,
        "commissionBps": report.commission_bps,
        "active": report.active,
        "payoutAddress": report.payout.as_ref().map(ToString::to_string),
        "delegationDetail": "unavailable",
    })
}

fn staking_rows(report: &StakingReport) -> Vec<(&'static str, String)> {
    let mut rows = vec![
        ("Address", report.address.to_string()),
        ("Total stake", format_kuna_fixed(report.total)),
        ("Own stake", format_kuna_fixed(report.own)),
        ("Delegated", format_kuna_fixed(report.delegated)),
        ("Rewards", format_kuna_fixed(report.rewards)),
        ("Validator rows", report.validator_rows.to_string()),
        (
            "Commission (bps)",
            report
                .commission_bps
                .map(|bps| bps.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        ),
        (
            "Active",
            match report.active {
                Some(true) => "yes".to_string(),
                Some(false) => "no".to_string(),
                None => "unknown".to_string(),
            },
        ),
        (
            "Payout",
            report
                .payout
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "unknown".to_string()),
        ),
        (
            "Delegation detail",
            "unavailable (the node returns one stake total)".to_string(),
        ),
    ];
    if !report.total_covers_own {
        rows.push((
            "Stake check",
            "total is smaller than own stake; delegated is zero".to_string(),
        ));
    }
    rows
}

/// `kovanica staking <address>` — own stake, delegations, and rewards.
pub async fn staking(
    client: &RpcClient,
    address: &str,
    chain_id: Option<u64>,
    json_output: bool,
) -> Result<()> {
    let address = parse_address(address, "address", chain_id.unwrap_or(0))?;
    let encoded = address.to_string();
    let total = parse_quantity(
        &client
            .call("kovanica_getStake", json!([encoded.clone()]))
            .await?,
    )
    .context("kovanica_getStake")?;
    let rewards = parse_quantity(&client.call("kovanica_getRewards", json!([encoded])).await?)
        .context("kovanica_getRewards")?;
    let validators = client.call("kovanica_getValidators", json!([])).await?;
    let validators = validators
        .as_array()
        .cloned()
        .ok_or_else(|| anyhow!("kovanica_getValidators: expected an array"))?;
    let report = assemble_staking(address, total, rewards, &validators)?;
    if json_output {
        return print_json(&staking_json(&report));
    }
    print_kv(&staking_rows(&report));
    Ok(())
}

/// `kovanica balance <address>` — native balance, displayed in KUNA.
pub async fn balance(
    client: &RpcClient,
    address: &str,
    chain_id: Option<u64>,
    json_output: bool,
) -> Result<()> {
    // No selected chain is not a dev chain: legacy hex is refused. The
    // canonical form still parses.
    let address = parse_address(address, "address", chain_id.unwrap_or(0))?;
    let value = client
        .call("kovanica_getBalance", json!([address.to_string()]))
        .await?;
    let atoms = parse_quantity(&value)?;

    if json_output {
        return print_json(&balance_report(&address, atoms));
    }

    print_kv(&balance_rows(&address, atoms));
    Ok(())
}

/// Params object for `kovanica_getTransactionHistory`.
///
/// The address is parsed with [`parse_address`] and sent in canonical
/// `kvnc…dag` form. `--sent` and `--received` are exclusive; neither means
/// the node default (`all`). A blank cursor is rejected.
pub fn history_params(
    address: &str,
    chain_id: Option<u64>,
    limit: Option<u64>,
    cursor: Option<&str>,
    sent: bool,
    received: bool,
) -> Result<Value> {
    if sent && received {
        return Err(anyhow!("--sent and --received cannot be used together"));
    }
    // No selected chain is not a dev chain: legacy hex is refused. The
    // canonical form still parses.
    let address = parse_address(address, "address", chain_id.unwrap_or(0))?;
    let mut params = serde_json::Map::new();
    params.insert("address".into(), json!(address.to_string()));
    if let Some(limit) = limit {
        params.insert("limit".into(), json!(limit));
    }
    if let Some(cursor) = cursor {
        let cursor = cursor.trim();
        if cursor.is_empty() {
            return Err(anyhow!("cursor: empty"));
        }
        params.insert("cursor".into(), json!(cursor));
    }
    if sent {
        params.insert("direction".into(), json!("sent"));
    } else if received {
        params.insert("direction".into(), json!("received"));
    }
    Ok(Value::Object(params))
}

/// JSON and table rows for one history page.
///
/// JSON keeps the node's hex quantities and adds `amountAtoms` /
/// `amountKuna` and `feeAtoms` / `feeKuna` (9 decimal places).
pub fn history_view(page: &Value) -> Result<HistoryView> {
    let entries = page
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("history: entries must be an array"))?;
    let next_cursor = match page.get("next_cursor") {
        None | Some(Value::Null) => None,
        Some(Value::String(cursor)) => Some(cursor.clone()),
        Some(other) => {
            return Err(anyhow!(
                "history: next_cursor must be a string or null, got {other}"
            ))
        }
    };

    let mut json_entries = Vec::with_capacity(entries.len());
    let mut rows = Vec::with_capacity(entries.len());
    for entry in entries {
        let amount = parse_quantity(
            entry
                .get("amount")
                .ok_or_else(|| anyhow!("history: entry missing amount"))?,
        )?;
        let fee = parse_quantity(
            entry
                .get("fee")
                .ok_or_else(|| anyhow!("history: entry missing fee"))?,
        )?;
        let amount_kuna = format_kuna(amount);
        let fee_kuna = format_kuna(fee);
        let height = entry
            .get("height")
            .ok_or_else(|| anyhow!("history: entry missing height"))?;
        let height_text = parse_quantity(height)?.to_string();
        let timestamp_text = match entry.get("timestamp") {
            None | Some(Value::Null) => "-".to_string(),
            Some(value) => parse_quantity(value)?.to_string(),
        };
        let kind = json_string(entry, "kind")?;
        let status = json_string(entry, "status")?;
        let from = json_string(entry, "from")?;
        let to = match entry.get("to") {
            None | Some(Value::Null) => "-".to_string(),
            Some(Value::String(value)) => value.clone(),
            Some(other) => {
                return Err(anyhow!("history: to must be a string or null, got {other}"))
            }
        };
        let hash = json_string(entry, "hash")?;
        let mut enriched = entry.clone();
        if let Some(object) = enriched.as_object_mut() {
            object.insert("amountAtoms".into(), json!(amount));
            object.insert("amountKuna".into(), json!(amount_kuna.clone()));
            object.insert("feeAtoms".into(), json!(fee));
            object.insert("feeKuna".into(), json!(fee_kuna.clone()));
        }
        json_entries.push(enriched);
        rows.push(vec![
            height_text,
            timestamp_text,
            kind,
            status,
            from,
            to,
            amount_kuna,
            fee_kuna,
            hash,
        ]);
    }

    Ok(HistoryView {
        json: json!({
            "entries": json_entries,
            "next_cursor": next_cursor,
        }),
        rows,
        next_cursor,
    })
}

fn json_string(entry: &Value, field: &str) -> Result<String> {
    entry
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow!("history: entry missing {field}"))
}

/// Rendered history page.
pub struct HistoryView {
    /// JSON object with atom counts and KUNA strings added to each entry.
    pub json: Value,
    /// Human table cells: height, timestamp, kind, status, from, to, amount, fee, hash.
    pub rows: Vec<Vec<String>>,
    /// Cursor for the next page, when the node returned one.
    pub next_cursor: Option<String>,
}

/// `kovanica history <address>` — newest-first committed transactions.
#[allow(clippy::too_many_arguments)]
pub async fn history(
    client: &RpcClient,
    address: &str,
    chain_id: Option<u64>,
    limit: Option<u64>,
    cursor: Option<&str>,
    sent: bool,
    received: bool,
    json_output: bool,
) -> Result<()> {
    let address_parsed = parse_address(address, "address", chain_id.unwrap_or(0))?;
    let params = history_params(address, chain_id, limit, cursor, sent, received)?;
    let page = client
        .call("kovanica_getTransactionHistory", params)
        .await?;
    let view = history_view(&page)?;
    if json_output {
        return print_json(&view.json);
    }
    print_kv(&[("Address", address_parsed.to_string())]);
    if view.rows.is_empty() {
        println!("No transactions.");
    } else {
        println!();
        print_table(
            &[
                "HEIGHT",
                "TIMESTAMP",
                "KIND",
                "STATUS",
                "FROM",
                "TO",
                "AMOUNT",
                "FEE",
                "HASH",
            ],
            &view.rows,
        );
    }
    println!();
    match &view.next_cursor {
        Some(cursor) => println!("Next cursor: {cursor}"),
        None => println!("Next cursor: none"),
    }
    Ok(())
}

/// Print a `TODO` for an operation whose RPC method is not implemented yet.
pub fn not_implemented(
    operation: &str,
    intended_rpc: &str,
    params: Value,
    json_output: bool,
) -> Result<()> {
    if json_output {
        return print_json(&json!({
            "status": "not_implemented",
            "operation": operation,
            "intendedRpc": intended_rpc,
            "params": params,
        }));
    }

    println!("TODO: `{operation}` is not implemented yet.");
    println!("      Intended RPC method: `{intended_rpc}`");
    println!("      Intended params:     {params}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sync(catching_up: bool, peers: usize) -> SyncSnapshot {
        parse_sync_status(&json!({
            "localTipRound": 36,
            "committedHeight": 12,
            "localHeight": 12,
            "catchingUp": catching_up,
            "catchUpTarget": if catching_up { Some(40) } else { None::<u64> },
            "behindBy": if catching_up { Some(4) } else { None::<u64> },
            "peerCount": peers,
            "peers": [{ "peerId": "12D3KooWexample", "reportedTipRound": 36 }],
        }))
        .unwrap()
    }

    #[test]
    fn status_shows_height_round_epoch_sync_and_a_zero_peer_count() {
        let sync = sample_sync(false, 0);
        let committee = json!({
            "epoch": "0x2",
            "members": [{
                "index": 0,
                "address": "kvncexampledag",
                "stake": "0x3b9aca00",
                "network_address": "validator.example:8000"
            }]
        });
        let (epoch, members) = parse_committee_info(&committee).unwrap();
        let status = assemble_status(
            "http://127.0.0.1:8545/rpc",
            Some(4),
            Some(9),
            Some(&sync),
            epoch,
            members,
            Some(99),
        );
        assert_eq!(status.height, Some(12));
        assert_eq!(status.round, Some(36));
        assert_eq!(status.epoch, Some(2));
        assert_eq!(status.sync, SyncState::InSync);
        // Zero from the sync method wins over a health fallback.
        assert_eq!(status.peer_count, Some(0));
        let output = status_json(&status);
        assert_eq!(output["chainIdReportedByNode"], json!(false));
        assert_eq!(output["signingChainId"], json!(4));
        assert_eq!(output["syncing"], json!(false));
        assert_eq!(output["latestBlock"], json!(12));
        assert_eq!(output["round"], json!(36));
        assert_eq!(output["epoch"], json!(2));
        let rows = status_rows(&status);
        assert_eq!(row(&rows, "Height"), "12");
        assert_eq!(row(&rows, "Round"), "36");
        assert_eq!(row(&rows, "Epoch"), "2");
        assert_eq!(row(&rows, "Sync"), "in sync");
        assert_eq!(row(&rows, "Peers"), "0");
        assert!(row(&rows, "Signing chain id").contains("local flag"));
        assert_eq!(stake_cell(Some(&json!("0x3b9aca00"))), "1.000000000 KUNA");
    }

    #[test]
    fn status_reports_catch_up_and_leaves_chain_id_unknown_without_a_flag() {
        let sync = sample_sync(true, 1);
        let status = assemble_status(
            "http://127.0.0.1:8545/rpc",
            None,
            None,
            Some(&sync),
            None,
            Vec::new(),
            None,
        );
        assert_eq!(
            status.sync,
            SyncState::CatchingUp {
                behind_by: Some(4),
                target: Some(40),
            }
        );
        let output = status_json(&status);
        assert_eq!(output["syncing"], json!(true));
        assert_eq!(output["signingChainId"], Value::Null);
        assert_eq!(output["peerCount"], json!(1));
        assert_eq!(output["peers"][0]["peerId"], json!("12D3KooWexample"));
        let rows = status_rows(&status);
        assert_eq!(
            row(&rows, "Sync"),
            "catching up (behind 4 rounds, target 40)"
        );
        assert_eq!(row(&rows, "Signing chain id"), "not reported by the node");

        let tagged = parse_sync_status(&json!({
            "committedHeight": 1,
            "catchingUp": false,
            "networkTag": "4-0123456789abcdef",
        }))
        .unwrap();
        assert_eq!(tagged.node_chain_id, Some(4));
        assert!(refuse_chain_mismatch(Some(4), tagged.node_chain_id).is_ok());
        let mismatch = refuse_chain_mismatch(Some(1), tagged.node_chain_id)
            .unwrap_err()
            .to_string();
        assert!(mismatch.contains("--chain-id 1"), "{mismatch}");
        assert!(mismatch.contains("node's chain 4"), "{mismatch}");
        let numeric = parse_sync_status(&json!({
            "committedHeight": 1,
            "chainId": 1,
        }))
        .unwrap();
        assert_eq!(numeric.node_chain_id, Some(1));
        assert!(refuse_chain_mismatch(Some(4), numeric.node_chain_id).is_err());
        let snake = parse_sync_status(&json!({
            "committedHeight": 1,
            "chain_id": "0x4",
        }))
        .unwrap();
        assert_eq!(snake.node_chain_id, Some(4));
        assert!(parse_sync_status(&json!({"networkTag": "nope-abcd"})).is_err());
        assert_eq!(sync.node_chain_id, None);
        assert!(refuse_chain_mismatch(Some(4), None).is_ok());
        assert!(refuse_chain_mismatch(None, Some(4)).is_ok());
        let matched = assemble_status(
            "http://127.0.0.1:8545/rpc",
            Some(4),
            None,
            Some(&tagged),
            None,
            Vec::new(),
            None,
        );
        assert_eq!(matched.node_chain_id, Some(4));
        assert_eq!(status_json(&matched)["chainIdReportedByNode"], json!(true));
        assert!(row(&status_rows(&matched), "Signing chain id").contains("matches the node"));
        assert_eq!(row(&rows, "Epoch"), "unknown");
    }

    #[test]
    fn missing_sync_status_stays_unknown_and_keeps_a_zero_health_peer_count() {
        let status = assemble_status(
            "http://127.0.0.1:8545/rpc",
            None,
            Some(12),
            None,
            None,
            Vec::new(),
            Some(0),
        );
        assert_eq!(status.sync, SyncState::Unknown);
        assert_eq!(status.height, Some(12));
        assert_eq!(status.peer_count, Some(0));
        assert_eq!(status_json(&status)["syncing"], Value::Null);
        let rows = status_rows(&status);
        assert_eq!(row(&rows, "Sync"), "unknown");
        assert_eq!(row(&rows, "Peers"), "0");
        assert_eq!(row(&rows, "Round"), "unknown");

        let absent = assemble_status(
            "http://127.0.0.1:8545/rpc",
            None,
            Some(12),
            None,
            None,
            Vec::new(),
            None,
        );
        assert_eq!(row(&status_rows(&absent), "Peers"), "unknown");
    }

    fn row<'a>(rows: &'a [(&'static str, String)], key: &str) -> &'a str {
        &rows.iter().find(|(label, _)| *label == key).unwrap().1
    }

    #[test]
    fn balance_is_shown_in_kuna_with_nine_decimals() {
        let address = Address([0x11; 32]);
        let report = balance_report(&address, 1_500_000_000);
        assert_eq!(report["balance"], json!(1_500_000_000));
        assert_eq!(report["balanceKuna"], json!("1.500000000"));
        assert_eq!(report["address"], json!(address.to_string()));
        let rows = balance_rows(&address, 1);
        assert_eq!(rows[1].1, "0.000000001 KUNA");
        assert_eq!(balance_rows(&address, 0)[1].1, "0.000000000 KUNA");
    }

    fn validator_row(address: &Address, stake: &str, commission: u64, active: bool) -> Value {
        json!({
            "address": address.to_string(),
            "stake": stake,
            "commission_bps": commission,
            "active": active,
            "payout_address": address.to_string(),
        })
    }

    #[test]
    fn staking_splits_own_stake_from_delegations() {
        let address = Address([0x11; 32]);
        let other = Address([0x22; 32]);
        let mut own_row = validator_row(&address, "0x3b9aca00", 500, true);
        own_row["address"] = json!(address.to_hex());
        let validators = vec![
            own_row,
            validator_row(&other, "0x1", 0, true),
            json!({"address": "not-an-address", "stake": "0x5"}),
        ];
        let report = assemble_staking(address, 1_500_000_000, 42, &validators).unwrap();
        assert_eq!(report.own, 1_000_000_000);
        assert_eq!(report.delegated, 500_000_000);
        assert_eq!(report.rewards, 42);
        assert!(report.total_covers_own);
        assert_eq!(report.validator_rows, 1);
        assert_eq!(report.commission_bps, Some(500));
        assert_eq!(report.active, Some(true));
        assert_eq!(report.payout, Some(address));

        let body = staking_json(&report);
        assert_eq!(body["address"], json!(address.to_string()));
        assert_eq!(body["total"], json!(1_500_000_000u64));
        assert_eq!(body["totalKuna"], json!("1.500000000"));
        assert_eq!(body["ownKuna"], json!("1.000000000"));
        assert_eq!(body["delegatedKuna"], json!("0.500000000"));
        assert_eq!(body["rewards"], json!(42));
        assert_eq!(body["rewardsKuna"], json!("0.000000042"));
        assert_eq!(body["payoutAddress"], json!(address.to_string()));
        assert_eq!(body["delegationDetail"], json!("unavailable"));

        let rows = staking_rows(&report);
        assert_eq!(row(&rows, "Total stake"), "1.500000000 KUNA");
        assert_eq!(row(&rows, "Own stake"), "1.000000000 KUNA");
        assert_eq!(row(&rows, "Delegated"), "0.500000000 KUNA");
        assert_eq!(row(&rows, "Rewards"), "0.000000042 KUNA");
        assert_eq!(row(&rows, "Payout"), address.to_string());
    }

    #[test]
    fn staking_does_not_invent_a_delegation_when_the_total_is_smaller() {
        let address = Address([0x33; 32]);
        let validators = vec![validator_row(&address, "0x3b9aca00", 100, false)];
        let report = assemble_staking(address, 10, 0, &validators).unwrap();
        assert_eq!(report.own, 1_000_000_000);
        assert_eq!(report.delegated, 0);
        assert!(!report.total_covers_own);
        assert_eq!(report.active, Some(false));
        let rows = staking_rows(&report);
        assert_eq!(
            row(&rows, "Stake check"),
            "total is smaller than own stake; delegated is zero"
        );
        assert_eq!(staking_json(&report)["totalCoversOwn"], json!(false));
    }

    #[test]
    fn staking_sums_duplicate_validator_rows_and_keeps_the_first() {
        let address = Address([0x44; 32]);
        let mut first = validator_row(&address, "0xffffffffffffffff", 1, true);
        first["payout_address"] = json!(Address([0x55; 32]).to_string());
        let second = validator_row(&address, "0x5", 9, false);
        let report = assemble_staking(address, u64::MAX, 0, &[first, second]).unwrap();
        assert_eq!(report.own, u64::MAX);
        assert_eq!(report.delegated, 0);
        assert!(report.total_covers_own);
        assert_eq!(report.validator_rows, 2);
        assert_eq!(report.commission_bps, Some(1));
        assert_eq!(report.active, Some(true));
        assert_eq!(report.payout, Some(Address([0x55; 32])));
    }

    #[test]
    fn staking_with_no_validator_row_treats_the_total_as_delegated() {
        let address = Address([0x66; 32]);
        let report = assemble_staking(address, 7, 3, &[]).unwrap();
        assert_eq!(report.own, 0);
        assert_eq!(report.delegated, 7);
        assert_eq!(report.rewards, 3);
        assert_eq!(report.validator_rows, 0);
        assert_eq!(report.commission_bps, None);
        assert_eq!(report.payout, None);
        let rows = staking_rows(&report);
        assert_eq!(row(&rows, "Commission (bps)"), "unknown");
        assert_eq!(row(&rows, "Active"), "unknown");
        assert_eq!(row(&rows, "Payout"), "unknown");
        assert!(staking_json(&report)["payoutAddress"].is_null());
    }

    #[test]
    fn history_params_canonicalizes_address_and_sets_direction() {
        let hex = "11".repeat(32);
        let canonical = kovanica_types::Address([0x11; 32]).to_string();
        let cursor = " ab ".to_string();
        let params = history_params(
            &hex,
            Some(kovanica_types::signing::chain_id::LOCAL),
            Some(5),
            Some(cursor.as_str()),
            true,
            false,
        )
        .unwrap();
        assert_eq!(params["address"], json!(canonical));
        assert!(canonical.starts_with("kvnc") && canonical.ends_with("dag"));
        assert_eq!(params["limit"], json!(5));
        assert_eq!(params["cursor"], json!("ab"));
        assert_eq!(params["direction"], json!("sent"));

        // Legacy hex is refused when chain_id is None (defaults to 0) or mainnet (1).
        assert!(history_params(&hex, None, None, None, false, false).is_err());
        assert!(history_params(
            &hex,
            Some(kovanica_types::signing::chain_id::MAINNET),
            None,
            None,
            false,
            false,
        )
        .is_err());

        let all = history_params(&canonical, None, None, None, false, false).unwrap();
        assert!(all.get("limit").is_none());
        assert!(all.get("cursor").is_none());
        assert!(all.get("direction").is_none());
        assert_eq!(all["address"], json!(canonical));

        let received = history_params(&canonical, None, None, None, false, true).unwrap();
        assert_eq!(received["direction"], json!("received"));

        assert!(history_params(&canonical, None, None, None, true, true).is_err());
        assert!(history_params("not-an-address", None, None, None, false, false).is_err());
        assert!(history_params(&canonical, None, None, Some("  "), false, false).is_err());
        let bad = format!("kvnc{}dag", "00".repeat(36));
        assert!(history_params(&bad, None, None, None, false, false).is_err());
    }

    #[test]
    fn history_view_formats_kuna_with_nine_decimals_and_keeps_atoms() {
        let page = json!({
            "entries": [
                {
                    "hash": "0xab",
                    "height": "0x2",
                    "timestamp": null,
                    "from": "kvnc-from",
                    "to": "kvnc-to",
                    "amount": "0x3b9aca00",
                    "fee": "0x1",
                    "kind": "transfer",
                    "status": "success"
                },
                {
                    "hash": "0xcd",
                    "height": "0x1",
                    "timestamp": "0x2a",
                    "from": "kvnc-from",
                    "to": null,
                    "amount": "0x0",
                    "fee": "0x5f5e100",
                    "kind": "stake",
                    "status": "failed"
                }
            ],
            "next_cursor": "aa"
        });
        let view = history_view(&page).unwrap();
        assert_eq!(view.next_cursor.as_deref(), Some("aa"));
        assert_eq!(
            view.json["entries"][0]["amountAtoms"],
            json!(1_000_000_000u64)
        );
        assert_eq!(view.json["entries"][0]["amountKuna"], json!("1 KUNA"));
        assert_eq!(view.json["entries"][0]["feeAtoms"], json!(1));
        assert_eq!(
            view.json["entries"][0]["feeKuna"],
            json!("0.000000001 KUNA")
        );
        assert_eq!(view.json["entries"][0]["amount"], json!("0x3b9aca00"));
        assert_eq!(view.json["entries"][1]["amountKuna"], json!("0 KUNA"));
        assert_eq!(view.json["entries"][1]["feeAtoms"], json!(100_000_000u64));
        assert_eq!(view.json["entries"][1]["feeKuna"], json!("0.1 KUNA"));
        assert_eq!(view.rows[0][0], "2");
        assert_eq!(view.rows[0][1], "-");
        assert_eq!(view.rows[0][6], "1 KUNA");
        assert_eq!(view.rows[0][7], "0.000000001 KUNA");
        assert_eq!(view.rows[1][1], "42");
        assert_eq!(view.rows[1][5], "-");
        assert_eq!(view.rows[1][2], "stake");
        assert_eq!(view.rows.len(), 2);

        let whole = format_kuna(1_500_000_000);
        assert_eq!(whole, "1.5 KUNA");
        let atom = format_kuna(1);
        assert_eq!(atom, "0.000000001 KUNA");

        let last = json!({"entries": [], "next_cursor": null});
        let empty = history_view(&last).unwrap();
        assert!(empty.rows.is_empty());
        assert!(empty.next_cursor.is_none());
        assert!(history_view(&json!({"entries": "no"})).is_err());
        assert!(history_view(&json!({
            "entries": [{"hash": "0x1", "height": "0x1", "from": "a", "kind": "transfer", "status": "success"}],
            "next_cursor": null
        }))
        .is_err());
    }
}
