//! RPC connection for Kovanica Console.
//!
//! The endpoint is a saved setting, otherwise `KOVANICA_RPC_URL`, otherwise
//! the public testnet DNS name. Chain id is proven only when commit seals
//! verify for one registered id and that id's committee matches a pinned
//! genesis checkpoint. The pin table is empty until a real checkpoint is
//! published. Address bytes stay inside `kovanica-light-ffi` and
//! `kovanica-types`.

use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::Duration;

use kovanica_types::epoch_for_round;
use kovanica_types::signing::chain_id;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::{Host, Url};

/// Public testnet JSON-RPC URL. A DNS name, never an address literal.
pub const DEFAULT_RPC_URL: &str = "https://rpc-testnet.kovanica.online/rpc";

/// Shown when seals verify against a pinned genesis committee.
const PROVEN_BY_SEALS: &str = "Proven by commit seals.";

/// Seals match the committee the node returned. That committee is not pinned.
const SEALS_CONSISTENT_UNVERIFIED: &str =
    "Seals consistent with the node's committee (committee not verified)";

/// `header.epoch` is not [`epoch_for_round`] of the header's leader round.
const HEADER_EPOCH_MISMATCH: &str =
    "The header epoch does not match the leader round, so the chain id is not proven.";

/// `kovanica_getCommitteeInfo` epoch is not the header's leader-round epoch.
const COMMITTEE_EPOCH_MISMATCH: &str =
    "The committee epoch does not match the leader round, so the chain id is not proven.";

/// The node did not return a committee epoch the console could compare.
const COMMITTEE_EPOCH_MISSING: &str =
    "The node did not return a committee epoch, so the chain id is not proven.";

/// Environment variable that supplies the endpoint when nothing is saved.
pub const RPC_URL_ENV: &str = "KOVANICA_RPC_URL";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);

/// Why a connection or a status read failed. The text is safe to show.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConnError {
    /// The node did not answer.
    #[error("{0}")]
    Unreachable(String),
    /// The node answered with something the console will not use.
    #[error("{0}")]
    Rejected(String),
}

/// One connected peer. Transport addresses are not kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerStatus {
    /// libp2p peer id, or `peer` when the value looked like an address.
    pub peer_id: String,
    /// Last advertised tip round, as a decimal string.
    pub reported_tip_round: Option<String>,
}

/// Node status for the connection screen.
///
/// Counters are decimal strings so the webview never rounds them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatus {
    /// Registered chain id when a pinned committee proves the seals.
    pub chain_id: Option<String>,
    /// Why `chain_id` is set, or why it is not.
    pub chain_note: String,
    /// Committed leader height from `kovanica_blockNumber`.
    pub height: String,
    /// Leader round of the sealed header, when it matches `height`.
    pub leader_round: Option<String>,
    /// Epoch of that sealed header.
    pub epoch: Option<String>,
    /// Connected peer count.
    pub peer_count: String,
    /// Connected peers, at most 64.
    pub peers: Vec<PeerStatus>,
}

/// Saved endpoint file. Only the URL is stored.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedEndpoint {
    rpc_url: String,
}

/// Choose the endpoint. A saved value wins, then the environment, then the default.
pub fn resolve_rpc_url(saved: Option<&str>, env_value: Option<&str>) -> String {
    for candidate in [saved, env_value] {
        if let Some(value) = candidate.map(str::trim).filter(|value| !value.is_empty()) {
            return value.to_string();
        }
    }
    DEFAULT_RPC_URL.to_string()
}

/// Accept an http(s) URL and fill in `/rpc` when the path is empty.
///
/// Plain http is only for loopback (`127.0.0.1`, `::1`, `localhost`). Every
/// other host must be https.
pub fn validate_rpc_url(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let mut url = Url::parse(raw).map_err(|_| "Enter an http or https URL.".to_string())?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err("The RPC URL must be http or https.".to_string());
    }
    if url.scheme() == "http" && !host_allows_plain_http(url.host()) {
        return Err(
            "Plain http is only allowed for loopback. Use https for any other host.".to_string(),
        );
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("The RPC URL must not include a username or password.".to_string());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("The RPC URL must not include a query or fragment.".to_string());
    }
    if url.host().is_none() {
        return Err("The RPC URL needs a host name.".to_string());
    }
    if url.path() == "/" || url.path().is_empty() {
        url.set_path("/rpc");
    }
    Ok(canonical_url(&url))
}

/// Host name to show. Address literals stay off the screen and out of errors.
pub fn endpoint_label(rpc_url: &str) -> String {
    let Ok(url) = Url::parse(rpc_url) else {
        return "configured endpoint".to_string();
    };
    match url.host() {
        Some(Host::Domain(host)) if !contains_ipv4(host) => host.to_string(),
        _ => "configured endpoint".to_string(),
    }
}

/// Read a saved endpoint. A missing file means "use the environment or the default".
pub fn read_saved_url(path: &Path) -> Result<Option<String>, ConnError> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).map_err(|_| read_failed())?;
    let saved: SavedEndpoint = serde_json::from_slice(&bytes).map_err(|_| read_failed())?;
    if saved.rpc_url.trim().is_empty() {
        return Ok(None);
    }
    let rpc_url = validate_rpc_url(&saved.rpc_url).map_err(|_| read_failed())?;
    Ok(Some(rpc_url))
}

/// Write the endpoint into the app data directory.
pub fn write_saved_url(path: &Path, rpc_url: &str) -> Result<String, ConnError> {
    let rpc_url = validate_rpc_url(rpc_url).map_err(ConnError::Rejected)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| save_failed())?;
    }
    let bytes = serde_json::to_vec_pretty(&SavedEndpoint {
        rpc_url: rpc_url.clone(),
    })
    .map_err(|_| save_failed())?;
    write_private(path, &bytes)?;
    Ok(rpc_url)
}

/// JSON-RPC transport. Tests use a script; the app uses HTTP.
pub trait Rpc {
    /// Call `method` and return the JSON-RPC `result`.
    fn call(&self, method: &str, params: Value) -> Result<Value, ConnError>;
}

/// Blocking HTTP client for one endpoint.
pub struct HttpRpc {
    url: String,
    client: reqwest::blocking::Client,
}

impl HttpRpc {
    /// Build a client. The URL must already be an http(s) endpoint.
    pub fn new(url: String) -> Result<Self, ConnError> {
        let url = validate_rpc_url(&url).map_err(ConnError::Rejected)?;
        let client = reqwest::blocking::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("kovanica-console/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| ConnError::Unreachable(unreachable_text(&url, FailKind::Other)))?;
        Ok(Self { url, client })
    }
}

impl Rpc for HttpRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, ConnError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let response = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .map_err(|err| ConnError::Unreachable(unreachable_text(&self.url, fail_kind(&err))))?;
        let status = response.status();
        if !status.is_success() {
            return Err(ConnError::Rejected(format!(
                "The node at {} returned HTTP {}.",
                endpoint_label(&self.url),
                status.as_u16()
            )));
        }
        let json: Value = response.json().map_err(|_| {
            ConnError::Rejected(format!(
                "The node at {} returned a response the console could not read.",
                endpoint_label(&self.url)
            ))
        })?;
        if let Some(error) = json.get("error").filter(|error| !error.is_null()) {
            return Err(rpc_failure(&self.url, method, error));
        }
        json.get("result").cloned().ok_or_else(|| {
            ConnError::Rejected(format!(
                "The node at {} returned a response the console could not read.",
                endpoint_label(&self.url)
            ))
        })
    }
}

/// Genesis committee trusted for one chain id.
///
/// `committee_json` is the `kovanica_getCommittee` member array. A chain stays
/// unproven until a checkpoint for it is published in [`pinned_committees`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedCommittee {
    /// Registered chain id this checkpoint belongs to.
    pub chain_id: u64,
    /// Committee JSON. Parsed before compare, so whitespace and key order cannot widen a match.
    pub committee_json: String,
}

/// Checkpoints shipped with this build. Empty until a real genesis committee is pinned.
pub fn pinned_committees() -> &'static [PinnedCommittee] {
    &[]
}

/// Read chain id, height, leader round, epoch, and peers.
///
/// Chain id is set only when [`pinned_committees`] contains this chain and
/// the node returned that committee. A seal match against the node's own
/// committee is not a proof.
pub fn fetch_status(rpc: &impl Rpc, endpoint: &str) -> Result<NodeStatus, ConnError> {
    fetch_status_with_pins(rpc, endpoint, pinned_committees())
}

fn fetch_status_with_pins(
    rpc: &impl Rpc,
    endpoint: &str,
    pins: &[PinnedCommittee],
) -> Result<NodeStatus, ConnError> {
    let height_value = rpc.call("kovanica_blockNumber", Value::Array(vec![]))?;
    let height = parse_qty(&height_value).map_err(|_| bad_payload(endpoint, "height"))?;
    let sync = rpc.call("kovanica_syncStatus", Value::Array(vec![]))?;
    let (peer_count, peers) = parse_peers(&sync).map_err(|_| bad_payload(endpoint, "peer list"))?;
    let header = rpc.call("kovanica_getLeaderHeader", Value::Array(vec![]))?;
    if header.is_null() {
        return Ok(NodeStatus {
            chain_id: None,
            chain_note: if height == 0 {
                "The node has not sealed a leader yet, so the chain id is not proven.".to_string()
            } else {
                "The node reported a committed height but no sealed leader, so the chain id is not proven.".to_string()
            },
            height: height.to_string(),
            leader_round: None,
            epoch: None,
            peer_count: peer_count.to_string(),
            peers,
        });
    }
    let sealed_height = field_qty(&header, "committedHeight")
        .map_err(|_| bad_payload(endpoint, "leader header"))?;
    let leader_round =
        field_qty(&header, "leaderRound").map_err(|_| bad_payload(endpoint, "leader header"))?;
    let epoch = field_qty(&header, "epoch").map_err(|_| bad_payload(endpoint, "leader header"))?;
    if sealed_height != height {
        return Ok(NodeStatus {
            chain_id: None,
            chain_note: "The sealed header does not match the committed height, so the chain id is not proven.".to_string(),
            height: height.to_string(),
            leader_round: None,
            epoch: None,
            peer_count: peer_count.to_string(),
            peers,
        });
    }
    // Same function `admit_seal` uses. Do not re-derive the epoch here.
    let expected_epoch = epoch_for_round(leader_round);
    if epoch != expected_epoch {
        return Ok(unproven(
            height,
            leader_round,
            epoch,
            peer_count,
            peers,
            HEADER_EPOCH_MISMATCH,
        ));
    }
    let committee = rpc.call("kovanica_getCommittee", Value::Array(vec![]))?;
    if !committee.is_array() {
        return Ok(unproven(
            height,
            leader_round,
            epoch,
            peer_count,
            peers,
            "The node returned a committee the console could not read.",
        ));
    }
    let info_epoch = match rpc.call("kovanica_getCommitteeInfo", Value::Array(vec![])) {
        Ok(info) => match field_qty(&info, "epoch") {
            Ok(value) => value,
            Err(()) => {
                return Ok(unproven(
                    height,
                    leader_round,
                    epoch,
                    peer_count,
                    peers,
                    COMMITTEE_EPOCH_MISSING,
                ));
            }
        },
        Err(ConnError::Rejected(_)) => {
            return Ok(unproven(
                height,
                leader_round,
                epoch,
                peer_count,
                peers,
                COMMITTEE_EPOCH_MISSING,
            ));
        }
        Err(err) => return Err(err),
    };
    if info_epoch != expected_epoch {
        return Ok(unproven(
            height,
            leader_round,
            epoch,
            peer_count,
            peers,
            COMMITTEE_EPOCH_MISMATCH,
        ));
    }
    let seals = rpc.call(
        "kovanica_getCommitSeals",
        Value::Array(vec![Value::from(sealed_height)]),
    )?;
    let (chain_id, chain_note) = match prove_chain_id(
        epoch,
        &committee.to_string(),
        &header.to_string(),
        &seals.to_string(),
    ) {
        Ok(id) if committee_is_pinned(id, &committee, pins) => {
            (Some(id.to_string()), PROVEN_BY_SEALS.to_string())
        }
        Ok(_) => (None, SEALS_CONSISTENT_UNVERIFIED.to_string()),
        Err(ProveError::None) => (
            None,
            "Commit seals did not verify for a registered chain.".to_string(),
        ),
        Err(ProveError::Ambiguous) => (
            None,
            "Commit seals verified for more than one registered chain.".to_string(),
        ),
    };
    Ok(NodeStatus {
        chain_id,
        chain_note,
        height: height.to_string(),
        leader_round: Some(leader_round.to_string()),
        epoch: Some(epoch.to_string()),
        peer_count: peer_count.to_string(),
        peers,
    })
}

/// Registered chain ids from `kovanica-types`.
///
/// A new registry entry has to be added here. The unit test walks the
/// registry so a forgotten id fails the build.
pub fn registered_chain_ids() -> &'static [u64] {
    &[
        chain_id::MAINNET,
        chain_id::TESTNET,
        chain_id::DEVNET,
        chain_id::TESTNET_V2,
        chain_id::LOCAL,
    ]
}

enum ProveError {
    None,
    Ambiguous,
}

fn prove_chain_id(
    epoch: u64,
    committee: &str,
    header: &str,
    seals: &str,
) -> Result<u64, ProveError> {
    let mut matched = Vec::new();
    for id in registered_chain_ids() {
        if kovanica_light_ffi::verify_header(
            *id,
            epoch,
            committee.to_string(),
            header.to_string(),
            seals.to_string(),
            String::new(),
        )
        .is_ok()
        {
            matched.push(*id);
        }
    }
    match matched.as_slice() {
        [id] => Ok(*id),
        [] => Err(ProveError::None),
        _ => Err(ProveError::Ambiguous),
    }
}

/// True when every pin for `chain_id` is this committee, and there is at least one.
fn committee_is_pinned(chain_id: u64, committee: &Value, pins: &[PinnedCommittee]) -> bool {
    let mut matched = false;
    for pin in pins.iter().filter(|pin| pin.chain_id == chain_id) {
        let Ok(pinned) = serde_json::from_str::<Value>(&pin.committee_json) else {
            return false;
        };
        if canonical_json(&pinned) != canonical_json(committee) {
            return false;
        }
        matched = true;
    }
    matched
}

/// Object keys sorted, array order kept. Member index is the array position the pin names.
fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonical_json).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut sorted = serde_json::Map::new();
            for key in keys {
                if let Some(child) = map.get(key) {
                    sorted.insert(key.clone(), canonical_json(child));
                }
            }
            Value::Object(sorted)
        }
        other => other.clone(),
    }
}

fn unproven(
    height: u64,
    leader_round: u64,
    epoch: u64,
    peer_count: u64,
    peers: Vec<PeerStatus>,
    note: &str,
) -> NodeStatus {
    NodeStatus {
        chain_id: None,
        chain_note: note.to_string(),
        height: height.to_string(),
        leader_round: Some(leader_round.to_string()),
        epoch: Some(epoch.to_string()),
        peer_count: peer_count.to_string(),
        peers,
    }
}

fn bad_payload(endpoint: &str, what: &str) -> ConnError {
    ConnError::Rejected(format!(
        "The node at {} returned a {what} the console could not read.",
        endpoint_label(endpoint)
    ))
}

fn rpc_failure(endpoint: &str, method: &str, error: &Value) -> ConnError {
    let label = endpoint_label(endpoint);
    if error.get("code").and_then(Value::as_i64) == Some(-32601) {
        return ConnError::Rejected(format!(
            "The node at {label} does not support {method}. It may be an older build."
        ));
    }
    ConnError::Rejected(format!("The node at {label} rejected {method}."))
}

enum FailKind {
    Timeout,
    Connect,
    Other,
}

fn fail_kind(err: &reqwest::Error) -> FailKind {
    if err.is_timeout() {
        FailKind::Timeout
    } else if err.is_connect() {
        FailKind::Connect
    } else {
        FailKind::Other
    }
}

fn unreachable_text(rpc_url: &str, kind: FailKind) -> String {
    let label = endpoint_label(rpc_url);
    match kind {
        FailKind::Timeout => format!("The node at {label} did not respond in time."),
        FailKind::Connect | FailKind::Other => {
            format!("The node at {label} is not reachable.")
        }
    }
}

fn read_failed() -> ConnError {
    ConnError::Rejected("The saved RPC setting could not be read.".to_string())
}

fn save_failed() -> ConnError {
    ConnError::Rejected("Could not save the RPC setting.".to_string())
}

/// `127.0.0.1`, `::1`, and `localhost`. The rest of `127.0.0.0/8` is not accepted.
fn host_allows_plain_http(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Ipv4(ip)) => ip == Ipv4Addr::LOCALHOST,
        Some(Host::Ipv6(ip)) => ip == Ipv6Addr::LOCALHOST,
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn canonical_url(url: &Url) -> String {
    let host = match url.host() {
        Some(Host::Domain(host)) => host.to_ascii_lowercase(),
        Some(Host::Ipv4(ip)) => ip.to_string(),
        Some(Host::Ipv6(ip)) => format!("[{ip}]"),
        None => "configured-endpoint".to_string(),
    };
    let port = match url.port() {
        Some(port) => format!(":{port}"),
        None => String::new(),
    };
    format!("{}://{host}{port}{}", url.scheme(), url.path())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ConnError> {
    use std::fs::OpenOptions;
    use std::io::Write;
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| save_failed())?;
    file.write_all(bytes).map_err(|_| save_failed())?;
    Ok(())
}

fn field_qty(value: &Value, name: &str) -> Result<u64, ()> {
    parse_qty(value.get(name).ok_or(())?)
}

pub(crate) fn parse_qty(value: &Value) -> Result<u64, ()> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    if value.is_number() {
        return Err(());
    }
    let Some(raw) = value.as_str() else {
        return Err(());
    };
    let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) else {
        return Err(());
    };
    if hex.is_empty() {
        return Err(());
    }
    u64::from_str_radix(hex, 16).map_err(|_| ())
}

fn parse_peers(sync: &Value) -> Result<(u64, Vec<PeerStatus>), ()> {
    let Some(items) = sync.get("peers").and_then(Value::as_array) else {
        return Err(());
    };
    let mut peers = Vec::new();
    for item in items.iter().take(64) {
        let Some(peer_id) = item.get("peerId").and_then(Value::as_str) else {
            return Err(());
        };
        let peer_id = peer_id.trim();
        if peer_id.is_empty()
            || peer_id.len() > 128
            || !peer_id.is_ascii()
            || peer_id.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(());
        }
        let reported = match item.get("reportedTipRound") {
            None | Some(Value::Null) => None,
            Some(value) => Some(parse_qty(value)?),
        };
        peers.push(PeerStatus {
            peer_id: display_peer_id(peer_id),
            reported_tip_round: reported.map(|round| round.to_string()),
        });
    }
    let peer_count = match sync.get("peerCount") {
        None | Some(Value::Null) => u64::try_from(peers.len()).map_err(|_| ())?,
        Some(value) => parse_qty(value)?,
    };
    Ok((peer_count, peers))
}

fn display_peer_id(raw: &str) -> String {
    if raw.contains(':') || raw.contains('/') || contains_ipv4(raw) {
        "peer".to_string()
    } else {
        raw.to_string()
    }
}

fn contains_ipv4(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes
        .iter()
        .enumerate()
        .any(|(index, byte)| byte.is_ascii_digit() && ipv4_at(bytes, index))
}

fn ipv4_at(bytes: &[u8], start: usize) -> bool {
    let mut index = start;
    for part in 0..4 {
        if part > 0 {
            if index >= bytes.len() || bytes[index] != b'.' {
                return false;
            }
            index += 1;
        }
        let begin = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        let digits = index - begin;
        if !(1..=3).contains(&digits) {
            return false;
        }
        let text = std::str::from_utf8(&bytes[begin..index]).unwrap_or("");
        if text.parse::<u8>().is_err() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_crypto::sign;
    use kovanica_types::{
        committee_seal_hash, epoch_for_round, leader_header, Address, CommittedSubDag, Hash,
        PublicKey, Signature, SigningKey, StatementBlock,
    };
    use serde_json::json;

    #[test]
    fn package_version_is_the_console_preview() {
        assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.0");
    }

    #[test]
    fn the_app_lockfile_is_not_ignored() {
        let gitignore = include_str!("../.gitignore");
        assert!(
            !gitignore.lines().any(|line| {
                let line = line.trim();
                line == "/Cargo.lock" || line == "Cargo.lock"
            }),
            "src-tauri/Cargo.lock must stay tracked"
        );
        let lockfile = include_str!("../Cargo.lock");
        assert!(lockfile.contains("name = \"kovanica-console\""));
    }

    #[test]
    fn default_endpoint_is_the_testnet_dns_name() {
        let url = Url::parse(DEFAULT_RPC_URL).unwrap();
        assert_eq!(url.scheme(), "https");
        assert!(
            matches!(url.host(), Some(Host::Domain(host)) if host == "rpc-testnet.kovanica.online")
        );
        assert_eq!(url.path(), "/rpc");
        assert!(!contains_ipv4(DEFAULT_RPC_URL));
        assert_eq!(
            endpoint_label(DEFAULT_RPC_URL),
            "rpc-testnet.kovanica.online"
        );
        assert_eq!(validate_rpc_url(DEFAULT_RPC_URL).unwrap(), DEFAULT_RPC_URL);
    }

    #[test]
    fn registry_entries_are_all_candidates() {
        let known = registered_chain_ids();
        for id in 0..=u16::MAX as u64 {
            if chain_id::is_registered(id) {
                assert!(known.contains(&id), "registered chain {id} is missing");
            }
        }
        assert!(known.contains(&chain_id::TESTNET_V2));
        assert_eq!(chain_id::TESTNET_V2, 4);
        assert_eq!(chain_id::MAINNET, 1);
    }

    #[test]
    fn saved_setting_wins_over_the_environment() {
        assert_eq!(
            resolve_rpc_url(
                Some(" https://rpc.kovanica.online/rpc "),
                Some(DEFAULT_RPC_URL)
            ),
            "https://rpc.kovanica.online/rpc"
        );
        assert_eq!(
            resolve_rpc_url(Some("  "), Some("https://rpc.kovanica.online/rpc")),
            "https://rpc.kovanica.online/rpc"
        );
        assert_eq!(resolve_rpc_url(None, Some(" ")), DEFAULT_RPC_URL);
        assert_eq!(resolve_rpc_url(None, None), DEFAULT_RPC_URL);
    }

    #[test]
    fn a_bare_host_gets_the_rpc_path() {
        assert_eq!(
            validate_rpc_url("https://rpc.kovanica.online").unwrap(),
            "https://rpc.kovanica.online/rpc"
        );
        assert!(validate_rpc_url("file:///tmp/rpc").is_err());
        assert!(validate_rpc_url("https://user:secret@rpc.kovanica.online/rpc").is_err());
        assert!(validate_rpc_url("https://rpc.kovanica.online/rpc?x=1").is_err());
    }

    #[test]
    fn plain_http_is_only_for_loopback() {
        let v4 = format!("{}.{}.{}.{}", 127, 0, 0, 1);
        assert_eq!(
            validate_rpc_url(&format!("http://{v4}/rpc")).unwrap(),
            format!("http://{v4}/rpc")
        );
        assert_eq!(
            validate_rpc_url("http://localhost").unwrap(),
            "http://localhost/rpc"
        );
        assert_eq!(
            validate_rpc_url("http://LOCALHOST/rpc").unwrap(),
            "http://localhost/rpc"
        );
        assert_eq!(
            validate_rpc_url("http://[::1]/rpc").unwrap(),
            "http://[::1]/rpc"
        );
        assert!(validate_rpc_url("https://rpc-testnet.kovanica.online/rpc").is_ok());
        assert!(validate_rpc_url("http://rpc-testnet.kovanica.online/rpc").is_err());
        assert!(validate_rpc_url("http://rpc.kovanica.online/rpc").is_err());
        let other = format!("{}.{}.{}.{}", 127, 0, 0, 2);
        assert!(validate_rpc_url(&format!("http://{other}/rpc")).is_err());
        assert!(validate_rpc_url(&format!("https://{other}/rpc")).is_ok());
    }

    #[test]
    fn jarvis_http_loopback_edge_cases() {
        assert_eq!(
            validate_rpc_url("http://127.0.0.1:8545").unwrap(),
            "http://127.0.0.1:8545/rpc"
        );
        assert_eq!(
            validate_rpc_url("http://[::1]:8545/rpc").unwrap(),
            "http://[::1]:8545/rpc"
        );
        assert_eq!(
            validate_rpc_url("http://[0:0:0:0:0:0:0:1]/rpc").unwrap(),
            "http://[::1]/rpc"
        );
        assert_eq!(
            validate_rpc_url("https://127.0.0.1/rpc").unwrap(),
            "https://127.0.0.1/rpc"
        );
        assert_eq!(
            validate_rpc_url("http://LOCALHOST:9").unwrap(),
            "http://localhost:9/rpc"
        );
        for blocked in [
            "http://0.0.0.0/rpc",
            "http://[::]/rpc",
            "http://[::ffff:127.0.0.1]/rpc",
            "http://127.0.0.1.example/rpc",
            "http://localhost.localdomain/rpc",
            "http://user:secret@127.0.0.1/rpc",
            "http://127.0.0.1/rpc?x=1",
            "http://127.0.0.1/rpc#frag",
            "http://127.0.0.1@evil.example/rpc",
        ] {
            assert!(validate_rpc_url(blocked).is_err(), "accepted {blocked}");
        }
    }

    #[test]
    fn saved_endpoint_roundtrip_drops_extra_fields() {
        let dir = temp_dir();
        let path = dir.join("rpc-endpoint.json");
        let saved = write_saved_url(&path, "https://RPC.kovanica.online").unwrap();
        assert_eq!(saved, "https://rpc.kovanica.online/rpc");
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("mnemonic"));
        assert_eq!(
            read_saved_url(&path).unwrap().as_deref(),
            Some("https://rpc.kovanica.online/rpc")
        );
        fs::write(
            &path,
            r#"{"rpcUrl":"https://rpc.kovanica.online/rpc","note":"ignore"}"#,
        )
        .unwrap();
        assert_eq!(
            read_saved_url(&path).unwrap().as_deref(),
            Some("https://rpc.kovanica.online/rpc")
        );
        assert!(read_saved_url(&dir.join("missing.json")).unwrap().is_none());
        fs::write(&path, b"{").unwrap();
        assert!(read_saved_url(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn address_literals_stay_out_of_labels() {
        let host = format!("{}.{}.{}.{}", 127, 0, 0, 1);
        let url = format!("http://{host}:9/rpc");
        assert_eq!(endpoint_label(&url), "configured endpoint");
        assert!(!endpoint_label(&url).contains(&host));
        assert_eq!(display_peer_id(&format!("peer-{host}")), "peer");
        assert_eq!(display_peer_id("12D3KooWexample"), "12D3KooWexample");
    }

    #[test]
    fn a_closed_port_is_a_clear_error_without_the_address() {
        let host = format!("{}.{}.{}.{}", 127, 0, 0, 1);
        let listener = std::net::TcpListener::bind((host.as_str(), 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let url = format!("http://{host}:{port}/rpc");
        let rpc = HttpRpc::new(url).unwrap();
        let message = rpc
            .call("kovanica_blockNumber", Value::Array(vec![]))
            .unwrap_err()
            .to_string();
        assert!(message.contains("configured endpoint"), "{message}");
        assert!(message.contains("not reachable"), "{message}");
        assert!(
            !message.contains(&host),
            "error included an address literal"
        );
        assert!(
            !message.contains(&port.to_string()),
            "error included a port"
        );
    }

    #[test]
    fn seals_without_a_pinned_committee_are_not_proven() {
        assert!(
            pinned_committees().is_empty(),
            "this build must not ship a committee pin"
        );
        let status = fetch_status(&Script::new(chain_id::TESTNET_V2), DEFAULT_RPC_URL).unwrap();
        assert_eq!(status.chain_id, None);
        assert_eq!(status.chain_note, SEALS_CONSISTENT_UNVERIFIED);
        assert_ne!(status.chain_note, PROVEN_BY_SEALS);
        assert_eq!(status.height, "16");
        assert_eq!(status.leader_round.as_deref(), Some("42"));
        let epoch = epoch_for_round(42).to_string();
        assert_eq!(epoch, "0");
        assert_eq!(status.epoch.as_deref(), Some(epoch.as_str()));
        assert_eq!(status.peer_count, "2");
        assert_eq!(status.peers.len(), 2);
        assert_eq!(status.peers[0].reported_tip_round.as_deref(), Some("42"));
        assert_eq!(status.peers[1].reported_tip_round, None);

        let mainnet = fetch_status(&Script::new(chain_id::MAINNET), DEFAULT_RPC_URL).unwrap();
        assert_eq!(mainnet.chain_id, None);
        assert_eq!(mainnet.chain_note, SEALS_CONSISTENT_UNVERIFIED);
    }

    #[test]
    fn a_pinned_committee_proves_only_that_chain() {
        let (committee, _, _) = sealed_fixture(chain_id::TESTNET_V2, true);
        let pretty =
            serde_json::to_string_pretty(&serde_json::from_str::<Value>(&committee).unwrap())
                .unwrap();
        assert_ne!(pretty, committee);
        let pins = [PinnedCommittee {
            chain_id: chain_id::TESTNET_V2,
            committee_json: pretty,
        }];
        let status =
            fetch_status_with_pins(&Script::new(chain_id::TESTNET_V2), DEFAULT_RPC_URL, &pins)
                .unwrap();
        assert_eq!(status.chain_id.as_deref(), Some("4"));
        assert_eq!(status.chain_note, PROVEN_BY_SEALS);

        let mainnet =
            fetch_status_with_pins(&Script::new(chain_id::MAINNET), DEFAULT_RPC_URL, &pins)
                .unwrap();
        assert_eq!(mainnet.chain_id, None);
        assert_eq!(mainnet.chain_note, SEALS_CONSISTENT_UNVERIFIED);

        let mut forged: Value = serde_json::from_str(&committee).unwrap();
        forged[0]["stake"] = json!("0x2");
        let wrong_committee = [PinnedCommittee {
            chain_id: chain_id::TESTNET_V2,
            committee_json: forged.to_string(),
        }];
        let forged_status = fetch_status_with_pins(
            &Script::new(chain_id::TESTNET_V2),
            DEFAULT_RPC_URL,
            &wrong_committee,
        )
        .unwrap();
        assert_eq!(forged_status.chain_id, None);
        assert_eq!(forged_status.chain_note, SEALS_CONSISTENT_UNVERIFIED);
    }

    #[test]
    fn a_wrong_epoch_is_not_proven() {
        let (committee, _, _) = sealed_fixture(chain_id::TESTNET_V2, true);
        let pins = [PinnedCommittee {
            chain_id: chain_id::TESTNET_V2,
            committee_json: committee,
        }];
        assert_ne!(7, epoch_for_round(42));

        let header_epoch =
            fetch_status_with_pins(&Script::with_header_epoch(7), DEFAULT_RPC_URL, &pins).unwrap();
        assert_eq!(header_epoch.chain_id, None);
        assert_eq!(header_epoch.chain_note, HEADER_EPOCH_MISMATCH);
        assert_eq!(header_epoch.leader_round.as_deref(), Some("42"));
        assert_eq!(header_epoch.epoch.as_deref(), Some("7"));

        let committee_epoch =
            fetch_status_with_pins(&Script::with_committee_epoch(7), DEFAULT_RPC_URL, &pins)
                .unwrap();
        assert_eq!(committee_epoch.chain_id, None);
        assert_eq!(committee_epoch.chain_note, COMMITTEE_EPOCH_MISMATCH);
        assert_eq!(committee_epoch.epoch.as_deref(), Some("0"));

        let missing =
            fetch_status_with_pins(&Script::without_committee_info(), DEFAULT_RPC_URL, &pins)
                .unwrap();
        assert_eq!(missing.chain_id, None);
        assert_eq!(missing.chain_note, COMMITTEE_EPOCH_MISSING);
    }

    #[test]
    fn jarvis_validly_sealed_wrong_epoch_with_pin_is_not_proven() {
        let epoch = 7;
        assert_ne!(epoch, epoch_for_round(42));
        let (committee, header, seals) =
            sealed_fixture_for_epoch(chain_id::TESTNET_V2, true, epoch);
        assert!(
            kovanica_light_ffi::verify_header(
                chain_id::TESTNET_V2,
                epoch,
                committee.clone(),
                header,
                seals,
                String::new(),
            )
            .is_ok(),
            "seals must verify for the header epoch"
        );
        let pins = [PinnedCommittee {
            chain_id: chain_id::TESTNET_V2,
            committee_json: committee,
        }];
        let status =
            fetch_status_with_pins(&Script::with_signed_epoch(epoch), DEFAULT_RPC_URL, &pins)
                .unwrap();
        assert_eq!(status.chain_id, None);
        assert_eq!(status.chain_note, HEADER_EPOCH_MISMATCH);
        assert_eq!(status.leader_round.as_deref(), Some("42"));
        assert_eq!(status.epoch.as_deref(), Some("7"));
    }

    #[test]
    fn a_missing_seal_does_not_invent_a_chain() {
        let status = fetch_status(&Script::unsigned(), DEFAULT_RPC_URL).unwrap();
        assert_eq!(status.chain_id, None);
        assert_eq!(
            status.chain_note,
            "Commit seals did not verify for a registered chain."
        );
        assert_eq!(status.height, "16");
        assert_eq!(status.leader_round.as_deref(), Some("42"));
    }

    #[test]
    fn a_height_mismatch_hides_the_header() {
        let status = fetch_status(&Script::mismatched_height(), DEFAULT_RPC_URL).unwrap();
        assert_eq!(status.chain_id, None);
        assert!(status.chain_note.contains("does not match"));
        assert_eq!(status.leader_round, None);
        assert_eq!(status.epoch, None);
        assert_eq!(status.height, "17");
    }

    #[test]
    fn an_unsealed_node_explains_the_missing_chain() {
        let fresh = fetch_status(&Script::no_header("0x0"), DEFAULT_RPC_URL).unwrap();
        assert_eq!(fresh.height, "0");
        assert!(fresh.chain_note.contains("has not sealed"));
        let ahead = fetch_status(&Script::no_header("0x4"), DEFAULT_RPC_URL).unwrap();
        assert_eq!(ahead.height, "4");
        assert!(ahead.chain_note.contains("no sealed leader"));
    }

    #[test]
    fn a_fractional_height_is_rejected() {
        let error = fetch_status(&Script::bad_height(), DEFAULT_RPC_URL).unwrap_err();
        assert!(error.to_string().contains("could not read"));
        assert!(!error.to_string().contains("127"));
    }

    struct Script {
        chain: u64,
        seals: bool,
        block_number: Value,
        header: Option<Value>,
        header_epoch: Option<u64>,
        committee_epoch: Option<u64>,
        committee_info: bool,
        /// When set, the header is sealed for this epoch instead of `epoch_for_round(42)`.
        signed_epoch: Option<u64>,
    }

    impl Script {
        fn new(chain: u64) -> Self {
            Self {
                chain,
                seals: true,
                block_number: json!("0x10"),
                header: None,
                header_epoch: None,
                committee_epoch: None,
                committee_info: true,
                signed_epoch: None,
            }
        }

        fn with_signed_epoch(epoch: u64) -> Self {
            Self {
                signed_epoch: Some(epoch),
                ..Self::new(chain_id::TESTNET_V2)
            }
        }

        fn with_header_epoch(epoch: u64) -> Self {
            Self {
                header_epoch: Some(epoch),
                ..Self::new(chain_id::TESTNET_V2)
            }
        }

        fn with_committee_epoch(epoch: u64) -> Self {
            Self {
                committee_epoch: Some(epoch),
                ..Self::new(chain_id::TESTNET_V2)
            }
        }

        fn without_committee_info() -> Self {
            Self {
                committee_info: false,
                ..Self::new(chain_id::TESTNET_V2)
            }
        }

        fn leader_header_value(&self, header_json: &str) -> Value {
            if let Some(header) = &self.header {
                return header.clone();
            }
            let mut value = parse_json(header_json);
            if let Some(epoch) = self.header_epoch {
                if let Some(object) = value.as_object_mut() {
                    object.insert("epoch".to_string(), json!(hex_qty(epoch)));
                }
            }
            value
        }

        fn unsigned() -> Self {
            Self {
                seals: false,
                ..Self::new(chain_id::TESTNET_V2)
            }
        }

        fn mismatched_height() -> Self {
            Self {
                block_number: json!("0x11"),
                ..Self::new(chain_id::TESTNET_V2)
            }
        }

        fn no_header(block_number: &str) -> Self {
            Self {
                block_number: Value::String(block_number.to_string()),
                header: Some(Value::Null),
                ..Self::new(chain_id::TESTNET_V2)
            }
        }

        fn bad_height() -> Self {
            Self {
                block_number: json!(1.5),
                ..Self::new(chain_id::TESTNET_V2)
            }
        }
    }

    impl Rpc for Script {
        fn call(&self, method: &str, _params: Value) -> Result<Value, ConnError> {
            let epoch = self.signed_epoch.unwrap_or_else(|| epoch_for_round(42));
            let (committee, header, seals) =
                sealed_fixture_for_epoch(self.chain, self.seals, epoch);
            match method {
                "kovanica_blockNumber" => Ok(self.block_number.clone()),
                "kovanica_syncStatus" => Ok(json!({
                    "peerCount": 2,
                    "peers": [
                        {"peerId": "12D3KooWexample", "reportedTipRound": 42},
                        {"peerId": "12D3KooWother"}
                    ]
                })),
                "kovanica_getLeaderHeader" => Ok(self.leader_header_value(&header)),
                "kovanica_getCommittee" => Ok(parse_json(&committee)),
                "kovanica_getCommitteeInfo" => {
                    if !self.committee_info {
                        return Err(ConnError::Rejected(
                            "The node does not support kovanica_getCommitteeInfo.".to_string(),
                        ));
                    }
                    let header_value = self.leader_header_value(&header);
                    let epoch = match self.committee_epoch {
                        Some(epoch) => json!(hex_qty(epoch)),
                        None => header_value.get("epoch").cloned().unwrap_or(Value::Null),
                    };
                    Ok(json!({
                        "epoch": epoch,
                        "members": parse_json(&committee),
                    }))
                }
                "kovanica_getCommitSeals" => Ok(parse_json(&seals)),
                other => Err(ConnError::Rejected(format!("unexpected method {other}"))),
            }
        }
    }

    fn parse_json(text: &str) -> Value {
        serde_json::from_str(text).unwrap()
    }

    fn sealed_fixture(chain: u64, with_seals: bool) -> (String, String, String) {
        sealed_fixture_for_epoch(chain, with_seals, epoch_for_round(42))
    }

    fn sealed_fixture_for_epoch(
        chain: u64,
        with_seals: bool,
        epoch: u64,
    ) -> (String, String, String) {
        let mut signers = Vec::new();
        let mut members = Vec::new();
        let mut seal_rows = Vec::new();
        for index in 0..4u16 {
            let signer = SigningKey::from_bytes(&[index as u8 + 1; 32]);
            let public_key = PublicKey::from(signer.verifying_key());
            let address = Address::from_public_key(&public_key);
            members.push(json!({
                "index": index,
                "address": address.to_string(),
                "stake": "0x1",
                "publicKey": hex_bytes(public_key.as_bytes()),
            }));
            seal_rows.push((index, public_key, 1u64));
            signers.push(signer);
        }
        let committee_json = Value::Array(members).to_string();
        let leader_round = 42;
        let committee_hash = committee_seal_hash(epoch, &seal_rows);
        let digest = Hash::new([3u8]);
        let leader = StatementBlock {
            author: 0,
            round: leader_round,
            parents: vec![],
            transactions: vec![],
            statements: vec![],
            signature: Signature([0; 64]),
            digest,
            merkle_root: Hash::zero(),
        };
        let subdag = CommittedSubDag {
            blocks: vec![leader.clone()],
            leader,
            leader_round,
            leader_author: 0,
            non_blue: vec![],
        };
        let header = leader_header(
            &subdag,
            16,
            Hash::zero(),
            Hash::new([9u8]),
            epoch,
            committee_hash,
            false,
        );
        let header_json = json!({
            "committedHeight": hex_qty(header.committed_height),
            "leaderRound": hex_qty(header.leader_round),
            "leaderDigest": hex_bytes(&header.leader_digest.0),
            "leaderAuthor": header.leader_author,
            "parentLeaderDigest": hex_bytes(&header.parent_leader_digest.0),
            "txMerkleRoot": hex_bytes(&header.tx_merkle_root.0),
            "executedTxRoot": hex_bytes(&header.executed_tx_root.0),
            "nonBlueRoot": hex_bytes(&header.non_blue_root.0),
            "blueRoot": hex_bytes(&header.blue_root.0),
            "mysticghost": header.mysticghost,
            "stateRoot": hex_bytes(&header.state_root.0),
            "epoch": hex_qty(header.epoch),
            "committeeHash": hex_bytes(&header.committee_hash.0),
            "timestamp": "0x0",
        })
        .to_string();
        let seals_json = if with_seals {
            let seals: Vec<_> = (0..3u16)
                .map(|index| {
                    let signature = sign(&signers[index as usize], &header.seal_message(chain));
                    json!({
                        "authorityIndex": index,
                        "signature": hex_bytes(signature.as_bytes()),
                    })
                })
                .collect();
            json!({ "seals": seals }).to_string()
        } else {
            json!({ "seals": [] }).to_string()
        };
        (committee_json, header_json, seals_json)
    }

    fn hex_qty(value: u64) -> String {
        format!("0x{value:x}")
    }

    fn hex_bytes(bytes: &[u8]) -> String {
        format!("0x{}", hex::encode(bytes))
    }

    fn temp_dir() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "kovanica-console-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
