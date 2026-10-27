//! End-to-end WebSocket subscription tests.
//!
//! These spin up a real [`RpcServer`], connect with a `tokio-tungstenite`
//! client, subscribe, and assert that node events published on the
//! [`EventBus`] arrive as `kovanica_subscription` notifications.

use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

use kovanica_consensus::{AuthorityInfo, CommitteeInfo};
use kovanica_dag::DagStore;
use kovanica_mempool::{Mempool, MempoolConfig};
use kovanica_rpc::{AuthConfig, EventBus, RateLimitConfig, RateLimiterState, RpcServer, RpcState};
use kovanica_staking::{StakingState, MIN_VALIDATOR_STAKE};
use kovanica_storage::Storage;
use kovanica_types::{crypto::PublicKey, Address, Hash, Signature, StatementBlock};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

fn test_state(storage: Arc<Storage>, events: EventBus) -> RpcState {
    let authority = AuthorityInfo {
        index: 0,
        stake: MIN_VALIDATOR_STAKE,
        public_key: PublicKey([7u8; 32]),
        vrf_public_key: None,
        address: Address([9u8; 32]),
        network_address: "127.0.0.1:9000".to_string(),
    };
    RpcState {
        health: kovanica_rpc::NodeHealth::new(),
        consensus_store: Arc::new(DagStore::from_storage(storage.clone())),
        mempool: Arc::new(Mempool::new(
            MempoolConfig::default(),
            storage.clone(),
            kovanica_types::SigningContext::new(kovanica_types::signing::chain_id::LOCAL),
        )),
        storage,
        staking: Arc::new(RwLock::new(StakingState::new())),
        committee: Arc::new(RwLock::new(
            CommitteeInfo::try_new(0, vec![authority]).expect("valid committee"),
        )),
        peer_count: Arc::new(AtomicUsize::new(0)),
        events,
        rate_limiter: Arc::new(RateLimiterState::new(RateLimitConfig::default())),
        auth_config: Arc::new(AuthConfig::default()),
        tx_gossip: None,
        sync_status: None,
    }
}

/// Start a server on an ephemeral port and return its handle and address.
async fn start_server() -> (
    tokio::task::JoinHandle<()>,
    SocketAddr,
    EventBus,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(Storage::new(dir.path().join("state.db")).expect("storage"));
    let events = EventBus::new();
    let state = test_state(storage, events.clone());
    let addr = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let server = RpcServer::new(addr, state, None, None).await;
    let handle = server.start().await.expect("start rpc server");
    (handle, addr, events, dir)
}

/// Connect to `/ws`, retrying briefly while the accept loop warms up.
async fn connect(url: &str) -> Ws {
    for _ in 0..50 {
        match connect_async(url).await {
            Ok((ws, _response)) => return ws,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    panic!("could not connect to {url}");
}

/// Read the next text frame and parse it as JSON (5s timeout).
async fn next_json(ws: &mut Ws) -> Value {
    let message = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("timed out waiting for a websocket frame")
        .expect("websocket closed unexpectedly")
        .expect("websocket error");
    let text = message.into_text().expect("expected a text frame");
    serde_json::from_str(&text).expect("frame is valid JSON")
}

async fn send_json(ws: &mut Ws, value: Value) {
    ws.send(Message::Text(value.to_string()))
        .await
        .expect("send json frame");
}

#[tokio::test]
async fn websocket_receives_new_head_notification() {
    let (handle, addr, events, _dir) = start_server().await;
    let mut ws = connect(&format!("ws://{addr}/ws")).await;

    send_json(
        &mut ws,
        json!({"jsonrpc": "2.0", "id": 1, "method": "subscribe", "params": ["newHeads"]}),
    )
    .await;
    let response = next_json(&mut ws).await;
    assert_eq!(response["result"], json!("0x1"));

    let block = StatementBlock {
        author: 0,
        round: 7,
        parents: Vec::new(),
        transactions: Vec::new(),
        statements: Vec::new(),
        signature: Signature([0u8; 64]),
        digest: Hash([0x42; 32]),
        merkle_root: Default::default(),
    };
    events.publish_new_head(&block);

    let notification = next_json(&mut ws).await;
    assert_eq!(notification["method"], json!("kovanica_subscription"));
    assert_eq!(notification["params"]["subscription"], json!("0x1"));
    assert_eq!(
        notification["params"]["result"]["hash"],
        json!(format!("0x{}", hex::encode(block.digest.0)))
    );
    assert_eq!(notification["params"]["result"]["number"], json!("0x7"));

    handle.abort();
}

#[tokio::test]
async fn websocket_unsubscribe_stops_notifications() {
    let (handle, addr, events, _dir) = start_server().await;
    let mut ws = connect(&format!("ws://{addr}/ws")).await;

    send_json(
        &mut ws,
        json!({"jsonrpc": "2.0", "id": 1, "method": "subscribe", "params": ["pendingTransactions"]}),
    )
    .await;
    let response = next_json(&mut ws).await;
    assert_eq!(response["result"], json!("0x1"));

    send_json(
        &mut ws,
        json!({"jsonrpc": "2.0", "id": 2, "method": "unsubscribe", "params": ["0x1"]}),
    )
    .await;
    let response = next_json(&mut ws).await;
    assert_eq!(response["result"], json!(true));

    let tx = sample_transaction();
    events.publish_pending_transaction(&tx);

    // No frame should arrive after unsubscribing.
    let quiet = tokio::time::timeout(Duration::from_millis(300), ws.next()).await;
    assert!(
        quiet.is_err(),
        "received unexpected frame after unsubscribe"
    );

    // Re-subscribing resumes delivery.
    send_json(
        &mut ws,
        json!({"jsonrpc": "2.0", "id": 3, "method": "subscribe", "params": ["pendingTransactions"]}),
    )
    .await;
    let response = next_json(&mut ws).await;
    assert_eq!(response["result"], json!("0x2"));

    events.publish_pending_transaction(&tx);
    let notification = next_json(&mut ws).await;
    assert_eq!(notification["params"]["subscription"], json!("0x2"));
    assert_eq!(
        notification["params"]["result"]["hash"],
        json!(format!("0x{}", hex::encode([0x01u8; 32])))
    );

    handle.abort();
}

#[tokio::test]
async fn websocket_receives_committed_leader_notification() {
    use kovanica_types::CommittedSubDag;

    let (handle, addr, events, _dir) = start_server().await;
    let mut ws = connect(&format!("ws://{addr}/ws")).await;

    send_json(
        &mut ws,
        json!({"jsonrpc": "2.0", "id": 1, "method": "subscribe", "params": ["newCommittedLeader"]}),
    )
    .await;
    let response = next_json(&mut ws).await;
    assert_eq!(response["result"], json!("0x1"));

    let leader = StatementBlock {
        author: 0,
        round: 4,
        parents: Vec::new(),
        transactions: Vec::new(),
        statements: Vec::new(),
        signature: Signature([0u8; 64]),
        digest: Hash([0x24; 32]),
        merkle_root: Default::default(),
    };
    let subdag = CommittedSubDag {
        blocks: vec![leader.clone()],
        leader,
        leader_round: 4,
        leader_author: 0,
        non_blue: Vec::new(),
    };
    events.publish_committed_leader(&subdag);

    let notification = next_json(&mut ws).await;
    assert_eq!(notification["params"]["subscription"], json!("0x1"));
    assert_eq!(
        notification["params"]["result"]["leader"]["hash"],
        json!(format!("0x{}", hex::encode([0x24u8; 32])))
    );
    assert_eq!(notification["params"]["result"]["leaderRound"], json!(4));
    assert_eq!(notification["params"]["result"]["leaderAuthor"], json!(0));

    handle.abort();
}

fn sample_transaction() -> kovanica_types::Transaction {
    use kovanica_types::{Transaction, TransactionKind};

    Transaction {
        sender: Address([0x11; 32]),
        nonce: 0,
        kind: TransactionKind::Transfer {
            to: Address([0x33; 32]),
            amount: 1,
        },
        fee: 1,
        signature: Signature([0u8; 64]),
        hash: Hash([0x01; 32]),
    }
}
