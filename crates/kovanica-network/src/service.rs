//! [`NetworkService`]: swarm lifecycle, gossip handling and peer bookkeeping.

use crate::{
    behaviour::{self, Behaviour},
    block_sync::{BlockSyncRequest, BlockSyncResponse, VoteSource},
    error::NetworkError,
    state_sync::{
        ExportedSnapshot, SnapshotChunk, StateSnapshotSource, StateSyncRequest, StateSyncResponse,
        MAX_STATE_SYNC_CHUNK_BYTES,
    },
    sync::SyncRequest,
    topics,
    validation::{
        admit_seal, AuthorityKeys, GossipValidator, LocalHeaderHash, Rejection, SealAdmission,
        VoteVerifier,
    },
    NetworkConfig, NetworkEvent,
};
use futures::StreamExt;
use kovanica_dag::DagStore;
use kovanica_mempool::{Mempool, MempoolError};
use kovanica_types::{
    epoch_for_round, SealAnnouncement, SigningContext, StatementBlock, Transaction, Vote,
};
use libp2p::{
    gossipsub::{self, MessageAcceptance},
    identify, kad, request_response,
    swarm::{dial_opts::DialOpts, ConnectionId, NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, Swarm,
};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard, PoisonError,
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Event type produced by the composite [`Behaviour`].
type BehaviourEvent = <Behaviour as NetworkBehaviour>::ToSwarm;

/// Consecutive ping failures tolerated before a peer is disconnected, banned
/// and evicted from the Kademlia routing table.
const PING_FAILURE_LIMIT: u32 = 3;

/// Maximum invalid messages (blocks, votes, transactions, sync traffic) a
/// peer may relay before it is banned.
const INVALID_BLOCK_FAILURE_LIMIT: u32 = 5;

/// Upper bound on outstanding block sync requests we remember. A response to a
/// request we no longer track is ignored **without penalty** (see
/// `NetworkService::handle_request_response_event`), and when this bound is
/// reached the oldest entry is evicted (never the whole map), so an honest
/// peer's own catch-up burst can never turn into a ban.
///
/// The bound covers the worst case comfortably: a catching-up peer pipelines
/// `ByHash` fetches with a bounded in-flight window (see the node's
/// `CATCH_UP_MAX_HASH_FETCHES`), so the true in-flight count per peer stays far
/// below one 512-hash window, and a few peers catching up together stay under
/// this total.
const MAX_PENDING_BLOCK_REQUESTS: usize = 8192;

/// How long a full state snapshot export is cached inside the service so a
/// chunked state-sync transfer pays for one serialization instead of one per
/// chunk request. Cleared implicitly by TTL and by the next export for a
/// different target height.
const STATE_SYNC_EXPORT_CACHE_TTL: Duration = Duration::from_secs(60);

/// Keep bootstrap retries bounded and separated so stale seeds do not trigger
/// a burst of simultaneous dials.
const BOOTSTRAP_RETRY_BASE: Duration = Duration::from_secs(1);
const BOOTSTRAP_RETRY_MAX: Duration = Duration::from_secs(60);
const BOOTSTRAP_DIAL_STAGGER: Duration = Duration::from_millis(250);
/// Retry delay for a bootstrap address that answered with another network
/// tag (another chain or genesis). Without it the address was redialled
/// about once a second forever: the connection itself succeeds, which resets
/// the backoff, and identify then drops it.
const BOOTSTRAP_FOREIGN_RETRY: Duration = Duration::from_secs(600);

/// Main network service.
pub struct NetworkService {
    /// Effective configuration.
    config: NetworkConfig,
    /// DAG store for serving block sync requests.
    dag_store: Arc<DagStore>,
    /// Mempool that ingests transactions received over gossip.
    mempool: Arc<Mempool>,
    /// Sender half of the event stream handed to the caller.
    event_tx: mpsc::UnboundedSender<NetworkEvent>,
    /// The swarm: polled by [`NetworkService::start`], published to by the
    /// broadcast methods.
    swarm: Mutex<Swarm<Behaviour>>,
    /// Peers we reported as connected; source of [`NetworkService::connected_peers`].
    connected: Mutex<HashSet<PeerId>>,
    /// Shared snapshot of the distinct connected-peer count for status surfaces.
    peer_count: Arc<AtomicUsize>,
    /// Consecutive ping failures per peer.
    ping_failures: Mutex<HashMap<PeerId, u32>>,
    /// Invalid block failures per peer (invalid sig, unknown author, bad parents, etc.)
    invalid_block_failures: Mutex<HashMap<PeerId, u32>>,
    /// Addresses learned for a peer (from Kademlia), used to evict banned peers
    /// from the routing table.
    peer_addresses: Mutex<HashMap<PeerId, Vec<Multiaddr>>>,
    /// Bootstrap transport attempts survive cancellation/re-entry of `start`.
    bootstrap: Mutex<BootstrapMaintenance>,
    /// Committee keys for the edge checks on votes and blocks.
    validator: GossipValidator,
    /// Outstanding block sync requests, so a response can be matched to what
    /// we actually asked for, and a failed request can be retried (bounded)
    /// on the same or an alternate peer.
    pending_block_requests: Mutex<PendingBlockRequests>,
    /// Monotonic send order for pending block sync requests, used to evict the
    /// oldest entry at the cap instead of clearing the whole map.
    next_block_request_seq: AtomicU64,
    /// Executed leader-header hashes. Unset until the node installs one.
    /// A seal is forwarded only when this index already has the same hash.
    header_index: Mutex<Option<Arc<dyn LocalHeaderHash>>>,
    /// Export side of the state sync protocol. Unset until the node installs
    /// one; while unset, state sync requests are answered `NotFound`.
    state_snapshot_source: Mutex<Option<Arc<dyn StateSnapshotSource>>>,
    /// Export side of the vote-transfer part of the block-sync protocol. Unset
    /// until the node installs one; while unset, vote requests are answered
    /// with an empty vote list.
    vote_source: Mutex<Option<Arc<dyn VoteSource>>>,
    /// Genesis hash bound into timeout signatures (PRO-40 (b)). Until the
    /// node sets it, timeout gossip is dropped unforwarded.
    timeout_genesis: Mutex<Option<kovanica_types::Hash>>,
    /// Short-lived cache of the last full snapshot export (see
    /// [`STATE_SYNC_EXPORT_CACHE_TTL`]).
    state_snapshot_cache: Mutex<Option<CachedSnapshotExport>>,
    /// Last DAG tip round each *connected* peer reported through a block-sync
    /// [`BlockSyncResponse::Status`] answer, keyed by peer id.
    ///
    /// Purely informational: it backs [`NetworkService::peer_status_snapshot`]
    /// (operator status surfaces). A reported tip is a fetch trigger, never a
    /// validation input. The map is bounded by the number of connected peers
    /// ([`NetworkConfig::max_peers`]) and its entry is dropped on disconnect
    /// and on ban.
    reported_tip: Mutex<HashMap<PeerId, u64>>,
}

/// Read-only snapshot of one connected peer, for status/RPC surfaces.
///
/// Carries only non-sensitive transport metadata: the libp2p peer id, a last
/// known network address (when one was learned via Kademlia/identify) and the
/// last DAG tip round the peer advertised through block-sync `Status`. It never
/// exposes validator keys or any signing material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStatus {
    /// libp2p peer id (transport identity, not the validator key).
    pub peer_id: PeerId,
    /// Last known network address of the peer, if one was learned.
    pub listen_addr: Option<String>,
    /// Last DAG tip round the peer reported via block-sync `Status`, if any.
    pub reported_tip_round: Option<u64>,
}

/// One cached full snapshot export served to chunked state sync requests.
struct CachedSnapshotExport {
    /// The export itself (height, state root, full bytes).
    snapshot: ExportedSnapshot,
    /// When the export was produced (TTL check).
    built_at: Instant,
}

/// State for one distinct, configured bootstrap address.
struct BootstrapAddress {
    address: Multiaddr,
    retry_at: Instant,
    failures: u32,
    pending: Option<ConnectionId>,
    peer: Option<PeerId>,
    endpoint: Option<Multiaddr>,
    /// The connected peer reported another network tag at identify.
    foreign: bool,
}

/// Small deterministic state machine for bootstrap-only transport maintenance.
/// It deliberately knows nothing about discovered or otherwise connected peers.
struct BootstrapMaintenance {
    addresses: Vec<BootstrapAddress>,
    next_dial_at: Option<Instant>,
}

impl BootstrapMaintenance {
    fn new(addresses: &[Multiaddr], max_peers: usize, now: Instant) -> Self {
        let mut seen = HashSet::new();
        let addresses = addresses
            .iter()
            .filter(|address| seen.insert((*address).clone()))
            .take(max_peers)
            .map(|address| BootstrapAddress {
                address: address.clone(),
                retry_at: now,
                failures: 0,
                pending: None,
                peer: None,
                endpoint: None,
                foreign: false,
            })
            .collect();
        Self {
            addresses,
            next_dial_at: None,
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        let retry = self
            .addresses
            .iter()
            .filter(|state| state.pending.is_none() && state.peer.is_none())
            .map(|state| state.retry_at)
            .min()?;
        Some(
            self.next_dial_at
                .map_or(retry, |stagger| retry.max(stagger)),
        )
    }

    fn due_address(&mut self, now: Instant) -> Option<(usize, Multiaddr)> {
        if self.next_dial_at.is_some_and(|deadline| now < deadline) {
            return None;
        }
        let (index, state) = self.addresses.iter_mut().enumerate().find(|(_, state)| {
            state.pending.is_none() && state.peer.is_none() && state.retry_at <= now
        })?;
        self.next_dial_at = Some(now + BOOTSTRAP_DIAL_STAGGER);
        Some((index, state.address.clone()))
    }

    fn set_attempt(&mut self, index: usize, connection_id: ConnectionId) {
        if let Some(state) = self.addresses.get_mut(index) {
            state.pending = Some(connection_id);
        }
    }

    fn fail_attempt(&mut self, connection_id: ConnectionId, now: Instant) -> bool {
        let Some((index, state)) = self
            .addresses
            .iter_mut()
            .enumerate()
            .find(|(_, state)| state.pending == Some(connection_id))
        else {
            return false;
        };
        state.pending = None;
        Self::schedule_retry(index, state, now);
        true
    }

    fn establish_attempt(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        endpoint: Multiaddr,
    ) -> bool {
        let Some(state) = self
            .addresses
            .iter_mut()
            .find(|state| state.pending == Some(connection_id))
        else {
            return false;
        };
        state.pending = None;
        state.failures = 0;
        state.peer = Some(peer);
        state.endpoint = Some(endpoint);
        true
    }

    fn peer_disconnected(&mut self, peer: PeerId, num_established: u32, now: Instant) -> bool {
        if num_established != 0 {
            return false;
        }
        let mut matched = false;
        for (index, state) in self.addresses.iter_mut().enumerate() {
            if state.peer == Some(peer) {
                state.peer = None;
                state.endpoint = None;
                if std::mem::take(&mut state.foreign) {
                    state.retry_at = now + BOOTSTRAP_FOREIGN_RETRY;
                } else {
                    Self::schedule_retry(index, state, now);
                }
                matched = true;
            }
        }
        matched
    }

    /// Mark the bootstrap address connected to `peer` as belonging to another
    /// network, so its disconnect schedules [`BOOTSTRAP_FOREIGN_RETRY`].
    /// Returns whether `peer` was a bootstrap peer.
    fn mark_foreign(&mut self, peer: PeerId) -> bool {
        let mut matched = false;
        for state in self.addresses.iter_mut().filter(|s| s.peer == Some(peer)) {
            state.foreign = true;
            matched = true;
        }
        matched
    }

    fn schedule_retry(index: usize, state: &mut BootstrapAddress, now: Instant) {
        state.failures = state.failures.saturating_add(1);
        let shift = state.failures.saturating_sub(1).min(31);
        let backoff = BOOTSTRAP_RETRY_BASE
            .checked_mul(1u32 << shift)
            .unwrap_or(BOOTSTRAP_RETRY_MAX)
            .min(BOOTSTRAP_RETRY_MAX);
        // Apply a stable per-address offset even when several failures happen
        // together, while keeping the total delay within the retry cap.
        let stagger = BOOTSTRAP_DIAL_STAGGER.saturating_mul((index as u32).min(240));
        state.retry_at = now + backoff.saturating_add(stagger).min(BOOTSTRAP_RETRY_MAX);
    }
}

/// A block sync request we sent, with the context needed to match its
/// response and to retry it after an [`request_response::OutboundFailure`].
#[derive(Debug, Clone)]
struct PendingBlockRequest {
    /// The request exactly as sent.
    request: BlockSyncRequest,
    /// The peer we asked (the retry may target another one).
    peer: PeerId,
    /// How many sends have already been made for this request
    /// (1 for the original send).
    attempts: u8,
    /// Monotonic send order; the smallest live value is evicted at the cap.
    sequence: u64,
}

/// Outstanding block sync requests, keyed by the libp2p request id.
type PendingBlockRequests = HashMap<request_response::OutboundRequestId, PendingBlockRequest>;

/// Drop the oldest tracked request when the pending map is at the cap.
///
/// A late response to the evicted id is ignored without penalty (see
/// `handle_request_response_event`), so evicting never blames a peer for our
/// own backlog; it only frees a slot for the newest request.
fn evict_oldest_pending(pending: &mut PendingBlockRequests) {
    if let Some(oldest) = pending
        .iter()
        .min_by_key(|(_, request)| request.sequence)
        .map(|(id, _)| *id)
    {
        pending.remove(&oldest);
    }
}

/// Decide where (if anywhere) a failed block sync request may be re-sent.
///
/// `attempts` is how many sends were already made for the request:
///
/// * first failure → retry once on the same peer while it is still connected
///   (otherwise fail over immediately);
/// * second failure → exactly one alternate connected peer;
/// * later failures → give up.
///
/// This caps a request at three sends total (original + retry + alternate),
/// so a flapping peer or network can never turn into an unbounded retry loop.
fn retry_peer(attempts: u8, failed: PeerId, connected: &HashSet<PeerId>) -> Option<PeerId> {
    match attempts {
        1 if connected.contains(&failed) => Some(failed),
        1 | 2 => connected
            .iter()
            .copied()
            .filter(|peer| *peer != failed)
            .min(),
        _ => None,
    }
}

/// Maximum number of hashes accepted in a `MissingBlocks` sync response.
const MAX_MISSING_BLOCKS: usize = 64;

/// Slice one bounded chunk out of a full snapshot export.
///
/// An offset at or past the end of the export is an invalid request (the
/// client asked for bytes that cannot exist), which keeps a peer from probing
/// for arbitrary offsets and bounds every response to one chunk.
fn slice_snapshot_chunk(snapshot: &ExportedSnapshot, offset: u64) -> StateSyncResponse {
    let total_len = snapshot.bytes.len() as u64;
    if offset >= total_len {
        return StateSyncResponse::InvalidRequest;
    }
    let start = offset as usize;
    let end = (start + MAX_STATE_SYNC_CHUNK_BYTES).min(snapshot.bytes.len());
    StateSyncResponse::Chunk(SnapshotChunk {
        height: snapshot.height,
        state_root: snapshot.state_root,
        total_len,
        offset,
        data: snapshot.bytes[start..end].to_vec(),
    })
}

/// Outcome of validating one gossip message.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// Valid: deliver and forward.
    Accept,
    /// Not forwarded, no penalty (duplicate, depends on local state, or we
    /// cannot judge it yet).
    Ignore,
    /// Invalid: not forwarded, counted against the relaying peer.
    Reject(String),
}

impl Verdict {
    fn reject(reason: &str) -> Self {
        Verdict::Reject(reason.to_string())
    }

    fn rejected(kind: &str, rejection: Rejection) -> Self {
        Verdict::Reject(format!("{kind}: {rejection}"))
    }
}

/// Lock a mutex, recovering from poisoning: a panic while a lock is held must
/// not take the whole network layer down.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl NetworkService {
    /// Create a new network service and its event stream.
    ///
    /// The swarm is built immediately (no ports are bound until
    /// [`NetworkService::start`]), so broadcasts work as soon as the service
    /// exists.
    pub fn new(
        config: NetworkConfig,
        dag_store: Arc<DagStore>,
        mempool: Arc<Mempool>,
    ) -> Result<(Self, mpsc::UnboundedReceiver<NetworkEvent>), NetworkError> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let swarm = behaviour::build_swarm(&config)?;
        let bootstrap =
            BootstrapMaintenance::new(&config.bootstrap_nodes, config.max_peers, Instant::now());
        info!(peer_id = %swarm.local_peer_id(), "network swarm created");

        Ok((
            Self {
                config,
                dag_store,
                mempool,
                event_tx,
                swarm: Mutex::new(swarm),
                connected: Mutex::new(HashSet::new()),
                peer_count: Arc::new(AtomicUsize::new(0)),
                ping_failures: Mutex::new(HashMap::new()),
                invalid_block_failures: Mutex::new(HashMap::new()),
                peer_addresses: Mutex::new(HashMap::new()),
                bootstrap: Mutex::new(bootstrap),
                validator: GossipValidator::default(),
                pending_block_requests: Mutex::new(HashMap::new()),
                next_block_request_seq: AtomicU64::new(0),
                header_index: Mutex::new(None),
                state_snapshot_source: Mutex::new(None),
                vote_source: Mutex::new(None),
                timeout_genesis: Mutex::new(None),
                state_snapshot_cache: Mutex::new(None),
                reported_tip: Mutex::new(HashMap::new()),
            },
            event_rx,
        ))
    }

    /// Start the network service: listen on every configured address, dial the
    /// bootstrap nodes and then run the swarm event loop.
    ///
    /// The loop only returns on an unrecoverable (storage) error; transport and
    /// dial failures are logged and tolerated.
    ///
    /// Takes `&self`: the swarm and all bookkeeping use interior mutability, so
    /// the listen/dial preamble is executed exactly once per call. Callers must
    /// run this loop in its own task, not inside a `select!` that can cancel it
    /// and re-enter the preamble (which leaks listeners/file descriptors).
    pub async fn start(&self) -> Result<(), NetworkError> {
        for addr in &self.config.listen_addrs {
            match self.swarm().listen_on(addr.clone()) {
                Ok(_) => info!(%addr, "listening"),
                Err(err) => warn!(%addr, %err, "failed to listen on address"),
            }
        }

        self.dial_due_bootstrap();

        if let Err(err) = self.swarm().behaviour_mut().kad.bootstrap() {
            debug!(%err, "kad bootstrap deferred: no known peers yet");
        }

        info!(
            listen = self.config.listen_addrs.len(),
            bootstraps = self.config.bootstrap_nodes.len(),
            "network service started"
        );

        loop {
            let event = match self.next_bootstrap_deadline() {
                Some(deadline) => {
                    tokio::select! {
                        event = self.next_swarm_event() => event,
                        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                            self.dial_due_bootstrap();
                            continue;
                        }
                    }
                }
                None => self.next_swarm_event().await,
            };
            let Some(event) = event else {
                return Err(NetworkError::Swarm(
                    "swarm event stream ended unexpectedly".to_string(),
                ));
            };
            self.handle_swarm_event(event)?;
        }
    }

    /// Broadcast a block to all peers.
    pub fn broadcast_block(&self, block: &StatementBlock) -> Result<(), NetworkError> {
        let payload = bincode::serialize(block)?;
        self.publish(topics::BLOCKS, payload)
    }

    /// Broadcast a transaction to all peers.
    pub fn broadcast_transaction(&self, tx: &Transaction) -> Result<(), NetworkError> {
        let payload = bincode::serialize(tx)?;
        self.publish(topics::TRANSACTIONS, payload)
    }

    /// Broadcast a vote to all peers.
    pub fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError> {
        let payload = bincode::serialize(vote)?;
        self.publish(topics::VOTES, payload)
    }

    /// Broadcast a leader-slot timeout (PRO-40 (b)).
    pub fn broadcast_timeout(&self, timeout: &kovanica_types::Timeout) -> Result<(), NetworkError> {
        let payload = bincode::serialize(&crate::TimeoutMessage::Timeout(timeout.clone()))?;
        self.publish(topics::TIMEOUTS, payload)
    }

    /// Broadcast a skip certificate (PRO-40 (b)).
    pub fn broadcast_skip_cert(&self, cert: &kovanica_types::SkipCert) -> Result<(), NetworkError> {
        let payload = bincode::serialize(&crate::TimeoutMessage::SkipCert(cert.clone()))?;
        self.publish(topics::TIMEOUTS, payload)
    }

    /// Set the genesis hash that timeout signatures are bound to.
    pub fn set_timeout_genesis(&self, genesis_hash: kovanica_types::Hash) {
        *lock(&self.timeout_genesis) = Some(genesis_hash);
    }

    /// Broadcast one locally produced commit seal.
    ///
    /// Consensus does not call this. Execution does, after the header is stored.
    pub fn broadcast_seal(&self, announcement: &SealAnnouncement) -> Result<(), NetworkError> {
        let payload = bincode::serialize(announcement)?;
        self.publish(topics::SEALS, payload)
    }

    /// Install the executed-header index used to decide whether a gossiped
    /// seal may be forwarded.
    pub fn set_header_index(&self, index: Arc<dyn LocalHeaderHash>) {
        *lock(&self.header_index) = Some(index);
    }

    /// Install the committee public keys used to authenticate gossiped votes
    /// and blocks (and block sync responses) at the network edge.
    ///
    /// Until this is called, votes and blocks are dropped without being
    /// forwarded: nothing can be authenticated without the committee.
    pub fn set_authority_keys(&self, keys: AuthorityKeys) {
        info!(
            authorities = keys.len(),
            "gossip validator committee keys set"
        );
        self.validator.set_keys(keys);
    }

    /// Inject the vote signature verifier used at the gossip edge.
    ///
    /// Defaults to [`crate::Ed25519VoteVerifier`]; the node sets it explicitly.
    pub fn set_vote_verifier(&self, verifier: Arc<dyn VoteVerifier>) {
        self.validator.set_vote_verifier(verifier);
    }

    /// Install the export side of the state sync protocol.
    ///
    /// Until this is called, inbound [`StateSyncRequest`]s are answered with
    /// [`StateSyncResponse::NotFound`]. The service slices the export into
    /// bounded chunks (at most [`MAX_STATE_SYNC_CHUNK_BYTES`] each) and caches
    /// the full export for [`STATE_SYNC_EXPORT_CACHE_TTL`] so a chunked
    /// transfer does not re-serialize the whole state per request.
    pub fn set_state_snapshot_source(&self, source: Arc<dyn StateSnapshotSource>) {
        *lock(&self.state_snapshot_source) = Some(source);
        info!("state snapshot source installed");
    }

    /// Install the export side of the vote-transfer part of the block-sync
    /// protocol.
    ///
    /// Until this is called, inbound [`BlockSyncRequest::VotesForRound`]
    /// requests are answered with an empty vote list. The source is consulted
    /// on the serving path only; it is never trusted for anything but the
    /// votes it hands out, and every vote is verified by the requester.
    ///
    /// See `docs/rfcs/RFC-009-VOTE-TRANSFER-OVER-BLOCK-SYNC.md`.
    pub fn set_vote_source(&self, source: Arc<dyn VoteSource>) {
        *lock(&self.vote_source) = Some(source);
        info!("vote source installed");
    }

    /// Our libp2p peer id (transport identity, not the validator key).
    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm().local_peer_id()
    }

    /// Get connected peers.
    pub fn connected_peers(&self) -> HashSet<PeerId> {
        lock(&self.connected).clone()
    }

    /// Get peer count.
    pub fn peer_count(&self) -> usize {
        lock(&self.connected).len()
    }

    /// Get a cloneable snapshot handle for the distinct connected-peer count.
    ///
    /// The value is updated by the network event loop whenever its existing
    /// distinct-peer bookkeeping changes.
    pub fn peer_count_handle(&self) -> Arc<AtomicUsize> {
        self.peer_count.clone()
    }

    /// Read-only snapshot of the connected peers and their last reported tip.
    ///
    /// One [`PeerStatus`] per connected peer, in a deterministic order (sorted
    /// by peer id) so a status surface is stable across calls. The list is
    /// inherently bounded by [`NetworkConfig::max_peers`] (only connected peers
    /// are included). The address is only present when one was learned via
    /// Kademlia/identify; the reported tip is only present once the peer has
    /// answered a block-sync `Status` probe.
    ///
    /// This only reads existing bookkeeping; it changes no network behaviour.
    pub fn peer_status_snapshot(&self) -> Vec<PeerStatus> {
        let connected = lock(&self.connected);
        let addresses = lock(&self.peer_addresses);
        let reported = lock(&self.reported_tip);
        let mut peers: Vec<PeerStatus> = connected
            .iter()
            .map(|peer_id| PeerStatus {
                peer_id: *peer_id,
                listen_addr: addresses
                    .get(peer_id)
                    .and_then(|addrs| addrs.first())
                    .map(|addr| addr.to_string()),
                reported_tip_round: reported.get(peer_id).copied(),
            })
            .collect();
        peers.sort_by_key(|status| status.peer_id.to_string());
        peers
    }

    /// Lock the swarm.
    fn swarm(&self) -> MutexGuard<'_, Swarm<Behaviour>> {
        lock(&self.swarm)
    }

    /// Poll the swarm for its next event.
    ///
    /// The lock is taken only for the duration of a single `poll`: the swarm
    /// stores the task waker internally when it returns `Pending`, so the guard
    /// can be dropped right away and re-acquired on the next wake-up. Holding it
    /// across an await point would block [`NetworkService::publish`].
    async fn next_swarm_event(&self) -> Option<SwarmEvent<BehaviourEvent>> {
        std::future::poll_fn(|ctx| lock(&self.swarm).poll_next_unpin(ctx)).await
    }

    fn next_bootstrap_deadline(&self) -> Option<Instant> {
        lock(&self.bootstrap).next_deadline()
    }

    /// Start at most one due configured-bootstrap dial. The next attempt is
    /// staggered, and pending connection IDs survive cancellation of `start`.
    fn dial_due_bootstrap(&self) {
        let now = Instant::now();
        let Some((index, address)) = lock(&self.bootstrap).due_address(now) else {
            return;
        };
        let opts = DialOpts::unknown_peer_id().address(address.clone()).build();
        let connection_id = opts.connection_id();
        lock(&self.bootstrap).set_attempt(index, connection_id);
        match self.swarm().dial(opts) {
            Ok(()) => debug!(%address, ?connection_id, "dialing configured bootstrap"),
            Err(error) => {
                lock(&self.bootstrap).fail_attempt(connection_id, Instant::now());
                warn!(%address, %error, "failed to dial bootstrap node");
            }
        }
    }

    /// Publish a serialized payload on a gossipsub topic.
    fn publish(&self, topic: &str, payload: Vec<u8>) -> Result<(), NetworkError> {
        let mut swarm = self.swarm();
        match swarm
            .behaviour_mut()
            .gossipsub
            .publish(topics::ident(&self.config.network_id, topic), payload)
        {
            Ok(_) => Ok(()),
            Err(gossipsub::PublishError::NoPeersSubscribedToTopic) => {
                // Nobody is subscribed yet (fresh node, no peers): the message
                // has nothing to propagate to, which is not an error for us.
                debug!(topic, "no peers to gossip to; broadcast skipped");
                Ok(())
            }
            Err(err) => Err(NetworkError::Gossipsub(err.to_string())),
        }
    }

    /// Respond to a block sync request.
    pub fn respond_block_sync(
        &self,
        channel: request_response::ResponseChannel<BlockSyncResponse>,
        response: BlockSyncResponse,
    ) -> Result<(), NetworkError> {
        let mut swarm = self.swarm();
        swarm
            .behaviour_mut()
            .block_sync
            .send_response(channel, response)
            .map_err(|e| NetworkError::Swarm(format!("failed to send block sync response: {e}")))
    }

    /// Send a block sync request to a peer.
    pub fn request_block_sync(
        &self,
        peer: PeerId,
        request: BlockSyncRequest,
    ) -> Result<request_response::OutboundRequestId, NetworkError> {
        Ok(self.send_block_sync(peer, request, 1))
    }

    /// Send a state sync request to a peer.
    ///
    /// Rate limiting (one transfer start per peer per interval) is the
    /// initiator's responsibility: the node's state-sync session manager only
    /// starts a fresh transfer when none is active, while chunk continuations
    /// (`offset > 0`) ride on the active session. Responses arrive as
    /// [`crate::NetworkEvent::StateSyncResponse`].
    pub fn request_state_sync(
        &self,
        peer: PeerId,
        request: StateSyncRequest,
    ) -> Result<request_response::OutboundRequestId, NetworkError> {
        Ok(self
            .swarm()
            .behaviour_mut()
            .state_sync
            .send_request(&peer, request))
    }

    /// Send a block sync request and remember it for response matching and
    /// the bounded [`retry_peer`] failover. `attempts` is how many sends have
    /// already been made for this request (1 for the original send).
    fn send_block_sync(
        &self,
        peer: PeerId,
        request: BlockSyncRequest,
        attempts: u8,
    ) -> request_response::OutboundRequestId {
        let mut swarm = self.swarm();
        let request_id = swarm
            .behaviour_mut()
            .block_sync
            .send_request(&peer, request.clone());
        drop(swarm);
        let sequence = self.next_block_request_seq.fetch_add(1, Ordering::Relaxed);
        let mut pending = lock(&self.pending_block_requests);
        if pending.len() >= MAX_PENDING_BLOCK_REQUESTS {
            // Requests time out after 30 s; anything this old has failed and
            // its failure event was lost. Evict only the single oldest entry:
            // a late response to it is ignored without penalty, so we never
            // need to blame a peer for our own backlog.
            evict_oldest_pending(&mut pending);
        }
        pending.insert(
            request_id,
            PendingBlockRequest {
                request,
                peer,
                attempts,
                sequence,
            },
        );
        request_id
    }

    /// Forward an event to the caller. A dropped receiver only means nobody is
    /// consuming events anymore, so this never fails the event loop.
    fn emit(&self, event: NetworkEvent) {
        if self.event_tx.send(event).is_err() {
            debug!("network event receiver dropped; event discarded");
        }
    }

    /// Turn a swarm event into [`NetworkEvent`]s.
    fn handle_swarm_event(&self, event: SwarmEvent<BehaviourEvent>) -> Result<(), NetworkError> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!(%address, "listening on new address");
                Ok(())
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } => {
                lock(&self.bootstrap).establish_attempt(
                    connection_id,
                    peer_id,
                    endpoint.get_remote_address().clone(),
                );
                self.on_peer_connected(peer_id)
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } => {
                if num_established == 0 {
                    if lock(&self.bootstrap).peer_disconnected(
                        peer_id,
                        num_established,
                        Instant::now(),
                    ) {
                        debug!(%peer_id, "configured bootstrap disconnected; retry scheduled");
                    }
                    self.on_peer_disconnected(peer_id);
                }
                Ok(())
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id,
                connection_id,
                error,
            } => {
                if lock(&self.bootstrap).fail_attempt(connection_id, Instant::now()) {
                    debug!(?peer_id, ?connection_id, %error, "bootstrap dial failed; retry scheduled");
                } else {
                    debug!(?peer_id, ?connection_id, %error, "outgoing connection failed");
                }
                Ok(())
            }
            SwarmEvent::IncomingConnectionError { error, .. } => {
                debug!(%error, "incoming connection failed");
                Ok(())
            }
            SwarmEvent::ListenerError { error, .. } => {
                warn!(%error, "listener error");
                Ok(())
            }
            SwarmEvent::Behaviour(event) => self.handle_behaviour_event(event),
            _ => Ok(()),
        }
    }

    /// Dispatch a behaviour-level event to the matching protocol handler.
    fn handle_behaviour_event(&self, event: BehaviourEvent) -> Result<(), NetworkError> {
        match event {
            BehaviourEvent::Gossipsub(event) => self.handle_gossipsub_event(event),
            BehaviourEvent::Kad(event) => self.handle_kad_event(event),
            BehaviourEvent::Ping(event) => self.handle_ping_event(event),
            BehaviourEvent::Identify(event) => self.handle_identify_event(event),
            BehaviourEvent::BlockSync(event) => self.handle_request_response_event(event),
            BehaviourEvent::StateSync(event) => self.handle_state_sync_event(event),
        }
    }

    /// Handle gossipsub traffic: route payloads by topic.
    fn handle_gossipsub_event(&self, event: gossipsub::Event) -> Result<(), NetworkError> {
        match event {
            gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            } => {
                let kind = self.config.network_id.topic_kind(message.topic.as_str());
                let acceptance = match kind {
                    Some(topics::BLOCKS) => {
                        self.on_block_message(propagation_source, &message.data)
                    }
                    Some(topics::TRANSACTIONS) => self.on_transaction_message(&message.data),
                    Some(topics::SYNC) => self.on_sync_message(message.source, &message.data),
                    Some(topics::VOTES) => self.on_vote_message(message.source, &message.data),
                    Some(topics::SEALS) => self.on_seal_message(message.source, &message.data),
                    Some(topics::TIMEOUTS) => {
                        self.on_timeout_message(message.source, &message.data)
                    }
                    _ => {
                        debug!(
                            topic = message.topic.as_str(),
                            "message on unexpected topic"
                        );
                        Verdict::Ignore
                    }
                };
                self.report_validation(&message_id, propagation_source, acceptance);
                Ok(())
            }
            gossipsub::Event::Subscribed { peer_id, topic } => {
                debug!(%peer_id, topic = topic.as_str(), "peer subscribed");
                Ok(())
            }
            gossipsub::Event::Unsubscribed { peer_id, topic } => {
                debug!(%peer_id, topic = topic.as_str(), "peer unsubscribed");
                Ok(())
            }
            gossipsub::Event::GossipsubNotSupported { peer_id } => {
                warn!(%peer_id, "peer does not support gossipsub");
                Ok(())
            }
            // libp2p-gossipsub >= 0.48 reports peers that lag behind on message
            // delivery. We have no backpressure hook for this yet, so just log.
            gossipsub::Event::SlowPeer { peer_id, .. } => {
                debug!(%peer_id, "gossipsub slow peer");
                Ok(())
            }
        }
    }

    /// Tell gossipsub whether to forward a message, and count rejected
    /// messages against the peer that relayed them to us.
    fn report_validation(
        &self,
        message_id: &gossipsub::MessageId,
        propagation_source: PeerId,
        verdict: Verdict,
    ) {
        let acceptance = match &verdict {
            Verdict::Accept => MessageAcceptance::Accept,
            Verdict::Ignore => MessageAcceptance::Ignore,
            Verdict::Reject(_) => MessageAcceptance::Reject,
        };
        let known = self
            .swarm()
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(message_id, &propagation_source, acceptance);
        if !known {
            debug!(%propagation_source, "validated message no longer in gossip cache");
        }
        if let Verdict::Reject(reason) = verdict {
            self.record_invalid_block_failure(propagation_source, &reason);
            self.enforce_score_ban(propagation_source);
        }
    }

    /// Handle Kademlia events: bootstrap progress and peer discovery.
    fn handle_kad_event(&self, event: kad::Event) -> Result<(), NetworkError> {
        match event {
            kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::Bootstrap(result),
                ..
            } => {
                match result {
                    Ok(ok) => debug!(?ok, "kad bootstrap finished"),
                    Err(err) => warn!(%err, "kad bootstrap failed"),
                }
                Ok(())
            }
            kad::Event::RoutingUpdated {
                peer,
                is_new_peer: true,
                addresses,
                ..
            } => {
                let learned = addresses.into_vec();
                let Some(address) = learned.first().cloned() else {
                    return Ok(());
                };
                lock(&self.peer_addresses).insert(peer, learned);
                debug!(%peer, %address, "peer discovered via kad");
                self.emit(NetworkEvent::PeerDiscovered(peer, address));
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Handle ping results: reset the failure counter on success, ban the peer
    /// once the failure limit is reached.
    fn handle_ping_event(&self, event: libp2p::ping::Event) -> Result<(), NetworkError> {
        match event.result {
            Ok(_) => {
                lock(&self.ping_failures).remove(&event.peer);
                Ok(())
            }
            Err(failure) => {
                let failures = {
                    let mut failures = lock(&self.ping_failures);
                    let counter = failures.entry(event.peer).or_insert(0);
                    *counter += 1;
                    *counter
                };
                if failures >= PING_FAILURE_LIMIT {
                    warn!(peer = %event.peer, failures, ?failure, "unreachable peer is being banned");
                    self.ban_peer(event.peer);
                } else {
                    debug!(peer = %event.peer, failures, ?failure, "ping failed");
                }
                Ok(())
            }
        }
    }

    /// Handle identify: learn the peer's listen addresses for Kademlia.
    fn handle_identify_event(&self, event: identify::Event) -> Result<(), NetworkError> {
        if let identify::Event::Received { peer_id, info, .. } = event {
            // Chain separation: a peer of another chain (or a pre-chain-4
            // build) is dropped and never enters the DHT.
            if !self
                .config
                .network_id
                .accepts_identify(&info.protocol_version)
            {
                warn!(
                    %peer_id,
                    theirs = %info.protocol_version,
                    ours = %self.config.network_id.identify_version(),
                    "peer is on another network; disconnecting"
                );
                if lock(&self.bootstrap).mark_foreign(peer_id) {
                    warn!(
                        %peer_id,
                        retry_secs = BOOTSTRAP_FOREIGN_RETRY.as_secs(),
                        "configured bootnode is on another network; check KOVANICA_BOOTNODES"
                    );
                }
                let _ = self.swarm().disconnect_peer_id(peer_id);
                return Ok(());
            }
            if !info.listen_addrs.is_empty() {
                let mut swarm = self.swarm();
                for address in info.listen_addrs {
                    swarm.behaviour_mut().kad.add_address(&peer_id, address);
                }
            }
        }
        Ok(())
    }

    /// Build the automatic response for a block sync request from the DAG store.
    ///
    /// Everything an untrusted peer can ask for is bounded: a `RoundRange`
    /// covers at most [`BlockSyncRequest::MAX_RANGE_ROUNDS`] rounds and
    /// returns at most [`BlockSyncResponse::MAX_RANGE_HASHES`] hashes, so one
    /// request costs a bounded number of storage reads and one bounded
    /// response (well under the 1 MiB frame cap).
    fn build_block_sync_response(&self, request: &BlockSyncRequest) -> BlockSyncResponse {
        match request {
            BlockSyncRequest::ByHash(hash) => match self.dag_store.get_block(hash) {
                Ok(block) => BlockSyncResponse::Block(block),
                Err(_) => BlockSyncResponse::NotFound,
            },
            BlockSyncRequest::ByAuthorRound { author, round } => {
                match self.dag_store.get_block_by_author_round(*author, *round) {
                    Ok(Some(block)) => BlockSyncResponse::Block(block),
                    Ok(None) => BlockSyncResponse::NotFound,
                    Err(_) => BlockSyncResponse::InvalidRequest,
                }
            }
            BlockSyncRequest::Status => {
                // The advertised tip is only a fetch trigger for the
                // requester; on a read error we simply claim "no tip", which
                // can never make a healthy peer look behind.
                let tip_round = match self.dag_store.max_dag_round() {
                    Ok(Some(round)) => round,
                    _ => 0,
                };
                BlockSyncResponse::Status { tip_round }
            }
            BlockSyncRequest::RoundRange { from, to } => {
                if to < from || to - from >= BlockSyncRequest::MAX_RANGE_ROUNDS {
                    return BlockSyncResponse::InvalidRequest;
                }
                // Never claim coverage of rounds beyond our own tip: a request
                // entirely past the DAG end is refused, a window that straddles
                // it is clamped to the tip. `up_to_round` then stays a round
                // whose hashes are complete.
                let tip = match self.dag_store.max_dag_round() {
                    Ok(Some(tip)) => tip,
                    Ok(None) | Err(_) => return BlockSyncResponse::InvalidRequest,
                };
                if *from > tip {
                    return BlockSyncResponse::InvalidRequest;
                }
                let to = (*to).min(tip);
                let mut hashes = Vec::new();
                let mut up_to_round = None;
                for round in *from..=to {
                    let Ok(blocks) = self.dag_store.get_blocks_by_round(round) else {
                        break;
                    };
                    // Stop *before* the round that would overflow the cap so
                    // coverage stays contiguous (`up_to_round` is always a
                    // round whose hashes are complete).
                    if hashes.len() + blocks.len() > BlockSyncResponse::MAX_RANGE_HASHES {
                        break;
                    }
                    hashes.extend(blocks.iter().map(|block| block.digest));
                    up_to_round = Some(round);
                }
                match up_to_round {
                    Some(up_to_round) => BlockSyncResponse::RoundHashes {
                        up_to_round,
                        hashes,
                    },
                    None => BlockSyncResponse::InvalidRequest,
                }
            }
            BlockSyncRequest::VotesForRound { round } => {
                // Serve the votes the node durably holds for this leader round.
                // A peer that asks for a round we have no votes for gets an
                // empty list, which the requester reads as "no evidence
                // available" and never as a decision.
                let votes = match lock(&self.vote_source).clone() {
                    Some(source) => source.votes_for_round(*round).unwrap_or_else(|e| {
                        warn!(round, error = %e, "vote source failed; serving no votes");
                        Vec::new()
                    }),
                    None => Vec::new(),
                };
                // Defensive: never hand out more votes than the bound allows,
                // even if the source misbehaves.
                let votes = votes
                    .into_iter()
                    .take(BlockSyncResponse::MAX_VOTES_PER_ROUND)
                    .collect();
                BlockSyncResponse::Votes {
                    round: *round,
                    votes,
                }
            }
        }
    }

    /// Handle request-response events (block sync).
    fn handle_request_response_event(
        &self,
        event: request_response::Event<BlockSyncRequest, BlockSyncResponse>,
    ) -> Result<(), NetworkError> {
        match event {
            request_response::Event::Message {
                peer,
                message,
                connection_id: _,
            } => match message {
                request_response::Message::Request {
                    request_id: _,
                    request,
                    channel,
                } => {
                    debug!(%peer, ?request, "block sync request received");
                    // Automatically respond using the DAG store; every request
                    // kind is bounded (see `build_block_sync_response`).
                    let response = self.build_block_sync_response(&request);
                    let mut swarm = self.swarm();
                    if let Err(e) = swarm
                        .behaviour_mut()
                        .block_sync
                        .send_response(channel, response)
                    {
                        warn!(%peer, %e, "failed to send block sync response");
                    }
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    debug!(%peer, ?request_id, %response, "block sync response received");
                    // A response to a request we no longer track is not the
                    // peer's fault: the pending map evicts oldest-first under a
                    // burst and 30 s timeouts can drop a late reply. Ignore it
                    // without any penalty (never `record_invalid_block_failure`)
                    // so an honest peer's own catch-up burst cannot ban it.
                    let Some(pending) = lock(&self.pending_block_requests).remove(&request_id)
                    else {
                        debug!(%peer, ?request_id, "ignoring response to an unknown block sync request");
                        return Ok(());
                    };
                    match self.check_block_sync_response(Some(&pending.request), &response) {
                        Ok(()) => {
                            // Remember the peer's advertised tip for status
                            // surfaces. Only connected peers are tracked, so the
                            // map stays bounded by `max_peers`; a stale entry can
                            // never outlive its connection (cleared on disconnect
                            // and on ban).
                            if let BlockSyncResponse::Status { tip_round } = &response {
                                // Check connectivity first and release the
                                // `connected` lock before taking `reported_tip`,
                                // so the two locks are never nested (consistent
                                // ordering with `peer_status_snapshot`).
                                let is_connected = lock(&self.connected).contains(&peer);
                                if is_connected {
                                    lock(&self.reported_tip).insert(peer, *tip_round);
                                }
                            }
                            self.emit(NetworkEvent::BlockSyncResponse {
                                peer,
                                request_id,
                                response,
                            })
                        }
                        Err(reason) => {
                            warn!(%peer, ?request_id, %reason, "dropping invalid block sync response");
                            self.record_invalid_block_failure(peer, &reason);
                        }
                    }
                }
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                connection_id: _,
            } => {
                let failed = lock(&self.pending_block_requests).remove(&request_id);
                warn!(%peer, ?request_id, %error, "block sync request failed");
                // A transport failure is not the peer calling the request
                // invalid: retry the same request once on the same peer and,
                // if that peer is unavailable, once on an alternate connected
                // peer — then give up (never an unbounded retry loop).
                let Some(pending) = failed else {
                    // Unknown or already-expired request: nothing to retry.
                    return Ok(());
                };
                let connected = lock(&self.connected).clone();
                let next = retry_peer(pending.attempts, pending.peer, &connected);
                match next {
                    Some(target) => {
                        let attempts = pending.attempts.saturating_add(1);
                        let retried =
                            self.send_block_sync(target, pending.request.clone(), attempts);
                        debug!(
                            %peer,
                            %request_id,
                            target = %target,
                            new_request_id = %retried,
                            attempts,
                            "retrying failed block sync request"
                        );
                    }
                    None => {
                        // Retry budget exhausted (or no other peer): report the
                        // request as "not obtained" — never as InvalidRequest,
                        // which would blame the peer for a transport failure.
                        debug!(%peer, ?request_id, "block sync request exhausted its retry budget");
                        self.emit(NetworkEvent::BlockSyncResponse {
                            peer: pending.peer,
                            request_id,
                            response: BlockSyncResponse::NotFound,
                        });
                    }
                }
            }
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
                connection_id: _,
            } => {
                warn!(%peer, ?request_id, %error, "incoming block sync request failed");
            }
            request_response::Event::ResponseSent { .. } => {
                debug!("block sync response sent");
            }
        }
        Ok(())
    }

    /// Edge checks for a block sync response: it must answer a request we
    /// actually sent, a returned block must be the one we asked for, and it
    /// must pass the same stateless checks as a gossiped block.
    fn check_block_sync_response(
        &self,
        expected: Option<&BlockSyncRequest>,
        response: &BlockSyncResponse,
    ) -> Result<(), String> {
        let Some(expected) = expected else {
            return Err("response to an unknown request".to_string());
        };
        match response {
            BlockSyncResponse::Block(block) => {
                let matches = match expected {
                    BlockSyncRequest::ByHash(hash) => block.digest == *hash,
                    BlockSyncRequest::ByAuthorRound { author, round } => {
                        block.author == *author && block.round == *round
                    }
                    // A single block never answers a catch-up status/range
                    // request, and never answers a vote request.
                    BlockSyncRequest::Status
                    | BlockSyncRequest::RoundRange { .. }
                    | BlockSyncRequest::VotesForRound { .. } => false,
                };
                if !matches {
                    return Err("returned block does not match the request".to_string());
                }
                self.validator
                    .verify_block(block)
                    .map_err(|rejection| format!("synced block: {rejection}"))
            }
            BlockSyncResponse::MissingBlocks(hashes) if hashes.len() > MAX_MISSING_BLOCKS => {
                Err(format!(
                    "{} missing blocks listed (max {MAX_MISSING_BLOCKS})",
                    hashes.len()
                ))
            }
            BlockSyncResponse::RoundHashes {
                up_to_round,
                hashes,
            } => {
                match expected {
                    BlockSyncRequest::RoundRange { from, to } => {
                        if hashes.len() > BlockSyncResponse::MAX_RANGE_HASHES {
                            return Err(format!(
                                "{} round hashes listed (max {})",
                                hashes.len(),
                                BlockSyncResponse::MAX_RANGE_HASHES
                            ));
                        }
                        if !(*from..=*to).contains(up_to_round) {
                            return Err(format!(
                                "coverage round {up_to_round} outside requested range {from}..={to}"
                            ));
                        }
                        // The hashes themselves are only fetch hints: each
                        // block is re-requested by hash and validated when it
                        // arrives, so no peer-supplied height/hash is trusted.
                        Ok(())
                    }
                    _ => Err("round hashes in response to a non-range request".to_string()),
                }
            }
            BlockSyncResponse::Status { .. } => match expected {
                BlockSyncRequest::Status => Ok(()),
                _ => Err("status in response to a non-status request".to_string()),
            },
            BlockSyncResponse::Votes { round, votes } => {
                match expected {
                    BlockSyncRequest::VotesForRound { round: asked } => {
                        if *asked != *round {
                            return Err(format!(
                                "votes for round {round} in response to a request for {asked}"
                            ));
                        }
                    }
                    _ => {
                        return Err("votes in response to a non-vote request".to_string());
                    }
                }
                if votes.len() > BlockSyncResponse::MAX_VOTES_PER_ROUND {
                    return Err(format!(
                        "{} votes listed (max {})",
                        votes.len(),
                        BlockSyncResponse::MAX_VOTES_PER_ROUND
                    ));
                }
                // The votes are only a hint about *who* voted; the requester
                // verifies every signature against the committee before it
                // counts a vote, so nothing here is trusted.
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Build the bounded response for an inbound state sync request.
    ///
    /// With no snapshot source installed this answers `NotFound`. Otherwise
    /// the full export is sliced into at most [`MAX_STATE_SYNC_CHUNK_BYTES`]
    /// bytes starting at the requested offset; the export is cached for
    /// [`STATE_SYNC_EXPORT_CACHE_TTL`] so a client walking chunk after chunk
    /// pays for a single serialization. An offset at or past the end is an
    /// `InvalidRequest` (the client asked for bytes that do not exist).
    fn build_state_sync_response(&self, request: &StateSyncRequest) -> StateSyncResponse {
        // Reuse the cached export when it is fresh and matches the requested
        // target height.
        let now = Instant::now();
        {
            let cache = lock(&self.state_snapshot_cache);
            if let Some(cached) = cache.as_ref() {
                let fresh =
                    now.saturating_duration_since(cached.built_at) < STATE_SYNC_EXPORT_CACHE_TTL;
                let matches = request.target_height.is_none()
                    || request.target_height == Some(cached.snapshot.height);
                if fresh && matches {
                    return slice_snapshot_chunk(&cached.snapshot, request.offset);
                }
            }
        }
        let Some(source) = lock(&self.state_snapshot_source).clone() else {
            return StateSyncResponse::NotFound;
        };
        let snapshot = match source.export_snapshot(request.target_height) {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => return StateSyncResponse::NotFound,
            Err(reason) => {
                warn!(%reason, "state snapshot export failed");
                return StateSyncResponse::NotFound;
            }
        };
        let response = slice_snapshot_chunk(&snapshot, request.offset);
        *lock(&self.state_snapshot_cache) = Some(CachedSnapshotExport {
            snapshot,
            built_at: now,
        });
        response
    }

    /// Handle request-response events (state sync / fast sync).
    fn handle_state_sync_event(
        &self,
        event: request_response::Event<StateSyncRequest, StateSyncResponse>,
    ) -> Result<(), NetworkError> {
        match event {
            request_response::Event::Message {
                peer,
                message,
                connection_id: _,
            } => match message {
                request_response::Message::Request {
                    request_id: _,
                    request,
                    channel,
                } => {
                    debug!(%peer, ?request, "state sync request received");
                    // Serve from the installed snapshot source; every request
                    // is answered with at most one bounded chunk (see
                    // `build_state_sync_response`).
                    let response = self.build_state_sync_response(&request);
                    let mut swarm = self.swarm();
                    if let Err(e) = swarm
                        .behaviour_mut()
                        .state_sync
                        .send_response(channel, response)
                    {
                        warn!(%peer, %e, "failed to send state sync response");
                    }
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    debug!(%peer, ?request_id, ?response, "state sync response received");
                    // Emit event for the node to handle snapshot import
                    self.emit(NetworkEvent::StateSyncResponse {
                        peer,
                        request_id,
                        response,
                    });
                }
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                connection_id: _,
            } => {
                warn!(%peer, ?request_id, %error, "state sync request failed");
                self.emit(NetworkEvent::StateSyncResponse {
                    peer,
                    request_id,
                    response: StateSyncResponse::InvalidRequest,
                });
            }
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
                connection_id: _,
            } => {
                warn!(%peer, ?request_id, %error, "incoming state sync request failed");
            }
            request_response::Event::ResponseSent { .. } => {
                debug!("state sync response sent");
            }
        }
        Ok(())
    }

    /// Decode a block received over gossip, run the stateless edge checks
    /// (digest, merkle root, committee author, signature) and announce it.
    ///
    /// DAG-level validation (parents, rounds) and persistence still belong to
    /// the BlockManager; this only keeps forged or tampered blocks from being
    /// forwarded or handed to consensus.
    fn on_block_message(&self, peer: PeerId, payload: &[u8]) -> Verdict {
        let block: StatementBlock = match bincode::deserialize(payload) {
            Ok(block) => block,
            Err(err) => {
                warn!(%err, "dropping malformed block gossip");
                return Verdict::reject("malformed block");
            }
        };
        if !self.validator.is_configured() {
            debug!("committee keys not set; block gossip dropped unforwarded");
            return Verdict::Ignore;
        }
        if let Err(rejection) = self.validator.verify_block(&block) {
            warn!(round = block.round, author = block.author, %rejection, "rejected block gossip");
            return Verdict::rejected("block", rejection);
        }
        let (round, digest) = (block.round, block.digest);
        info!(round, %digest, "block received over gossip");
        self.emit(NetworkEvent::BlockReceived { peer, block });
        Verdict::Accept
    }

    /// Ingest a transaction received over gossip and announce it to the caller.
    ///
    /// Only transactions the mempool admits are forwarded. Transactions that
    /// are invalid on their own (bad signature, zero fee, oversized, ...) are
    /// (including hash mismatch and fee below the floor) are rejected and
    /// counted against the relaying peer; ones that fail only
    /// because of local state (nonce, balance, full pool, duplicate) are
    /// ignored without penalty.
    fn on_transaction_message(&self, payload: &[u8]) -> Verdict {
        let tx: Transaction = match bincode::deserialize(payload) {
            Ok(tx) => tx,
            Err(err) => {
                warn!(%err, "dropping malformed transaction gossip");
                return Verdict::reject("malformed transaction");
            }
        };
        let hash = tx.hash;
        match self.mempool.add_transaction(tx.clone()) {
            Ok(()) => {
                info!(%hash, "accepted transaction received over gossip");
                self.emit(NetworkEvent::TransactionReceived(tx));
                Verdict::Accept
            }
            Err(MempoolError::AlreadyExists) => {
                debug!(%hash, "transaction already in the mempool");
                Verdict::Ignore
            }
            Err(
                err @ (MempoolError::InvalidSignature
                | MempoolError::ZeroFee
                | MempoolError::GasLimitTooHigh
                | MempoolError::TransactionTooLarge(_)
                | MempoolError::HashMismatch
                | MempoolError::Crypto(_)
                | MempoolError::Serialization(_)),
            ) => {
                warn!(%hash, %err, "rejected invalid transaction received over gossip");
                Verdict::Reject(format!("transaction: {err}"))
            }
            // Exec-Network decision: min fee is node-local config, not a
            // network rule yet, so a low fee is not misbehaviour. Ignore =
            // no forwarding, no gossipsub P4 penalty, no ban counter.
            Err(err @ MempoolError::FeeTooLow { .. }) => {
                debug!(%hash, %err, "transaction below local min fee; ignored");
                Verdict::Ignore
            }
            Err(err) => {
                debug!(%hash, %err, "transaction not admitted (local state)");
                Verdict::Ignore
            }
        }
    }

    /// Decode a vote received over gossip, authenticate it and announce it.
    ///
    /// The voter must be a committee member and the signature must verify
    /// over [`Vote::signature_data`] under that member's key. Votes failing
    /// this are neither forwarded nor handed to consensus. Whether a valid
    /// vote *counts* (leader round, duplicates, ...) is still decided by the
    /// consensus engine.
    fn on_vote_message(&self, source: Option<PeerId>, payload: &[u8]) -> Verdict {
        let vote: Vote = match bincode::deserialize(payload) {
            Ok(vote) => vote,
            Err(err) => {
                warn!(%err, "dropping malformed vote gossip");
                return Verdict::reject("malformed vote");
            }
        };
        let Some(peer) = source else {
            warn!("dropping vote message without an author");
            return Verdict::reject("vote without author");
        };
        if !self.validator.is_configured() {
            debug!("committee keys not set; vote gossip dropped unforwarded");
            return Verdict::Ignore;
        }
        // B1d (PRO-B1d): a vote's signature is over `vote.signature_data(ctx)`
        // where the engine's `vote_signing_ctx` uses epoch =
        // `vote.leader_round / EPOCH_ROUNDS`. Verifying with the mempool's
        // boot-time epoch (0) made every vote past the first epoch boundary fail
        // with BadSignature, so honest peers lost score and banned each other.
        // Derive the SAME round-based epoch here from the vote itself.
        let vote_ctx = SigningContext {
            chain_id: self.mempool.signing_context().chain_id,
            epoch: epoch_for_round(vote.leader_round),
        };
        if let Err(rejection) = self.validator.verify_vote(&vote, &vote_ctx) {
            warn!(%peer, voter = vote.voter, leader_round = vote.leader_round, %rejection, "rejected vote gossip");
            return Verdict::rejected("vote", rejection);
        }
        debug!(%peer, leader_round = vote.leader_round, %vote.leader_hash, "vote received over gossip");
        self.emit(NetworkEvent::VoteReceived { peer, vote });
        Verdict::Accept
    }

    /// Decode a timeout or skip certificate, authenticate it and announce it
    /// (PRO-40 (b)). The range, deduplication and quorum checks are done by
    /// consensus.
    fn on_timeout_message(&self, source: Option<PeerId>, payload: &[u8]) -> Verdict {
        let message: crate::TimeoutMessage = match bincode::deserialize(payload) {
            Ok(message) => message,
            Err(err) => {
                warn!(%err, "dropping malformed timeout gossip");
                return Verdict::reject("malformed timeout");
            }
        };
        let Some(peer) = source else {
            return Verdict::reject("timeout without author");
        };
        let Some(genesis) = *lock(&self.timeout_genesis) else {
            debug!("timeout genesis not set; timeout gossip dropped unforwarded");
            return Verdict::Ignore;
        };
        if !self.validator.is_configured() {
            return Verdict::Ignore;
        }
        let chain_id = self.mempool.signing_context().chain_id;
        match message {
            crate::TimeoutMessage::Timeout(timeout) => {
                if let Err(rejection) = self.validator.verify_timeout(&timeout, chain_id, &genesis)
                {
                    warn!(%peer, voter = timeout.voter, round = timeout.round, %rejection, "rejected timeout gossip");
                    return Verdict::rejected("timeout", rejection);
                }
                self.emit(NetworkEvent::TimeoutReceived { peer, timeout });
            }
            crate::TimeoutMessage::SkipCert(cert) => {
                if let Err(rejection) = self.validator.verify_skip_cert(&cert, chain_id, &genesis) {
                    warn!(%peer, round = cert.round, %rejection, "rejected skip certificate gossip");
                    return Verdict::rejected("skip certificate", rejection);
                }
                self.emit(NetworkEvent::SkipCertReceived { peer, cert });
            }
        }
        Verdict::Accept
    }

    /// Decode a commit seal, check one signature, and deliver it only when
    /// local execution already stored the same header.
    ///
    /// A valid seal for a header we have not executed is ignored: it is not
    /// forwarded and the peer is not penalised. Consensus never waits on
    /// this topic.
    fn on_seal_message(&self, source: Option<PeerId>, payload: &[u8]) -> Verdict {
        let announcement: SealAnnouncement = match bincode::deserialize(payload) {
            Ok(announcement) => announcement,
            Err(err) => {
                warn!(%err, "dropping malformed commit seal");
                return Verdict::reject("malformed commit seal");
            }
        };
        let Some(peer) = source else {
            warn!("dropping commit seal without an author");
            return Verdict::reject("commit seal without author");
        };
        if !self.validator.is_configured() {
            debug!("committee keys not set; commit seal dropped unforwarded");
            return Verdict::Ignore;
        }
        let local_hash = lock(&self.header_index)
            .as_ref()
            .and_then(|index| index.local_header_hash(announcement.header.committed_height));
        let ctx = self.mempool.signing_context();
        match admit_seal(
            &self.validator.authority_keys_snapshot(),
            ctx.chain_id,
            &announcement,
            local_hash,
        ) {
            SealAdmission::Accept => {
                debug!(
                    %peer,
                    height = announcement.header.committed_height,
                    authority = announcement.seal.authority_index,
                    "commit seal matches local header"
                );
                self.emit(NetworkEvent::SealReceived { peer, announcement });
                Verdict::Accept
            }
            SealAdmission::Ignore => {
                debug!(
                    %peer,
                    height = announcement.header.committed_height,
                    "commit seal ignored until local header matches"
                );
                Verdict::Ignore
            }
            SealAdmission::Reject(rejection) => {
                warn!(%peer, %rejection, "rejected commit seal");
                Verdict::rejected("commit seal", rejection)
            }
        }
    }

    /// Decode a sync-range request and announce it to the caller.
    fn on_sync_message(&self, source: Option<PeerId>, payload: &[u8]) -> Verdict {
        let request = match SyncRequest::decode(payload) {
            Ok(request) => request,
            Err(err) => {
                warn!(%err, "dropping malformed sync request");
                return Verdict::reject("malformed sync request");
            }
        };
        let Some(peer) = source else {
            warn!("dropping sync request without an author");
            return Verdict::reject("sync request without author");
        };
        if !request.is_valid() {
            warn!(
                %peer,
                from = request.from_round,
                to = request.to_round,
                "dropping inverted sync request"
            );
            return Verdict::reject("inverted sync request");
        }
        debug!(
            %peer,
            from = request.from_round,
            to = request.to_round,
            "sync request received"
        );
        self.emit(NetworkEvent::SyncRequest {
            peer,
            from_round: request.from_round,
            to_round: request.to_round,
        });
        Verdict::Accept
    }

    /// Record a new peer, enforcing [`NetworkConfig::max_peers`].
    fn on_peer_connected(&self, peer: PeerId) -> Result<(), NetworkError> {
        let mut connected = lock(&self.connected);
        if connected.contains(&peer) {
            return Ok(());
        }
        if connected.len() >= self.config.max_peers {
            drop(connected);
            warn!(
                %peer,
                max_peers = self.config.max_peers,
                "rejecting peer: peer limit reached"
            );
            let _ = self.swarm().disconnect_peer_id(peer);
            return Ok(());
        }
        connected.insert(peer);
        self.peer_count.store(connected.len(), Ordering::Relaxed);
        drop(connected);
        info!(%peer, "peer connected");
        self.emit(NetworkEvent::PeerConnected(peer));
        Ok(())
    }

    /// Record a disconnected peer (and only report it once).
    fn on_peer_disconnected(&self, peer: PeerId) {
        let removed = {
            let mut connected = lock(&self.connected);
            let removed = connected.remove(&peer);
            if removed {
                self.peer_count.store(connected.len(), Ordering::Relaxed);
            }
            removed
        };
        if removed {
            lock(&self.ping_failures).remove(&peer);
            lock(&self.peer_addresses).remove(&peer);
            lock(&self.reported_tip).remove(&peer);
            info!(%peer, "peer disconnected");
            self.emit(NetworkEvent::PeerDisconnected(peer));
        }
    }

    /// Disconnect a peer and evict it from the Kademlia routing table so the
    /// swarm stops redialing it.
    fn ban_peer(&self, peer: PeerId) {
        lock(&self.ping_failures).remove(&peer);
        lock(&self.invalid_block_failures).remove(&peer);
        lock(&self.reported_tip).remove(&peer);
        let known: Vec<Multiaddr> = lock(&self.peer_addresses).remove(&peer).unwrap_or_default();

        let mut swarm = self.swarm();
        if swarm.disconnect_peer_id(peer).is_err() {
            debug!(%peer, "peer was already disconnected");
        }
        let kad = &mut swarm.behaviour_mut().kad;
        if known.is_empty() {
            // Nothing learned about the peer: evict it outright.
            kad.remove_peer(&peer);
        } else {
            // Removing the last known address evicts the peer from the table.
            for address in &known {
                kad.remove_address(&peer, address);
            }
        }
        info!(%peer, "banned peer");
    }

    /// Record an invalid block failure from a peer. If the failure limit is
    /// reached, ban the peer.
    pub fn record_invalid_block_failure(&self, peer: PeerId, reason: &str) {
        let failures = {
            let mut failures = lock(&self.invalid_block_failures);
            let counter = failures.entry(peer).or_insert(0);
            *counter += 1;
            *counter
        };
        if failures >= INVALID_BLOCK_FAILURE_LIMIT {
            warn!(peer = %peer, failures, reason, "peer exceeded invalid block limit; banning");
            self.ban_peer(peer);
        } else {
            debug!(peer = %peer, failures, reason, "invalid block failure recorded");
        }
    }

    /// Ban `peer` once its gossipsub score drops below the configured ban
    /// threshold. Returns whether the peer was banned.
    fn enforce_score_ban(&self, peer: PeerId) -> bool {
        let scoring = &self.config.peer_scoring;
        if !scoring.enabled {
            return false;
        }
        let score = self.swarm().behaviour().gossipsub.peer_score(&peer);
        match score {
            Some(score) if score < scoring.ban_threshold => {
                warn!(%peer, score, threshold = scoring.ban_threshold, "peer score below ban threshold; banning");
                self.ban_peer(peer);
                true
            }
            _ => false,
        }
    }

    /// Reset invalid block failure counter for a peer (e.g., on successful validation).
    pub fn reset_invalid_block_failures(&self, peer: PeerId) {
        lock(&self.invalid_block_failures).remove(&peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::test_support;
    use kovanica_mempool::MempoolConfig;
    use kovanica_storage::Storage;
    use kovanica_types::{Hash, Round, Signature};

    /// Build a service over throwaway databases. No ports are bound.
    fn test_service() -> (tempfile::TempDir, NetworkService) {
        let dir = tempfile::tempdir().expect("temp dir");
        let dag_storage = Storage::new(dir.path().join("dag.db")).expect("dag storage");
        let mempool_storage =
            Arc::new(Storage::new(dir.path().join("mempool.db")).expect("mempool storage"));
        let dag_store = Arc::new(DagStore::new(dag_storage).expect("dag store"));
        let mempool = Arc::new(Mempool::new(
            MempoolConfig::default(),
            mempool_storage,
            test_support::TEST_CTX,
        ));
        let (service, _events) =
            NetworkService::new(NetworkConfig::default(), dag_store, mempool).expect("service");
        (dir, service)
    }

    fn sample_block() -> StatementBlock {
        StatementBlock {
            author: 0,
            round: 1,
            parents: Vec::new(),
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: Signature([0u8; 64]),
            digest: Hash::zero(),
            merkle_root: Default::default(),
        }
    }

    /// Like [`test_service`] but with a custom network config.
    fn test_service_with(config: NetworkConfig) -> (tempfile::TempDir, Arc<NetworkService>) {
        let dir = tempfile::tempdir().expect("temp dir");
        let dag_storage = Storage::new(dir.path().join("dag.db")).expect("dag storage");
        let mempool_storage =
            Arc::new(Storage::new(dir.path().join("mempool.db")).expect("mempool storage"));
        let dag_store = Arc::new(DagStore::new(dag_storage).expect("dag store"));
        let mempool = Arc::new(Mempool::new(
            MempoolConfig::default(),
            mempool_storage,
            test_support::TEST_CTX,
        ));
        let (service, _events) = NetworkService::new(config, dag_store, mempool).expect("service");
        (dir, Arc::new(service))
    }

    fn free_tcp_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .expect("free port")
            .port()
    }

    /// Two live services: the sender gossips malformed transactions, the
    /// receiver rejects them, its gossipsub score for the sender falls below
    /// the ban threshold and the sender is disconnected — before the legacy
    /// invalid-message counter (5) would have fired.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejected_gossip_lowers_score_and_bans_peer() {
        let port = free_tcp_port();
        let scoring = crate::PeerScoringConfig {
            // Two rejects on the tx topic (weight 0.5): 0.5 * -100 * 2^2 = -200.
            invalid_message_weight: -100.0,
            ..Default::default()
        };
        let (_da, receiver) = test_service_with(NetworkConfig {
            listen_addrs: vec![address(&format!("/ip4/127.0.0.1/tcp/{port}"))],
            bootstrap_nodes: Vec::new(),
            peer_scoring: scoring,
            ..NetworkConfig::default()
        });
        let receiver_id = receiver.local_peer_id();
        let (_db, sender) = test_service_with(NetworkConfig {
            listen_addrs: vec![address("/ip4/127.0.0.1/tcp/0")],
            bootstrap_nodes: vec![address(&format!(
                "/ip4/127.0.0.1/tcp/{port}/p2p/{receiver_id}"
            ))],
            ..NetworkConfig::default()
        });
        let sender_id = sender.local_peer_id();
        let r = receiver.clone();
        let rx_task = tokio::spawn(async move { r.start().await });
        let s = sender.clone();
        let tx_task = tokio::spawn(async move { s.start().await });

        // Wait for the connection and the gossip mesh (heartbeat ~1s).
        let deadline = Instant::now() + Duration::from_secs(20);
        while !receiver.connected_peers().contains(&sender_id) {
            assert!(Instant::now() < deadline, "peers never connected");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;

        let mut banned = false;
        for i in 0u8..4 {
            // Distinct payloads (content-addressed ids), all undecodable.
            let _ = sender.publish(topics::TRANSACTIONS, vec![0xff, i, 0xee]);
            tokio::time::sleep(Duration::from_millis(500)).await;
            if !receiver.connected_peers().contains(&sender_id) {
                banned = true;
                break;
            }
        }
        rx_task.abort();
        tx_task.abort();
        assert!(banned, "sender should be banned by peer score");
        let failures = lock(&receiver.invalid_block_failures)
            .get(&sender_id)
            .copied()
            .unwrap_or(0);
        assert!(failures < INVALID_BLOCK_FAILURE_LIMIT);
    }

    // #87 follow-up (integration): two nodes of the same chain id with
    // different genesis files never stay connected, and the node that has the
    // other one as bootnode backs off for ten minutes instead of redialling.
    #[tokio::test]
    async fn nodes_with_different_genesis_never_peer_and_back_off() {
        let port = free_tcp_port();
        let genesis_a = kovanica_types::Hash([0xa1; 32]);
        let genesis_b = kovanica_types::Hash([0xb2; 32]);
        let (_da, receiver) = test_service_with(NetworkConfig {
            listen_addrs: vec![address(&format!("/ip4/127.0.0.1/tcp/{port}"))],
            bootstrap_nodes: Vec::new(),
            network_id: crate::NetworkId::new(4, genesis_a),
            ..NetworkConfig::default()
        });
        let receiver_id = receiver.local_peer_id();
        let (_db, sender) = test_service_with(NetworkConfig {
            listen_addrs: vec![address("/ip4/127.0.0.1/tcp/0")],
            bootstrap_nodes: vec![address(&format!(
                "/ip4/127.0.0.1/tcp/{port}/p2p/{receiver_id}"
            ))],
            network_id: crate::NetworkId::new(4, genesis_b),
            ..NetworkConfig::default()
        });
        let r = receiver.clone();
        let rx_task = tokio::spawn(async move { r.start().await });
        let s = sender.clone();
        let tx_task = tokio::spawn(async move { s.start().await });

        // Wait until the sender's bootstrap entry is marked foreign and
        // rescheduled (connect, identify mismatch, disconnect).
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let backed_off = {
                let bootstrap = lock(&sender.bootstrap);
                let state = &bootstrap.addresses[0];
                state.peer.is_none()
                    && state.pending.is_none()
                    && state.retry_at > Instant::now() + Duration::from_secs(300)
            };
            if backed_off {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "foreign bootnode was not backed off"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(!receiver.connected_peers().contains(&sender.local_peer_id()));
        assert!(!sender.connected_peers().contains(&receiver_id));
        rx_task.abort();
        tx_task.abort();
    }

    fn address(text: &str) -> Multiaddr {
        text.parse().expect("valid test multiaddr")
    }

    fn test_id(id: usize) -> ConnectionId {
        ConnectionId::new_unchecked(id)
    }

    #[test]
    fn bootstrap_addresses_are_deduplicated_and_capped() {
        let now = Instant::now();
        let first = address("/ip4/127.0.0.1/tcp/19001");
        let second = address("/ip4/127.0.0.1/tcp/19002");
        let third = address("/ip4/127.0.0.1/tcp/19003");
        let maintenance = BootstrapMaintenance::new(
            &[first.clone(), first.clone(), second.clone(), third],
            2,
            now,
        );

        assert_eq!(maintenance.addresses.len(), 2);
        assert_eq!(maintenance.addresses[0].address, first);
        assert_eq!(maintenance.addresses[1].address, second);
    }

    // #87 follow-up: a bootnode of another chain/genesis connects fine and is
    // then dropped at identify. It must not be redialled every second.
    #[test]
    fn a_foreign_bootnode_is_retried_after_ten_minutes_not_every_second() {
        let now = Instant::now();
        let mut maintenance = BootstrapMaintenance::new(
            &[
                address("/ip4/127.0.0.1/tcp/19001"),
                address("/ip4/127.0.0.1/tcp/19002"),
            ],
            2,
            now,
        );
        let foreign_peer = PeerId::random();
        let own_peer = PeerId::random();
        for (i, peer) in [foreign_peer, own_peer].into_iter().enumerate() {
            let at = now + BOOTSTRAP_DIAL_STAGGER * i as u32;
            let (index, addr) = maintenance.due_address(at).expect("dial due");
            maintenance.set_attempt(index, test_id(10 + i));
            assert!(maintenance.establish_attempt(test_id(10 + i), peer, addr));
        }
        assert!(maintenance.mark_foreign(foreign_peer));
        assert!(
            !maintenance.mark_foreign(PeerId::random()),
            "not a bootnode"
        );
        assert!(maintenance.peer_disconnected(foreign_peer, 0, now));
        assert!(maintenance.peer_disconnected(own_peer, 0, now));
        assert_eq!(
            maintenance.addresses[0].retry_at,
            now + BOOTSTRAP_FOREIGN_RETRY
        );
        assert!(maintenance.addresses[1].retry_at < now + BOOTSTRAP_RETRY_MAX);
        assert!(!maintenance.addresses[0].foreign, "flag is consumed");
    }

    #[test]
    fn bootstrap_retry_backoff_is_exponential_and_capped() {
        let now = Instant::now();
        let mut maintenance =
            BootstrapMaintenance::new(&[address("/ip4/127.0.0.1/tcp/19001")], 1, now);

        let (index, _) = maintenance.due_address(now).expect("initial dial due");
        let first_id = test_id(1);
        maintenance.set_attempt(index, first_id);
        assert!(maintenance.fail_attempt(first_id, now));
        assert_eq!(
            maintenance.addresses[0].retry_at,
            now + Duration::from_secs(1)
        );

        let second_due = now + Duration::from_secs(1);
        let (index, _) = maintenance
            .due_address(second_due)
            .expect("second dial due");
        let second_id = test_id(2);
        maintenance.set_attempt(index, second_id);
        assert!(maintenance.fail_attempt(second_id, second_due));
        assert_eq!(
            maintenance.addresses[0].retry_at,
            second_due + Duration::from_secs(2)
        );

        let mut retry_at = maintenance.addresses[0].retry_at;
        let mut latest_attempt_at = None;
        for id in 3..16 {
            latest_attempt_at = Some(retry_at);
            let (index, _) = maintenance.due_address(retry_at).expect("retry due");
            let connection_id = test_id(id);
            maintenance.set_attempt(index, connection_id);
            assert!(maintenance.fail_attempt(connection_id, retry_at));
            retry_at = maintenance.addresses[0].retry_at;
        }
        assert_eq!(
            retry_at - latest_attempt_at.expect("at least one capped retry"),
            BOOTSTRAP_RETRY_MAX
        );
    }

    #[test]
    fn pending_bootstrap_attempt_survives_start_reentry_and_old_events_are_exact() {
        let now = Instant::now();
        let mut maintenance =
            BootstrapMaintenance::new(&[address("/ip4/127.0.0.1/tcp/19001")], 1, now);
        let (index, _) = maintenance.due_address(now).expect("initial dial due");
        let older_id = test_id(41);
        maintenance.set_attempt(index, older_id);

        // Re-entering `start` sees the same pending state and does not create a
        // replacement dial just because the start future was canceled.
        assert!(maintenance
            .due_address(now + Duration::from_secs(10))
            .is_none());
        assert_eq!(maintenance.addresses[0].pending, Some(older_id));

        assert!(maintenance.fail_attempt(older_id, now));
        let retry_at = maintenance.addresses[0].retry_at;
        let (index, _) = maintenance.due_address(retry_at).expect("retry due");
        let newer_id = test_id(42);
        maintenance.set_attempt(index, newer_id);
        assert!(!maintenance.fail_attempt(older_id, retry_at + Duration::from_secs(1)));
        assert_eq!(maintenance.addresses[0].pending, Some(newer_id));
    }

    #[test]
    fn bootstrap_disconnect_retries_only_associated_peer_after_last_connection() {
        let now = Instant::now();
        let mut maintenance =
            BootstrapMaintenance::new(&[address("/ip4/127.0.0.1/tcp/19001")], 1, now);
        let (index, _) = maintenance.due_address(now).expect("initial dial due");
        let connection_id = test_id(51);
        let peer = PeerId::random();
        maintenance.set_attempt(index, connection_id);
        assert!(maintenance.establish_attempt(
            connection_id,
            peer,
            address("/ip4/127.0.0.1/tcp/19001")
        ));

        assert!(!maintenance.peer_disconnected(peer, 1, now));
        assert_eq!(maintenance.addresses[0].peer, Some(peer));
        assert!(!maintenance.peer_disconnected(PeerId::random(), 0, now));
        assert!(maintenance.peer_disconnected(peer, 0, now));
        assert_eq!(maintenance.addresses[0].peer, None);
        assert_eq!(
            maintenance.addresses[0].retry_at,
            now + BOOTSTRAP_RETRY_BASE
        );
    }

    #[tokio::test]
    async fn new_service_starts_with_no_peers() {
        let (_dir, service) = test_service();
        assert_eq!(service.peer_count(), 0);
        assert!(service.connected_peers().is_empty());
    }

    #[tokio::test]
    async fn broadcast_without_peers_is_not_an_error() {
        let (_dir, service) = test_service();
        service
            .broadcast_block(&sample_block())
            .expect("broadcast with no peers");
        assert_eq!(service.peer_count(), 0);
    }

    fn test_service_with_mempool(config: MempoolConfig) -> (tempfile::TempDir, NetworkService) {
        let dir = tempfile::tempdir().expect("temp dir");
        let dag_storage = Storage::new(dir.path().join("dag.db")).expect("dag storage");
        let mempool_storage =
            Arc::new(Storage::new(dir.path().join("mempool.db")).expect("mempool storage"));
        let dag_store = Arc::new(DagStore::new(dag_storage).expect("dag store"));
        let mempool = Arc::new(Mempool::new(
            config,
            mempool_storage,
            test_support::TEST_CTX,
        ));
        let (service, _events) =
            NetworkService::new(NetworkConfig::default(), dag_store, mempool).expect("service");
        (dir, service)
    }

    fn signed_transfer(fee: u64) -> Transaction {
        let signer = kovanica_types::SigningKey::from_bytes(&[9; 32]);
        let mut tx = Transaction {
            sender: kovanica_types::Address([1; 32]),
            nonce: 0,
            kind: kovanica_types::transaction::TransactionKind::Transfer {
                to: kovanica_types::Address([7; 32]),
                amount: 1,
            },
            fee,
            signature: Signature([0; 64]),
            hash: Hash::zero(),
        };
        tx.hash = tx.signing_hash(&test_support::TEST_CTX);
        tx.signature = kovanica_crypto::sign(&signer, tx.hash.as_ref());
        tx
    }

    #[tokio::test]
    async fn hash_mismatch_is_rejected_and_fee_too_low_is_ignored_at_gossip_edge() {
        // HashMismatch: cached hash is not the signing hash -> Reject.
        let (_dir, service) = test_service();
        let mut tx = signed_transfer(1_000);
        tx.hash = Hash::new(b"not the signing hash");
        let payload = bincode::serialize(&tx).expect("serialize");
        match service.on_transaction_message(&payload) {
            Verdict::Reject(reason) => assert!(reason.contains("hash"), "{reason}"),
            other => panic!("HashMismatch must be Reject, got {other:?}"),
        }

        // FeeTooLow: below this node's floor -> Ignore, no penalty.
        let (_dir, service) = test_service_with_mempool(MempoolConfig {
            min_fee_rate: 1_000_000,
            ..MempoolConfig::default()
        });
        let payload = bincode::serialize(&signed_transfer(1)).expect("serialize");
        let verdict = service.on_transaction_message(&payload);
        assert!(
            matches!(verdict, Verdict::Ignore),
            "FeeTooLow must be Ignore, got {verdict:?}"
        );
        // Reporting the verdict must not count against the relaying peer.
        let peer = PeerId::random();
        for i in 0..(INVALID_BLOCK_FAILURE_LIMIT + 2) {
            let verdict = service.on_transaction_message(&payload);
            let id = gossipsub::MessageId::from(vec![i as u8]);
            service.report_validation(&id, peer, verdict);
        }
        assert!(lock(&service.invalid_block_failures).get(&peer).is_none());
        assert!(
            !service.enforce_score_ban(peer),
            "no score ban for FeeTooLow"
        );
    }

    #[tokio::test]
    async fn gossip_message_ingestion_is_reversible_on_bad_data() {
        let (_dir, service) = test_service();
        // Malformed payloads are dropped and rejected, never propagated.
        assert!(matches!(
            service.on_block_message(PeerId::random(), &[0xff, 0xff]),
            Verdict::Reject(_)
        ));
        assert!(matches!(
            service.on_transaction_message(&[0xff, 0xff]),
            Verdict::Reject(_)
        ));
        assert!(matches!(
            service.on_sync_message(None, &[0xff, 0xff]),
            Verdict::Reject(_)
        ));
        assert!(matches!(
            service.on_sync_message(Some(PeerId::random()), &[0xff, 0xff]),
            Verdict::Reject(_)
        ));
        assert!(matches!(
            service.on_vote_message(Some(PeerId::random()), &[0xff, 0xff]),
            Verdict::Reject(_)
        ));
    }

    /// Service with an event receiver and a 4-member committee installed.
    fn validating_service() -> (
        tempfile::TempDir,
        NetworkService,
        mpsc::UnboundedReceiver<NetworkEvent>,
        Vec<kovanica_types::SigningKey>,
    ) {
        let dir = tempfile::tempdir().expect("temp dir");
        let dag_storage = Storage::new(dir.path().join("dag.db")).expect("dag storage");
        let mempool_storage =
            Arc::new(Storage::new(dir.path().join("mempool.db")).expect("mempool storage"));
        let dag_store = Arc::new(DagStore::new(dag_storage).expect("dag store"));
        let mempool = Arc::new(Mempool::new(
            MempoolConfig::default(),
            mempool_storage,
            test_support::TEST_CTX,
        ));
        let (service, events) =
            NetworkService::new(NetworkConfig::default(), dag_store, mempool).expect("service");
        let (signers, keys) = test_support::committee(4);
        service.set_authority_keys(keys);
        (dir, service, events, signers)
    }

    #[tokio::test]
    async fn valid_vote_is_accepted_and_delivered() {
        let (_dir, service, mut events, signers) = validating_service();
        let vote = test_support::signed_vote(&signers[1], 1);
        let payload = bincode::serialize(&vote).expect("serialize vote");
        assert_eq!(
            service.on_vote_message(Some(PeerId::random()), &payload),
            Verdict::Accept
        );
        match events.try_recv().expect("vote event emitted") {
            NetworkEvent::VoteReceived { vote: got, .. } => assert_eq!(got, vote),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    fn signed_timeout(
        key: &kovanica_types::SigningKey,
        voter: u16,
        round: u64,
        genesis: &kovanica_types::Hash,
    ) -> kovanica_types::Timeout {
        let mut t = kovanica_types::Timeout {
            round,
            voter,
            signature: kovanica_types::Signature([0; 64]),
        };
        t.signature = kovanica_crypto::sign(
            key,
            &t.signature_data(test_support::TEST_CTX.chain_id, genesis),
        );
        t
    }

    // PRO-40 (b): timeouts and skip certificates are authenticated at the
    // gossip edge against this chain's genesis.
    #[tokio::test]
    async fn timeout_gossip_is_authenticated_against_the_genesis() {
        let (_dir, service, mut events, signers) = validating_service();
        let genesis = kovanica_types::Hash([3; 32]);
        let timeout = signed_timeout(&signers[1], 1, 3, &genesis);
        let payload = bincode::serialize(&crate::TimeoutMessage::Timeout(timeout.clone())).unwrap();
        assert_eq!(
            service.on_timeout_message(Some(PeerId::random()), &payload),
            Verdict::Ignore,
            "no genesis set: dropped unforwarded"
        );
        service.set_timeout_genesis(genesis);
        assert_eq!(
            service.on_timeout_message(Some(PeerId::random()), &payload),
            Verdict::Accept
        );
        match events.try_recv().expect("timeout event") {
            NetworkEvent::TimeoutReceived { timeout: got, .. } => assert_eq!(got, timeout),
            other => panic!("unexpected event: {other:?}"),
        }

        let foreign = signed_timeout(&signers[1], 1, 3, &kovanica_types::Hash([4; 32]));
        let payload = bincode::serialize(&crate::TimeoutMessage::Timeout(foreign)).unwrap();
        assert!(matches!(
            service.on_timeout_message(Some(PeerId::random()), &payload),
            Verdict::Reject(_)
        ));

        let cert = kovanica_types::SkipCert {
            round: 3,
            timeouts: (0..3u16)
                .map(|v| signed_timeout(&signers[v as usize], v, 3, &genesis))
                .collect(),
        };
        let payload = bincode::serialize(&crate::TimeoutMessage::SkipCert(cert.clone())).unwrap();
        assert_eq!(
            service.on_timeout_message(Some(PeerId::random()), &payload),
            Verdict::Accept
        );
        match events.try_recv().expect("cert event") {
            NetworkEvent::SkipCertReceived { cert: got, .. } => assert_eq!(got, cert),
            other => panic!("unexpected event: {other:?}"),
        }

        let mut dup = cert;
        dup.timeouts.push(dup.timeouts[0].clone());
        let payload = bincode::serialize(&crate::TimeoutMessage::SkipCert(dup)).unwrap();
        assert!(matches!(
            service.on_timeout_message(Some(PeerId::random()), &payload),
            Verdict::Reject(_)
        ));
        assert!(events.try_recv().is_err());
    }

    /// B1d (PRO-B1d) regression: a vote cast in a later epoch must pass the
    /// gossip edge.
    ///
    /// The engine signs votes with epoch `leader_round / EPOCH_ROUNDS`
    /// (`vote_signing_ctx`), but the gossip edge used to verify with the
    /// mempool's boot-time epoch (0). After the first epoch boundary
    /// (`EPOCH_ROUNDS` rounds) every honest vote then failed with
    /// `BadSignature`, peers lost score, and validators banned each other.
    ///
    /// A vote at `leader_round = EPOCH_ROUNDS + 1` (epoch 1) signed with the
    /// canonical round-derived epoch MUST be accepted here.
    #[tokio::test]
    async fn b1d_jarvis_vote_after_epoch_boundary_passes_gossip_edge() {
        let (_dir, service, mut events, signers) = validating_service();
        let leader_round = kovanica_types::EPOCH_ROUNDS + 1;
        let mut vote = Vote {
            leader_round,
            leader_hash: Hash::new(b"leader-in-epoch-1"),
            voter: 1,
            signature: Signature([0; 64]),
        };
        let epoch_ctx = SigningContext {
            chain_id: test_support::TEST_CTX.chain_id,
            epoch: epoch_for_round(leader_round),
        };
        assert_ne!(
            epoch_ctx.epoch,
            test_support::TEST_CTX.epoch,
            "test must exercise a NON-zero epoch to be a regression"
        );
        vote.signature = kovanica_crypto::sign(&signers[1], &vote.signature_data(&epoch_ctx));
        let payload = bincode::serialize(&vote).expect("serialize vote");
        assert_eq!(
            service.on_vote_message(Some(PeerId::random()), &payload),
            Verdict::Accept,
            "a vote at leader_round = EPOCH_ROUNDS + 1 must pass the gossip edge"
        );
        match events.try_recv().expect("vote event emitted") {
            NetworkEvent::VoteReceived { vote: got, .. } => assert_eq!(got, vote),
            other => panic!("unexpected event: {other:?}"),
        }

        // Negative control: a vote signed with the boot-time epoch 0 at the
        // same leader round must still be rejected — the edge derives the
        // epoch from the round, it does not fall back to the mempool ctx.
        let mut stale = Vote {
            leader_round,
            leader_hash: Hash::new(b"leader-in-epoch-1"),
            voter: 1,
            signature: Signature([0; 64]),
        };
        stale.signature =
            kovanica_crypto::sign(&signers[1], &stale.signature_data(&test_support::TEST_CTX));
        let payload = bincode::serialize(&stale).expect("serialize vote");
        assert!(matches!(
            service.on_vote_message(Some(PeerId::random()), &payload),
            Verdict::Reject(_)
        ));
    }

    #[tokio::test]
    async fn forged_vote_is_rejected_and_not_delivered() {
        let (_dir, service, mut events, signers) = validating_service();
        // Signed by validator 0 but claiming to be validator 2.
        let mut vote = test_support::signed_vote(&signers[0], 2);
        vote.signature =
            kovanica_crypto::sign(&signers[0], &vote.signature_data(&test_support::TEST_CTX));
        let payload = bincode::serialize(&vote).expect("serialize vote");
        assert!(matches!(
            service.on_vote_message(Some(PeerId::random()), &payload),
            Verdict::Reject(_)
        ));
        // Unsigned vote.
        vote.signature = Signature([0; 64]);
        let payload = bincode::serialize(&vote).expect("serialize vote");
        assert!(matches!(
            service.on_vote_message(Some(PeerId::random()), &payload),
            Verdict::Reject(_)
        ));
        // Voter outside the committee.
        let outsider = test_support::signed_vote(&signers[0], 42);
        let payload = bincode::serialize(&outsider).expect("serialize vote");
        assert!(matches!(
            service.on_vote_message(Some(PeerId::random()), &payload),
            Verdict::Reject(_)
        ));
        assert!(events.try_recv().is_err(), "no vote may reach consensus");
    }

    #[tokio::test]
    async fn votes_and_blocks_are_not_forwarded_before_committee_is_known() {
        let (_dir, service) = test_service();
        let (signers, _) = test_support::committee(1);
        let vote = bincode::serialize(&test_support::signed_vote(&signers[0], 0)).unwrap();
        let block = bincode::serialize(&test_support::signed_block(&signers[0], 0)).unwrap();
        assert_eq!(
            service.on_vote_message(Some(PeerId::random()), &vote),
            Verdict::Ignore
        );
        assert_eq!(
            service.on_block_message(PeerId::random(), &block),
            Verdict::Ignore
        );
    }

    #[tokio::test]
    async fn signed_block_is_accepted_and_delivered() {
        let (_dir, service, mut events, signers) = validating_service();
        let block = test_support::signed_block(&signers[3], 3);
        let payload = bincode::serialize(&block).expect("serialize block");
        assert_eq!(
            service.on_block_message(PeerId::random(), &payload),
            Verdict::Accept
        );
        match events.try_recv().expect("block event emitted") {
            NetworkEvent::BlockReceived { block: got, .. } => assert_eq!(got, block),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn repeated_invalid_messages_ban_the_relaying_peer() {
        let (_dir, service, _events, _signers) = validating_service();
        let peer = PeerId::random();
        for _ in 0..INVALID_BLOCK_FAILURE_LIMIT - 1 {
            service.record_invalid_block_failure(peer, "test");
        }
        assert_eq!(
            lock(&service.invalid_block_failures).get(&peer).copied(),
            Some(INVALID_BLOCK_FAILURE_LIMIT - 1)
        );
        service.record_invalid_block_failure(peer, "test");
        // Banned: counter cleared.
        assert!(lock(&service.invalid_block_failures).get(&peer).is_none());
    }

    #[tokio::test]
    async fn block_sync_response_must_match_request_and_validate() {
        let (_dir, service, _events, signers) = validating_service();
        let block = test_support::signed_block(&signers[1], 1);
        let response = BlockSyncResponse::Block(block.clone());

        // Unsolicited.
        assert!(service.check_block_sync_response(None, &response).is_err());
        // Right block.
        let by_hash = BlockSyncRequest::ByHash(block.digest);
        assert!(service
            .check_block_sync_response(Some(&by_hash), &response)
            .is_ok());
        let by_slot = BlockSyncRequest::ByAuthorRound {
            author: 1,
            round: 1,
        };
        assert!(service
            .check_block_sync_response(Some(&by_slot), &response)
            .is_ok());
        // A different (valid) block than the one requested.
        let other = BlockSyncRequest::ByHash(Hash::new(b"other"));
        assert!(service
            .check_block_sync_response(Some(&other), &response)
            .is_err());
        // Requested block with tampered content (signature replayed).
        let mut tampered = block.clone();
        tampered.statements = vec![1];
        tampered.round = 9;
        let slot9 = BlockSyncRequest::ByAuthorRound {
            author: 1,
            round: 9,
        };
        assert!(service
            .check_block_sync_response(Some(&slot9), &BlockSyncResponse::Block(tampered))
            .is_err());
        // Oversized missing-blocks list.
        let flood = BlockSyncResponse::MissingBlocks(vec![Hash::zero(); MAX_MISSING_BLOCKS + 1]);
        assert!(service
            .check_block_sync_response(Some(&by_hash), &flood)
            .is_err());
        assert!(service
            .check_block_sync_response(Some(&by_hash), &BlockSyncResponse::NotFound)
            .is_ok());
    }

    #[tokio::test]
    async fn invalid_block_gossip_is_rejected_and_never_stored() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dag_storage = Storage::new(dir.path().join("dag.db")).expect("dag storage");
        let dag_store = Arc::new(DagStore::new(dag_storage).expect("dag store"));
        let mempool_storage =
            Arc::new(Storage::new(dir.path().join("mempool.db")).expect("mempool storage"));
        let mempool = Arc::new(Mempool::new(
            MempoolConfig::default(),
            mempool_storage,
            test_support::TEST_CTX,
        ));
        let (service, mut events) =
            NetworkService::new(NetworkConfig::default(), dag_store.clone(), mempool)
                .expect("service");
        let (_, keys) = test_support::committee(4);
        service.set_authority_keys(keys);

        // Structurally decodable, but invalid digest and signature.
        let block = sample_block();
        let payload = bincode::serialize(&block).expect("serialize block");
        assert!(matches!(
            service.on_block_message(PeerId::random(), &payload),
            Verdict::Reject(_)
        ));
        assert!(!dag_store.has_block(&block.digest).expect("query store"));
        assert!(
            events.try_recv().is_err(),
            "invalid block must not be announced"
        );
    }

    #[tokio::test]
    async fn valid_sync_request_reaches_the_caller() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dag_storage = Storage::new(dir.path().join("dag.db")).expect("dag storage");
        let mempool_storage =
            Arc::new(Storage::new(dir.path().join("mempool.db")).expect("mempool storage"));
        let dag_store = Arc::new(DagStore::new(dag_storage).expect("dag store"));
        let mempool = Arc::new(Mempool::new(
            MempoolConfig::default(),
            mempool_storage,
            test_support::TEST_CTX,
        ));
        let (service, mut events) =
            NetworkService::new(NetworkConfig::default(), dag_store, mempool).expect("service");

        let peer = PeerId::random();
        let payload = SyncRequest::new(4, 8).encode().expect("encodes");
        assert_eq!(
            service.on_sync_message(Some(peer), &payload),
            Verdict::Accept
        );

        match events.try_recv().expect("event emitted") {
            NetworkEvent::SyncRequest {
                peer: got,
                from_round,
                to_round,
            } => {
                assert_eq!(got, peer);
                assert_eq!(from_round, 4);
                assert_eq!(to_round, 8);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn peer_bookkeeping_enforces_max_peers() {
        let (_dir, service) = test_service();
        let shared_peer_count = service.peer_count_handle();
        let first = PeerId::random();

        service.on_peer_connected(first).expect("connect");
        assert_eq!(service.peer_count(), 1);
        assert_eq!(shared_peer_count.load(Ordering::Relaxed), 1);
        // Duplicate connection events do not double count.
        service.on_peer_connected(first).expect("reconnect");
        assert_eq!(service.peer_count(), 1);
        assert_eq!(shared_peer_count.load(Ordering::Relaxed), 1);

        service.on_peer_disconnected(first);
        assert_eq!(service.peer_count(), 0);
        assert_eq!(shared_peer_count.load(Ordering::Relaxed), 0);

        // Fill up to the configured limit, then the next peer must be rejected.
        let mut peers = Vec::new();
        for _ in 0..service.config.max_peers {
            let peer = PeerId::random();
            peers.push(peer);
            service.on_peer_connected(peer).expect("connect");
        }
        assert_eq!(service.peer_count(), service.config.max_peers);

        let overflow = PeerId::random();
        service.on_peer_connected(overflow).expect("reject");
        assert!(!service.connected_peers().contains(&overflow));
        assert_eq!(service.peer_count(), service.config.max_peers);

        for peer in peers {
            service.on_peer_disconnected(peer);
        }
        assert_eq!(service.peer_count(), 0);
    }

    #[tokio::test]
    async fn peer_status_snapshot_reports_tip_and_address_then_clears_on_disconnect() {
        let (_dir, service) = test_service();
        let peer = PeerId::random();
        let other = PeerId::random();

        service.on_peer_connected(peer).expect("connect");
        service.on_peer_connected(other).expect("connect");

        // Bookkeeping the status surface reads: one learned address and one
        // reported tip. Only connected peers are included.
        lock(&service.peer_addresses)
            .insert(peer, vec!["/ip4/127.0.0.1/tcp/8000".parse().unwrap()]);
        lock(&service.reported_tip).insert(peer, 42);

        let snapshot = service.peer_status_snapshot();
        assert_eq!(snapshot.len(), 2);
        // Deterministic order (sorted by peer id string).
        assert!(snapshot
            .windows(2)
            .all(|w| w[0].peer_id.to_string() <= w[1].peer_id.to_string()));

        let with_tip = snapshot
            .iter()
            .find(|status| status.peer_id == peer)
            .expect("peer present");
        assert_eq!(with_tip.reported_tip_round, Some(42));
        assert_eq!(
            with_tip.listen_addr.as_deref(),
            Some("/ip4/127.0.0.1/tcp/8000")
        );

        let without_tip = snapshot
            .iter()
            .find(|status| status.peer_id == other)
            .expect("other present");
        assert_eq!(without_tip.reported_tip_round, None);
        assert_eq!(without_tip.listen_addr, None);

        // Disconnect drops the peer (and its reported tip) from the snapshot.
        service.on_peer_disconnected(peer);
        let snapshot = service.peer_status_snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].peer_id, other);
        assert!(lock(&service.reported_tip).get(&peer).is_none());
    }

    #[tokio::test]
    async fn banning_a_peer_drops_its_reported_tip() {
        let (_dir, service) = test_service();
        let peer = PeerId::random();

        service.on_peer_connected(peer).expect("connect");
        lock(&service.reported_tip).insert(peer, 7);
        assert_eq!(lock(&service.reported_tip).get(&peer), Some(&7));

        service.ban_peer(peer);
        assert!(lock(&service.reported_tip).get(&peer).is_none());
    }

    #[tokio::test]
    async fn repeated_ping_failures_ban_a_peer() {
        let (_dir, service) = test_service();
        let peer = PeerId::random();

        for attempt in 0..PING_FAILURE_LIMIT {
            service
                .handle_ping_event(libp2p::ping::Event {
                    peer,
                    connection: libp2p::swarm::ConnectionId::new_unchecked(attempt as usize),
                    result: Err(libp2p::ping::Failure::Timeout),
                })
                .expect("ping failure handled");
        }

        // Once banned, both the failure counter and the address snapshot are gone.
        assert!(lock(&service.ping_failures).get(&peer).is_none());
        assert!(lock(&service.peer_addresses).get(&peer).is_none());

        // A later successful ping starts counting from scratch.
        service
            .handle_ping_event(libp2p::ping::Event {
                peer,
                connection: libp2p::swarm::ConnectionId::new_unchecked(0),
                result: Ok(std::time::Duration::from_millis(5)),
            })
            .expect("ping success handled");
        assert!(lock(&service.ping_failures).get(&peer).is_none());
    }

    // ---- block sync catch-up serving + retry/failover (#1, #2) ----

    /// A vote request is answered from the installed vote source, and an
    /// empty answer when no source is installed (RFC-009).
    #[tokio::test]
    async fn votes_for_round_are_served_from_the_vote_source() {
        let (_dir, service) = test_service();

        // Without a vote source the service answers with an empty list.
        assert_eq!(
            service.build_block_sync_response(&BlockSyncRequest::VotesForRound { round: 3 }),
            BlockSyncResponse::Votes {
                round: 3,
                votes: Vec::new()
            }
        );

        struct StubVoteSource {
            votes: Vec<Vote>,
        }

        impl VoteSource for StubVoteSource {
            fn votes_for_round(&self, round: Round) -> Result<Vec<Vote>, String> {
                Ok(self
                    .votes
                    .iter()
                    .filter(|vote| vote.leader_round == round)
                    .cloned()
                    .collect())
            }
        }

        let vote = Vote {
            leader_round: 3,
            leader_hash: Hash::new("leader"),
            voter: 1,
            signature: Signature([7u8; 64]),
        };
        service.set_vote_source(Arc::new(StubVoteSource {
            votes: vec![vote.clone()],
        }));

        match service.build_block_sync_response(&BlockSyncRequest::VotesForRound { round: 3 }) {
            BlockSyncResponse::Votes { round, votes } => {
                assert_eq!(round, 3);
                assert_eq!(votes, vec![vote]);
            }
            other => panic!("expected a votes response, got {other:?}"),
        }

        // A round the source holds nothing for is answered with an empty list.
        assert_eq!(
            service.build_block_sync_response(&BlockSyncRequest::VotesForRound { round: 9 }),
            BlockSyncResponse::Votes {
                round: 9,
                votes: Vec::new()
            }
        );
    }

    /// A vote response that does not answer the request it was sent for is
    /// rejected by the edge checks.
    #[tokio::test]
    async fn votes_response_must_answer_the_vote_request() {
        let (_dir, service) = test_service();
        let votes = vec![Vote {
            leader_round: 3,
            leader_hash: Hash::new("leader"),
            voter: 1,
            signature: Signature([7u8; 64]),
        }];

        // The round does not match the request.
        let response = BlockSyncResponse::Votes {
            round: 9,
            votes: votes.clone(),
        };
        assert!(service
            .check_block_sync_response(
                Some(&BlockSyncRequest::VotesForRound { round: 3 }),
                &response,
            )
            .is_err());

        // The response does not answer a vote request at all.
        let response = BlockSyncResponse::Votes {
            round: 3,
            votes: Vec::new(),
        };
        assert!(service
            .check_block_sync_response(Some(&BlockSyncRequest::Status), &response)
            .is_err());

        // The matching response passes.
        let response = BlockSyncResponse::Votes {
            round: 3,
            votes: votes.clone(),
        };
        service
            .check_block_sync_response(
                Some(&BlockSyncRequest::VotesForRound { round: 3 }),
                &response,
            )
            .expect("a matching vote response passes the edge checks");

        // Too many votes is refused.
        let response = BlockSyncResponse::Votes {
            round: 3,
            votes: (0..=BlockSyncResponse::MAX_VOTES_PER_ROUND as u16)
                .map(|voter| Vote {
                    leader_round: 3,
                    leader_hash: Hash::new("leader"),
                    voter,
                    signature: Signature([0u8; 64]),
                })
                .collect(),
        };
        assert!(service
            .check_block_sync_response(
                Some(&BlockSyncRequest::VotesForRound { round: 3 }),
                &response,
            )
            .is_err());
    }

    /// Catch-up responses are bounded and the DAG tip is reported honestly.
    #[tokio::test]
    async fn catch_up_serving_is_bounded_and_reports_the_tip() {
        let (dir, service) = test_service();

        // Empty DAG: tip 0 and nothing to serve.
        assert_eq!(
            service.build_block_sync_response(&BlockSyncRequest::Status),
            BlockSyncResponse::Status { tip_round: 0 }
        );
        assert_eq!(
            service.build_block_sync_response(&BlockSyncRequest::RoundRange { from: 1, to: 2 }),
            BlockSyncResponse::InvalidRequest
        );

        // 25 rounds x 21 authors = 525 blocks, above the 512-hash response cap.
        for round in 1..=25u64 {
            for author in 0..21u16 {
                let mut block = sample_block();
                block.round = round;
                block.author = author;
                block.digest = Hash::new(format!("r{round}a{author}"));
                service.dag_store.put_block(&block).expect("store block");
            }
        }
        assert_eq!(
            service.build_block_sync_response(&BlockSyncRequest::Status),
            BlockSyncResponse::Status { tip_round: 25 }
        );

        match service.build_block_sync_response(&BlockSyncRequest::RoundRange { from: 1, to: 25 }) {
            BlockSyncResponse::RoundHashes {
                up_to_round,
                hashes,
            } => {
                assert_eq!(up_to_round, 24, "coverage stops before the hash cap");
                assert_eq!(hashes.len(), 24 * 21);
                assert!(hashes.len() <= BlockSyncResponse::MAX_RANGE_HASHES);
            }
            other => panic!("expected truncated round hashes, got {other:?}"),
        }

        // Inverted and over-wide windows are refused, not served partially.
        assert_eq!(
            service.build_block_sync_response(&BlockSyncRequest::RoundRange { from: 9, to: 2 }),
            BlockSyncResponse::InvalidRequest
        );
        assert_eq!(
            service.build_block_sync_response(&BlockSyncRequest::RoundRange {
                from: 1,
                to: 1 + BlockSyncRequest::MAX_RANGE_ROUNDS,
            }),
            BlockSyncResponse::InvalidRequest
        );

        // A window that straddles the tip is clamped to the tip, and one
        // entirely past it is refused.
        match service.build_block_sync_response(&BlockSyncRequest::RoundRange { from: 20, to: 30 })
        {
            BlockSyncResponse::RoundHashes {
                up_to_round,
                hashes,
            } => {
                assert_eq!(up_to_round, 25);
                assert_eq!(hashes.len(), 6 * 21);
            }
            other => panic!("expected a clamped range, got {other:?}"),
        }
        assert_eq!(
            service.build_block_sync_response(&BlockSyncRequest::RoundRange { from: 26, to: 27 }),
            BlockSyncResponse::InvalidRequest
        );

        let _ = dir;
    }

    /// A catch-up response must answer the request that was actually sent.
    #[tokio::test]
    async fn catch_up_edge_checks_reject_mismatched_responses() {
        let (_dir, service) = test_service();
        let range = BlockSyncRequest::RoundRange { from: 5, to: 9 };
        let status = BlockSyncRequest::Status;

        assert!(service
            .check_block_sync_response(
                Some(&range),
                &BlockSyncResponse::RoundHashes {
                    up_to_round: 9,
                    hashes: Vec::new(),
                },
            )
            .is_ok());
        // Coverage round outside the requested window.
        assert!(service
            .check_block_sync_response(
                Some(&range),
                &BlockSyncResponse::RoundHashes {
                    up_to_round: 12,
                    hashes: Vec::new(),
                },
            )
            .is_err());
        // Above the hash cap.
        assert!(service
            .check_block_sync_response(
                Some(&range),
                &BlockSyncResponse::RoundHashes {
                    up_to_round: 9,
                    hashes: vec![Hash::zero(); BlockSyncResponse::MAX_RANGE_HASHES + 1],
                },
            )
            .is_err());
        // Round hashes never answer a non-range request.
        assert!(service
            .check_block_sync_response(
                Some(&status),
                &BlockSyncResponse::RoundHashes {
                    up_to_round: 0,
                    hashes: Vec::new(),
                },
            )
            .is_err());
        // Status only answers a status request.
        assert!(service
            .check_block_sync_response(Some(&range), &BlockSyncResponse::Status { tip_round: 3 })
            .is_err());
        assert!(service
            .check_block_sync_response(Some(&status), &BlockSyncResponse::Status { tip_round: 3 })
            .is_ok());
        // A single block never answers a status/range request.
        let block = BlockSyncResponse::Block(sample_block());
        assert!(service
            .check_block_sync_response(Some(&status), &block)
            .is_err());
        assert!(service
            .check_block_sync_response(Some(&range), &block)
            .is_err());
    }

    fn outbound_failure(
        peer: PeerId,
        request_id: request_response::OutboundRequestId,
    ) -> request_response::Event<BlockSyncRequest, BlockSyncResponse> {
        request_response::Event::OutboundFailure {
            peer,
            request_id,
            error: request_response::OutboundFailure::Timeout,
            connection_id: test_id(1),
        }
    }

    /// A failed request retries once on the same peer, once on an alternate
    /// peer, then gives up as NotFound — never an unbounded retry loop.
    #[tokio::test]
    async fn failed_block_sync_request_retries_fails_over_then_gives_up() {
        let (_dir, service, mut events, _signers) = validating_service();
        let failed_peer = PeerId::random();
        let alternate_peer = PeerId::random();
        lock(&service.connected).insert(failed_peer);
        lock(&service.connected).insert(alternate_peer);

        let first_id = service
            .request_block_sync(failed_peer, BlockSyncRequest::ByHash(Hash::new("b")))
            .expect("request queued");
        assert_eq!(
            lock(&service.pending_block_requests)
                .get(&first_id)
                .map(|pending| (pending.peer, pending.attempts)),
            Some((failed_peer, 1))
        );

        // First failure: one retry on the same (still connected) peer.
        service
            .handle_request_response_event(outbound_failure(failed_peer, first_id))
            .expect("handled");
        let (second_id, retry) = {
            let pending = lock(&service.pending_block_requests);
            assert_eq!(pending.len(), 1, "the retry replaced the failed request");
            let (&id, entry) = pending.iter().next().expect("retry pending");
            (id, (entry.peer, entry.attempts))
        };
        assert_eq!(retry, (failed_peer, 2));

        // Second failure: fail over to exactly one alternate connected peer.
        service
            .handle_request_response_event(outbound_failure(failed_peer, second_id))
            .expect("handled");
        let (third_id, failover) = {
            let pending = lock(&service.pending_block_requests);
            assert_eq!(pending.len(), 1, "the failover replaced the retry");
            let (&id, entry) = pending.iter().next().expect("failover pending");
            (id, (entry.peer, entry.attempts))
        };
        assert_eq!(failover, (alternate_peer, 3));

        // Third failure: budget exhausted, reported as NotFound (not a bogus
        // InvalidRequest) and no request is left pending.
        service
            .handle_request_response_event(outbound_failure(alternate_peer, third_id))
            .expect("handled");
        assert!(lock(&service.pending_block_requests).is_empty());
        match events.try_recv().expect("give-up event emitted") {
            NetworkEvent::BlockSyncResponse {
                peer,
                response: BlockSyncResponse::NotFound,
                ..
            } => assert_eq!(peer, alternate_peer),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    /// A failure for a request we never sent (or already resolved) is ignored.
    #[tokio::test]
    async fn failure_for_an_unknown_request_is_ignored() {
        let (_dir, service, mut events, _signers) = validating_service();
        let peer = PeerId::random();
        lock(&service.connected).insert(peer);

        // Fabricate a failure referencing an id we never issued: not in map.
        let unknown = service
            .request_block_sync(peer, BlockSyncRequest::Status)
            .expect("request queued");
        lock(&service.pending_block_requests).remove(&unknown);

        service
            .handle_request_response_event(outbound_failure(peer, unknown))
            .expect("handled");
        assert!(lock(&service.pending_block_requests).is_empty());
        assert!(
            events.try_recv().is_err(),
            "no event for an unknown request"
        );
    }

    fn response_event(
        peer: PeerId,
        request_id: request_response::OutboundRequestId,
        response: BlockSyncResponse,
    ) -> request_response::Event<BlockSyncRequest, BlockSyncResponse> {
        request_response::Event::Message {
            peer,
            connection_id: test_id(1),
            message: request_response::Message::Response {
                request_id,
                response,
            },
        }
    }

    /// A response to a request we no longer track (evicted at the cap, or a
    /// late reply) must never count against the peer (audit HIGH-2a).
    #[tokio::test]
    async fn response_to_unknown_request_does_not_increment_ban_counter() {
        let (_dir, service, mut events, _signers) = validating_service();
        let peer = PeerId::random();
        lock(&service.connected).insert(peer);

        for i in 0..(INVALID_BLOCK_FAILURE_LIMIT + 3) {
            let id = service
                .request_block_sync(peer, BlockSyncRequest::Status)
                .expect("request queued");
            lock(&service.pending_block_requests).remove(&id);
            service
                .handle_request_response_event(response_event(
                    peer,
                    id,
                    BlockSyncResponse::Status {
                        tip_round: u64::from(i),
                    },
                ))
                .expect("handled");
        }
        assert!(
            lock(&service.invalid_block_failures).get(&peer).is_none(),
            "unknown responses must never be counted against a peer"
        );
        assert!(
            events.try_recv().is_err(),
            "unknown responses are dropped, not delivered"
        );
    }

    /// At the pending-request cap the oldest entry is evicted (not the whole
    /// map), and a late response to the evicted id is ignored (audit HIGH-2b).
    #[tokio::test]
    async fn pending_request_cap_evicts_the_oldest_without_banning() {
        let (_dir, service, _events, _signers) = validating_service();
        let peer = PeerId::random();
        lock(&service.connected).insert(peer);

        let mut ids = Vec::with_capacity(MAX_PENDING_BLOCK_REQUESTS + 1);
        for _ in 0..MAX_PENDING_BLOCK_REQUESTS {
            ids.push(
                service
                    .request_block_sync(peer, BlockSyncRequest::Status)
                    .expect("queued"),
            );
        }
        let newest = service
            .request_block_sync(peer, BlockSyncRequest::Status)
            .expect("queued");
        {
            let pending = lock(&service.pending_block_requests);
            assert_eq!(pending.len(), MAX_PENDING_BLOCK_REQUESTS);
            assert!(!pending.contains_key(&ids[0]), "oldest request evicted");
            assert!(pending.contains_key(&newest), "newest request tracked");
            assert!(pending.contains_key(&ids[ids.len() - 1]));
        }
        assert!(lock(&service.invalid_block_failures).get(&peer).is_none());

        // A late response to the evicted id is ignored without penalty.
        service
            .handle_request_response_event(response_event(
                peer,
                ids[0],
                BlockSyncResponse::Status { tip_round: 1 },
            ))
            .expect("handled");
        assert!(lock(&service.invalid_block_failures).get(&peer).is_none());
    }

    /// A burst larger than the cap (two peers, repeated full 512-hash windows)
    /// completes with no peer banned (audit HIGH-2c).
    #[tokio::test]
    async fn catch_up_burst_over_cap_bans_no_peer() {
        let (_dir, service, _events, _signers) = validating_service();
        let first = PeerId::random();
        let second = PeerId::random();
        lock(&service.connected).insert(first);
        lock(&service.connected).insert(second);

        // Two peers each firing a full 512-hash catch-up window plus a range
        // request, repeated past the cap so eviction must kick in.
        let mut all_ids = Vec::new();
        for round in 0..9u32 {
            for peer in [first, second] {
                all_ids.push(
                    service
                        .request_block_sync(peer, BlockSyncRequest::RoundRange { from: 0, to: 31 })
                        .expect("queued"),
                );
                for i in 0..BlockSyncResponse::MAX_RANGE_HASHES {
                    all_ids.push(
                        service
                            .request_block_sync(
                                peer,
                                BlockSyncRequest::ByHash(Hash::new(format!("r{round}i{i}"))),
                            )
                            .expect("queued"),
                    );
                }
            }
        }
        assert!(all_ids.len() > MAX_PENDING_BLOCK_REQUESTS);

        let live: HashSet<_> = lock(&service.pending_block_requests)
            .keys()
            .copied()
            .collect();
        let evicted: Vec<_> = all_ids
            .into_iter()
            .filter(|id| !live.contains(id))
            .collect();
        assert!(
            !evicted.is_empty(),
            "the burst must have exercised eviction"
        );

        // Deliver a late response for every evicted id: none may ban a peer.
        for id in evicted {
            service
                .handle_request_response_event(response_event(
                    first,
                    id,
                    BlockSyncResponse::Status { tip_round: 3 },
                ))
                .expect("handled");
        }
        assert!(lock(&service.invalid_block_failures).get(&first).is_none());
        assert!(lock(&service.invalid_block_failures).get(&second).is_none());
        assert_eq!(
            lock(&service.pending_block_requests).len(),
            MAX_PENDING_BLOCK_REQUESTS
        );
    }

    /// Deterministic export source for the state sync handler tests.
    struct MockSnapshotSource {
        snapshot: Option<ExportedSnapshot>,
        fail: bool,
        exports: std::sync::atomic::AtomicUsize,
    }

    impl MockSnapshotSource {
        fn with_bytes(bytes: Vec<u8>) -> Arc<Self> {
            Arc::new(Self {
                snapshot: Some(ExportedSnapshot {
                    height: 77,
                    state_root: [9u8; 32],
                    bytes,
                }),
                fail: false,
                exports: std::sync::atomic::AtomicUsize::new(0),
            })
        }
    }

    impl StateSnapshotSource for MockSnapshotSource {
        fn export_snapshot(
            &self,
            _target_height: Option<u64>,
        ) -> Result<Option<ExportedSnapshot>, String> {
            self.exports.fetch_add(1, Ordering::Relaxed);
            if self.fail {
                return Err("export failed".to_string());
            }
            Ok(self.snapshot.clone())
        }
    }

    #[test]
    fn state_sync_without_source_is_not_found() {
        let (_dir, service) = test_service();
        let response = service.build_state_sync_response(&StateSyncRequest::latest());
        assert_eq!(response, StateSyncResponse::NotFound);
    }

    #[test]
    fn state_sync_export_failure_is_not_found() {
        let (_dir, service) = test_service();
        service.set_state_snapshot_source(Arc::new(MockSnapshotSource {
            snapshot: None,
            fail: true,
            exports: std::sync::atomic::AtomicUsize::new(0),
        }));
        let response = service.build_state_sync_response(&StateSyncRequest::latest());
        assert_eq!(response, StateSyncResponse::NotFound);
    }

    #[test]
    fn state_sync_serves_bounded_chunks() {
        let (_dir, service) = test_service();
        let total = MAX_STATE_SYNC_CHUNK_BYTES * 2 + 7;
        let bytes: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let source = MockSnapshotSource::with_bytes(bytes.clone());
        service.set_state_snapshot_source(source.clone());

        // First chunk: exactly the cap, metadata propagated.
        let first = service.build_state_sync_response(&StateSyncRequest::latest());
        let StateSyncResponse::Chunk(first) = first else {
            panic!("expected a chunk, got {first}");
        };
        assert_eq!(first.offset, 0);
        assert_eq!(first.data.len(), MAX_STATE_SYNC_CHUNK_BYTES);
        assert_eq!(first.total_len, total as u64);
        assert_eq!(first.height, 77);
        assert_eq!(first.state_root, [9u8; 32]);
        assert_eq!(&first.data[..], &bytes[..MAX_STATE_SYNC_CHUNK_BYTES]);

        // Final partial chunk.
        let last = service.build_state_sync_response(&StateSyncRequest::at_height_from(
            77,
            (MAX_STATE_SYNC_CHUNK_BYTES * 2) as u64,
        ));
        let StateSyncResponse::Chunk(last) = last else {
            panic!("expected a chunk, got {last}");
        };
        assert_eq!(last.offset, (MAX_STATE_SYNC_CHUNK_BYTES * 2) as u64);
        assert_eq!(last.data.len(), 7);

        // An offset at or past the end cannot be served.
        assert_eq!(
            service.build_state_sync_response(&StateSyncRequest::at_height_from(77, total as u64)),
            StateSyncResponse::InvalidRequest
        );

        // Two chunk requests must not re-serialize the whole state.
        assert_eq!(source.exports.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn state_sync_rebuilds_export_when_target_height_changes() {
        let (_dir, service) = test_service();
        let source = MockSnapshotSource::with_bytes(vec![1u8; 16]);
        service.set_state_snapshot_source(source.clone());
        let _ = service.build_state_sync_response(&StateSyncRequest::latest());
        // A specific height that the cached (latest) export does not match
        // forces a fresh export.
        let _ = service.build_state_sync_response(&StateSyncRequest::at_height(12345));
        assert_eq!(source.exports.load(Ordering::Relaxed), 2);
    }
}
