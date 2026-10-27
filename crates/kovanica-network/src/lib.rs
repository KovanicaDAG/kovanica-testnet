//! P2P networking layer (libp2p).
//!
//! The crate runs a [`libp2p::Swarm`] composed of gossipsub (topics `blocks`,
//! `transactions`, `votes`, `sync`, `state_sync` and `seals`), Kademlia peer
//! discovery, ping-based liveness and identify, wrapped in [`NetworkService`].
//! Every protocol id and topic is scoped to one chain ([`NetworkId`]). Swarm activity is
//! translated into a stream of [`NetworkEvent`]s for the rest of the node.

#![deny(unsafe_code)]
#![allow(missing_docs)]
#![allow(clippy::result_large_err)]
#![allow(clippy::large_enum_variant)]

mod behaviour;
mod block_sync;
mod error;
pub mod identity;
pub mod network_id;
pub mod scoring;
mod service;
mod state_sync;
mod sync;
pub mod topics;
pub mod validation;

pub use block_sync::{
    BlockSyncRequest, BlockSyncRequestEvent, BlockSyncResponse, BlockSyncResponseEvent, VoteSource,
    BLOCK_SYNC_PROTOCOL,
};
pub use network_id::NetworkId;

/// Identify protocol version suffix; the advertised version is
/// [`NetworkId::identify_version`].
pub const IDENTIFY_VERSION: &str = "1.0.0";

/// Kademlia protocol suffix; the full id is `NetworkId::protocol(KAD_PROTOCOL)`.
/// Peers speaking another chain's id are ignored by the DHT.
pub const KAD_PROTOCOL: &str = "kad/1.0.0";
pub use error::NetworkError;
pub use scoring::PeerScoringConfig;
pub use service::{NetworkService, PeerStatus};
pub use state_sync::{
    ExportedSnapshot, SnapshotChunk, StateSnapshotSource, StateSyncCodec, StateSyncRequest,
    StateSyncResponse, MAX_STATE_SYNC_CHUNK_BYTES, MAX_STATE_SYNC_SNAPSHOT_BYTES,
    STATE_SYNC_PROTOCOL,
};
pub use sync::SyncRequest;
pub use validation::{
    admit_seal, AuthorityKeys, Ed25519VoteVerifier, LocalHeaderHash, Rejection, SealAdmission,
    SigError, VoteVerifier,
};

/// Payload of the [`topics::TIMEOUTS`] gossip topic (PRO-40 (b)).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TimeoutMessage {
    /// One validator's timeout for a leader slot.
    Timeout(kovanica_types::Timeout),
    /// A quorum of timeouts for one leader slot.
    SkipCert(kovanica_types::SkipCert),
}

use kovanica_types::{
    block::StatementBlock, transaction::Transaction, Round, SealAnnouncement, Vote,
};
use std::time::Duration;

// Re-export libp2p types for downstream crates
pub use libp2p::{Multiaddr, PeerId};

/// Network event emitted by the networking layer.
#[derive(Debug)]
pub enum NetworkEvent {
    /// A new block was received.
    ///
    /// Only emitted after the block passed edge validation (digest, merkle
    /// root, committee author, signature; see [`validation::verify_block`]).
    /// `peer` is the gossip propagation source (used to fetch missing
    /// parents from the peer that delivered the block).
    BlockReceived { peer: PeerId, block: StatementBlock },
    /// A new transaction was received.
    TransactionReceived(Transaction),
    /// A new peer was connected.
    PeerConnected(PeerId),
    /// A peer was disconnected.
    PeerDisconnected(PeerId),
    /// A new peer was discovered.
    PeerDiscovered(PeerId, Multiaddr),
    /// Sync request received (gossipsub-based).
    SyncRequest {
        /// Peer that issued the request.
        peer: PeerId,
        /// First round of the requested range.
        from_round: Round,
        /// Last round of the requested range.
        to_round: Round,
    },
    /// Block sync response received (request-response).
    BlockSyncResponse {
        /// Peer that sent the response.
        peer: PeerId,
        /// The request ID this response corresponds to.
        request_id: libp2p::request_response::OutboundRequestId,
        /// The response.
        response: BlockSyncResponse,
    },
    /// State sync response received (request-response).
    StateSyncResponse {
        /// Peer that sent the response.
        peer: PeerId,
        /// The request ID this response corresponds to.
        request_id: libp2p::request_response::OutboundRequestId,
        /// The response.
        response: StateSyncResponse,
    },
    /// A consensus vote was received.
    ///
    /// Only emitted after the vote passed edge validation: the voter is a
    /// committee member and the signature verifies under its committee key
    /// (see [`validation::verify_vote`]).
    VoteReceived {
        /// Peer that sent the vote.
        peer: PeerId,
        /// The vote.
        vote: Vote,
    },
    /// A leader-slot timeout whose signer is a committee member and whose
    /// signature verifies for this chain and genesis (PRO-40 (b)).
    TimeoutReceived {
        /// Peer that sent the timeout.
        peer: PeerId,
        /// The timeout.
        timeout: kovanica_types::Timeout,
    },
    /// A skip certificate that passed the edge checks
    /// ([`validation::verify_skip_cert`]); consensus checks the quorum.
    SkipCertReceived {
        /// Peer that sent the certificate.
        peer: PeerId,
        /// The certificate.
        cert: kovanica_types::SkipCert,
    },
    /// A post-execution commit seal whose signature verified and whose
    /// header hash matches the header this node already executed.
    ///
    /// Seals that arrive before local execution are not emitted. Consensus
    /// does not consume this event.
    SealReceived {
        /// Peer that relayed the seal.
        peer: PeerId,
        /// Header plus one validator signature.
        announcement: SealAnnouncement,
    },
}

/// Network configuration.
#[derive(Clone, Debug)]
pub struct NetworkConfig {
    /// Listening addresses.
    pub listen_addrs: Vec<Multiaddr>,
    /// Bootstrap nodes for initial peer discovery.
    pub bootstrap_nodes: Vec<Multiaddr>,
    /// Maximum number of peers.
    pub max_peers: usize,
    /// Ping interval.
    pub ping_interval: Duration,
    /// File holding the persistent libp2p node identity (transport key, not
    /// the validator key). Created with mode `0600` on first start. `None`
    /// uses a fresh identity per process (tests).
    pub node_key_path: Option<std::path::PathBuf>,
    /// Gossipsub peer scoring (on by default, see [`PeerScoringConfig`]).
    pub peer_scoring: PeerScoringConfig,
    /// Chain id + genesis digest bound into every protocol id and topic.
    pub network_id: NetworkId,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        // No bootstrap nodes are hard-coded: kovanica must never reference another
        // project's infrastructure. Seeds are supplied at deploy time from
        // kovanica-native DNS names (TBD before the public testnet launch) via
        // `NetworkConfig::bootstrap_nodes` / `KOVANICA_BOOTNODES`, together with the
        // seed's real libp2p peer id in the `/p2p/` component.
        Self {
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/8000"
                .parse()
                .expect("valid listen multiaddr")],
            bootstrap_nodes: Vec::new(),
            max_peers: 50,
            ping_interval: Duration::from_secs(10),
            node_key_path: None,
            peer_scoring: PeerScoringConfig::default(),
            network_id: NetworkId::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_parses_without_panicking() {
        let config = NetworkConfig::default();
        assert_eq!(config.listen_addrs.len(), 1);
        assert_eq!(config.listen_addrs[0].to_string(), "/ip4/0.0.0.0/tcp/8000");
        assert_eq!(config.bootstrap_nodes.len(), 0);
        assert_eq!(config.max_peers, 50);
        assert_eq!(config.ping_interval, Duration::from_secs(10));
    }

    #[test]
    fn network_events_carry_their_payloads() {
        let peer = PeerId::random();
        let event = NetworkEvent::PeerDiscovered(
            peer,
            "/ip4/127.0.0.1/tcp/9000".parse().expect("valid multiaddr"),
        );
        match event {
            NetworkEvent::PeerDiscovered(seen, addr) => {
                assert_eq!(seen, peer);
                assert_eq!(addr.to_string(), "/ip4/127.0.0.1/tcp/9000");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
}
