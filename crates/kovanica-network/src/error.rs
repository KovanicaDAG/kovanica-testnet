//! Errors surfaced by the networking layer.

use libp2p::PeerId;
use thiserror::Error;

/// Errors that can occur in network operations.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// Transport-level error.
    #[error("Transport error: {0}")]
    Transport(String),
    /// Swarm-level error.
    #[error("Swarm error: {0}")]
    Swarm(String),
    /// Gossipsub error.
    #[error("Gossipsub error: {0}")]
    Gossipsub(String),
    /// Kademlia error.
    #[error("Kademlia error: {0}")]
    Kademlia(String),
    /// Peer not found.
    #[error("Peer not found: {0}")]
    PeerNotFound(PeerId),
    /// Invalid network configuration (e.g. a malformed bootstrap address).
    #[error("Configuration error: {0}")]
    Config(String),
    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    /// DAG store error.
    #[error("DAG store error: {0}")]
    DagStore(#[from] kovanica_dag::DagStoreError),
    /// Mempool error.
    #[error("Mempool error: {0}")]
    Mempool(#[from] kovanica_mempool::MempoolError),
    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
