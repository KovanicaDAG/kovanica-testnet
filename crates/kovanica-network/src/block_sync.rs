//! Block sync request-response protocol (`/kovanica/<chain tag>/block-sync/1.1.0`).
//!
//! Uses libp2p's request-response behaviour to fetch blocks by hash or by
//! (author, round) pair, plus two bounded catch-up messages:
//!
//! * `Status` asks a peer for its current DAG tip round. The answer is only a
//!   *trigger* to start fetching; it is never trusted for validation.
//! * `RoundRange` asks for the block hashes of a bounded window of rounds so
//!   a node that is behind can fetch the missing range (each hash is then
//!   re-fetched via `ByHash` and validated as usual).
//!
//! All variants are appended after the original ones, so the encoding of the
//! pre-existing variants is unchanged.
//!
//! # Compatibility
//!
//! `Status` and `RoundRange` came with `1.1.0`. The `1.0.0` fallback name was
//! removed with the chain-4 network separation: the protocol id is now
//! `/kovanica/<chain tag>/block-sync/1.1.0` (see [`crate::network_id`]), and
//! a peer of another chain, or a pre-chain-4 build, cannot negotiate it.

use futures::{AsyncReadExt, AsyncWriteExt};
use kovanica_types::{block::StatementBlock, hash::Hash, AuthorityIndex, Round, Vote};
use libp2p::request_response::{OutboundRequestId, ProtocolSupport, ResponseChannel};
use serde::{Deserialize, Serialize};

/// Protocol suffix for block sync request-response. The id on the wire is
/// `/kovanica/<chain tag>/block-sync/1.1.0` ([`crate::NetworkId::protocol`]).
///
/// `1.1.0` has the `Status`/`RoundRange` catch-up messages. The
/// chain-independent `/kovanica/block-sync/1.0.0` fallback was removed with
/// the chain-4 network separation: it let any chain's peer sync from us.
pub const BLOCK_SYNC_PROTOCOL: &str = "block-sync/1.1.0";

/// Maximum response size (1 MiB): one block, same cap as a gossip frame.
pub const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

/// Maximum request size. Requests are a hash or an (author, round) pair, so
/// anything larger than this is garbage.
pub const MAX_REQUEST_SIZE: usize = 1024;

/// Read the rest of a request-response stream, failing once more than
/// `limit` bytes arrive instead of buffering an arbitrarily large message
/// from a hostile peer.
pub(crate) async fn read_bounded<T>(io: &mut T, limit: usize) -> std::io::Result<Vec<u8>>
where
    T: AsyncReadExt + Unpin + Send,
{
    let mut buf = Vec::new();
    // Read one byte past the limit so "exactly at the limit" is accepted and
    // "over the limit" is detected without reading the whole stream.
    io.take(limit as u64 + 1).read_to_end(&mut buf).await?;
    if buf.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("message exceeds {limit} byte limit"),
        ));
    }
    Ok(buf)
}

/// Block sync request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockSyncRequest {
    /// Request by block hash.
    ByHash(Hash),
    /// Request by author and round.
    ByAuthorRound {
        author: AuthorityIndex,
        round: Round,
    },
    /// Ask for the peer's current DAG tip round (proactive catch-up trigger).
    Status,
    /// Request the block hashes of rounds `from..=to` (inclusive), bounded by
    /// [`BlockSyncRequest::MAX_RANGE_ROUNDS`] rounds per request.
    RoundRange {
        /// First round of the window (inclusive).
        from: Round,
        /// Last round of the window (inclusive).
        to: Round,
    },
    /// Request the votes cast for one leader round.
    ///
    /// A node that joins a running network syncs leader *blocks* but the votes
    /// for those rounds were cast before it connected and are not replayed by
    /// gossipsub. Without the votes the requester can never reach a quorum for
    /// the leader it synced, and the commit walk stalls at that round
    /// (`docs/rfcs/RFC-009-VOTE-TRANSFER-OVER-BLOCK-SYNC.md`).
    VotesForRound {
        /// The leader round whose votes are requested.
        round: Round,
    },
}

impl BlockSyncRequest {
    /// Maximum number of rounds covered by one [`BlockSyncRequest::RoundRange`]
    /// window. Bounds the storage reads a single request can cost the peer.
    pub const MAX_RANGE_ROUNDS: Round = 32;
}

/// Block sync response — includes missing blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockSyncResponse {
    /// The requested block.
    Block(StatementBlock),
    /// Block not found.
    NotFound,
    /// Request invalid.
    InvalidRequest,
    /// List of missing parent blocks required before the requested block.
    MissingBlocks(Vec<Hash>),
    /// Block hashes for rounds `..=up_to_round` in ascending round order,
    /// bounded by [`BlockSyncResponse::MAX_RANGE_HASHES`] hashes.
    ///
    /// `up_to_round` may be lower than the requested window end when the hash
    /// cap was reached; it is the round the requester continues from.
    RoundHashes {
        /// Highest round fully covered by `hashes`.
        up_to_round: Round,
        /// Block digests, grouped by ascending round.
        hashes: Vec<Hash>,
    },
    /// The responder's current DAG tip round (catch-up trigger only).
    Status {
        /// Advertised tip round; never trusted for validation.
        tip_round: Round,
    },
    /// The votes cast for one leader round.
    ///
    /// The responder serves these from its durable vote store, so a peer that
    /// has restarted can still hand a joining node the evidence for the rounds
    /// it already decided. Every vote is signed by its voter and is verified
    /// by the requester against the committee before it is counted, so a peer
    /// cannot make the requester accept a different leader.
    Votes {
        /// The leader round these votes belong to.
        round: Round,
        /// The votes for that round, bounded by
        /// [`BlockSyncResponse::MAX_VOTES_PER_ROUND`].
        votes: Vec<Vote>,
    },
}

impl BlockSyncResponse {
    /// Maximum number of hashes in one [`BlockSyncResponse::RoundHashes`]
    /// response (bounds the response size well under the 1 MiB frame cap).
    pub const MAX_RANGE_HASHES: usize = 512;

    /// Maximum number of votes in one [`BlockSyncResponse::Votes`] response.
    ///
    /// A committee has at most `MAX_ACTIVE_VALIDATORS` members, so this is a
    /// generous bound; it exists so a hostile or buggy peer cannot inflate one
    /// response past the frame cap.
    pub const MAX_VOTES_PER_ROUND: usize = 64;
}

impl std::fmt::Display for BlockSyncResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockSyncResponse::Block(_) => write!(f, "Block"),
            BlockSyncResponse::NotFound => write!(f, "NotFound"),
            BlockSyncResponse::InvalidRequest => write!(f, "InvalidRequest"),
            BlockSyncResponse::MissingBlocks(_) => write!(f, "MissingBlocks"),
            BlockSyncResponse::RoundHashes { up_to_round, .. } => {
                write!(f, "RoundHashes(up_to={up_to_round})")
            }
            BlockSyncResponse::Status { tip_round } => write!(f, "Status(tip={tip_round})"),
            BlockSyncResponse::Votes { round, votes } => {
                write!(f, "Votes(round={round}, n={})", votes.len())
            }
        }
    }
}

/// Export side of the vote-transfer part of the block-sync protocol.
///
/// Implemented by the node over its durable vote store and injected into
/// [`crate::NetworkService`] via [`crate::NetworkService::set_vote_source`].
///
/// The service serves what this returns verbatim (bounded by
/// [`BlockSyncResponse::MAX_VOTES_PER_ROUND`]), so an implementation must only
/// return votes it actually holds for the requested round. Returning an empty
/// vec answers the requester with "no votes for that round".
///
/// See `docs/rfcs/RFC-009-VOTE-TRANSFER-OVER-BLOCK-SYNC.md`.
pub trait VoteSource: Send + Sync {
    /// The votes held for `round`, if any.
    fn votes_for_round(&self, round: Round) -> Result<Vec<Vote>, String>;
}

/// Codec for the block sync protocol.
#[derive(Debug, Clone, Default)]
pub struct BlockSyncCodec;

impl libp2p::request_response::Codec for BlockSyncCodec {
    type Protocol = libp2p::StreamProtocol;
    type Request = BlockSyncRequest;
    type Response = BlockSyncResponse;

    async fn read_request<T>(
        &mut self,
        _: &libp2p::StreamProtocol,
        io: &mut T,
    ) -> Result<Self::Request, std::io::Error>
    where
        T: AsyncReadExt + Unpin + Send,
    {
        let buf = read_bounded(io, MAX_REQUEST_SIZE).await?;
        bincode::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _: &libp2p::StreamProtocol,
        io: &mut T,
    ) -> Result<Self::Response, std::io::Error>
    where
        T: AsyncReadExt + Unpin + Send,
    {
        let buf = read_bounded(io, MAX_RESPONSE_SIZE).await?;
        bincode::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _: &libp2p::StreamProtocol,
        io: &mut T,
        req: Self::Request,
    ) -> Result<(), std::io::Error>
    where
        T: AsyncWriteExt + Unpin + Send,
    {
        let data = bincode::serialize(&req)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        io.write_all(&data).await
    }

    async fn write_response<T>(
        &mut self,
        _: &libp2p::StreamProtocol,
        io: &mut T,
        resp: Self::Response,
    ) -> Result<(), std::io::Error>
    where
        T: AsyncWriteExt + Unpin + Send,
    {
        let data = bincode::serialize(&resp)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        io.write_all(&data).await
    }
}

/// Protocol config.
pub fn block_sync_protocol() -> libp2p::request_response::Config {
    libp2p::request_response::Config::default()
        .with_request_timeout(std::time::Duration::from_secs(30))
        .with_max_concurrent_streams(100)
}

/// Protocols advertised for block sync: only this chain's `1.1.0` id.
pub fn block_sync_protocols(
    network: &crate::NetworkId,
) -> [(libp2p::StreamProtocol, ProtocolSupport); 1] {
    [(network.protocol(BLOCK_SYNC_PROTOCOL), ProtocolSupport::Full)]
}

/// Request event.
#[derive(Debug)]
pub struct BlockSyncRequestEvent {
    pub peer: libp2p::PeerId,
    pub request: BlockSyncRequest,
    pub channel: ResponseChannel<BlockSyncResponse>,
}

/// Response event.
#[derive(Debug, Clone)]
pub struct BlockSyncResponseEvent {
    pub peer: libp2p::PeerId,
    pub request_id: OutboundRequestId,
    pub response: BlockSyncResponse,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_types::hash::Hash;

    #[test]
    fn bounded_read_accepts_up_to_the_limit_and_rejects_beyond() {
        futures::executor::block_on(async {
            let mut exact = futures::io::Cursor::new(vec![1u8; 16]);
            assert_eq!(
                read_bounded(&mut exact, 16).await.expect("at limit").len(),
                16
            );
            let mut over = futures::io::Cursor::new(vec![1u8; 17]);
            let err = read_bounded(&mut over, 16).await.expect_err("over limit");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        });
    }

    #[test]
    fn oversized_block_sync_response_is_rejected_by_the_codec() {
        use libp2p::request_response::Codec;
        futures::executor::block_on(async {
            let mut codec = BlockSyncCodec;
            let protocol = crate::NetworkId::default().protocol(BLOCK_SYNC_PROTOCOL);
            let mut io = futures::io::Cursor::new(vec![0u8; MAX_RESPONSE_SIZE + 1]);
            assert!(codec.read_response(&protocol, &mut io).await.is_err());
            let mut io = futures::io::Cursor::new(vec![0u8; MAX_REQUEST_SIZE + 1]);
            assert!(codec.read_request(&protocol, &mut io).await.is_err());
        });
    }

    #[test]
    fn block_sync_request_by_hash_round_trip() {
        let hash = Hash::new("test-hash");
        let req = BlockSyncRequest::ByHash(hash);
        let encoded = bincode::serialize(&req).expect("serializes");
        let decoded: BlockSyncRequest = bincode::deserialize(&encoded).expect("deserializes");
        assert_eq!(req, decoded);
    }

    #[test]
    fn block_sync_request_by_author_round_round_trip() {
        let req = BlockSyncRequest::ByAuthorRound {
            author: 5,
            round: 42,
        };
        let encoded = bincode::serialize(&req).expect("serializes");
        let decoded: BlockSyncRequest = bincode::deserialize(&encoded).expect("deserializes");
        assert_eq!(req, decoded);
    }

    #[test]
    fn block_sync_response_round_trip() {
        let resp = BlockSyncResponse::NotFound;
        let encoded = bincode::serialize(&resp).expect("serializes");
        let decoded: BlockSyncResponse = bincode::deserialize(&encoded).expect("deserializes");
        assert_eq!(resp, decoded);
    }

    #[test]
    fn block_sync_response_missing_blocks_round_trip() {
        let resp = BlockSyncResponse::MissingBlocks(vec![Hash::new("a"), Hash::new("b")]);
        let encoded = bincode::serialize(&resp).expect("serializes");
        let decoded: BlockSyncResponse = bincode::deserialize(&encoded).expect("deserializes");
        assert_eq!(resp, decoded);
    }

    #[test]
    fn block_sync_status_round_trip() {
        let req = BlockSyncRequest::Status;
        let encoded = bincode::serialize(&req).expect("serializes");
        let decoded: BlockSyncRequest = bincode::deserialize(&encoded).expect("deserializes");
        assert_eq!(req, decoded);

        let resp = BlockSyncResponse::Status { tip_round: 7 };
        let encoded = bincode::serialize(&resp).expect("serializes");
        let decoded: BlockSyncResponse = bincode::deserialize(&encoded).expect("deserializes");
        assert_eq!(resp, decoded);
        assert_eq!(resp.to_string(), "Status(tip=7)");
    }

    #[test]
    fn block_sync_round_range_round_trip() {
        let req = BlockSyncRequest::RoundRange { from: 2, to: 9 };
        let encoded = bincode::serialize(&req).expect("serializes");
        let decoded: BlockSyncRequest = bincode::deserialize(&encoded).expect("deserializes");
        assert_eq!(req, decoded);

        let resp = BlockSyncResponse::RoundHashes {
            up_to_round: 9,
            hashes: vec![Hash::new("a"), Hash::new("b")],
        };
        let encoded = bincode::serialize(&resp).expect("serializes");
        let decoded: BlockSyncResponse = bincode::deserialize(&encoded).expect("deserializes");
        assert_eq!(resp, decoded);
        assert_eq!(resp.to_string(), "RoundHashes(up_to=9)");
    }

    /// Catch-up bounds must fit comfortably inside the framing caps: a range
    /// request is tiny and a range response stays far below the 1 MiB frame.
    #[test]
    fn catch_up_bounds_fit_the_frame_caps() {
        let worst_request = BlockSyncRequest::RoundRange {
            from: 0,
            to: BlockSyncRequest::MAX_RANGE_ROUNDS - 1,
        };
        let encoded = bincode::serialize(&worst_request).expect("serializes");
        assert!(encoded.len() <= MAX_REQUEST_SIZE);

        let worst_hashes = vec![Hash::zero(); BlockSyncResponse::MAX_RANGE_HASHES];
        let worst_response = BlockSyncResponse::RoundHashes {
            up_to_round: u64::MAX,
            hashes: worst_hashes,
        };
        let encoded = bincode::serialize(&worst_response).expect("serializes");
        assert!(encoded.len() <= MAX_RESPONSE_SIZE);
    }

    #[test]
    fn block_sync_votes_for_round_round_trip() {
        let req = BlockSyncRequest::VotesForRound { round: 42 };
        let encoded = bincode::serialize(&req).expect("serializes");
        let decoded: BlockSyncRequest = bincode::deserialize(&encoded).expect("deserializes");
        assert_eq!(req, decoded);

        let vote = kovanica_types::Vote {
            leader_round: 42,
            leader_hash: Hash::new("leader"),
            voter: 3,
            signature: kovanica_types::crypto::Signature([7u8; 64]),
        };
        let resp = BlockSyncResponse::Votes {
            round: 42,
            votes: vec![vote],
        };
        let encoded = bincode::serialize(&resp).expect("serializes");
        let decoded: BlockSyncResponse = bincode::deserialize(&encoded).expect("deserializes");
        assert_eq!(resp, decoded);
        assert_eq!(resp.to_string(), "Votes(round=42, n=1)");
    }

    /// The new variants are appended, so the encoding of the pre-existing
    /// variants is unchanged and an old peer can still decode what it knows.
    #[test]
    fn votes_variants_are_appended_after_the_existing_ones() {
        // `Block` is variant 0 of the response enum and must stay there.
        let encoded = bincode::serialize(&BlockSyncResponse::NotFound).expect("serializes");
        assert_eq!(
            &encoded[..4],
            &1u32.to_le_bytes(),
            "NotFound must keep variant index 1"
        );
        let encoded = bincode::serialize(&BlockSyncRequest::Status).expect("serializes");
        assert_eq!(
            &encoded[..4],
            &2u32.to_le_bytes(),
            "Status must keep variant index 2"
        );
    }

    /// A worst-case vote response must stay well inside the frame cap.
    #[test]
    fn votes_response_fits_the_frame_caps() {
        let votes: Vec<kovanica_types::Vote> = (0..BlockSyncResponse::MAX_VOTES_PER_ROUND)
            .map(|voter| kovanica_types::Vote {
                leader_round: 7,
                leader_hash: Hash::new("leader"),
                voter: voter as u16,
                signature: kovanica_types::crypto::Signature([0u8; 64]),
            })
            .collect();
        let worst_response = BlockSyncResponse::Votes { round: 7, votes };
        let encoded = bincode::serialize(&worst_response).expect("serializes");
        assert!(
            encoded.len() <= MAX_RESPONSE_SIZE,
            "worst-case vote response must fit the frame cap"
        );
    }

    /// Only this chain's `1.1.0` id is advertised; the chain-independent
    /// `1.0.0` legacy name is gone (Jarvis #81 review, P1).
    #[test]
    fn block_sync_advertises_only_the_chain_scoped_protocol() {
        assert_eq!(BLOCK_SYNC_PROTOCOL, "block-sync/1.1.0");
        let network = crate::NetworkId::default();
        let protocols = block_sync_protocols(&network);
        assert_eq!(protocols.len(), 1);
        assert_eq!(
            protocols[0].0.as_ref(),
            format!("/kovanica/{}/block-sync/1.1.0", network.tag())
        );
        assert!(protocols[0].1.inbound() && protocols[0].1.outbound());
        assert!(protocols
            .iter()
            .all(|(p, _)| !p.as_ref().contains("block-sync/1.0.0")));
    }
}
