//! State sync protocol for fast sync using snapshots.
//!
//! This module implements the fast sync protocol where a node can request
//! a state snapshot from a peer to quickly catch up without replaying all
//! blocks.
//!
//! A snapshot can be far larger than one request-response frame, so the
//! transfer is chunked: the request carries a byte [`StateSyncRequest::offset`]
//! into the serialized snapshot and the response returns at most
//! [`MAX_STATE_SYNC_CHUNK_BYTES`] bytes of it. Every chunk repeats the
//! snapshot's committed height, state root and total length so the client can
//! detect a peer that changes its answer mid-transfer, and the client refuses
//! to reassemble anything larger than [`MAX_STATE_SYNC_SNAPSHOT_BYTES`].
//!
//! Protocol version 2.0.0: the request gained `offset` and the `Snapshot`
//! response variant became [`StateSyncResponse::Chunk`]. Version 1.x was never
//! served by any node (the handler always answered `NotFound`), so the layout
//! change is not a live-compatibility break.

use crate::error::NetworkError;
use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::{request_response::Codec, StreamProtocol};
use serde::{Deserialize, Serialize};

/// Protocol suffix for state sync request-response. The id on the wire is
/// `/kovanica/<chain tag>/state-sync/2.0.0` ([`crate::NetworkId::protocol`]).
pub const STATE_SYNC_PROTOCOL: &str = "state-sync/2.0.0";

/// Maximum state sync request size.
pub const MAX_STATE_SYNC_REQUEST_SIZE: usize = 1024;

/// Maximum response size (10 MB for state snapshots).
pub const MAX_STATE_SYNC_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum chunk bytes returned in a single state sync response.
///
/// Kept well below [`MAX_STATE_SYNC_RESPONSE_SIZE`] so a single frame stays
/// small and a requesting peer can never make us push an unbounded frame.
/// Follows the same bounding style as `BlockSyncRequest::MAX_RANGE_ROUNDS`
/// and `BlockSyncResponse::MAX_RANGE_HASHES`.
pub const MAX_STATE_SYNC_CHUNK_BYTES: usize = 1024 * 1024;

/// Maximum total snapshot bytes a client will accept while reassembling a
/// chunked transfer. A peer claiming a larger `total_len` is ignored (the
/// session is dropped) so a hostile peer cannot make the client buffer an
/// unbounded amount.
pub const MAX_STATE_SYNC_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;

/// State sync request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSyncRequest {
    /// The committed leader height to sync to (optional - if None, sync to latest).
    pub target_height: Option<u64>,
    /// Byte offset into the serialized snapshot; 0 starts a transfer, a
    /// positive value fetches the next chunk.
    pub offset: u64,
}

impl StateSyncRequest {
    /// Create a request for the latest state, starting at byte 0.
    pub fn latest() -> Self {
        Self {
            target_height: None,
            offset: 0,
        }
    }

    /// Create a request for a specific height, starting at byte 0.
    pub fn at_height(height: u64) -> Self {
        Self {
            target_height: Some(height),
            offset: 0,
        }
    }

    /// Create a request for a specific height starting at `offset` bytes into
    /// the serialized snapshot (chunk continuation).
    pub fn at_height_from(height: u64, offset: u64) -> Self {
        Self {
            target_height: Some(height),
            offset,
        }
    }

    /// Serialize the request for the wire.
    pub fn encode(&self) -> Result<Vec<u8>, NetworkError> {
        Ok(bincode::serialize(self)?)
    }

    /// Deserialize a request received from the wire.
    pub fn decode(payload: &[u8]) -> Result<Self, NetworkError> {
        Ok(bincode::deserialize(payload)?)
    }
}

/// One bounded chunk of a state snapshot plus its framing metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotChunk {
    /// Committed-leader height the snapshot was taken at.
    pub height: u64,
    /// State root of the full snapshot. Repeated on every chunk so the client
    /// can detect a peer that changes its answer mid-transfer.
    pub state_root: [u8; 32],
    /// Total serialized snapshot length in bytes.
    pub total_len: u64,
    /// Byte offset of `data` within the full snapshot.
    pub offset: u64,
    /// The chunk bytes (at most [`MAX_STATE_SYNC_CHUNK_BYTES`]).
    pub data: Vec<u8>,
}

/// State sync response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateSyncResponse {
    /// One chunk of a snapshot (bincode-encoded snapshot from state_store).
    Chunk(SnapshotChunk),
    /// Requested height not available.
    NotFound,
    /// Request invalid.
    InvalidRequest,
}

impl std::fmt::Display for StateSyncResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateSyncResponse::Chunk(chunk) => write!(
                f,
                "Chunk(offset={}, len={}, total={})",
                chunk.offset,
                chunk.data.len(),
                chunk.total_len
            ),
            StateSyncResponse::NotFound => write!(f, "NotFound"),
            StateSyncResponse::InvalidRequest => write!(f, "InvalidRequest"),
        }
    }
}

impl StateSyncResponse {
    /// Serialize the response for the wire.
    pub fn encode(&self) -> Result<Vec<u8>, NetworkError> {
        Ok(bincode::serialize(self)?)
    }

    /// Deserialize a response received from the wire.
    pub fn decode(payload: &[u8]) -> Result<Self, NetworkError> {
        Ok(bincode::deserialize(payload)?)
    }
}

/// A full snapshot export produced by the export side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedSnapshot {
    /// Committed-leader height the snapshot was taken at.
    pub height: u64,
    /// State root of the snapshot.
    pub state_root: [u8; 32],
    /// The full serialized snapshot bytes.
    pub bytes: Vec<u8>,
}

/// Export side of the state sync protocol.
///
/// Implemented by the node over its state storage and injected into
/// [`crate::NetworkService`] via
/// [`crate::NetworkService::set_state_snapshot_source`]. Returning `Ok(None)`
/// answers the requester with `NotFound` (for example when
/// `target_height` names a height this node cannot serve). The service slices
/// the returned bytes into bounded chunks and caches the export briefly so a
/// chunked transfer does not re-serialize the whole state per request.
pub trait StateSnapshotSource: Send + Sync {
    /// Export the full snapshot this node can serve at `target_height`
    /// (`None` = whatever it currently holds).
    fn export_snapshot(
        &self,
        target_height: Option<u64>,
    ) -> Result<Option<ExportedSnapshot>, String>;
}

/// Codec for the state sync protocol.
#[derive(Debug, Clone, Default)]
pub struct StateSyncCodec;

impl Codec for StateSyncCodec {
    type Protocol = StreamProtocol;
    type Request = StateSyncRequest;
    type Response = StateSyncResponse;

    async fn read_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> Result<Self::Request, std::io::Error>
    where
        T: AsyncReadExt + Unpin + Send,
    {
        let buf = crate::block_sync::read_bounded(io, MAX_STATE_SYNC_REQUEST_SIZE).await?;
        bincode::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> Result<Self::Response, std::io::Error>
    where
        T: AsyncReadExt + Unpin + Send,
    {
        let buf = crate::block_sync::read_bounded(io, MAX_STATE_SYNC_RESPONSE_SIZE).await?;
        bincode::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
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
        _: &StreamProtocol,
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

/// Protocol config for state sync.
pub fn state_sync_protocol() -> libp2p::request_response::Config {
    libp2p::request_response::Config::default()
        .with_request_timeout(std::time::Duration::from_secs(60))
        .with_max_concurrent_streams(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_sync_request_latest_round_trip() {
        let req = StateSyncRequest::latest();
        let encoded = req.encode().expect("encodes");
        let decoded = StateSyncRequest::decode(&encoded).expect("decodes");
        assert_eq!(req, decoded);
        assert!(decoded.target_height.is_none());
        assert_eq!(decoded.offset, 0);
    }

    #[test]
    fn state_sync_request_at_height_round_trip() {
        let req = StateSyncRequest::at_height(1000);
        let encoded = req.encode().expect("encodes");
        let decoded = StateSyncRequest::decode(&encoded).expect("decodes");
        assert_eq!(req, decoded);
        assert_eq!(decoded.target_height, Some(1000));
        assert_eq!(decoded.offset, 0);
    }

    #[test]
    fn state_sync_request_chunk_continuation_round_trip() {
        let req = StateSyncRequest::at_height_from(1000, MAX_STATE_SYNC_CHUNK_BYTES as u64);
        let encoded = req.encode().expect("encodes");
        let decoded = StateSyncRequest::decode(&encoded).expect("decodes");
        assert_eq!(req, decoded);
        assert_eq!(decoded.target_height, Some(1000));
        assert_eq!(decoded.offset, MAX_STATE_SYNC_CHUNK_BYTES as u64);
    }

    #[test]
    fn state_sync_response_chunk_round_trip() {
        let resp = StateSyncResponse::Chunk(SnapshotChunk {
            height: 42,
            state_root: [7u8; 32],
            total_len: 10,
            offset: 0,
            data: vec![1, 2, 3, 4],
        });
        let encoded = resp.encode().expect("encodes");
        let decoded = StateSyncResponse::decode(&encoded).expect("decodes");
        assert_eq!(resp, decoded);
    }

    #[test]
    fn state_sync_response_not_found_round_trip() {
        let resp = StateSyncResponse::NotFound;
        let encoded = resp.encode().expect("encodes");
        let decoded = StateSyncResponse::decode(&encoded).expect("decodes");
        assert_eq!(resp, decoded);
    }

    #[test]
    fn chunk_bounds_are_sane() {
        // One chunk must fit in one frame; the reassembly cap must be a
        // multiple of the chunk cap so a transfer terminates in whole chunks.
        const _: () = assert!(MAX_STATE_SYNC_CHUNK_BYTES < MAX_STATE_SYNC_RESPONSE_SIZE);
        const _: () = assert!(
            (MAX_STATE_SYNC_SNAPSHOT_BYTES as usize).is_multiple_of(MAX_STATE_SYNC_CHUNK_BYTES),
            "reassembly cap should be a whole number of chunks"
        );
    }

    #[test]
    fn state_sync_codec_round_trip() {
        let _codec = StateSyncCodec;
        // Just verify the protocol constants
        assert_eq!(STATE_SYNC_PROTOCOL, "state-sync/2.0.0");
    }
}
