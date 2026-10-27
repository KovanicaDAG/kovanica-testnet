//! Sync-range gossip: the payload exchanged on [`crate::topics::SYNC`].

use crate::error::NetworkError;
use kovanica_types::Round;
use serde::{Deserialize, Serialize};

/// Request for a contiguous range of rounds from a peer.
///
/// The receiving side answers by emitting [`crate::NetworkEvent::SyncRequest`];
/// serving the range is up to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRequest {
    /// First round of the requested range (inclusive).
    pub from_round: Round,
    /// Last round of the requested range (inclusive).
    pub to_round: Round,
}

impl SyncRequest {
    /// Create a request for the inclusive range `[from_round, to_round]`.
    pub fn new(from_round: Round, to_round: Round) -> Self {
        Self {
            from_round,
            to_round,
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

    /// Whether the requested range is well-formed.
    pub fn is_valid(&self) -> bool {
        self.from_round <= self.to_round
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let request = SyncRequest::new(10, 20);
        let encoded = request.encode().expect("encodes");
        let decoded = SyncRequest::decode(&encoded).expect("decodes");
        assert_eq!(request, decoded);
        assert!(decoded.is_valid());
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(SyncRequest::decode(&[0xff, 0xff]).is_err());
    }

    #[test]
    fn inverted_range_is_invalid() {
        assert!(!SyncRequest::new(20, 10).is_valid());
    }
}
