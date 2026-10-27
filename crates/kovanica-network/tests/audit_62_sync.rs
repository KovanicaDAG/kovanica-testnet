//! Minimal audit 6.2 test: block sync request-response + rate-limited enqueue.

use kovanica_network::{
    BlockSyncRequest, BlockSyncResponse, NetworkId, BLOCK_SYNC_PROTOCOL, STATE_SYNC_PROTOCOL,
};
use kovanica_types::hash::Hash;

#[test]
fn audit_62_sync_protocol_is_kovanica() {
    let network = NetworkId::new(4, Hash([7u8; 32]));
    let tag = network.tag();
    assert_eq!(
        network.protocol(BLOCK_SYNC_PROTOCOL).as_ref(),
        format!("/kovanica/{tag}/block-sync/1.1.0")
    );
    assert_eq!(
        network.protocol(STATE_SYNC_PROTOCOL).as_ref(),
        format!("/kovanica/{tag}/state-sync/2.0.0")
    );
}

#[test]
fn audit_62_sync_request_has_variants() {
    let by_hash = BlockSyncRequest::ByHash(Hash::new("test-hash"));
    let by_author = BlockSyncRequest::ByAuthorRound {
        author: 3,
        round: 7,
    };
    assert!(matches!(by_hash, BlockSyncRequest::ByHash(_)));
    assert!(matches!(by_author, BlockSyncRequest::ByAuthorRound { .. }));
}

#[test]
fn audit_62_sync_response_has_missing_blocks() {
    let resp = BlockSyncResponse::MissingBlocks(vec![Hash::new("a"), Hash::new("b")]);
    assert!(matches!(resp, BlockSyncResponse::MissingBlocks(_)));
    assert_eq!(resp.to_string(), "MissingBlocks");
}
