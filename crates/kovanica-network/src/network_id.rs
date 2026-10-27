//! Chain separation at the libp2p layer.
//!
//! Every libp2p protocol id this node speaks and every gossip topic it uses
//! carries the chain id and a prefix of the genesis digest, so two chains
//! that share transport (same seeds, a mis-set bootnode, a reset testnet next
//! to the old one) cannot exchange blocks, votes, sync data or DHT records:
//!
//! * identify version `/kovanica/<tag>/1.0.0`; a peer that reports another
//!   version is disconnected and not added to the DHT;
//! * Kademlia `/kovanica/<tag>/kad/1.0.0`;
//! * block sync `/kovanica/<tag>/block-sync/1.1.0` (the chain-independent
//!   `1.0.0` fallback is gone);
//! * state sync `/kovanica/<tag>/state-sync/2.0.0`;
//! * gossip topics `kovanica/<tag>/<name>`.
//!
//! `<tag>` is `<chain_id>-<first 16 hex chars of the genesis digest>`
//! (see [`NetworkId::tag`]). Signatures already bind the chain id; this keeps
//! the wrong chain's traffic off the wire before any decoding happens.

use kovanica_types::hash::Hash;
use libp2p::StreamProtocol;

/// Number of hex characters of the genesis digest used in [`NetworkId::tag`]
/// (64 bits).
pub const GENESIS_TAG_HEX_CHARS: usize = 16;

/// The chain this node belongs to: chain id plus genesis digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkId {
    /// Signed chain id (`kovanica_types::signing::chain_id`).
    pub chain_id: u64,
    /// Digest of the genesis configuration (the value the node persists in
    /// its data dir).
    pub genesis: Hash,
}

impl Default for NetworkId {
    /// Local/test network with an all-zero genesis digest.
    fn default() -> Self {
        Self::new(kovanica_types::signing::chain_id::LOCAL, Hash([0u8; 32]))
    }
}

impl NetworkId {
    #[must_use]
    pub fn new(chain_id: u64, genesis: Hash) -> Self {
        Self { chain_id, genesis }
    }

    /// `<chain_id>-<first 16 hex chars of the genesis digest>`.
    #[must_use]
    pub fn tag(&self) -> String {
        let hex = self.genesis.to_hex();
        format!("{}-{}", self.chain_id, &hex[..GENESIS_TAG_HEX_CHARS])
    }

    /// `/kovanica/<tag>/<suffix>`, e.g. `suffix = "kad/1.0.0"`.
    #[must_use]
    pub fn protocol(&self, suffix: &str) -> StreamProtocol {
        StreamProtocol::try_from_owned(format!("/kovanica/{}/{suffix}", self.tag()))
            .expect("protocol id starts with '/'")
    }

    /// Identify protocol version advertised to peers.
    #[must_use]
    pub fn identify_version(&self) -> String {
        format!("/kovanica/{}/{}", self.tag(), crate::IDENTIFY_VERSION)
    }

    /// Full gossip topic name for a base name from [`crate::topics`].
    #[must_use]
    pub fn topic(&self, name: &str) -> String {
        format!("kovanica/{}/{name}", self.tag())
    }

    /// Base topic name (one of [`crate::topics::ALL`]) of a full topic name
    /// of this network, or `None` for any other network's or unknown topic.
    #[must_use]
    pub fn topic_kind(&self, full: &str) -> Option<&'static str> {
        let prefix = format!("kovanica/{}/", self.tag());
        let base = full.strip_prefix(prefix.as_str())?;
        crate::topics::ALL.into_iter().find(|name| *name == base)
    }

    /// Whether a peer's identify `protocol_version` is this network's.
    #[must_use]
    pub fn accepts_identify(&self, protocol_version: &str) -> bool {
        protocol_version == self.identify_version()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(chain: u64, byte: u8) -> NetworkId {
        NetworkId::new(chain, Hash([byte; 32]))
    }

    #[test]
    fn tag_binds_chain_id_and_genesis_prefix() {
        let a = id(4, 0xab);
        assert_eq!(a.tag(), "4-abababababababab");
        assert_ne!(a.tag(), id(2, 0xab).tag(), "chain id");
        assert_ne!(a.tag(), id(4, 0xac).tag(), "genesis");
    }

    #[test]
    fn protocol_ids_and_topics_carry_the_tag() {
        let a = id(4, 0x01);
        let tag = a.tag();
        assert_eq!(
            a.protocol(crate::block_sync::BLOCK_SYNC_PROTOCOL).as_ref(),
            format!("/kovanica/{tag}/block-sync/1.1.0")
        );
        assert_eq!(
            a.protocol(crate::KAD_PROTOCOL).as_ref(),
            format!("/kovanica/{tag}/kad/1.0.0")
        );
        assert_eq!(
            a.protocol(crate::state_sync::STATE_SYNC_PROTOCOL).as_ref(),
            format!("/kovanica/{tag}/state-sync/2.0.0")
        );
        assert_eq!(a.identify_version(), format!("/kovanica/{tag}/1.0.0"));
        assert_eq!(a.topic("blocks"), format!("kovanica/{tag}/blocks"));
    }

    #[test]
    fn another_chains_ids_and_topics_are_not_accepted() {
        let ours = id(4, 0x01);
        for other in [id(2, 0x01), id(4, 0x02)] {
            assert_ne!(
                ours.protocol(crate::block_sync::BLOCK_SYNC_PROTOCOL),
                other.protocol(crate::block_sync::BLOCK_SYNC_PROTOCOL)
            );
            assert_ne!(
                ours.protocol(crate::KAD_PROTOCOL),
                other.protocol(crate::KAD_PROTOCOL)
            );
            assert!(!ours.accepts_identify(&other.identify_version()));
            for name in crate::topics::ALL {
                assert_eq!(ours.topic_kind(&other.topic(name)), None, "{name}");
            }
        }
        assert!(ours.accepts_identify(&ours.identify_version()));
        // The pre-separation names are refused too.
        assert!(!ours.accepts_identify("/kovanica/1.0.0"));
        for name in crate::topics::ALL {
            assert_eq!(ours.topic_kind(name), None, "bare {name}");
            assert_eq!(ours.topic_kind(&ours.topic(name)), Some(name));
        }
        assert_eq!(ours.topic_kind(&ours.topic("not-a-topic")), None);
    }
}
