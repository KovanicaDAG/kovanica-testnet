//! Swarm construction: transport, security and the composite [`Behaviour`].

use crate::{block_sync, error::NetworkError, state_sync, topics, NetworkConfig};
use libp2p::{
    gossipsub, identify, kad, kad::store::MemoryStore, noise, ping, request_response,
    request_response::ProtocolSupport, swarm::NetworkBehaviour, tcp, yamux, Multiaddr, PeerId,
    Swarm, SwarmBuilder,
};
use std::{error::Error, time::Duration};

/// Maximum gossip frame size: large enough for a full block, small enough to
/// keep a hostile peer from forcing us to buffer an unbounded message.
const MAX_TRANSMIT_SIZE: usize = 1024 * 1024;

/// Composite libp2p behaviour: gossip, peer routing, liveness, identification and request-response.
#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    /// Gossipsub carrying blocks, transactions, votes and sync requests.
    pub(crate) gossipsub: gossipsub::Behaviour,
    /// Kademlia routing table for peer discovery and bootstrapping.
    pub(crate) kad: kad::Behaviour<MemoryStore>,
    /// Ping used for liveness checks and peer banning.
    pub(crate) ping: ping::Behaviour,
    /// Identify used for protocol exchange and address discovery.
    pub(crate) identify: identify::Behaviour,
    /// Request-response for block sync.
    pub(crate) block_sync: request_response::Behaviour<block_sync::BlockSyncCodec>,
    /// Request-response for state sync (fast sync).
    pub(crate) state_sync: request_response::Behaviour<state_sync::StateSyncCodec>,
}

/// Deterministic message id: BLAKE3 of the payload.
///
/// Content addressing means the same block or transaction relayed by several
/// peers is only delivered to the node once, no matter who forwarded it.
pub(crate) fn message_id(data: &[u8]) -> gossipsub::MessageId {
    gossipsub::MessageId::from(kovanica_types::Hash::new(data).0.to_vec())
}

/// Gossipsub configuration: signed messages, strict validation and
/// deterministic message ids.
///
/// `validate_messages` is on: gossipsub holds every received message until
/// the service reports a [`gossipsub::MessageAcceptance`] for it, so nothing
/// is forwarded to the mesh before it passed the edge checks in
/// [`crate::validation`].
pub(crate) fn gossipsub_config() -> Result<gossipsub::Config, NetworkError> {
    gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Strict)
        .validate_messages()
        .message_id_fn(|message| message_id(&message.data))
        .max_transmit_size(MAX_TRANSMIT_SIZE)
        .build()
        .map_err(|err| NetworkError::Gossipsub(err.to_string()))
}

/// Split a bootstrap address at its trailing `/p2p/<peer-id>` component.
///
/// Returns `Ok(None)` for addresses without a peer id (they can still be
/// dialed, we just cannot preload them into Kademlia) and an error when the
/// peer id component is present but malformed.
pub(crate) fn split_peer_suffix(
    addr: &Multiaddr,
) -> Result<Option<(PeerId, Multiaddr)>, NetworkError> {
    let text = addr.to_string();
    let Some(index) = text.rfind("/p2p/") else {
        return Ok(None);
    };
    let peer: PeerId = text[index + "/p2p/".len()..].parse().map_err(|err| {
        NetworkError::Config(format!(
            "invalid peer id in bootstrap address {text}: {err}"
        ))
    })?;
    let base: Multiaddr = text[..index]
        .parse()
        .map_err(|err| NetworkError::Config(format!("invalid bootstrap address {text}: {err}")))?;
    Ok(Some((peer, base)))
}

/// Build the swarm: TCP + Noise + Yamux over a DNS-enabled transport, running
/// [`Behaviour`].
///
/// Bootstrap addresses that carry `/p2p/<id>` are pre-loaded into the Kademlia
/// routing table so the first `bootstrap()` query has somewhere to go.
pub(crate) fn build_swarm(config: &NetworkConfig) -> Result<Swarm<Behaviour>, NetworkError> {
    let mut bootstrap_peers = Vec::new();
    for addr in &config.bootstrap_nodes {
        if let Some(entry) = split_peer_suffix(addr)? {
            bootstrap_peers.push(entry);
        }
    }

    let ping_interval = config.ping_interval;
    let network = config.network_id;
    let scoring = config.peer_scoring.clone();
    scoring
        .validate()
        .map_err(|err| NetworkError::Config(format!("peer scoring: {err}")))?;
    // Keep connections alive well past the ping interval; the default idle
    // timeout (5s) would otherwise drop peers between pings.
    let idle_timeout = std::cmp::max(ping_interval * 4, Duration::from_secs(60));

    let identity = match &config.node_key_path {
        Some(path) => crate::identity::load_or_create_node_identity(path)?,
        None => libp2p::identity::Keypair::generate_ed25519(),
    };

    let swarm = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|err| NetworkError::Transport(err.to_string()))?
        .with_dns()
        .map_err(|err| NetworkError::Transport(err.to_string()))?
        .with_behaviour(|key| -> Result<Behaviour, Box<dyn Error + Send + Sync>> {
            let local_peer_id = key.public().to_peer_id();

            let mut gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config()?,
            )
            .map_err(|err| NetworkError::Gossipsub(err.to_string()))?;
            if scoring.enabled {
                gossipsub
                    .with_peer_score(scoring.params(&network), scoring.thresholds())
                    .map_err(NetworkError::Gossipsub)?;
            }
            for name in topics::ALL {
                gossipsub
                    .subscribe(&topics::ident(&network, name))
                    .map_err(|err| NetworkError::Gossipsub(err.to_string()))?;
            }

            let mut kad = kad::Behaviour::with_config(
                local_peer_id,
                MemoryStore::new(local_peer_id),
                kad::Config::new(network.protocol(crate::KAD_PROTOCOL)),
            );
            for (peer, addr) in &bootstrap_peers {
                kad.add_address(peer, addr.clone());
            }

            let ping = ping::Behaviour::new(ping::Config::new().with_interval(ping_interval));
            let identify = identify::Behaviour::new(identify::Config::new(
                network.identify_version(),
                key.public(),
            ));

            // Block sync request-response: only this chain's 1.1.0 id.
            let block_sync = request_response::Behaviour::new(
                block_sync::block_sync_protocols(&network),
                block_sync::block_sync_protocol(),
            );

            // State sync request-response protocol (fast sync)
            let state_sync = request_response::Behaviour::new(
                [(
                    network.protocol(state_sync::STATE_SYNC_PROTOCOL),
                    ProtocolSupport::Full,
                )],
                state_sync::state_sync_protocol(),
            );

            Ok(Behaviour {
                gossipsub,
                kad,
                ping,
                identify,
                block_sync,
                state_sync,
            })
        })
        .map_err(|err| NetworkError::Swarm(err.to_string()))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(idle_timeout))
        .build();

    Ok(swarm)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical libp2p protocol namespace is `/kovanica/` (decided 2026-10-13);
    /// this locks the identify + Kademlia prefixes so they cannot drift back to
    /// `/kvanc/` or the old typo.
    #[test]
    fn protocol_namespace_is_kovanica() {
        let network = crate::NetworkId::default();
        let tag = network.tag();
        assert_eq!(network.identify_version(), format!("/kovanica/{tag}/1.0.0"));
        assert_eq!(
            network.protocol(crate::KAD_PROTOCOL).as_ref(),
            format!("/kovanica/{tag}/kad/1.0.0")
        );
    }

    /// The consensus block cap must stay below the gossip frame cap: a block
    /// that passes consensus validation has to be relayable in one message.
    /// If either constant moves, this relationship must be re-derived.
    // Clippy sees two constants and calls the assertions tautological; that is
    // exactly the point — it fails the build when the relationship is broken.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn consensus_block_cap_fits_the_gossip_frame() {
        assert!(
            kovanica_types::MAX_BLOCK_BYTES < MAX_TRANSMIT_SIZE,
            "MAX_BLOCK_BYTES ({}) must stay below MAX_TRANSMIT_SIZE ({})",
            kovanica_types::MAX_BLOCK_BYTES,
            MAX_TRANSMIT_SIZE
        );
        // Leave real headroom for the message envelope, not a byte or two.
        assert!(
            MAX_TRANSMIT_SIZE - kovanica_types::MAX_BLOCK_BYTES >= 64 * 1024,
            "at least 64 KiB of envelope headroom is expected"
        );
    }

    #[test]
    fn message_id_is_deterministic() {
        let first = message_id(b"kovanica-block");
        let second = message_id(b"kovanica-block");
        let other = message_id(b"kovanica-transaction");
        assert_eq!(first, second);
        assert_ne!(first, other);
    }

    #[test]
    fn split_peer_suffix_handles_bootstrap_addresses() {
        let addr: Multiaddr = "/dns4/seed1.kovanica.invalid/tcp/8000/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
            .parse()
            .expect("valid multiaddr");
        let (peer, base) = split_peer_suffix(&addr)
            .expect("parses")
            .expect("has a peer id suffix");
        assert_eq!(base.to_string(), "/dns4/seed1.kovanica.invalid/tcp/8000");
        assert_eq!(addr.to_string(), format!("{base}/p2p/{peer}"));
    }

    #[test]
    fn split_peer_suffix_accepts_dial_only_addresses() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/9000".parse().expect("valid multiaddr");
        assert!(split_peer_suffix(&addr).expect("parses").is_none());
    }

    #[test]
    fn gossip_forwarding_waits_for_validation() {
        let config = gossipsub_config().expect("config builds");
        assert!(config.validate_messages());
    }

    #[test]
    fn build_swarm_subscribes_to_every_topic() {
        let swarm = build_swarm(&NetworkConfig::default()).expect("swarm builds");
        let subscribed: Vec<String> = swarm
            .behaviour()
            .gossipsub
            .topics()
            .map(ToString::to_string)
            .collect();
        let network = crate::NetworkId::default();
        for name in topics::ALL {
            let full = network.topic(name);
            assert!(
                subscribed.contains(&full),
                "missing subscription for topic {full}"
            );
        }
        assert!(
            subscribed
                .iter()
                .all(|topic| topic.starts_with("kovanica/")),
            "every topic is chain-scoped: {subscribed:?}"
        );
        assert!(!swarm.local_peer_id().to_string().is_empty());
    }

    #[test]
    fn build_swarm_reuses_persistent_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = NetworkConfig {
            node_key_path: Some(dir.path().join("p2p_node.key")),
            ..NetworkConfig::default()
        };
        let first = *build_swarm(&config).expect("swarm builds").local_peer_id();
        let second = *build_swarm(&config).expect("swarm builds").local_peer_id();
        assert_eq!(first, second, "peer id must survive restarts");

        let ephemeral = *build_swarm(&NetworkConfig::default())
            .expect("swarm builds")
            .local_peer_id();
        assert_ne!(first, ephemeral);
    }

    #[test]
    fn build_swarm_enables_peer_scoring_by_default() {
        let swarm = build_swarm(&NetworkConfig::default()).expect("swarm builds");
        let stranger = PeerId::random();
        // With scoring active, gossipsub reports a score for any peer id.
        assert_eq!(swarm.behaviour().gossipsub.peer_score(&stranger), Some(0.0));

        let off = NetworkConfig {
            peer_scoring: crate::PeerScoringConfig {
                enabled: false,
                ..Default::default()
            },
            ..NetworkConfig::default()
        };
        let swarm = build_swarm(&off).expect("swarm builds");
        assert_eq!(swarm.behaviour().gossipsub.peer_score(&stranger), None);
    }

    #[test]
    fn build_swarm_rejects_invalid_scoring_config() {
        let bad = NetworkConfig {
            peer_scoring: crate::PeerScoringConfig {
                ban_threshold: 0.0,
                ..Default::default()
            },
            ..NetworkConfig::default()
        };
        assert!(build_swarm(&bad).is_err());
    }
}
