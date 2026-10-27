//! Gossipsub peer scoring: topic parameters for blocks, votes and
//! transactions, a strong penalty for messages we [`Reject`], and
//! graylist/ban thresholds.
//!
//! The defaults are tuned for a small, low-traffic validator network:
//! only *negative* behaviour (invalid messages, protocol misbehaviour) can
//! push a peer below zero. Mesh-delivery-rate penalties (P3/P3b) are disabled
//! because quiet but honest peers would otherwise be graylisted whenever the
//! chain is idle.
//!
//! [`Reject`]: libp2p::gossipsub::MessageAcceptance::Reject

use std::time::Duration;

use libp2p::gossipsub::{PeerScoreParams, PeerScoreThresholds, TopicScoreParams};
use serde::Deserialize;

use crate::topics;

/// Operator-tunable peer scoring knobs. All thresholds are `<= 0` and must be
/// ordered `ban <= graylist <= publish <= gossip <= 0`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct PeerScoringConfig {
    /// Turn peer scoring on (default) or off.
    pub enabled: bool,
    /// Below this score we stop gossiping (IHAVE/IWANT) with the peer.
    pub gossip_threshold: f64,
    /// Below this score we stop publishing our own messages to the peer.
    pub publish_threshold: f64,
    /// Below this score all RPCs from the peer are ignored (graylist).
    pub graylist_threshold: f64,
    /// Below this score the peer is disconnected and evicted (ban).
    pub ban_threshold: f64,
    /// Weight of the invalid-message (Reject) penalty, per topic. Must be
    /// negative. The penalty grows with the square of the decayed reject count.
    pub invalid_message_weight: f64,
}

impl Default for PeerScoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            gossip_threshold: -10.0,
            publish_threshold: -50.0,
            graylist_threshold: -80.0,
            ban_threshold: -100.0,
            invalid_message_weight: -10.0,
        }
    }
}

impl PeerScoringConfig {
    /// Check sign and ordering constraints.
    pub fn validate(&self) -> Result<(), String> {
        let t = [
            ("gossip_threshold", self.gossip_threshold),
            ("publish_threshold", self.publish_threshold),
            ("graylist_threshold", self.graylist_threshold),
            ("ban_threshold", self.ban_threshold),
        ];
        for (name, value) in t {
            if !value.is_finite() || value > 0.0 {
                return Err(format!("{name} must be a finite value <= 0"));
            }
        }
        if !(self.ban_threshold <= self.graylist_threshold
            && self.graylist_threshold <= self.publish_threshold
            && self.publish_threshold <= self.gossip_threshold)
        {
            return Err("thresholds must satisfy ban <= graylist <= publish <= gossip".into());
        }
        if !self.invalid_message_weight.is_finite() || self.invalid_message_weight >= 0.0 {
            return Err("invalid_message_weight must be negative".into());
        }
        Ok(())
    }

    /// Gossipsub thresholds derived from this config.
    pub fn thresholds(&self) -> PeerScoreThresholds {
        PeerScoreThresholds {
            gossip_threshold: self.gossip_threshold,
            publish_threshold: self.publish_threshold,
            graylist_threshold: self.graylist_threshold,
            ..PeerScoreThresholds::default()
        }
    }

    /// Gossipsub score parameters with per-topic params for blocks, votes,
    /// timeouts and transactions.
    pub fn params(&self, network: &crate::NetworkId) -> PeerScoreParams {
        let mut params = PeerScoreParams {
            // Same-IP peers are normal in local/devnet setups; keep the
            // libp2p default threshold (10) but a mild weight.
            ip_colocation_factor_weight: -1.0,
            ..PeerScoreParams::default()
        };
        // Blocks, votes and timeouts are consensus-critical: a bad one weighs
        // more.
        for (name, weight) in [
            (topics::BLOCKS, 1.0),
            (topics::VOTES, 1.0),
            (topics::TIMEOUTS, 1.0),
            (topics::TRANSACTIONS, 0.5),
        ] {
            params.topics.insert(
                topics::ident(network, name).hash(),
                self.topic_params(weight),
            );
        }
        params
    }

    fn topic_params(&self, topic_weight: f64) -> TopicScoreParams {
        TopicScoreParams {
            topic_weight,
            // P1: small reward for staying in the mesh, capped at 10.
            time_in_mesh_weight: 0.01,
            time_in_mesh_quantum: Duration::from_secs(1),
            time_in_mesh_cap: 1000.0,
            // P2: small reward for first deliveries of valid messages.
            first_message_deliveries_weight: 0.1,
            first_message_deliveries_decay: 0.9,
            first_message_deliveries_cap: 100.0,
            // P3/P3b disabled: low traffic must not look like misbehaviour.
            mesh_message_deliveries_weight: 0.0,
            mesh_failure_penalty_weight: 0.0,
            // P4: Reject penalty (square of decayed count).
            invalid_message_deliveries_weight: self.invalid_message_weight,
            invalid_message_deliveries_decay: 0.5,
            ..TopicScoreParams::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_for_gossipsub() {
        let cfg = PeerScoringConfig::default();
        cfg.validate().expect("default config valid");
        cfg.params(&crate::NetworkId::default())
            .validate()
            .expect("params valid");
        cfg.thresholds().validate().expect("thresholds valid");
        assert!(cfg.enabled);
    }

    #[test]
    fn scored_topics_are_blocks_votes_timeouts_transactions() {
        let network = crate::NetworkId::default();
        let params = PeerScoringConfig::default().params(&network);
        for name in [
            topics::BLOCKS,
            topics::VOTES,
            topics::TIMEOUTS,
            topics::TRANSACTIONS,
        ] {
            let p = &params.topics[&topics::ident(&network, name).hash()];
            assert!(p.invalid_message_deliveries_weight < 0.0, "{name}");
            assert_eq!(p.mesh_message_deliveries_weight, 0.0, "{name}");
        }
        assert_eq!(params.topics.len(), 4);
    }

    #[test]
    fn misordered_or_positive_thresholds_are_rejected() {
        let ok = PeerScoringConfig::default();
        let cases = [
            PeerScoringConfig {
                gossip_threshold: 1.0,
                ..ok.clone()
            },
            PeerScoringConfig {
                ban_threshold: -10.0,
                ..ok.clone()
            },
            PeerScoringConfig {
                publish_threshold: -5.0,
                ..ok.clone()
            },
            PeerScoringConfig {
                invalid_message_weight: 0.0,
                ..ok.clone()
            },
            PeerScoringConfig {
                graylist_threshold: f64::NAN,
                ..ok.clone()
            },
        ];
        for c in cases {
            assert!(c.validate().is_err(), "{c:?}");
        }
    }
}
