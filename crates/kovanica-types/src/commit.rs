//! Commit-related types for Kovanica.
//!
#![allow(missing_docs)]
//! Contains types related to committed sub-DAGs and leader blocks.

use crate::block::{BlockReference, StatementBlock};
use crate::{AuthorityIndex, Round};
use serde::{Deserialize, Serialize};

/// A committed sub-DAG ready for execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommittedSubDag {
    /// The leader block that triggered this commit.
    pub leader: StatementBlock,
    /// All blocks in causal history that are now committed (in topological order).
    pub blocks: Vec<StatementBlock>,
    /// Round of the leader.
    pub leader_round: Round,
    /// Authority that proposed the leader.
    pub leader_author: AuthorityIndex,
    /// Red (non-blue) blocks of the leader's mergeset (#13 contract, variant A).
    ///
    /// - Deterministic topological order, with the block digest as tie-break.
    /// - Never part of [`Self::blocks`]: these blocks are not executed; their
    ///   transactions are returned to the mempool by the consensus helper.
    /// - Empty on the linearizer / fallback path.
    /// - The `execution_committed_subdags` key is unchanged by this field.
    ///
    /// `#[serde(default)]` only helps self-describing formats (JSON). With
    /// bincode a record written without this field is rejected; the type is
    /// not persisted, so no migration is needed.
    #[serde(default)]
    pub non_blue: Vec<BlockReference>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signature;
    use crate::hash::Hash;

    fn block(author: AuthorityIndex, round: Round) -> StatementBlock {
        StatementBlock {
            author,
            round,
            parents: vec![],
            transactions: vec![],
            statements: vec![],
            signature: Signature([0; 64]),
            digest: StatementBlock::compute_digest(author, round, &[], &[]),
            merkle_root: Hash::zero(),
        }
    }

    fn subdag(non_blue: Vec<BlockReference>) -> CommittedSubDag {
        let leader = block(0, 3);
        CommittedSubDag {
            blocks: vec![leader.clone()],
            leader,
            leader_round: 3,
            leader_author: 0,
            non_blue,
        }
    }

    fn red() -> Vec<BlockReference> {
        let b = block(1, 2);
        vec![BlockReference {
            author: b.author,
            round: b.round,
            digest: b.digest,
        }]
    }

    /// Pre-#13 layout, used to pin the bincode behaviour for old records.
    #[derive(Serialize)]
    struct LegacyCommittedSubDag {
        leader: StatementBlock,
        blocks: Vec<StatementBlock>,
        leader_round: Round,
        leader_author: AuthorityIndex,
    }

    #[test]
    fn bincode_round_trip_with_non_blue() {
        let s = subdag(red());
        let bytes = bincode::serialize(&s).unwrap();
        let back: CommittedSubDag = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back.non_blue, s.non_blue);
        assert_eq!(back.leader, s.leader);
        assert_eq!(back.blocks, s.blocks);
    }

    #[test]
    fn json_without_non_blue_loads_empty() {
        let mut v = serde_json::to_value(subdag(red())).unwrap();
        let obj = v.as_object_mut().unwrap();
        obj.remove("non_blue");
        // `Signature` deserializes via `deserialize_bytes` only; serde_json feeds
        // a JSON string's bytes to it, so give each signature a 64-byte string.
        let sig = serde_json::Value::String("0".repeat(64));
        obj.get_mut("leader").unwrap()["signature"] = sig.clone();
        for b in obj.get_mut("blocks").unwrap().as_array_mut().unwrap() {
            b["signature"] = sig.clone();
        }
        let s = serde_json::to_string(&v).unwrap();
        let back: CommittedSubDag = serde_json::from_str(&s).unwrap();
        assert!(back.non_blue.is_empty());
        assert_eq!(back.leader_round, 3);
    }

    #[test]
    fn old_bincode_record_without_field_is_rejected() {
        let s = subdag(vec![]);
        let legacy = LegacyCommittedSubDag {
            leader: s.leader,
            blocks: s.blocks,
            leader_round: s.leader_round,
            leader_author: s.leader_author,
        };
        let bytes = bincode::serialize(&legacy).unwrap();
        assert!(
            bincode::deserialize::<CommittedSubDag>(&bytes).is_err(),
            "bincode is not self-describing: serde(default) does not make old records readable"
        );
    }
}
