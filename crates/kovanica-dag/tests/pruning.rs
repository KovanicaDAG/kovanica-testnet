//! Unit tests for DAG pruning functionality.

use kovanica_dag::DagStore;
use kovanica_storage::Storage;
use kovanica_types::{
    block::{BlockReference, StatementBlock},
    crypto::SigningKey,
    AuthorityIndex, Round,
};
use tempfile::tempdir;

/// Build a test block with the given parameters.
fn make_block(
    author: AuthorityIndex,
    round: Round,
    parents: Vec<BlockReference>,
    tag: &str,
    key: &SigningKey,
) -> StatementBlock {
    let digest = StatementBlock::compute_digest(author, round, &parents, &[]);
    let signature = kovanica_crypto::sign(key, digest.as_ref());
    StatementBlock {
        author,
        round,
        parents,
        transactions: Vec::new(),
        statements: tag.as_bytes().to_vec(),
        signature,
        digest,
        merkle_root: Default::default(),
    }
}

fn block_ref(block: &StatementBlock) -> BlockReference {
    BlockReference {
        author: block.author,
        round: block.round,
        digest: block.digest,
    }
}

#[test]
fn test_prune_non_blue_removes_correct_blocks() {
    let dir = tempdir().unwrap();
    let storage = Storage::new(dir.path().join("test.db")).unwrap();
    let dag = DagStore::new(storage).unwrap();

    let (key, _) = kovanica_crypto::generate_keypair();

    // Create blocks in wave 0 (rounds 0-2, WAVE_LENGTH=3)
    // Wave 0: rounds 0, 1, 2
    let genesis = make_block(0, 0, Vec::new(), "genesis", &key);
    let b1 = make_block(1, 1, vec![block_ref(&genesis)], "b1", &key);
    let b2 = make_block(2, 1, vec![block_ref(&genesis)], "b2", &key);
    let b3 = make_block(0, 2, vec![block_ref(&b1), block_ref(&b2)], "b3", &key);

    dag.put_block(&genesis).unwrap();
    dag.put_block(&b1).unwrap();
    dag.put_block(&b2).unwrap();
    dag.put_block(&b3).unwrap();

    // Verify all blocks exist
    assert!(dag.has_block(&genesis.digest).unwrap());
    assert!(dag.has_block(&b1.digest).unwrap());
    assert!(dag.has_block(&b2.digest).unwrap());
    assert!(dag.has_block(&b3.digest).unwrap());

    // Simulate MysticGhost colouring: only genesis, b1, b3 are blue (b2 is red)
    let blue_hashes = vec![genesis.digest, b1.digest, b3.digest];
    let pruned = dag.prune_non_blue(&blue_hashes, 0).unwrap();

    // Should have pruned b2 (1 non-blue block)
    assert_eq!(pruned, 1);

    // Blue blocks should still exist
    assert!(dag.has_block(&genesis.digest).unwrap());
    assert!(dag.has_block(&b1.digest).unwrap());
    assert!(dag.has_block(&b3.digest).unwrap());

    // Red block should be pruned
    assert!(!dag.has_block(&b2.digest).unwrap());
}

#[test]
fn test_prune_non_blue_keeps_blue_blocks() {
    let dir = tempdir().unwrap();
    let storage = Storage::new(dir.path().join("test.db")).unwrap();
    let dag = DagStore::new(storage).unwrap();

    let (key, _) = kovanica_crypto::generate_keypair();

    // Create multiple blocks in wave 0
    let genesis = make_block(0, 0, Vec::new(), "genesis", &key);
    let b1 = make_block(1, 1, vec![block_ref(&genesis)], "b1", &key);
    let b2 = make_block(2, 1, vec![block_ref(&genesis)], "b2", &key);
    let b3 = make_block(3, 1, vec![block_ref(&genesis)], "b3", &key);
    let b4 = make_block(0, 2, vec![block_ref(&b1), block_ref(&b2)], "b4", &key);

    dag.put_block(&genesis).unwrap();
    dag.put_block(&b1).unwrap();
    dag.put_block(&b2).unwrap();
    dag.put_block(&b3).unwrap();
    dag.put_block(&b4).unwrap();

    // Blue set: genesis, b1, b4 (b2 and b3 are red)
    let blue_hashes = vec![genesis.digest, b1.digest, b4.digest];
    let pruned = dag.prune_non_blue(&blue_hashes, 0).unwrap();

    // Should have pruned b2 and b3 (2 non-blue blocks)
    assert_eq!(pruned, 2);

    // Blue blocks should still exist
    assert!(dag.has_block(&genesis.digest).unwrap());
    assert!(dag.has_block(&b1.digest).unwrap());
    assert!(dag.has_block(&b4.digest).unwrap());

    // Red blocks should be pruned
    assert!(!dag.has_block(&b2.digest).unwrap());
    assert!(!dag.has_block(&b3.digest).unwrap());
}

#[test]
fn test_prune_waves_before_removes_old_waves() {
    let dir = tempdir().unwrap();
    let storage = Storage::new(dir.path().join("test.db")).unwrap();
    let dag = DagStore::new(storage).unwrap();

    let (key, _) = kovanica_crypto::generate_keypair();

    // WAVE_LENGTH = 3
    // Wave 0: rounds 0, 1, 2
    // Wave 1: rounds 3, 4, 5
    // Wave 2: rounds 6, 7, 8
    // Wave 3: rounds 9, 10, 11

    // Create blocks in waves 0, 1, 2, 3
    // Wave 0
    let w0_b1 = make_block(0, 0, Vec::new(), "w0_b1", &key);
    let w0_b2 = make_block(1, 1, vec![block_ref(&w0_b1)], "w0_b2", &key);

    // Wave 1
    let w1_b1 = make_block(0, 3, vec![block_ref(&w0_b2)], "w1_b1", &key);
    let w1_b2 = make_block(1, 4, vec![block_ref(&w1_b1)], "w1_b2", &key);

    // Wave 2
    let w2_b1 = make_block(0, 6, vec![block_ref(&w1_b2)], "w2_b1", &key);
    let w2_b2 = make_block(1, 7, vec![block_ref(&w2_b1)], "w2_b2", &key);

    // Wave 3
    let w3_b1 = make_block(0, 9, vec![block_ref(&w2_b2)], "w3_b1", &key);
    let w3_b2 = make_block(1, 10, vec![block_ref(&w3_b1)], "w3_b2", &key);

    let all_blocks = vec![
        w0_b1.clone(),
        w0_b2.clone(),
        w1_b1.clone(),
        w1_b2.clone(),
        w2_b1.clone(),
        w2_b2.clone(),
        w3_b1.clone(),
        w3_b2.clone(),
    ];

    for block in &all_blocks {
        dag.put_block(block).unwrap();
    }

    // Verify all blocks exist
    for block in &all_blocks {
        assert!(
            dag.has_block(&block.digest).unwrap(),
            "Block {} should exist",
            block.digest
        );
    }

    // Prune waves before wave 3 with prune_window_waves = 2
    // min_wave_to_keep = 3 - 2 = 1
    // max_round_to_prune = 1 * 3 = 3 (all rounds in waves < 1, i.e., wave 0: rounds 0, 1, 2)
    let pruned = dag.prune_waves_before(3, 2).unwrap();

    // Should have pruned wave 0 blocks (2 blocks)
    assert_eq!(pruned, 2);

    // Wave 0 blocks should be pruned
    assert!(!dag.has_block(&w0_b1.digest).unwrap());
    assert!(!dag.has_block(&w0_b2.digest).unwrap());

    // Waves 1, 2, 3 should still exist
    assert!(dag.has_block(&w1_b1.digest).unwrap());
    assert!(dag.has_block(&w1_b2.digest).unwrap());
    assert!(dag.has_block(&w2_b1.digest).unwrap());
    assert!(dag.has_block(&w2_b2.digest).unwrap());
    assert!(dag.has_block(&w3_b1.digest).unwrap());
    assert!(dag.has_block(&w3_b2.digest).unwrap());
}

#[test]
fn test_prune_waves_before_keeps_recent_waves() {
    let dir = tempdir().unwrap();
    let storage = Storage::new(dir.path().join("test.db")).unwrap();
    let dag = DagStore::new(storage).unwrap();

    let (key, _) = kovanica_crypto::generate_keypair();

    // Create blocks in waves 0, 1, 2 (current wave = 2)
    // Wave 0
    let w0_b1 = make_block(0, 0, Vec::new(), "w0_b1", &key);

    // Wave 1
    let w1_b1 = make_block(0, 3, vec![block_ref(&w0_b1)], "w1_b1", &key);

    // Wave 2
    let w2_b1 = make_block(0, 6, vec![block_ref(&w1_b1)], "w2_b1", &key);

    let all_blocks = vec![w0_b1.clone(), w1_b1.clone(), w2_b1.clone()];

    for block in &all_blocks {
        dag.put_block(block).unwrap();
    }

    // Prune waves before wave 2 with prune_window_waves = 5 (larger than current wave)
    // min_wave_to_keep = 2.saturating_sub(5) = 0
    // max_round_to_prune = 0 (no waves pruned)
    let pruned = dag.prune_waves_before(2, 5).unwrap();

    assert_eq!(pruned, 0);

    // All blocks should still exist
    for block in &all_blocks {
        assert!(dag.has_block(&block.digest).unwrap());
    }
}

#[test]
fn test_prune_non_blue_only_prunes_in_committed_wave() {
    let dir = tempdir().unwrap();
    let storage = Storage::new(dir.path().join("test.db")).unwrap();
    let dag = DagStore::new(storage).unwrap();

    let (key, _) = kovanica_crypto::generate_keypair();

    // Wave 0: rounds 0, 1, 2
    let w0_b1 = make_block(0, 0, Vec::new(), "w0_b1", &key);
    let w0_b2 = make_block(1, 1, vec![block_ref(&w0_b1)], "w0_b2", &key);
    let w0_b3 = make_block(2, 2, vec![block_ref(&w0_b2)], "w0_b3", &key);

    // Wave 1: rounds 3, 4, 5
    let w1_b1 = make_block(0, 3, vec![block_ref(&w0_b3)], "w1_b1", &key);
    let w1_b2 = make_block(1, 4, vec![block_ref(&w1_b1)], "w1_b2", &key);

    dag.put_block(&w0_b1).unwrap();
    dag.put_block(&w0_b2).unwrap();
    dag.put_block(&w0_b3).unwrap();
    dag.put_block(&w1_b1).unwrap();
    dag.put_block(&w1_b2).unwrap();

    // Prune non-blue in wave 0 (committed_wave = 0)
    // Only w0_b1 and w0_b3 are blue, w0_b2 is red
    let blue_hashes = vec![w0_b1.digest, w0_b3.digest];
    let pruned = dag.prune_non_blue(&blue_hashes, 0).unwrap();

    assert_eq!(pruned, 1);
    assert!(!dag.has_block(&w0_b2.digest).unwrap());

    // Wave 1 blocks should NOT be affected
    assert!(dag.has_block(&w1_b1.digest).unwrap());
    assert!(dag.has_block(&w1_b2.digest).unwrap());
}

#[test]
fn test_prune_waves_before_does_not_break_recovery() {
    let dir = tempdir().unwrap();
    let storage = Storage::new(dir.path().join("test.db")).unwrap();
    let dag = DagStore::new(storage).unwrap();

    let (key, _) = kovanica_crypto::generate_keypair();

    // Create blocks and commit some rounds
    let genesis = make_block(0, 0, Vec::new(), "genesis", &key);
    let b1 = make_block(1, 3, vec![block_ref(&genesis)], "b1", &key); // Round 3 = leader round

    dag.put_block(&genesis).unwrap();
    dag.put_block(&b1).unwrap();

    // Mark round 3 as decided
    dag.mark_round_decided(3, &b1.digest).unwrap();

    // Verify recovery data exists before pruning
    assert!(dag.is_round_decided(3).unwrap());
    assert_eq!(dag.get_decided_leaders(3).unwrap(), vec![b1.digest]);
    assert!(dag.get_decided_rounds(u64::MAX).unwrap().contains(&3));

    // Prune waves before wave 2 (wave 0: rounds 0-2, wave 1: rounds 3-5)
    // prune_window_waves = 1, so min_wave_to_keep = 2 - 1 = 1
    // max_round_to_prune = 1 * 3 = 3 (prunes round 0, 1, 2 - wave 0)
    let _pruned = dag.prune_waves_before(2, 1).unwrap();

    // Recovery data should still exist (decided rounds are not touched)
    assert!(dag.is_round_decided(3).unwrap());
    assert_eq!(dag.get_decided_leaders(3).unwrap(), vec![b1.digest]);
    assert!(dag.get_decided_rounds(u64::MAX).unwrap().contains(&3));

    // Genesis (round 0) should be pruned, but b1 (round 3) should remain
    assert!(!dag.has_block(&genesis.digest).unwrap());
    assert!(dag.has_block(&b1.digest).unwrap());
}
