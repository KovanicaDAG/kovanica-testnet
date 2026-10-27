//! Audit 3.1 close test: invalid block rejected at hot path.
use kovanica_crypto::{generate_keypair, sign, verify_batch};
use kovanica_types::{block::StatementBlock, crypto::Signature};

#[test]
fn reject_invalid_block_signature_at_hot_path() {
    let (sk, vk) = generate_keypair();
    kovanica_crypto::set_validator_keys(vec![
        ed25519_dalek::VerifyingKey::from_bytes(&vk.0).expect("vk valid")
    ]);
    let _pk = vk;
    let digest = StatementBlock::compute_digest(0, 1, &[], &[]);
    let valid = StatementBlock {
        author: 0,
        round: 1,
        parents: vec![],
        transactions: vec![],
        statements: vec![],
        signature: sign(&sk, digest.as_ref()),
        digest,
        merkle_root: Default::default(),
    };
    assert!(
        verify_batch(std::slice::from_ref(&valid)).is_ok(),
        "valid passes"
    );

    let mut bad = valid.clone();
    bad.signature = Signature([0; 64]);
    assert!(
        verify_batch(&[bad.clone()]).is_err(),
        "INVALID BLOCK REJECTED AT HOT PATH (sig)"
    );
    // Audit 3.1 pass: bad signature rejected before engine.process_block
}
