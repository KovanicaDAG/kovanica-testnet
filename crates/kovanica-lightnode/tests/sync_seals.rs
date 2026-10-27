//! Seal sync stores a header only after `kovanica-light` accepts it.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use kovanica_light::committee_from_members;
use kovanica_lightnode::config::LightConfig;
use kovanica_lightnode::decode::{leader_header_json, seals_json};
use kovanica_lightnode::rpc::RpcClient;
use kovanica_lightnode::sync::{self, SyncOutcome};
use kovanica_lightnode::{confirm_account, encode_raw, signed_transfer};
use kovanica_types::{
    committee_seal_hash, leader_header, AccountSmt, Address, CommitSeal, CommittedSubDag,
    Committee, Hash, LeaderHeader, PublicKey, Signature, SigningKey, StateProof, StatementBlock,
};
use serde_json::{json, Value};

fn keys(n: u16) -> (Vec<SigningKey>, Committee) {
    let mut signers = Vec::new();
    let mut members = Vec::new();
    for index in 0..n {
        let signer = SigningKey::from_bytes(&[index as u8 + 1; 32]);
        let public_key = PublicKey::from(signer.verifying_key());
        let address = Address::from_public_key(&public_key);
        members.push((index, public_key, 1u64, address));
        signers.push(signer);
    }
    (signers, committee_from_members(0, &members))
}

fn header_for(committee: &Committee, height: u64, parent: Hash, state: Hash) -> LeaderHeader {
    let digest = Hash::new([height as u8 + 1]);
    let leader = StatementBlock {
        author: 0,
        round: height.saturating_mul(3),
        parents: vec![],
        transactions: vec![],
        statements: vec![],
        signature: Signature([0; 64]),
        digest,
        merkle_root: Hash::zero(),
    };
    let subdag = CommittedSubDag {
        blocks: vec![leader.clone()],
        leader,
        leader_round: height.saturating_mul(3),
        leader_author: 0,
        non_blue: vec![],
    };
    let members: Vec<_> = committee
        .authorities
        .iter()
        .map(|authority| (authority.index, authority.public_key, authority.stake))
        .collect();
    leader_header(
        &subdag,
        height,
        parent,
        state,
        committee.epoch,
        committee_seal_hash(committee.epoch, &members),
        false,
    )
}

fn seals_for(signers: &[SigningKey], header: &LeaderHeader, n: u16) -> Vec<CommitSeal> {
    (0..n)
        .map(|index| CommitSeal {
            authority_index: index,
            signature: kovanica_crypto::sign(&signers[index as usize], &header.seal_message(1337)),
        })
        .collect()
}

#[test]
fn a_bad_seal_is_not_stored() {
    let (signers, committee) = keys(4);
    let header = header_for(&committee, 0, Hash::zero(), Hash::new([4u8]));
    let mut seals = seals_for(&signers, &header, 3);
    seals[0].signature = Signature([9u8; 64]);
    let dir = tempfile_dir();
    let err = sync::accept_and_store(&dir, 1337, &committee, &header, &seals, None).unwrap_err();
    assert!(err.to_string().contains("rejected") || err.root_cause().to_string().contains("seal"));
    assert!(sync::load_header(&dir).unwrap().is_none());
    assert!(!dir.join(sync::HEADER_FILE).exists());
}

#[test]
fn a_valid_checkpoint_is_stored_and_the_next_header_must_follow_it() {
    let (signers, committee) = keys(4);
    let first = header_for(&committee, 0, Hash::zero(), Hash::zero());
    let dir = tempfile_dir();
    sync::accept_and_store(
        &dir,
        1337,
        &committee,
        &first,
        &seals_for(&signers, &first, 3),
        None,
    )
    .unwrap();
    let stored = sync::load_header(&dir).unwrap().unwrap();
    assert_eq!(stored.hash(), first.hash());

    let broken = header_for(&committee, 1, Hash::new([9u8]), Hash::new([2u8]));
    let err = sync::accept_and_store(
        &dir,
        1337,
        &committee,
        &broken,
        &seals_for(&signers, &broken, 3),
        Some(&stored),
    )
    .unwrap_err();
    assert!(err.to_string().contains("rejected"));
    assert_eq!(
        sync::load_header(&dir).unwrap().unwrap().hash(),
        first.hash()
    );

    let second = header_for(&committee, 1, first.leader_digest, Hash::new([2u8]));
    sync::accept_and_store(
        &dir,
        1337,
        &committee,
        &second,
        &seals_for(&signers, &second, 3),
        Some(&stored),
    )
    .unwrap();
    assert_eq!(
        sync::load_header(&dir).unwrap().unwrap().committed_height,
        1
    );
}

#[test]
fn sync_over_http_stores_a_good_header_and_rejects_a_bad_one() {
    let (signers, committee) = keys(4);
    let header = header_for(&committee, 4, Hash::zero(), Hash::new([8u8]));
    let good = seals_for(&signers, &header, 3);
    let header_rpc = header.clone();
    let committee_rpc = committee.clone();
    let url = serve(move |method, _params| match method {
        "kovanica_getLeaderHeader" => leader_header_json(&header_rpc),
        "kovanica_getCommitSeals" => {
            seals_json(header_rpc.committed_height, Some(header_rpc.hash()), &good)
        }
        "kovanica_getCommittee" => committee_json(&committee_rpc),
        _ => Value::Null,
    });
    let dir = tempfile_dir();
    let cfg = LightConfig {
        rpc: url.clone(),
        chain_id: 1337,
        epoch: 0,
        keystore: "keystore.json".into(),
    };
    let rpc = RpcClient::new(&url).unwrap();
    let outcome = sync::sync_rpc(&dir, &cfg, &rpc).unwrap();
    assert_eq!(
        outcome,
        SyncOutcome::Verified {
            height: 4,
            hash: header.hash(),
        }
    );

    let mut bad = seals_for(&signers, &header, 3);
    bad[0].signature = Signature([7u8; 64]);
    let header_rpc = header.clone();
    let committee_rpc = committee.clone();
    let url = serve(move |method, _params| match method {
        "kovanica_getLeaderHeader" => leader_header_json(&header_rpc),
        "kovanica_getCommitSeals" => {
            seals_json(header_rpc.committed_height, Some(header_rpc.hash()), &bad)
        }
        "kovanica_getCommittee" => committee_json(&committee_rpc),
        _ => Value::Null,
    });
    let dir = tempfile_dir();
    let cfg = LightConfig {
        rpc: url.clone(),
        chain_id: 1337,
        epoch: 0,
        keystore: "keystore.json".into(),
    };
    let err = sync::sync_rpc(&dir, &cfg, &RpcClient::new(&url).unwrap()).unwrap_err();
    assert!(err.to_string().contains("rejected"));
    assert!(sync::load_header(&dir).unwrap().is_none());
}

#[test]
fn an_account_proof_confirms_the_recipient_and_a_transfer_roundtrips() {
    let (_signers, committee) = keys(4);
    let address = Address([7u8; 32]);
    let mut tree = AccountSmt::empty();
    tree.insert(address, 25, 2);
    let proof = tree.prove(&address, 25, 2, true);
    let header = header_for(&committee, 3, Hash::zero(), tree.root());
    let state = StateProof {
        state_root: tree.root(),
        address,
        balance: 25,
        nonce: 2,
        present: true,
        siblings: proof.siblings.to_vec(),
    };
    confirm_account(&header, 3, &state).unwrap();
    let mut lie = state.clone();
    lie.balance = 26;
    assert!(confirm_account(&header, 3, &lie).is_err());

    let signer = SigningKey::from_bytes(&[9u8; 32]);
    let sender = Address::from_public_key(&PublicKey::from(signer.verifying_key()));
    let tx = signed_transfer(1337, &signer, sender, address, 10, 1, 1);
    let raw = encode_raw(&tx).unwrap();
    let bytes = hex::decode(raw.strip_prefix("0x").unwrap()).unwrap();
    let decoded: kovanica_types::Transaction = bincode::deserialize(&bytes).unwrap();
    assert_eq!(decoded.hash, tx.hash);
    assert!(decoded.verify_signature(&kovanica_types::SigningContext::new(1337)));
    assert!(!decoded.verify_signature(&kovanica_types::SigningContext::new(2)));
}

fn committee_json(committee: &Committee) -> Value {
    Value::Array(
        committee
            .authorities
            .iter()
            .map(|authority| {
                json!({
                    "index": authority.index,
                    "address": authority.address.to_string(),
                    "stake": format!("0x{:x}", authority.stake),
                    "publicKey": format!("0x{}", hex::encode(authority.public_key.as_bytes())),
                    "network_address": "",
                })
            })
            .collect(),
    )
}

fn tempfile_dir() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "kovanica-lightnode-{}-{}",
        std::process::id(),
        next_id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn next_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static ID: AtomicU64 = AtomicU64::new(1);
    ID.fetch_add(1, Ordering::Relaxed)
}

fn serve(handler: impl Fn(&str, &Value) -> Value + Send + 'static) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for _ in 0..8 {
            let Ok((mut sock, _)) = listener.accept() else {
                break;
            };
            sock.set_read_timeout(Some(Duration::from_secs(2))).ok();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                match sock.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let header = String::from_utf8_lossy(&buf[..end]);
                            let len = content_length(&header);
                            if buf.len() >= end + 4 + len {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            let text = String::from_utf8_lossy(&buf);
            let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
            let request: Value = serde_json::from_str(body).unwrap_or(json!({}));
            let method = request["method"].as_str().unwrap_or("");
            let result = handler(method, &request["params"]);
            let resp_body = serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": result,
            }))
            .unwrap();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                resp_body.len()
            );
            let _ = sock.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

fn content_length(header: &str) -> usize {
    header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}
