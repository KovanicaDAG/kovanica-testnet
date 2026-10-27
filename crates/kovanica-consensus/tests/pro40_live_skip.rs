//! Five validators, real round timers, one offline leader.
//!
//! The other PRO-40 PR 4 cases already sit on this branch, next to the engine:
//! `failed_vote_write_is_not_broadcast`,
//! `restart_after_min_digest_swap_does_not_vote_the_replacement`,
//! `restart_after_own_vote_refuses_the_timeout`, and
//! `the_own_timeout_lock_survives_a_restart`.
//! The epoch-boundary certificate case is
//! `epoch_boundary_skip_certs_bind_epoch_of_the_round`.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use common::{committee, make_engine, MockBlockManager, MockDag};
use kovanica_consensus::{
    BlockBroadcaster, ConsensusConfig, ConsensusEngine, ConsensusError, TimeoutBroadcaster,
    VoteRejection,
};
use kovanica_types::block::StatementBlock;
use kovanica_types::{Round, SkipCert, Timeout, Vote};

type Engine = ConsensusEngine<MockDag, MockBlockManager>;

enum Wire {
    Block(StatementBlock),
    Vote(Vote),
    Timeout(Timeout),
    Cert(SkipCert),
}

struct Bus {
    tx: mpsc::Sender<Wire>,
    timeouts: Arc<AtomicUsize>,
    certs: Arc<AtomicUsize>,
}

impl BlockBroadcaster for Bus {
    fn broadcast_block(&self, block: &StatementBlock) {
        let _ = self.tx.send(Wire::Block(block.clone()));
    }
}

impl kovanica_consensus::VoteBroadcaster for Bus {
    fn broadcast_vote(&self, vote: &Vote) {
        let _ = self.tx.send(Wire::Vote(vote.clone()));
    }
}

impl TimeoutBroadcaster for Bus {
    fn broadcast_timeout(&self, timeout: &Timeout) {
        self.timeouts.fetch_add(1, Ordering::SeqCst);
        let _ = self.tx.send(Wire::Timeout(timeout.clone()));
    }

    fn broadcast_skip_cert(&self, cert: &SkipCert) {
        self.certs.fetch_add(1, Ordering::SeqCst);
        let _ = self.tx.send(Wire::Cert(cert.clone()));
    }
}

fn deliver(
    engines: &[Arc<Engine>],
    origin: usize,
    silent: usize,
    wire: &Wire,
    errors: &std::sync::Mutex<Vec<String>>,
) {
    for (index, engine) in engines.iter().enumerate() {
        // `silent` is the offline leader: it is not running and it is not a
        // gossip recipient. Delivering to it would move its commit cursor
        // without it ever proposing.
        if index == origin || index == silent {
            continue;
        }
        let result = match wire {
            Wire::Block(block) => engine.process_block(block).map(|_| ()),
            Wire::Vote(vote) => match engine.process_vote(vote) {
                Ok(()) => Ok(()),
                Err(ConsensusError::VoteRejected(VoteRejection::Duplicate { .. })) => Ok(()),
                Err(e) => Err(e),
            },
            Wire::Timeout(timeout) => engine.process_timeout(timeout),
            Wire::Cert(cert) => engine.process_skip_cert(cert),
        };
        if let Err(e) = result {
            let mut errors = errors.lock().expect("error log");
            if errors.len() < 16 {
                errors.push(format!("node {origin} -> {index}: {e}"));
            }
        }
    }
}

/// The leader of slot 3 never starts and receives no gossip. The other four
/// run the real round loop, time the slot out, build a skip certificate, and
/// commit the next leader.
#[tokio::test]
async fn five_nodes_with_real_timers_skip_an_offline_leader_and_keep_committing() {
    const N: usize = 5;
    let members = committee(N as u16);
    let offline = members.leader(3) as usize;
    let next_leader = members.leader(6) as usize;
    assert_eq!(members.quorum_threshold(), 4, "4 of 5 is the skip quorum");
    assert_ne!(offline, next_leader, "the next leader has to be online");

    let config = ConsensusConfig {
        round_duration_ms: 20,
        // T_skip = 8 rounds = 160 ms after the vote round. Long enough that
        // the following leader's block and votes arrive before its own timer,
        // short enough that the skipped slot resolves inside this test.
        skip_timeout_rounds: 8,
        lookahead_rounds: 24,
        use_vrf_leader: false,
        use_min_digest_fork: false,
        leader_timeout_ms: 60_000,
        ..ConsensusConfig::default()
    };

    let (tx, rx) = mpsc::channel();
    let timeouts = Arc::new(AtomicUsize::new(0));
    let certs = Arc::new(AtomicUsize::new(0));
    let mut engines = Vec::with_capacity(N);
    let mut managers = Vec::with_capacity(N);
    let mut commit_rx = Vec::with_capacity(N);
    for index in 0..N {
        let (engine, _dag, manager) = make_engine(index as u16, members.clone(), config.clone());
        let bus = Arc::new(Bus {
            tx: tx.clone(),
            timeouts: timeouts.clone(),
            certs: certs.clone(),
        });
        engine.set_block_broadcaster(bus.clone());
        engine.set_vote_broadcaster(bus.clone());
        engine.set_timeout_broadcaster(bus);
        let (commit_tx, rx) = tokio::sync::mpsc::unbounded_channel();
        engine.set_commit_sender(commit_tx);
        engines.push(Arc::new(engine));
        managers.push(manager);
        commit_rx.push(rx);
    }
    drop(tx);

    let engines_for_bus = engines.clone();
    let bus_errors = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let errors_for_bus = bus_errors.clone();
    let router = tokio::spawn(async move {
        loop {
            match rx.try_recv() {
                Ok(wire) => {
                    // Attribute by author/voter when we have one, so a node
                    // does not apply its own broadcast twice. Certificates
                    // have no single author; every running engine sees them.
                    // The offline leader is excluded in `deliver`.
                    let origin = match &wire {
                        Wire::Block(block) => block.author as usize,
                        Wire::Vote(vote) => vote.voter as usize,
                        Wire::Timeout(timeout) => timeout.voter as usize,
                        Wire::Cert(_) => usize::MAX,
                    };
                    deliver(&engines_for_bus, origin, offline, &wire, &errors_for_bus);
                }
                Err(mpsc::TryRecvError::Empty) => {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }
    });

    let mut tasks = Vec::new();
    for (index, engine) in engines.iter().cloned().enumerate() {
        if index == offline {
            continue;
        }
        tasks.push(tokio::spawn(async move { engine.start().await }));
    }

    let online: Vec<usize> = (0..N).filter(|index| *index != offline).collect();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut committed: Vec<Vec<Round>> = vec![Vec::new(); N];
    let mut failed = String::new();
    while Instant::now() < deadline {
        for (index, rx) in commit_rx.iter_mut().enumerate() {
            while let Ok(subdag) = rx.try_recv() {
                committed[index].push(subdag.leader_round);
            }
        }
        let ready = online.iter().all(|index| {
            engines[*index].last_decided_round() >= 6 && committed[*index].contains(&6)
        });
        if ready {
            failed.clear();
            break;
        }
        failed = online
            .iter()
            .map(|index| {
                format!(
                    "node {index} decided {} commits {:?}",
                    engines[*index].last_decided_round(),
                    committed[*index]
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    for engine in &engines {
        engine.stop();
    }
    for task in tasks {
        match tokio::time::timeout(Duration::from_secs(2), task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => panic!("round loop failed: {e}"),
            Ok(Err(e)) => panic!("round loop task join: {e}"),
            Err(_) => panic!("round loop did not stop"),
        }
    }
    tokio::time::sleep(Duration::from_millis(30)).await;
    let bus_errors = bus_errors.lock().expect("error log").clone();
    router.abort();

    assert!(
        failed.is_empty(),
        "offline leader {offline} was not skipped within 20s ({failed}); timeouts {}, certs {}, delivery {bus_errors:?}",
        timeouts.load(Ordering::SeqCst),
        certs.load(Ordering::SeqCst)
    );
    assert!(
        bus_errors.is_empty(),
        "gossip delivery failed: {bus_errors:?}"
    );
    assert!(
        timeouts.load(Ordering::SeqCst) >= 4,
        "each online node signs a timeout from its own timer"
    );
    assert!(
        certs.load(Ordering::SeqCst) >= 1,
        "a skip certificate was gossiped"
    );
    assert_eq!(
        managers[offline].read().propose_calls(),
        0,
        "the offline leader proposed nothing"
    );
    assert!(
        !managers[offline].read().signing_key_set(),
        "the offline leader never started"
    );
    assert_eq!(engines[offline].current_round(), 0);
    assert_eq!(engines[offline].last_decided_round(), 0);
    for index in (0..N).filter(|index| *index != offline) {
        assert!(
            committed[index].contains(&6),
            "node {index} did not commit the next leader: {:?}",
            committed[index]
        );
        assert!(
            committed[index].iter().all(|round| *round != 3),
            "node {index} committed the skipped slot: {:?}",
            committed[index]
        );
        assert!(engines[index].last_decided_round() >= 6);
    }
}
