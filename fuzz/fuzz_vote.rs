//! Fuzzing harness for Vote deserialization
#![no_main]
use libfuzzer_sys::fuzz_target;
use kovanica_types::Vote;
use bincode;

fuzz_target!(|data: &[u8]| {
    // Try to deserialize as Vote
    if let Ok(vote) = bincode::deserialize::<Vote>(data) {
        let _ = vote.leader_round;
        let _ = vote.voter;
        let _ = vote.leader_hash;
    }
});