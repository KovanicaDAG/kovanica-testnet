//! Unit tests for the wave arithmetic helpers in `kovanica-consensus`:
//! `wave_of`, `offset_in_wave`, `is_leader_round`.
//!
//! Wave length is 3: offset 0 = leader round, 1 = vote round, 2 = decide round.

use kovanica_consensus::{is_leader_round, offset_in_wave, wave_of};
use kovanica_types::WAVE_LENGTH;

#[test]
fn test_wave_length_is_three() {
    // Wave length 3 is a protocol constant (leader / vote / decide).
    assert_eq!(WAVE_LENGTH, 3);
}

#[test]
fn test_wave_of_exact_values() {
    // Wave 0: rounds 0,1,2
    assert_eq!(wave_of(0), 0);
    assert_eq!(wave_of(1), 0);
    assert_eq!(wave_of(2), 0);
    // Wave 1: rounds 3,4,5
    assert_eq!(wave_of(3), 1);
    assert_eq!(wave_of(4), 1);
    assert_eq!(wave_of(5), 1);
    // Wave 2 starts at round 6
    assert_eq!(wave_of(6), 2);
    // Boundary: last round of wave 99 is 299
    assert_eq!(wave_of(299), 99);
    assert_eq!(wave_of(300), 100);
    // Large round
    assert_eq!(wave_of(1_000_000), 1_000_000 / 3);
}

#[test]
fn test_offset_in_wave_exact_values() {
    assert_eq!(offset_in_wave(0), 0); // leader
    assert_eq!(offset_in_wave(1), 1); // vote
    assert_eq!(offset_in_wave(2), 2); // decide
    assert_eq!(offset_in_wave(3), 0);
    assert_eq!(offset_in_wave(4), 1);
    assert_eq!(offset_in_wave(5), 2);
    assert_eq!(offset_in_wave(7), 1);
    assert_eq!(offset_in_wave(299), 2);
    assert_eq!(offset_in_wave(300), 0);
    assert_eq!(offset_in_wave(1_000_002), 0);
}

#[test]
fn test_is_leader_round_exact_values() {
    for round in 0..24u64 {
        let expected = round % 3 == 0;
        assert_eq!(
            is_leader_round(round),
            expected,
            "round {round} should have is_leader_round = {expected}"
        );
    }
    assert!(is_leader_round(0));
    assert!(is_leader_round(3));
    assert!(is_leader_round(999));
    assert!(!is_leader_round(1));
    assert!(!is_leader_round(2));
    assert!(!is_leader_round(1000));
}

/// Round-to-wave mapping must be an exact decomposition:
/// `round = wave_of(r) * WAVE_LENGTH + offset_in_wave(r)`.
#[test]
fn test_wave_decomposition_identity_over_large_range() {
    for round in 0..=10_000u64 {
        let wave = wave_of(round);
        let offset = offset_in_wave(round);
        assert_eq!(wave * WAVE_LENGTH + offset, round, "round {round}");
        assert!(offset < WAVE_LENGTH, "offset out of range at round {round}");
        assert_eq!(wave, round / WAVE_LENGTH);
    }
}

/// Leader rounds are exactly the rounds with offset 0.
#[test]
fn test_leader_rounds_are_exactly_offset_zero() {
    for round in 0..=10_000u64 {
        assert_eq!(
            is_leader_round(round),
            offset_in_wave(round) == 0,
            "round {round}"
        );
        assert_eq!(is_leader_round(round), round % WAVE_LENGTH == 0);
    }
}

/// `wave_of` never decreases as rounds increase (monotonicity of waves).
#[test]
fn test_wave_of_monotone() {
    let mut prev = 0u64;
    for round in 0..=5_000u64 {
        let wave = wave_of(round);
        assert!(
            wave >= prev,
            "wave decreased at round {round}: {prev} -> {wave}"
        );
        prev = wave;
    }
}

/// Decomposition must also hold at the very top of the u64 range without
/// overflow (wave * WAVE_LENGTH + offset reconstructs the round exactly).
#[test]
fn test_wave_decomposition_at_u64_boundary() {
    let max_wave = u64::MAX / WAVE_LENGTH;
    let last_full_round = max_wave * WAVE_LENGTH;
    for round in last_full_round..=u64::MAX {
        let wave = wave_of(round);
        let offset = offset_in_wave(round);
        assert!(offset < WAVE_LENGTH);
        // wave * WAVE_LENGTH <= round, so this multiplication cannot overflow.
        assert_eq!(wave * WAVE_LENGTH + offset, round, "round {round}");
    }
    assert_eq!(wave_of(last_full_round), max_wave);
    assert_eq!(offset_in_wave(last_full_round), 0);
    assert!(is_leader_round(last_full_round));
}

/// Each wave contains exactly one leader round (offset 0) and the wave index
/// advances exactly every WAVE_LENGTH rounds.
#[test]
fn test_one_leader_round_per_wave() {
    for wave in 0..100u64 {
        let leader_round = wave * WAVE_LENGTH;
        assert!(is_leader_round(leader_round));
        assert_eq!(wave_of(leader_round), wave);
        // The other two rounds of the wave are not leader rounds.
        for offset in 1..WAVE_LENGTH {
            let round = leader_round + offset;
            assert!(!is_leader_round(round));
            assert_eq!(wave_of(round), wave);
            assert_eq!(offset_in_wave(round), offset);
        }
    }
}
