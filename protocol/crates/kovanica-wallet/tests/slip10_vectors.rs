//! Known-answer vectors for the frozen Kovanica key derivation.
//!
//! Two independent layers are pinned here:
//!
//! 1. The primitives are real SLIP-0010. The official ed25519 spec vectors
//!    are asserted in the `slip10` unit tests, so the name is verified, rather
//!    than merely asserted.
//! 2. The Kovanica path `m/44'/3007'/0'/0'/i'`, applied to 64 bytes of BIP-39
//!    master material, is pinned below at indices 0, 1 and 2. An end-to-end
//!    vector then runs all the way through, to a rendered address.
//!
//! These constants are mirrors, not the origin. The authoritative copies live
//! in the SDK crate `kovanica-keys`, and in the TypeScript web wallet. The
//! path itself is specified in `docs/DERIVATION.md`. Any implementation that
//! drifts fails one of these suites, loudly.
//!
//! This file guards a real incident. Derivation used to be duplicated across
//! two binaries, and the copies disagreed: one used this path, while the other
//! truncated the material, to its first 32 bytes. The same key file therefore
//! resolved to a different address, depending on which binary read it.
//!
//! Every input is a zero-entropy test phrase, built from entropy bytes so that
//! no sensitive literal appears in source. These are never real wallets.

use bip39::Mnemonic;
use kovanica_wallet::{bip39_material, slip10, Wallet};

/// Zero-entropy 128-bit entropy: the canonical 12-word test phrase.
fn zero_phrase() -> Mnemonic {
    Mnemonic::from_entropy_in(bip39::Language::English, &[0u8; 16]).expect("valid entropy length")
}

/// The 64-byte BIP-39 master material for the zero-entropy phrase.
fn zero_material(passphrase: &str) -> [u8; 64] {
    bip39_material(&zero_phrase().to_string(), passphrase).expect("valid phrase")
}

fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

// --- Official SLIP-0010 ed25519 spec vectors ----------------------------

/// Test vector 1 from the SLIP-0010 specification, whose input is 16 raw bytes
/// rather than a 64-byte BIP-39 output. The spec lists the key at every node of
/// the chain, so walking the prefixes checks the whole walk and not just the
/// leaf.
#[test]
fn official_spec_vector_1() {
    let material = [
        0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    let expected: &[(&[u32], &str)] = &[
        (
            &[],
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
        ),
        (
            &[0],
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
        ),
        (
            &[0, 1],
            "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
        ),
        (
            &[0, 1, 2],
            "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
        ),
        (
            &[0, 1, 2, 2],
            "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
        ),
        (
            &[0, 1, 2, 2, 1_000_000_000],
            "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
        ),
    ];

    for (path, key) in expected {
        assert_eq!(
            &hex32(&slip10::derive_path(&material, path)),
            key,
            "path {path:?}"
        );
    }
}

// --- Frozen Kovanica path: m/44'/3007'/0'/0'/i' ---------------------------

#[test]
fn frozen_path_index_0() {
    let key = slip10::derive_ed25519(&zero_material(""), 0);
    assert_eq!(
        hex32(&key),
        "99d5e3a2a167ffae4407e9485105f301ab88d49ec9951f008eb7840ffded804d"
    );
}

#[test]
fn frozen_path_index_1() {
    let key = slip10::derive_ed25519(&zero_material(""), 1);
    assert_eq!(
        hex32(&key),
        "58b3767fe602f53bb4ff9082c72e76d92acf9b4d966159fb42a3898f0ee822d7"
    );
}

#[test]
fn frozen_path_index_2() {
    let key = slip10::derive_ed25519(&zero_material(""), 2);
    assert_eq!(
        hex32(&key),
        "2ac511aa2558e239e00191802f26a7498890744718849df701d4ffb027ab348e"
    );
}

#[test]
fn frozen_path_constants_match_the_spec() {
    assert_eq!(kovanica_wallet::SLIP44_COIN_TYPE, 3007);
    assert_eq!(kovanica_wallet::DERIVATION_ACCOUNT, 0);
    assert_eq!(kovanica_wallet::DERIVATION_PATH, "m/44'/3007'/0'/0'/i'");
    assert_eq!(kovanica_wallet::DEFAULT_ADDRESS_INDEX, 0);
}

// --- End to end: phrase -> key -> address ---------------------------------

/// The default account of the zero-entropy phrase, pinned at every stage.
///
/// This is the vector that catches a truncation bug: a different rule yields a
/// different public key, and therefore a different address.
#[test]
fn zero_phrase_default_account_end_to_end() {
    let wallet = Wallet::from_mnemonic(&zero_phrase().to_string()).expect("valid phrase");

    assert_eq!(
        hex32(&wallet.public_key()),
        "862f70cfafc9b581699f8d67598eac699cbc92bdfc940e95ed7ee1e8d8100e7e"
    );
    assert_eq!(
        wallet.address().to_hex(),
        "00862f70cfafc9b581699f8d67598eac699cbc92bdfc940e95ed7ee1e8d8100e7e"
    );
    assert_eq!(
        wallet.address().to_kvnc(),
        "kvnc1A2ob7wBpGDrzuyLudnqwMyiqgwKhdN8RtcVGbTChbtvZdag"
    );

    // The chain is pinned end to end by the literals above: `frozen_path_index_0`
    // pins the derived material, and the public-key and address literals here
    // pin material -> public key -> rendered address. That these belong to the
    // same phrase is covered by `from_seed_agrees_with_derivation` and
    // `public_key_is_the_address_payload` in the crate's unit tests.
}

/// The rendered address must survive a parse round-trip: a base58 regression
/// would otherwise silently hand users an unspendable address.
#[test]
fn rendered_address_round_trips() {
    let address = Wallet::from_mnemonic(&zero_phrase().to_string())
        .expect("valid phrase")
        .address();
    let parsed = kovanica_state::Address::parse(&address.to_kvnc()).expect("kvnc form parses");
    assert_eq!(parsed, address);
    assert_eq!(parsed.to_kvnc(), address.to_kvnc());
}

// --- Passphrase behaviour ------------------------------------------------

#[test]
fn passphrase_changes_every_index() {
    let plain = zero_material("");
    let salted = zero_material("test passphrase");
    assert_ne!(
        plain, salted,
        "a passphrase must change the master material"
    );
    for index in [0u32, 1, 2] {
        assert_ne!(
            slip10::derive_ed25519(&plain, index),
            slip10::derive_ed25519(&salted, index),
            "passphrase must change the key at index {index}"
        );
    }
}

#[test]
fn wrong_passphrase_never_matches() {
    let phrase = zero_phrase().to_string();
    let right = Wallet::from_mnemonic_with_passphrase(&phrase, "hunter2").unwrap();
    let wrong = Wallet::from_mnemonic_with_passphrase(&phrase, "hunter3").unwrap();
    let none = Wallet::from_mnemonic(&phrase).unwrap();
    assert_ne!(right.address(), wrong.address());
    assert_ne!(right.address(), none.address());
}

// --- Properties ----------------------------------------------------------

#[test]
fn different_indices_differ() {
    let material = zero_material("");
    let mut seen: Vec<[u8; 32]> = Vec::new();
    for index in 0..8u32 {
        let key = slip10::derive_ed25519(&material, index);
        assert!(!seen.contains(&key), "index {index} collided");
        seen.push(key);
    }
}

#[test]
fn derivation_is_deterministic() {
    let material = zero_material("");
    assert_eq!(
        slip10::derive_ed25519(&material, 3),
        slip10::derive_ed25519(&material, 3)
    );
}

/// Round-trip generate, then restore, must be byte-identical at every
/// passphrase, and an explicit index must agree with the default while a
/// different index gives a different address.
///
/// Generation is random, so the phrase under test is the one the wallet reports
/// — restoring a fixed fixture here would only test the fixture.
#[test]
fn roundtrip_generate_restore_same_keys() {
    for words in [12usize, 24] {
        for generation_passphrase in ["", "round trip"] {
            let generated =
                Wallet::generate_with_mnemonic_words(words, generation_passphrase).unwrap();
            let phrase = generated
                .mnemonic()
                .expect("generated wallet has a phrase")
                .to_string();
            assert_eq!(phrase.split(' ').count(), words);

            // Restoring with the generating passphrase must reproduce the key.
            assert_eq!(
                Wallet::from_mnemonic_with_passphrase(&phrase, generation_passphrase)
                    .unwrap()
                    .address(),
                generated.address(),
                "{words} words / {generation_passphrase:?}"
            );

            // The default index and explicit index 0 must agree.
            let at_zero = Wallet::from_mnemonic_at(&phrase, generation_passphrase, 0).unwrap();
            assert_eq!(at_zero.address(), generated.address());

            // Any other index must not.
            for index in [1u32, 7, 4_294_967_295] {
                let other =
                    Wallet::from_mnemonic_at(&phrase, generation_passphrase, index).unwrap();
                assert_ne!(other.address(), generated.address(), "index {index}");
            }

            // A passphrase the wallet was not generated under never matches.
            for wrong in ["", "hunter2", "Round Trip"] {
                let other = Wallet::from_mnemonic_with_passphrase(&phrase, wrong).unwrap();
                if wrong != generation_passphrase {
                    assert_ne!(other.address(), generated.address(), "{wrong:?}");
                }
            }
        }
    }
}
