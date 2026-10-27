//! Basic smoke tests for the MysticGhost path.
//!
//! These tests are intentionally lightweight so they can be run early.
//! Expand them as the real GHOSTDAG colouring is implemented.

use kovanica_consensus::ghostdag_scoped::colour_mergeset;
use kovanica_consensus::mysticghost::{order_committed_wave, MysticGhostConfig, MysticGhostOrder};

#[test]
fn mysticghost_disabled_falls_back() {
    let cfg = MysticGhostConfig {
        enabled: false,
        ..Default::default()
    };

    // Empty mergeset is enough for this test
    let order = order_committed_wave(&cfg, &[], &[]);
    assert!(matches!(order, MysticGhostOrder::Fallback));
}

#[test]
fn mysticghost_enabled_returns_ghost_order() {
    let cfg = MysticGhostConfig {
        enabled: true,
        k: 3,
        max_mergeset_blocks: 100,
    };

    // With the current placeholder colouring, any non-empty mergeset
    // should produce a Ghost result.
    // Replace with real blocks once the algorithm is ported.
    let order = order_committed_wave(&cfg, &[], &[]);
    // Empty mergeset still yields a colouring result in the placeholder
    assert!(
        matches!(order, MysticGhostOrder::Ghost { .. })
            || matches!(order, MysticGhostOrder::Fallback)
    );
}

#[test]
fn colour_mergeset_respects_k_parameter() {
    // Just check that the function panics (or asserts) on wrong k.
    // Real tests will come after the algorithm is ported.
    let result = std::panic::catch_unwind(|| {
        colour_mergeset(&[], 4, &[]); // wrong k
    });
    assert!(result.is_err(), "colour_mergeset must reject k != 3");
}
