//! Phase 8.2 CLI — delegation commands (delegate / claim-rewards).
//! Deterministic output; no HashMap ordering; tokenomics untouched.
//!
//! `stake` / `unstake` / `delegate` / `claim-rewards` are implemented as signed native
//! transactions that go out over the ordinary `kovanica_sendRawTransaction` path.
//! Private key material never leaves the machine.
//!
//! `kovanica staking <address>` is read-only. It calls the existing
//! `kovanica_getStake`, `kovanica_getRewards`, and `kovanica_getValidators`
//! methods. `getStake` is one total (own validator stake plus delegations).
//! The node does not return one row per delegation.
//!
//! The actual command implementations are in `main.rs` using the shared
//! `sign_and_submit_self` helper for consistency with `stake`/`unstake`.
