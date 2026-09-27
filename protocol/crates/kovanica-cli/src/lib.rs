//! Kovanica CLI library — API client and wallet re-export.
//!
//! Two things live here, both of which the `kovanica` binary consumes and both
//! of which are useful to any other client of the explorer JSON API:
//!
//! * [`api`] — a thin HTTP client mirroring the node's `/api/*` surface. It is
//!   deliberately *complete* rather than minimal: it covers every endpoint the
//!   explorer exposes, including ones no screen surfaces yet (multisig, RWA
//!   detail, fee estimation, faucet). Keeping it in the library is what makes
//!   that legitimate — as binary-only code those methods would be dead code.
//! * [`Wallet`] — re-exported from [`kovanica_wallet`], which is also what the
//!   node uses for genesis keys. Re-exporting keeps `kovanica_cli::Wallet`
//!   working for existing callers while there is exactly one implementation of
//!   key derivation in the tree.

pub mod api;

pub use kovanica_wallet::Wallet;
