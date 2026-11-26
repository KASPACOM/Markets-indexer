//! TN12 RPC clients.
//!
//! Used to live in a dedicated `tn12-indexer-rpc` crate; folded into
//! `tn12-indexer-crawl` 2026-05-13 because the crate was a thin shim
//! (one HTTP client + a few serde types) used only by the crawl/watch
//! /scan path. Keeping it inside the crate that consumes it removes a
//! workspace member without losing anything.
//!
//! Two surfaces:
//!   * wRPC (`ws://tn12-node.kaspa.com:17210`) — live block stream + UTXO
//!     entries (where `entry.covenantId` is exposed, per rusty-kaspa
//!     v1.1.0-rc.3). Lands with Phase 1c-v2.
//!   * REST (`https://api-tn12.kaspa.org`) — what the watcher + scanner
//!     use today.

pub mod rest;

pub use rest::RestClient;
// Types now live in `tn12_indexer_core::rest_types` (so the `db` crate can
// depend on them without a cycle through `crawl`). Re-export for callers
// that imported them from `tn12-indexer-rpc` historically.
pub use tn12_indexer_core::{RestBlock, RestTransaction, RestTxInput, RestTxOutput};
