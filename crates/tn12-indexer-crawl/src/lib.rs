//! TN12 covenant-detection engine.
//!
//! v1 (this module) runs against captured REST transactions. v2 (deferred) wires
//! the same engine behind the wRPC live subscription + reorg handler.
//!
//! Contract:
//!   Feed `Engine::process_tx(tx)` a `RestTransaction`. It emits zero or more
//!   `CovenantEvent`s describing what happened: deploys, spends, continuations.
//!   The engine keeps an in-memory registry of known covenant UTXOs so spends
//!   resolve to a covenant id.

pub mod engine;
pub mod live_recovery;
pub mod live_supervisor;
mod recovery_policy;
pub mod recovery_state;
pub mod reorg;
pub mod rest_replay_fence;
pub mod rpc;
pub mod scan;
pub mod source_observation;
pub mod tip;
pub mod watch;
pub mod wrpc;

pub use engine::{
    CovenantEvent, CovenantSummary, EngineSnapshot, EventKind, IndexerEngine, KnownCovenant,
};
pub use reorg::{ReorgHandler, ReorgStats};
pub use rpc::{RestBlock, RestClient, RestTransaction, RestTxInput, RestTxOutput};
pub use scan::{ChainScanner, CursorStore, PgCursorStore, ScannerConfig};
pub use tip::{ChainTipFollower, TipFollowerConfig, TipFollowerStats};
pub use watch::{AddressWatcher, PersistStatsAccum, TickStats, WatcherConfig};
pub use wrpc::{WrpcVirtualChainWatcher, WrpcWatcherConfig, WrpcWatcherStats};

pub mod durable_inbox;
pub mod bounded_wrpc_intake;
pub mod bounded_notification;
pub mod durable_join;
pub mod durable_consumer;
pub mod shadow_source;

mod cached_prevout;
