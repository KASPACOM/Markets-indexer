//! A byte-bounded body cache for the durable consumer. It never owns acceptance
//! progress: missing or evicted bodies leave the original inbox receipt pending.
use anyhow::{ensure, Context, Result};
#[path = "durable_event.rs"]
mod event;
pub use event::DurableEventPlan;
#[path = "durable_continuity.rs"]
mod continuity;
pub use continuity::ContiguousEventPlan;
use kaspa_addresses::Prefix;
use kaspa_wrpc_client::prelude::{RpcAcceptedTransactionIds, RpcBlock};
use std::collections::BTreeMap;
use tn12_indexer_core::{RestTransaction, RestTxInput, RestTxOutput};

// Reserve the rest of the 128 MiB application envelope for decoded frames,
// prepared effects, serialization and transport. These are cache limits only;
// the controller must enforce the aggregate envelope before activation.
pub const JOIN_CACHE_BYTES: usize = 32 * 1024 * 1024;
pub const JOIN_EFFECT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockCoordinates {
    pub hash: String,
    pub blue_score: u64,
    pub timestamp: u64,
    pub selected_parent: Option<String>,
}

enum Key {
    Transaction(String),
    Block(String),
}

pub struct DurableJoin {
    transactions: BTreeMap<String, (RestTransaction, usize)>,
    blocks: BTreeMap<String, BlockCoordinates>,
    order: BTreeMap<u64, Key>,
    next_order: u64,
    used: usize,
    limit: usize,
}

impl DurableJoin {
    pub fn new(limit: usize) -> Result<Self> {
        ensure!(
            (8192..=JOIN_CACHE_BYTES).contains(&limit),
            "unsupported join cache budget"
        );
        Ok(Self {
            transactions: BTreeMap::new(),
            blocks: BTreeMap::new(),
            order: BTreeMap::new(),
            next_order: 0,
            used: 0,
            limit,
        })
    }

    pub fn charged_bytes(&self) -> usize {
        self.used
    }

    pub fn coordinates(&self, hash: &str) -> Option<&BlockCoordinates> {
        self.blocks.get(hash)
    }

    /// May evict old bodies, including bodies mentioned by a pending receipt.
    /// No acceptance is removed: resolve returns None until all bodies exist.
    pub fn remember_block(&mut self, block: &RpcBlock, prefix: Prefix) -> Result<()> {
        let hash = block.header.hash.to_string();
        let selected_parent = if let Some(verbose) = &block.verbose_data {
            ensure!(
                verbose.hash == block.header.hash && verbose.blue_score == block.header.blue_score,
                "block coordinates disagree with verbose metadata"
            );
            ensure!(
                block
                    .header
                    .parents_by_level
                    .first()
                    .is_some_and(|parents| parents.contains(&verbose.selected_parent_hash)),
                "selected parent is not a direct block parent"
            );
            Some(verbose.selected_parent_hash.to_string())
        } else {
            None
        };
        if let Some(existing) = self.blocks.get_mut(&hash) {
            ensure!(
                existing.blue_score == block.header.blue_score
                    && existing.timestamp == block.header.timestamp,
                "duplicate block coordinates disagree"
            );
            ensure!(
                existing.selected_parent.is_none()
                    || selected_parent.is_none()
                    || existing.selected_parent == selected_parent,
                "duplicate selected parent disagrees"
            );
            if existing.selected_parent.is_none() {
                existing.selected_parent = selected_parent.clone();
            }
        }
        if !self.blocks.contains_key(&hash) {
            self.reserve(2048)?;
            self.blocks.insert(
                hash.clone(),
                BlockCoordinates {
                    hash: hash.clone(),
                    blue_score: block.header.blue_score,
                    timestamp: block.header.timestamp,
                    selected_parent,
                },
            );
            self.push_order(Key::Block(hash))?;
        }
        for rpc in &block.transactions {
            let tx = crate::wrpc::rpc_transaction_to_rest(rpc, block, prefix)?;
            self.remember_transaction(tx)?;
        }
        Ok(())
    }

    fn remember_transaction(&mut self, tx: RestTransaction) -> Result<()> {
        // A transaction can appear in many DAG blocks. Repeated bodies do not
        // allocate a second FIFO key or let duplicate traffic grow the cache.
        if self.transactions.contains_key(&tx.transaction_id) {
            return Ok(());
        }
        let cost = transaction_bytes(&tx)
            .checked_add(8192)
            .context("cache charge overflow")?;
        self.reserve(cost)?;
        let id = tx.transaction_id.clone();
        self.transactions.insert(id.clone(), (tx, cost));
        self.push_order(Key::Transaction(id))?;
        Ok(())
    }

    fn push_order(&mut self, key: Key) -> Result<()> {
        let next = self
            .next_order
            .checked_add(1)
            .context("join cache sequence exhausted")?;
        self.order.insert(self.next_order, key);
        self.next_order = next;
        Ok(())
    }

    fn reserve(&mut self, cost: usize) -> Result<()> {
        ensure!(
            cost <= self.limit,
            "one body exceeds join cache budget; retain receipt for repair"
        );
        while self.used > self.limit - cost {
            match self
                .order
                .pop_first()
                .context("join cache accounting mismatch")?
                .1
            {
                Key::Transaction(id) => {
                    let (_, charge) = self
                        .transactions
                        .remove(&id)
                        .context("missing cached body")?;
                    self.used -= charge;
                }
                Key::Block(hash) => {
                    ensure!(self.blocks.remove(&hash).is_some(), "missing cached block");
                    self.used -= 2048;
                }
            }
        }
        self.used += cost;
        Ok(())
    }

    /// Resolve one complete notification without mutating cache or acceptance.
    /// None means hydrate/look ahead or reconcile; it must never authorize ack.
    pub fn resolve(
        &self,
        groups: &[RpcAcceptedTransactionIds],
    ) -> Result<Option<Vec<RestTransaction>>> {
        let mut charge = 0usize;
        let mut count = 0usize;
        for group in groups {
            if !self
                .blocks
                .contains_key(&group.accepting_block_hash.to_string())
            {
                return Ok(None);
            }
            for id in &group.accepted_transaction_ids {
                let Some((tx, _)) = self.transactions.get(&id.to_string()) else {
                    return Ok(None);
                };
                let mut hydration = 0usize;
                for input in &tx.inputs {
                    if let Some((parent, _)) = self.transactions.get(&input.previous_outpoint_hash)
                    {
                        if let Some(output) = crate::cached_prevout::compatible(input, parent) {
                            hydration = hydration
                                .checked_add(crate::cached_prevout::added_bytes(input, output))
                                .context("prevout hydration charge overflow")?;
                        }
                    }
                }
                charge = charge
                    .checked_add(transaction_bytes(tx))
                    .and_then(|v| v.checked_add(128))
                    .and_then(|v| v.checked_add(hydration))
                    .context("effect charge overflow")?;
                ensure!(
                    charge <= JOIN_EFFECT_BYTES,
                    "joined effect exceeds budget; retain receipt for repair"
                );
                count += 1;
            }
        }
        let mut ready = Vec::with_capacity(count);
        for group in groups {
            let hash = group.accepting_block_hash.to_string();
            let block = &self.blocks[&hash];
            for id in &group.accepted_transaction_ids {
                let mut tx = self.transactions[&id.to_string()].0.clone();
                tx.is_accepted = true;
                tx.accepting_block_hash = Some(hash.clone());
                tx.accepting_block_blue_score = Some(block.blue_score);
                tx.accepting_block_time = Some(block.timestamp);
                for input in &mut tx.inputs {
                    if let Some((parent, _)) = self.transactions.get(&input.previous_outpoint_hash)
                    {
                        if let Some(output) = crate::cached_prevout::compatible(input, parent) {
                            crate::cached_prevout::hydrate(input, output);
                        }
                    }
                }
                ready.push(tx);
            }
        }
        Ok(Some(ready))
    }
}

// Count owned allocations by capacity, not encoded JSON size. Container-node,
// FIFO and duplicated-key overhead is charged separately per entry above.
fn transaction_bytes(tx: &RestTransaction) -> usize {
    fn optional(v: &Option<String>) -> usize {
        v.as_ref().map_or(0, String::capacity)
    }
    std::mem::size_of::<RestTransaction>()
        + tx.transaction_id.capacity()
        + tx.subnetwork_id.capacity()
        + tx.hash.capacity()
        + tx.mass.capacity()
        + optional(&tx.payload)
        + optional(&tx.accepting_block_hash)
        + tx.block_hash.capacity() * std::mem::size_of::<String>()
        + tx.block_hash.iter().map(String::capacity).sum::<usize>()
        + tx.inputs.capacity() * std::mem::size_of::<RestTxInput>()
        + tx.inputs
            .iter()
            .map(|i| {
                i.transaction_id.capacity()
                    + i.previous_outpoint_hash.capacity()
                    + i.previous_outpoint_index.capacity()
                    + optional(&i.previous_outpoint_address)
                    + optional(&i.previous_outpoint_script)
                    + i.signature_script.capacity()
                    + i.sig_op_count.capacity()
            })
            .sum::<usize>()
        + tx.outputs.capacity() * std::mem::size_of::<RestTxOutput>()
        + tx.outputs
            .iter()
            .map(|o| {
                o.transaction_id.capacity()
                    + o.script_public_key.capacity()
                    + optional(&o.script_public_key_address)
                    + optional(&o.script_public_key_type)
                    + optional(&o.covenant_id)
                    + o.covenant.as_ref().map_or(0, |c| optional(&c.covenant_id))
            })
            .sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tx(n: u8) -> RestTransaction {
        RestTransaction {
            transaction_id: format!("{n:02x}").repeat(32),
            ..Default::default()
        }
    }
    fn group(ids: Vec<String>) -> RpcAcceptedTransactionIds {
        RpcAcceptedTransactionIds {
            accepting_block_hash: "aa".repeat(32).parse().unwrap(),
            accepted_transaction_ids: ids.iter().map(|id| id.parse().unwrap()).collect(),
        }
    }
    fn block(cache: &mut DurableJoin) {
        cache.reserve(2048).unwrap();
        cache.blocks.insert(
            "aa".repeat(32),
            BlockCoordinates {
                hash: "aa".repeat(32),
                blue_score: 10,
                timestamp: 11,
                selected_parent: None,
            },
        );
        cache.push_order(Key::Block("aa".repeat(32))).unwrap();
    }
    #[test]
    fn missing_body_leaves_whole_receipt_unresolved_then_reordered_body_completes() {
        let mut cache = DurableJoin::new(32 * 1024).unwrap();
        block(&mut cache);
        let a = tx(1);
        let b = tx(2);
        let event = vec![group(vec![
            a.transaction_id.clone(),
            b.transaction_id.clone(),
        ])];
        cache.remember_transaction(b).unwrap();
        assert!(cache.resolve(&event).unwrap().is_none());
        cache.remember_transaction(a).unwrap();
        let ready = cache.resolve(&event).unwrap().unwrap();
        assert_eq!(ready[0].transaction_id, tx(1).transaction_id);
        assert_eq!(ready[1].accepting_block_blue_score, Some(10));
        assert_eq!(cache.resolve(&event).unwrap().unwrap().len(), 2);
    }
    #[test]
    fn eviction_and_duplicates_cannot_discard_acceptance_or_grow_memory() {
        let mut cache = DurableJoin::new(32768).unwrap();
        block(&mut cache);
        let first = tx(1);
        let event = vec![group(vec![first.transaction_id.clone()])];
        cache.remember_transaction(first.clone()).unwrap();
        let charged = cache.charged_bytes();
        for _ in 0..100 {
            cache.remember_transaction(first.clone()).unwrap();
        }
        assert_eq!(cache.charged_bytes(), charged);
        for n in 2..100 {
            cache.remember_transaction(tx(n)).unwrap();
            assert!(cache.charged_bytes() <= 32768);
        }
        assert!(cache.resolve(&event).unwrap().is_none());
    }
    #[test]
    fn spare_string_and_vector_capacity_counts_before_cache_mutation() {
        let mut cache = DurableJoin::new(32768).unwrap();
        let mut large = tx(1);
        large.payload = Some(String::with_capacity(65536));
        assert!(cache.remember_transaction(large).is_err());
        assert_eq!(cache.charged_bytes(), 0);
        let mut large = tx(2);
        large.inputs = Vec::with_capacity(512);
        assert!(cache.remember_transaction(large).is_err());
        assert_eq!(cache.charged_bytes(), 0);
    }
    #[test]
    fn repeated_accepted_ids_cannot_allocate_unbounded_prepared_effect() {
        let mut cache = DurableJoin::new(32 * 1024).unwrap();
        block(&mut cache);
        let a = tx(1);
        let id = a.transaction_id.clone();
        cache.remember_transaction(a).unwrap();
        let event = vec![group(vec![id; 100_000])];
        assert!(cache
            .resolve(&event)
            .unwrap_err()
            .to_string()
            .contains("exceeds budget"));
    }
    fn family(script_bytes: usize) -> (RestTransaction, RestTransaction) {
        let mut parent = tx(1);
        parent.outputs.push(RestTxOutput {
            transaction_id: parent.transaction_id.clone(),
            index: 0,
            amount: 17,
            script_public_key: "a".repeat(script_bytes),
            script_public_key_address: Some("kaspatest:cached".into()),
            ..Default::default()
        });
        let mut child = tx(2);
        child.inputs.push(RestTxInput {
            previous_outpoint_hash: parent.transaction_id.clone(),
            previous_outpoint_index: "0".into(),
            ..Default::default()
        });
        (parent, child)
    }
    #[test]
    fn cached_prevouts_match_legacy_hydration_and_preserve_conflicts() {
        let mut cache = DurableJoin::new(JOIN_CACHE_BYTES).unwrap();
        block(&mut cache);
        let (parent, child) = family(66);
        let id = child.transaction_id.clone();
        cache.remember_transaction(parent).unwrap();
        cache.remember_transaction(child).unwrap();
        let ready = cache.resolve(&[group(vec![id.clone()])]).unwrap().unwrap();
        assert_eq!(ready[0].inputs[0].previous_outpoint_amount, Some(17));
        assert_eq!(
            ready[0].inputs[0].previous_outpoint_script,
            Some("a".repeat(66))
        );
        assert_eq!(
            ready[0].inputs[0].previous_outpoint_address,
            Some("kaspatest:cached".into())
        );
        assert!(cache.transactions[&id].0.inputs[0]
            .previous_outpoint_amount
            .is_none());
        cache.transactions.get_mut(&id).unwrap().0.inputs[0].previous_outpoint_script =
            Some("conflict".into());
        let ready = cache.resolve(&[group(vec![id])]).unwrap().unwrap();
        assert_eq!(
            ready[0].inputs[0].previous_outpoint_script.as_deref(),
            Some("conflict")
        );
        assert!(ready[0].inputs[0].previous_outpoint_amount.is_none());
    }
    #[test]
    fn hydration_is_charged_before_cloning_repeated_accepted_transactions() {
        let mut cache = DurableJoin::new(JOIN_CACHE_BYTES).unwrap();
        block(&mut cache);
        let (parent, child) = family(64 * 1024);
        let id = child.transaction_id.clone();
        cache.remember_transaction(parent).unwrap();
        cache.remember_transaction(child).unwrap();
        assert!(cache
            .resolve(&[group(vec![id; 512])])
            .unwrap_err()
            .to_string()
            .contains("exceeds budget"));
    }
}
