//! Prepare the complete notification before its first database effect. Missing
//! metadata leaves the receipt pending; future cache entries never apply effects.
use super::{BlockCoordinates, DurableJoin};
use crate::live_recovery::LiveWriteWindow;
use anyhow::{ensure, Context, Result};
use kaspa_wrpc_client::prelude::VirtualChainChangedNotification;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub struct DurableEventPlan {
    pub window: Option<LiveWriteWindow>,
    /// Exact source removal order, applied before any additions.
    pub removed: Vec<String>,
    /// Coordinates only. The controller must verify connection continuity.
    pub last_added: Option<BlockCoordinates>,
}

impl DurableEventPlan {
    pub fn requires_canonical_anchor(&self) -> bool {
        !self.removed.is_empty() && self.last_added.is_none()
    }
}

impl DurableJoin {
    pub fn prepare_change(
        &self,
        event: &VirtualChainChangedNotification,
    ) -> Result<Option<DurableEventPlan>> {
        // Cover strings, set/map nodes and the ordered removal list. Body and
        // hydration allocations retain their separate 16-MiB prepared limit.
        let hashes = event
            .removed_chain_block_hashes
            .len()
            .checked_add(event.added_chain_block_hashes.len())
            .context("event metadata count overflow")?;
        let accepted = event
            .accepted_transaction_ids
            .iter()
            .try_fold(0usize, |n, g| {
                n.checked_add(g.accepted_transaction_ids.len())
                    .context("accepted count overflow")
            })?;
        let charge = hashes
            .checked_mul(512)
            .and_then(|n| accepted.checked_mul(128).and_then(|m| n.checked_add(m)))
            .context("event metadata charge overflow")?;
        ensure!(
            charge <= 2 * 1024 * 1024,
            "event metadata exceeds preparation budget; retain receipt"
        );
        let added: BTreeSet<_> = event.added_chain_block_hashes.iter().copied().collect();
        let removed: BTreeSet<_> = event.removed_chain_block_hashes.iter().copied().collect();
        ensure!(
            added.len() == event.added_chain_block_hashes.len()
                && removed.len() == event.removed_chain_block_hashes.len()
                && added.is_disjoint(&removed),
            "duplicate or overlapping chain changes"
        );
        let mut accepted_ids = BTreeSet::new();
        for group in event.accepted_transaction_ids.iter() {
            ensure!(
                added.contains(&group.accepting_block_hash),
                "acceptance is outside added chain blocks"
            );
            for id in &group.accepted_transaction_ids {
                ensure!(
                    accepted_ids.insert(*id),
                    "duplicate accepted transaction in notification"
                );
            }
        }
        let mut observed: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
        for hash in event
            .removed_chain_block_hashes
            .iter()
            .chain(event.added_chain_block_hashes.iter())
        {
            let text = hash.to_string();
            let Some(coordinates) = self.coordinates(&text) else {
                return Ok(None);
            };
            observed
                .entry(coordinates.blue_score / 10 * 10)
                .or_default()
                .insert(text);
        }
        let Some(transactions) = self.resolve(&event.accepted_transaction_ids)? else {
            return Ok(None);
        };
        let window = if transactions.is_empty() && observed.is_empty() {
            None
        } else {
            let window = LiveWriteWindow {
                unresolved_blocks: Vec::new(),
                transactions,
                affected_transaction_ids: Vec::new(),
                rejected_transactions: Vec::new(),
                observed_blocks: observed,
                window_width: Some(10),
            };
            window.validate()?;
            Some(window)
        };
        let last_added = event.added_chain_block_hashes.last().map(|hash| {
            self.coordinates(&hash.to_string())
                .expect("coordinates checked above")
                .clone()
        });
        Ok(Some(DurableEventPlan {
            window,
            last_added,
            removed: event
                .removed_chain_block_hashes
                .iter()
                .map(ToString::to_string)
                .collect(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_wrpc_client::prelude::RpcAcceptedTransactionIds;
    use std::sync::Arc;
    fn cache() -> DurableJoin {
        let mut cache = DurableJoin::new(32 * 1024).unwrap();
        for (byte, score) in [(1, 19), (2, 18), (3, 20)] {
            let hash = format!("{byte:02x}").repeat(32);
            cache.reserve(2048).unwrap();
            cache.blocks.insert(
                hash.clone(),
                BlockCoordinates {
                    hash: hash.clone(),
                    blue_score: score,
                    timestamp: score * 100,
                    selected_parent: None,
                },
            );
            cache.push_order(super::super::Key::Block(hash)).unwrap();
        }
        cache
    }
    fn event() -> VirtualChainChangedNotification {
        VirtualChainChangedNotification {
            removed_chain_block_hashes: Arc::new(vec![
                "01".repeat(32).parse().unwrap(),
                "02".repeat(32).parse().unwrap(),
            ]),
            added_chain_block_hashes: Arc::new(vec!["03".repeat(32).parse().unwrap()]),
            accepted_transaction_ids: Arc::new(vec![]),
        }
    }
    #[test]
    fn complete_reorg_intent_precedes_effects_and_preserves_source_order() {
        let plan = cache().prepare_change(&event()).unwrap().unwrap();
        assert_eq!(plan.removed, vec!["01".repeat(32), "02".repeat(32)]);
        assert_eq!(plan.last_added.as_ref().unwrap().blue_score, 20);
        assert!(!plan.requires_canonical_anchor());
        let intent = plan.window.unwrap();
        assert_eq!(intent.window_width, Some(10));
        assert_eq!(intent.observed_blocks[&10].len(), 2);
        assert_eq!(intent.observed_blocks[&20].len(), 1);
        intent.validate().unwrap();
    }
    #[test]
    fn missing_removed_metadata_or_body_cannot_prepare_partial_effect() {
        let mut cache = cache();
        cache.blocks.remove(&"02".repeat(32));
        assert!(cache.prepare_change(&event()).unwrap().is_none());
        let mut e = event();
        e.accepted_transaction_ids = Arc::new(vec![RpcAcceptedTransactionIds {
            accepting_block_hash: "03".repeat(32).parse().unwrap(),
            accepted_transaction_ids: vec!["04".repeat(32).parse().unwrap()],
        }]);
        assert!(self::cache().prepare_change(&e).unwrap().is_none());
    }
    #[test]
    fn reorg_only_requires_a_new_verified_anchor_and_empty_event_is_noop() {
        let mut e = event();
        e.added_chain_block_hashes = Arc::new(vec![]);
        let plan = cache().prepare_change(&e).unwrap().unwrap();
        assert!(plan.requires_canonical_anchor());
        assert!(plan.window.is_some());
        e.removed_chain_block_hashes = Arc::new(vec![]);
        let plan = cache().prepare_change(&e).unwrap().unwrap();
        assert!(plan.window.is_none());
    }
    #[test]
    fn ambiguous_or_oversized_metadata_is_rejected_before_join_allocation() {
        let mut e = event();
        e.removed_chain_block_hashes = Arc::new(vec!["01".repeat(32).parse().unwrap(); 5000]);
        assert!(cache()
            .prepare_change(&e)
            .unwrap_err()
            .to_string()
            .contains("budget"));
        let mut e = event();
        e.accepted_transaction_ids = Arc::new(vec![RpcAcceptedTransactionIds {
            accepting_block_hash: "03".repeat(32).parse().unwrap(),
            accepted_transaction_ids: vec!["04".repeat(32).parse().unwrap(); 2],
        }]);
        assert!(cache()
            .prepare_change(&e)
            .unwrap_err()
            .to_string()
            .contains("duplicate accepted"));
    }
}
