//! An ordered notification extends a committed anchor only when every selected
//! parent link agrees. Scores alone cannot establish continuity through a reorg.
use super::{DurableEventPlan, DurableJoin};
use crate::durable_inbox::ChainAnchor;
use anyhow::{ensure, Result};
use kaspa_wrpc_client::prelude::VirtualChainChangedNotification;

pub struct ContiguousEventPlan {
    event: DurableEventPlan,
    previous: ChainAnchor,
    next: ChainAnchor,
}
impl ContiguousEventPlan {
    pub fn event(&self) -> &DurableEventPlan {
        &self.event
    }
    pub fn previous_anchor(&self) -> &ChainAnchor {
        &self.previous
    }
    pub fn next_anchor(&self) -> &ChainAnchor {
        &self.next
    }
}

impl DurableJoin {
    /// The controller must obtain `previous` from the durable checkpoint for
    /// this receipt. This proof never establishes initial coverage or permits
    /// replacing a newer checkpoint with an older raw event.
    pub fn prepare_contiguous_change(
        &self,
        network: &str,
        previous: &ChainAnchor,
        change: &VirtualChainChangedNotification,
    ) -> Result<Option<ContiguousEventPlan>> {
        ensure!(
            !network.is_empty() && previous.network == network,
            "anchor network mismatch"
        );
        ensure!(
            hex::decode(&previous.block_hash).is_ok_and(|h| h.len() == 32),
            "invalid previous anchor"
        );
        let Some(event) = self.prepare_change(change)? else {
            return Ok(None);
        };
        let Some(mut cursor) = self.coordinates(&previous.block_hash) else {
            return Ok(None);
        };
        ensure!(
            cursor.blue_score == previous.blue_score,
            "anchor score disagrees with cached block"
        );
        for hash in change.removed_chain_block_hashes.iter() {
            if cursor.hash != hash.to_string() {
                return Ok(None);
            }
            let Some(parent) = cursor
                .selected_parent
                .as_deref()
                .and_then(|p| self.coordinates(p))
            else {
                return Ok(None);
            };
            cursor = parent;
        }
        for hash in change.added_chain_block_hashes.iter() {
            let Some(added) = self.coordinates(&hash.to_string()) else {
                return Ok(None);
            };
            if added.selected_parent.as_deref() != Some(cursor.hash.as_str()) {
                return Ok(None);
            }
            cursor = added;
        }
        Ok(Some(ContiguousEventPlan {
            event,
            previous: previous.clone(),
            next: ChainAnchor {
                network: network.into(),
                block_hash: cursor.hash.clone(),
                blue_score: cursor.blue_score,
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{BlockCoordinates, Key};
    use super::*;
    use std::sync::Arc;
    fn hash(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }
    fn cache() -> DurableJoin {
        let mut cache = DurableJoin::new(32 * 1024).unwrap();
        for (id, parent, score) in [(1, 0, 10), (2, 1, 20), (3, 2, 30), (4, 1, 25), (5, 4, 35)] {
            cache.reserve(2048).unwrap();
            cache.blocks.insert(
                hash(id),
                BlockCoordinates {
                    hash: hash(id),
                    blue_score: score,
                    timestamp: score,
                    selected_parent: Some(hash(parent)),
                },
            );
            cache.push_order(Key::Block(hash(id))).unwrap();
        }
        cache
    }
    fn event(removed: &[u8], added: &[u8]) -> VirtualChainChangedNotification {
        VirtualChainChangedNotification {
            removed_chain_block_hashes: Arc::new(
                removed.iter().map(|n| hash(*n).parse().unwrap()).collect(),
            ),
            added_chain_block_hashes: Arc::new(
                added.iter().map(|n| hash(*n).parse().unwrap()).collect(),
            ),
            accepted_transaction_ids: Arc::new(vec![]),
        }
    }
    fn anchor(id: u8, score: u64) -> ChainAnchor {
        ChainAnchor {
            network: "testnet-10".into(),
            block_hash: hash(id),
            blue_score: score,
        }
    }
    #[test]
    fn ordered_additions_extend_exact_hash_anchor() {
        let previous = anchor(1, 10);
        let proof = cache()
            .prepare_contiguous_change("testnet-10", &previous, &event(&[], &[2, 3]))
            .unwrap()
            .unwrap();
        assert_eq!(proof.previous_anchor(), &previous);
        assert_eq!(proof.next_anchor(), &anchor(3, 30));
        assert!(proof.event().window.is_some());
    }
    #[test]
    fn reorg_and_removal_only_follow_parent_links_in_order() {
        let previous = anchor(3, 30);
        let proof = cache()
            .prepare_contiguous_change("testnet-10", &previous, &event(&[3, 2], &[4, 5]))
            .unwrap()
            .unwrap();
        assert_eq!(proof.next_anchor(), &anchor(5, 35));
        let proof = cache()
            .prepare_contiguous_change("testnet-10", &previous, &event(&[3, 2], &[]))
            .unwrap()
            .unwrap();
        assert_eq!(proof.next_anchor(), &anchor(1, 10));
    }
    #[test]
    fn delayed_reordered_or_missing_links_never_establish_continuity() {
        let c = cache();
        assert!(c
            .prepare_contiguous_change("testnet-10", &anchor(3, 30), &event(&[], &[2]))
            .unwrap()
            .is_none());
        assert!(c
            .prepare_contiguous_change("testnet-10", &anchor(3, 30), &event(&[2, 3], &[4]))
            .unwrap()
            .is_none());
        assert!(c
            .prepare_contiguous_change("testnet-10", &anchor(1, 10), &event(&[], &[3, 2]))
            .unwrap()
            .is_none());
        let mut c = cache();
        c.blocks.get_mut(&hash(2)).unwrap().selected_parent = None;
        assert!(c
            .prepare_contiguous_change("testnet-10", &anchor(1, 10), &event(&[], &[2]))
            .unwrap()
            .is_none());
    }
    #[test]
    fn network_and_coordinate_disagreement_are_errors() {
        assert!(cache()
            .prepare_contiguous_change("testnet-11", &anchor(1, 10), &event(&[], &[2]))
            .is_err());
        assert!(cache()
            .prepare_contiguous_change("testnet-10", &anchor(1, 11), &event(&[], &[2]))
            .is_err());
    }

    #[test]
    fn block_parent_metadata_can_be_hydrated_but_not_changed_or_fabricated() {
        use kaspa_wrpc_client::prelude::{RpcBlock, RpcBlockVerboseData, RpcHeader};
        let zero = hash(0).parse().unwrap();
        let id = hash(1).parse().unwrap();
        let parent = hash(2).parse().unwrap();
        let other = hash(3).parse().unwrap();
        let mut block = RpcBlock {
            header: RpcHeader {
                hash: id,
                version: 1,
                parents_by_level: vec![vec![parent, other]],
                hash_merkle_root: zero,
                accepted_id_merkle_root: zero,
                utxo_commitment: zero,
                timestamp: 1,
                bits: 0,
                nonce: 0,
                daa_score: 10,
                blue_work: Default::default(),
                blue_score: 10,
                pruning_point: zero,
            },
            transactions: vec![],
            verbose_data: None,
        };
        let mut cache = DurableJoin::new(8192).unwrap();
        cache
            .remember_block(&block, kaspa_addresses::Prefix::Testnet)
            .unwrap();
        let bytes = cache.charged_bytes();
        assert!(cache
            .coordinates(&hash(1))
            .unwrap()
            .selected_parent
            .is_none());
        block.verbose_data = Some(RpcBlockVerboseData {
            hash: id,
            difficulty: 0.0,
            selected_parent_hash: parent,
            transaction_ids: vec![],
            is_header_only: false,
            blue_score: 10,
            children_hashes: vec![],
            merge_set_blues_hashes: vec![],
            merge_set_reds_hashes: vec![],
            is_chain_block: true,
        });
        cache
            .remember_block(&block, kaspa_addresses::Prefix::Testnet)
            .unwrap();
        assert_eq!(
            cache.coordinates(&hash(1)).unwrap().selected_parent,
            Some(hash(2))
        );
        assert_eq!(cache.charged_bytes(), bytes);
        block.verbose_data.as_mut().unwrap().selected_parent_hash = other;
        assert!(cache
            .remember_block(&block, kaspa_addresses::Prefix::Testnet)
            .is_err());
        block.verbose_data.as_mut().unwrap().selected_parent_hash = zero;
        assert!(cache
            .remember_block(&block, kaspa_addresses::Prefix::Testnet)
            .is_err());
        block.verbose_data.as_mut().unwrap().selected_parent_hash = parent;
        block.verbose_data.as_mut().unwrap().blue_score = 11;
        assert!(cache
            .remember_block(&block, kaspa_addresses::Prefix::Testnet)
            .is_err());
        assert_eq!(
            cache.coordinates(&hash(1)).unwrap().selected_parent,
            Some(hash(2))
        );
    }
}
