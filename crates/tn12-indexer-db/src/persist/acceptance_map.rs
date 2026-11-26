//! Settled acceptance windows for historical split/merge recovery.
//!
//! This does not authorize database writes. Application additionally needs a
//! complete locked cohort, content validation, and an atomic ledger update.
use anyhow::{ensure, Result};

#[derive(Debug, thiserror::Error)]
#[error("acceptance evidence is immature: source tip {source_tip}, required tip {required_tip}")]
pub struct AcceptanceWindowPending {
    pub source_tip: u64,
    pub required_tip: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("canonical acceptance evidence changed during verification")]
pub struct AcceptanceEvidenceChanged;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

use super::acceptance::{validate_acceptance_membership, validate_accepting_block_evidence};
use super::{AcceptedInputEvidence, AcceptedOutputEvidence, AcceptingBlockEvidence};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoricalAcceptanceBlock {
    pub block: AcceptingBlockEvidence,
    pub transaction_ids: Vec<Vec<u8>>,
    pub inputs: Vec<AcceptedInputEvidence>,
    pub outputs: Vec<AcceptedOutputEvidence>,
}

/// One bounded source-response observation. The proof requires complete
/// membership for the stored cohort; this is not an exhaustive external-history
/// claim. Transport byte/time limits are enforced before in-memory validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoricalAcceptanceWindow {
    pub source_tip: u64,
    pub start_score: u64,
    pub end_score: u64,
    pub removed: Vec<AcceptingBlockEvidence>,
    pub canonical: Vec<HistoricalAcceptanceBlock>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoricalAcceptanceTarget {
    pub old_hash: Vec<u8>,
    pub transaction_id: Vec<u8>,
    pub target_hash: Vec<u8>,
    pub target_score: u64,
    pub target_time_ms: u64,
}

/// Source-side proof only. Its constructor is deliberately separate from the
/// database proof, which must bind the complete persisted cohort and content.
#[derive(Debug, Clone)]
pub struct HistoricalAcceptanceSourceProof {
    window: HistoricalAcceptanceWindow,
    targets: Vec<HistoricalAcceptanceTarget>,
    window_digest: [u8; 32],
    normalized_window: Vec<u8>,
}

impl HistoricalAcceptanceSourceProof {
    pub fn verify(
        first: HistoricalAcceptanceWindow,
        second: HistoricalAcceptanceWindow,
        cohort_transactions: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<Self> {
        let first = normalize_window(first)?;
        let second = normalize_window(second)?;
        if first != second {
            return Err(AcceptanceEvidenceChanged.into());
        }
        ensure!(
            !cohort_transactions.is_empty() && cohort_transactions.len() <= 8192,
            "invalid historical acceptance cohort size"
        );
        let removed: BTreeSet<_> = first.removed.iter().map(|b| &b.hash).collect();
        let mut cohort = BTreeMap::new();
        let mut used_sources = BTreeSet::new();
        for (old, txid) in cohort_transactions {
            ensure!(
                old.len() == 32 && txid.len() == 32 && removed.contains(old),
                "cohort references an unverified removed block"
            );
            ensure!(
                cohort.insert(txid.clone(), old.clone()).is_none(),
                "transaction belongs to multiple or duplicate old cohorts"
            );
            used_sources.insert(old);
        }
        ensure!(
            used_sources == removed,
            "removed block has no complete cohort"
        );
        let mut membership = BTreeMap::new();
        for accepted in &first.canonical {
            for txid in &accepted.transaction_ids {
                ensure!(
                    membership.insert(txid, &accepted.block).is_none(),
                    "transaction has multiple canonical accepting blocks"
                );
            }
        }
        let targets = cohort
            .into_iter()
            .map(|(transaction_id, old_hash)| {
                let block = membership.get(&transaction_id).ok_or_else(|| {
                    anyhow::anyhow!("cohort transaction absent from canonical window")
                })?;
                Ok(HistoricalAcceptanceTarget {
                    old_hash,
                    transaction_id,
                    target_hash: block.hash.clone(),
                    target_score: block.blue_score,
                    target_time_ms: block.timestamp,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let bytes = serde_json::to_vec(&first)?;
        ensure!(
            bytes.len() <= 64 * 1024 * 1024,
            "normalized source evidence exceeds byte bound"
        );
        let window_digest = tn12_indexer_core::blake2b_256(&bytes);
        Ok(Self {
            window: first,
            targets,
            window_digest,
            normalized_window: bytes,
        })
    }

    pub fn targets(&self) -> &[HistoricalAcceptanceTarget] {
        &self.targets
    }
    pub fn window(&self) -> &HistoricalAcceptanceWindow {
        &self.window
    }
    pub fn normalized_window(&self) -> &[u8] {
        &self.normalized_window
    }
    pub fn window_digest(&self) -> &[u8; 32] {
        &self.window_digest
    }
}

fn normalize_window(mut window: HistoricalAcceptanceWindow) -> Result<HistoricalAcceptanceWindow> {
    ensure!(
        window.start_score < window.end_score
            && window.end_score - window.start_score <= 1000
            && window.end_score <= i64::MAX as u64 - 1000
            && window.source_tip <= i64::MAX as u64,
        "invalid historical acceptance window"
    );
    ensure!(
        !window.removed.is_empty()
            && window.removed.len() <= 8192
            && !window.canonical.is_empty()
            && window.canonical.len() <= 1001,
        "invalid historical acceptance block count"
    );
    let mut hashes = BTreeSet::new();
    let mut scores = BTreeSet::new();
    for block in &window.removed {
        validate_accepting_block_evidence(block)?;
        ensure!(
            !block.is_chain_block
                && block.blue_score >= window.start_score
                && block.blue_score <= window.end_score
                && hashes.insert(block.hash.clone()),
            "invalid removed block in historical acceptance window"
        );
    }
    let mut tx_count = 0usize;
    let mut io_count = 0usize;
    for accepted in &mut window.canonical {
        let block = &accepted.block;
        validate_accepting_block_evidence(block)?;
        ensure!(
            block.is_chain_block
                && block.blue_score >= window.start_score
                && block.blue_score <= window.end_score
                && hashes.insert(block.hash.clone())
                && scores.insert(block.blue_score),
            "invalid canonical block in historical acceptance window"
        );
        tx_count = tx_count
            .checked_add(accepted.transaction_ids.len())
            .ok_or_else(|| anyhow::anyhow!("source transaction count overflow"))?;
        io_count = io_count
            .checked_add(accepted.inputs.len())
            .and_then(|n| n.checked_add(accepted.outputs.len()))
            .ok_or_else(|| anyhow::anyhow!("source input/output count overflow"))?;
        ensure!(
            tx_count <= 50_000 && io_count <= 200_000,
            "historical acceptance window exceeds membership bounds"
        );
        // Empty canonical blocks carry useful boundary evidence. They must not
        // claim any input/output membership without transactions.
        if accepted.transaction_ids.is_empty() {
            ensure!(
                accepted.inputs.is_empty() && accepted.outputs.is_empty(),
                "empty canonical block contains transaction evidence"
            );
        } else {
            validate_acceptance_membership(
                &accepted.transaction_ids,
                &accepted.inputs,
                &accepted.outputs,
            )?;
        }
        accepted.transaction_ids.sort();
        accepted.inputs.sort_by(|a, b| {
            (&a.transaction_id, &a.previous_txid, a.previous_vout).cmp(&(
                &b.transaction_id,
                &b.previous_txid,
                b.previous_vout,
            ))
        });
        accepted
            .outputs
            .sort_by(|a, b| (&a.transaction_id, a.vout).cmp(&(&b.transaction_id, b.vout)));
    }
    // Validate content before distinguishing an otherwise valid immature proof.
    let required_tip = window.end_score + 1000;
    if window.source_tip < required_tip {
        return Err(AcceptanceWindowPending { source_tip: window.source_tip, required_tip }.into());
    }
    window.removed.sort_by(|a, b| a.hash.cmp(&b.hash));
    window
        .canonical
        .sort_by(|a, b| a.block.hash.cmp(&b.block.hash));
    Ok(window)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn block(byte: u8, score: u64, canonical: bool) -> AcceptingBlockEvidence {
        AcceptingBlockEvidence {
            hash: vec![byte; 32],
            is_chain_block: canonical,
            blue_score: score,
            timestamp: score * 100,
            selected_parent: vec![7; 32],
            parents: vec![vec![vec![7; 32]]],
            accepted_id_merkle_root: vec![byte; 32],
            utxo_commitment: vec![byte; 32],
        }
    }
    fn window() -> HistoricalAcceptanceWindow {
        HistoricalAcceptanceWindow {
            source_tip: 2000,
            start_score: 100,
            end_score: 110,
            removed: vec![block(1, 102, false)],
            canonical: vec![
                HistoricalAcceptanceBlock {
                    block: block(2, 103, true),
                    transaction_ids: vec![vec![11; 32]],
                    inputs: vec![],
                    outputs: vec![],
                },
                HistoricalAcceptanceBlock {
                    block: block(3, 106, true),
                    transaction_ids: vec![vec![12; 32]],
                    inputs: vec![],
                    outputs: vec![],
                },
            ],
        }
    }
    fn cohort() -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![(vec![1; 32], vec![11; 32]), (vec![1; 32], vec![12; 32])]
    }
    fn verify(w: HistoricalAcceptanceWindow) -> Result<HistoricalAcceptanceSourceProof> {
        HistoricalAcceptanceSourceProof::verify(w.clone(), w, &cohort())
    }
    #[test]
    fn immature_split_is_typed_and_rechecked_after_maturity() {
        let mut w = window();
        w.source_tip = w.end_score + 999;
        let error = verify(w.clone()).unwrap_err();
        assert_eq!(error.downcast_ref::<AcceptanceWindowPending>().unwrap().required_tip, 1110);
        w.source_tip += 1;
        assert_eq!(verify(w.clone()).unwrap().targets().len(), 2);
        w.source_tip = 0;
        w.canonical[0].block.hash.clear();
        assert!(verify(w).unwrap_err().downcast_ref::<AcceptanceWindowPending>().is_none());
    }
    #[test]
    fn split_maps_every_transaction_to_its_own_target() {
        let proof = verify(window()).unwrap();
        assert_eq!(proof.targets().len(), 2);
        assert_eq!(proof.targets()[0].target_hash, vec![2; 32]);
        assert_eq!(proof.targets()[1].target_hash, vec![3; 32]);
        assert_eq!(proof.targets()[1].target_time_ms, 10600);
    }
    #[test]
    fn merge_supports_disjoint_old_cohorts() {
        let mut w = window();
        w.removed.push(block(4, 101, false));
        w.canonical[0].transaction_ids.push(vec![12; 32]);
        w.canonical.pop();
        let c = vec![(vec![1; 32], vec![11; 32]), (vec![4; 32], vec![12; 32])];
        let p = HistoricalAcceptanceSourceProof::verify(w.clone(), w, &c).unwrap();
        assert!(p.targets().iter().all(|t| t.target_hash == vec![2; 32]));
    }
    #[test]
    fn rejects_missing_and_duplicate_membership() {
        let mut w = window();
        w.canonical.pop();
        assert!(verify(w).is_err());
        let mut w = window();
        w.canonical[1].transaction_ids.push(vec![11; 32]);
        assert!(verify(w).is_err());
    }
    #[test]
    fn rejects_ambiguous_old_cohorts_and_unused_removed_blocks() {
        let mut w = window();
        w.removed.push(block(4, 101, false));
        assert!(verify(w.clone()).is_err());
        let mut c = cohort();
        c.push((vec![4; 32], vec![11; 32]));
        assert!(HistoricalAcceptanceSourceProof::verify(w.clone(), w, &c).is_err());
    }
    #[test]
    fn rejects_changed_source_content() {
        let w = window();
        let mut changed = w.clone();
        changed.canonical[0].block.timestamp += 1;
        assert!(HistoricalAcceptanceSourceProof::verify(w, changed, &cohort()).is_err());
    }
    #[test]
    fn canonical_order_does_not_change_proof_digest() {
        let w = window();
        let mut reverse = w.clone();
        reverse.canonical.reverse();
        let a = verify(w.clone()).unwrap();
        let b = HistoricalAcceptanceSourceProof::verify(w, reverse, &cohort()).unwrap();
        assert_eq!(a.window_digest(), b.window_digest());
    }
    #[test]
    fn rejects_unsettled_noncanonical_and_out_of_window_targets() {
        let mut w = window();
        w.source_tip = 1100;
        assert!(verify(w).is_err());
        let mut w = window();
        w.canonical[0].block.is_chain_block = false;
        assert!(verify(w).is_err());
        let mut w = window();
        w.canonical[0].block.blue_score = 111;
        assert!(verify(w).is_err());
        let mut w = window();
        w.removed[0].is_chain_block = true;
        assert!(verify(w).is_err());
    }
    #[test]
    fn rejects_oversized_window_and_invalid_input_content() {
        let mut w = window();
        w.end_score = w.start_score;
        assert!(verify(w).is_err());
        let mut w = window();
        w.end_score = 1101;
        assert!(verify(w).is_err());
        let mut w = window();
        w.canonical[0].inputs.push(AcceptedInputEvidence {
            transaction_id: vec![11; 32],
            previous_txid: vec![9; 32],
            previous_vout: 0,
            previous_amount: None,
            previous_script: None,
        });
        assert!(verify(w).is_err());
    }
}
