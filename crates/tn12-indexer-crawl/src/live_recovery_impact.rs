//! Build the removal dependency closure before granting any write authority.
use super::*;
use tn12_indexer_db::persist::PgPersister;
use tn12_indexer_db::persist::{PagedRecoveryOwner, RecoveryBlockImpact, RecoveryReplayPage, StagedRecoveryBlock};

impl<P: Persister + ?Sized + 'static> ChainTipFollower<P> {
    pub(super) async fn run_paged_live_recovery(
        &self,
        journal: &dyn crate::live_recovery::LiveWriteJournal,
        window: &crate::live_recovery::LiveWriteWindow,
        removed_roots: &BTreeSet<String>,
        tip: u64,
        width: u64,
    ) -> Result<()> {
        let key = journal
            .intent_key()
            .context("paged recovery requires a durable PostgreSQL journal")?;
        let writer = self
            .persister
            .paged_recovery_writer()
            .context("paged recovery requires a PostgreSQL writer")?;
        let pool = &self.store.pool;
        let existing = PagedRecoveryOwner::plan_exists(pool, key).await?;
        anyhow::ensure!(
            existing || !removed_roots.is_empty(),
            "paged recovery has no removed roots"
        );
        let roots = if existing {
            Vec::new()
        } else {
            removed_roots.iter().cloned().collect()
        };
        let owner = PagedRecoveryOwner::claim(pool, key, &roots).await?;
        if owner.phase(pool).await? == "discover" {
            self.stage_paged_recovery_source(&owner, window, tip, width)
                .await?;
        }
        if owner.phase(pool).await? == "revert" {
            self.remove_paged_recovery_blocks(&owner, writer).await?;
        }
        if owner.phase(pool).await? == "replay" {
            self.replay_paged_recovery_transactions(&owner, writer)
                .await?;
        }
        anyhow::ensure!(
            matches!(owner.phase(pool).await?.as_str(), "verify" | "complete"),
            "paged recovery stopped before verification"
        );
        self.verify_paged_recovery_source(&owner, writer, width)
            .await?;
        owner.mark_complete(pool).await?;
        Ok(())
    }

    pub(super) async fn verify_paged_recovery_source(
        &self,
        owner: &PagedRecoveryOwner,
        writer: &PgPersister,
        width: u64,
    ) -> Result<()> {
        let mut after_block: Option<String> = None;
        loop {
            let page = owner
                .verification_blocks(&self.store.pool, after_block.as_deref())
                .await?;
            if page.is_empty() {
                break;
            }
            for block in &page {
                owner.heartbeat(&self.store.pool).await?;
                let fresh = self
                    .prefetch_rest
                    .recovery_block_evidence(&block.impact.block_hash)
                    .await?;
                anyhow::ensure!(
                    fresh.hash == hex::decode(&block.impact.block_hash)?
                        && i64::try_from(fresh.blue_score)? == block.blue_score
                        && fresh.is_chain_block == block.source_is_chain_block,
                    crate::live_supervisor::RecoveryPending(
                        "paged block changed during final verification"
                    )
                );
            }
            after_block = page.last().map(|block| block.impact.block_hash.clone());
        }
        let mut after_tx: Option<String> = None;
        loop {
            let page = owner
                .verification_transactions(&self.store.pool, after_tx.as_deref())
                .await?;
            if page.is_empty() {
                break;
            }
            for staged in &page {
                owner.heartbeat(&self.store.pool).await?;
                let fresh = self
                    .prefetch_rest
                    .get_transaction_with_explicit_acceptance(&staged.transaction_id)
                    .await?;
                anyhow::ensure!(
                    fresh.recovery_identity() == staged.recovery_identity(),
                    crate::live_supervisor::RecoveryPending(
                        "paged transaction changed during final verification"
                    )
                );
                if fresh.is_accepted {
                    let score = fresh
                        .accepting_block_blue_score
                        .context("paged accepted transaction has no score")?;
                    let start = score / width * width;
                    let prepared = self
                        .scanner
                        .prepare_recovery_batch(start, std::slice::from_ref(&fresh))
                        .await?;
                    let present = prepared
                        .as_ref()
                        .map(PreparedBatch::acceptance_coordinates)
                        .is_some_and(|coordinates| contains_acceptance(&coordinates, &fresh));
                    anyhow::ensure!(
                        present,
                        crate::live_supervisor::RecoveryPending(
                            "paged acceptance is absent from canonical REST window"
                        )
                    );
                } else {
                    anyhow::ensure!(
                        !writer
                            .rejected_recovery_tx_has_effect(&fresh.transaction_id)
                            .await?,
                        crate::live_supervisor::RecoveryPending(
                            "rejected paged transaction still has indexed effects"
                        )
                    );
                }
            }
            after_tx = page.last().map(|body| body.transaction_id.clone());
        }
        Ok(())
    }

    /// Recheck every source block and its transactions before each bounded,
    /// descendant-first removal. The DB rechecks the indexed dependencies
    /// under the writer lock and commits each removal with its checkpoint.
    pub(super) async fn remove_paged_recovery_blocks(
        &self,
        owner: &PagedRecoveryOwner,
        writer: &PgPersister,
    ) -> Result<()> {
        loop {
            let ready = owner.ready_removals(&self.store.pool).await?;
            if ready.is_empty() {
                break;
            }
            for block in ready {
                owner.heartbeat(&self.store.pool).await?;
                let evidence = self
                    .prefetch_rest
                    .recovery_block_evidence(&block.impact.block_hash)
                    .await?;
                anyhow::ensure!(
                    evidence.hash == hex::decode(&block.impact.block_hash)?
                        && i64::try_from(evidence.blue_score)? == block.blue_score
                        && evidence.is_chain_block == block.source_is_chain_block,
                    crate::live_supervisor::RecoveryPending(
                        "paged source block changed before removal"
                    )
                );
                for ids in block.impact.transaction_ids.chunks(32) {
                    let mut bodies = Vec::with_capacity(ids.len());
                    for id in ids {
                        owner.heartbeat(&self.store.pool).await?;
                        let body = self
                            .prefetch_rest
                            .get_transaction_with_explicit_acceptance(id)
                            .await?;
                        anyhow::ensure!(
                            body.transaction_id == *id,
                            "paged removal transaction identity changed"
                        );
                        bodies.push(body);
                    }
                    owner.stage_transactions(&self.store.pool, &bodies).await?;
                }
                match owner.revert_one(writer, &block).await {
                        Err(error) if error.downcast_ref::<tn12_indexer_db::persist::RecoveryRemovalRetry>().is_some() => {
                            // Keep the owner, but return through ready_removals
                            // and source validation before retrying this block.
                            tracing::warn!(%error, "canonical removal retry retains owner");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                        result => { result?; }
                }
            }
        }
        owner.finish_removal(&self.store.pool).await
    }

    pub(super) async fn replay_paged_recovery_transactions(
        &self,
        owner: &PagedRecoveryOwner,
        writer: &PgPersister,
    ) -> Result<()> {
        loop {
            let ready = match owner.pending_replay(&self.store.pool).await? {
                RecoveryReplayPage::Preparing => {
                    tokio::task::yield_now().await;
                    continue;
                }
                RecoveryReplayPage::Ready(ready) => ready,
            };
            if ready.is_empty() {
                break;
            }
            // At most four source bodies in flight or buffered. Fetching does
            // not mutate canonical state; preserve selected order for writes.
            for page in ready.chunks(4) {
                let fresh = self.fetch_paged_recovery_acceptances(owner, page).await?;
                let guarded=crate::rest_replay_fence::for_transactions(writer,&self.prefetch_rest,&fresh).await?;
                for body in fresh {
                    owner.heartbeat(&self.store.pool).await?;
                    guarded.replay_paged_recovery_tx(owner, &body).await?;
                }
            }
        }
        loop {
            let rejected = owner.pending_rejected(&self.store.pool).await?;
            if rejected.is_empty() {
                break;
            }
            for page in rejected.chunks(4) {
                let fresh = self.fetch_paged_recovery_acceptances(owner, page).await?;
                for body in fresh {
                    owner.heartbeat(&self.store.pool).await?;
                    owner.verify_rejected(&self.store.pool, &body).await?;
                }
            }
        }
        owner.finish_replay(&self.store.pool).await
    }

    async fn fetch_paged_recovery_acceptances(
        &self,
        owner: &PagedRecoveryOwner,
        page: &[RestTransaction],
    ) -> Result<Vec<RestTransaction>> {
        anyhow::ensure!(page.len() <= 4, "recovery fetch page exceeds bound");
        let fetch = self.fetch_current_acceptances(page);
        tokio::pin!(fetch);
        let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                result = &mut fetch => {
                    let bodies = result?;
                    for body in &bodies {
                        anyhow::ensure!(serde_json::to_vec(body)?.len() <= 1024 * 1024,
                            "recovery source body is too large");
                    }
                    return Ok(bodies);
                }
                _ = heartbeat.tick() => owner.heartbeat(&self.store.pool).await?,
            }
        }
    }

    /// Discover one retained intent into durable pages before any removal.
    /// Every pending block is checked against fresh REST evidence. Repeating
    /// discovery after a process restart reads the committed frontier.
    pub(super) async fn stage_paged_recovery_source(
        &self,
        owner: &PagedRecoveryOwner,
        intent: &crate::live_recovery::LiveWriteWindow,
        tip: u64,
        width: u64,
    ) -> Result<()> {
        let pool = &self.store.pool;
        let roots: BTreeSet<_> = owner.roots(pool).await?.into_iter().collect();
        let intent_ids: Vec<_> = intent
            .transactions
            .iter()
            .chain(&intent.rejected_transactions)
            .map(|body| body.transaction_id.clone())
            .chain(intent.affected_transaction_ids.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        for ids in intent_ids.chunks(32) {
            owner.enqueue_transactions(pool, ids).await?;
        }
        loop {
            let pending = owner.pending_blocks(pool).await?;
            if pending.is_empty() {
                break;
            }
            for hash in pending {
                owner.heartbeat(pool).await?;
                let evidence = self.prefetch_rest.recovery_block_evidence(&hash).await?;
                anyhow::ensure!(
                    evidence.hash == hex::decode(&hash)?,
                    "paged recovery source block identity changed"
                );
                if roots.contains(&hash) && evidence.is_chain_block {
                    return Err(crate::live_supervisor::RecoveryPending(
                        "removed root became canonical during paged discovery",
                    )
                    .into());
                }
                let start = evidence.blue_score / width * width;
                if tip <= window_end(start, width) {
                    return Err(crate::live_supervisor::RecoveryPending(
                        "paged recovery acceptance window is not published yet",
                    )
                    .into());
                }
                let impact = match self.persister.recovery_block_impact(&hash).await {
                    Ok(impact) => impact,
                    Err(error) if error.is::<tn12_indexer_db::persist::RecoveryImpactLimit>() => {
                        let writer = self.persister.paged_recovery_writer().context("chunked recovery requires PostgreSQL")?;
                        owner.stage_chunked_block(writer, &hash, i64::try_from(evidence.blue_score)?, evidence.is_chain_block).await?;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                anyhow::ensure!(impact.block_hash == hash, "paged impact identity changed");
                owner
                    .stage_blocks(
                        pool,
                        &[StagedRecoveryBlock {
                            impact,
                            blue_score: i64::try_from(evidence.blue_score)?,
                            source_is_chain_block: evidence.is_chain_block,
                        }],
                    )
                    .await?;
            }
        }
        loop {
            let pending = owner.pending_transactions(pool).await?;
            if pending.is_empty() {
                break;
            }
            let mut bodies = Vec::with_capacity(pending.len());
            for id in pending {
                owner.heartbeat(pool).await?;
                let body = self
                    .prefetch_rest
                    .get_transaction_with_explicit_acceptance(&id)
                    .await?;
                anyhow::ensure!(
                    body.transaction_id == id,
                    "paged source transaction identity changed"
                );
                if body.is_accepted {
                    let score = body
                        .accepting_block_blue_score
                        .context("paged source acceptance score missing")?;
                    if tip <= window_end(score / width * width, width) {
                        return Err(crate::live_supervisor::RecoveryPending(
                            "paged transaction acceptance window is not published yet",
                        )
                        .into());
                    }
                }
                bodies.push(body);
            }
            let missing_parents = self
                .scanner
                .missing_recovery_p2sh_parent_txids(&bodies)
                .await?;
            for ids in missing_parents.chunks(32) {
                owner.enqueue_transactions(pool, ids).await?;
            }
            owner.stage_transactions(pool, &bodies).await?;
        }
        owner.finish_discovery(pool).await
    }

    pub(super) async fn discover_recovery_impacts(
        &self,
        roots: &BTreeSet<String>,
        tip: u64,
        width: u64,
    ) -> Result<(Vec<RecoveryBlockImpact>, BTreeMap<u64, BTreeSet<String>>)> {
        let mut pending = roots.clone();
        let mut impacts = BTreeMap::new();
        let mut observed = BTreeMap::<u64, BTreeSet<String>>::new();
        let mut ids = BTreeSet::new();
        while let Some(hash) = pending.pop_first() {
            if impacts.contains_key(&hash) {
                continue;
            }
            anyhow::ensure!(
                impacts.len() < 256,
                crate::recovery_policy::RecoveryBlocked("affected_block_limit")
            );
            let evidence = self.prefetch_rest.recovery_block_evidence(&hash).await?;
            anyhow::ensure!(
                evidence.hash == hex::decode(&hash)?,
                "recovery block identity changed"
            );
            if roots.contains(&hash) && evidence.is_chain_block {
                return Err(crate::live_supervisor::RecoveryPending(
                    "removed root became canonical during discovery",
                )
                .into());
            }
            let start = evidence.blue_score / width * width;
            if tip <= window_end(start, width) {
                return Err(crate::live_supervisor::RecoveryPending(
                    "descendant acceptance window is not published yet",
                )
                .into());
            }
            let impact = self.persister.recovery_block_impact(&hash).await?;
            anyhow::ensure!(
                impact.block_hash == hash,
                "recovery impact block identity changed"
            );
            ids.extend(impact.transaction_ids.iter().cloned());
            anyhow::ensure!(
                ids.len() <= 256,
                crate::recovery_policy::RecoveryBlocked("affected_transaction_limit")
            );
            for child in &impact.descendants {
                anyhow::ensure!(
                    hex::decode(child).is_ok_and(|v| v.len() == 32),
                    "invalid recovery descendant hash"
                );
                if !impacts.contains_key(child) {
                    pending.insert(child.clone());
                }
            }
            anyhow::ensure!(
                pending.len() + impacts.len() <= 256,
                crate::recovery_policy::RecoveryBlocked("affected_block_limit")
            );
            observed.entry(start).or_default().insert(hash.clone());
            impacts.insert(hash, impact);
        }
        Ok((descendants_first(impacts)?, observed))
    }
}

pub(super) fn descendants_first(
    mut impacts: BTreeMap<String, RecoveryBlockImpact>,
) -> Result<Vec<RecoveryBlockImpact>> {
    let mut ordered = Vec::new();
    let mut done = BTreeSet::new();
    while !impacts.is_empty() {
        let next = impacts
            .iter()
            .find(|(_, impact)| impact.descendants.iter().all(|child| done.contains(child)))
            .map(|(hash, _)| hash.clone());
        let Some(next) = next else {
            return Err(crate::live_supervisor::RecoveryPending(
                "indexed recovery dependency cycle or missing descendant",
            )
            .into());
        };
        ordered.push(impacts.remove(&next).expect("selected recovery impact"));
        done.insert(next);
    }
    Ok(ordered)
}

fn body_identity(tx: &RestTransaction) -> serde_json::Value {
    tx.recovery_identity()
}

pub(super) fn retain_body(
    bodies: &mut BTreeMap<String, RestTransaction>,
    tx: &RestTransaction,
) -> Result<()> {
    if let Some(previous) = bodies.get(&tx.transaction_id) {
        if body_identity(previous) != body_identity(tx) {
            return Err(crate::live_supervisor::RecoveryPending(
                "transaction body changed while preparing recovery",
            )
            .into());
        }
    } else {
        crate::recovery_policy::check_capacity("recovery_body_count", bodies.len() + 1, 256)?;
        bodies.insert(tx.transaction_id.clone(), tx.clone());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn changed_body_cannot_replace_the_prepared_recovery_payload() {
        let original = RestTransaction {
            transaction_id: "11".repeat(32),
            payload: Some("aa".into()),
            ..Default::default()
        };
        let mut bodies = BTreeMap::new();
        retain_body(&mut bodies, &original).unwrap();
        retain_body(&mut bodies, &original).unwrap();
        assert_eq!(bodies.len(), 1);
        let changed = RestTransaction {
            payload: Some("bb".into()),
            ..original.clone()
        };
        assert!(retain_body(&mut bodies, &changed).is_err());
        assert_eq!(bodies[&original.transaction_id].payload, original.payload);
    }
    #[test]
    fn observational_block_metadata_does_not_duplicate_the_body() {
        let original = RestTransaction {
            transaction_id: "11".repeat(32),
            ..Default::default()
        };
        let changed = RestTransaction {
            block_hash: vec!["22".repeat(32)],
            block_time: 123,
            ..original.clone()
        };
        let mut bodies = BTreeMap::new();
        retain_body(&mut bodies, &original).unwrap();
        retain_body(&mut bodies, &changed).unwrap();
        assert_eq!(bodies.len(), 1);
    }
    fn impact(hash: &str, children: &[&str]) -> RecoveryBlockImpact {
        RecoveryBlockImpact {
            block_hash: hash.into(),
            transaction_ids: vec![],
            descendants: children.iter().map(|h| (*h).into()).collect(),
        }
    }
    #[test]
    fn shared_nested_descendant_is_removed_once_before_every_parent() {
        let impacts = [
            impact("a", &["b", "c"]),
            impact("b", &["d"]),
            impact("c", &["d"]),
            impact("d", &[]),
        ];
        let order = descendants_first(
            impacts
                .into_iter()
                .map(|i| (i.block_hash.clone(), i))
                .collect(),
        )
        .unwrap();
        assert_eq!(
            order
                .iter()
                .map(|i| i.block_hash.as_str())
                .collect::<Vec<_>>(),
            vec!["d", "b", "c", "a"]
        );
    }
    #[test]
    fn cycle_or_missing_child_never_produces_a_partial_removal_plan() {
        for impacts in [
            vec![impact("a", &["b"]), impact("b", &["a"])],
            vec![impact("a", &["missing"])],
        ] {
            assert!(descendants_first(
                impacts
                    .into_iter()
                    .map(|i| (i.block_hash.clone(), i))
                    .collect()
            )
            .is_err());
        }
    }
}

#[cfg(test)]
#[path = "paged_replay_fetch_tests.rs"]
mod paged_replay_fetch_tests;
