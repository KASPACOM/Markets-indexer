//! Apply one parent-verified event and commit its receipt and anchor together.
//! Initial coverage and canonical recovery remain controller responsibilities.
use super::{DurableInbox, EffectStart, InboxEffectJournal};
use crate::durable_join::{ContiguousEventPlan, DurableEventPlan};
use crate::live_recovery::{LiveWriteJournal, LiveWriteWindow};
use anyhow::{ensure, Result};
use std::collections::BTreeSet;
use std::sync::Arc;
use tn12_indexer_db::{persist::DurableConsumerFence, PersistStats, Persister, PgPersister};

enum DurableApplyOutcome {
    NoEffects,
    /// All writes returned success. The controller still owns the intent and
    /// must atomically acknowledge it with its verified continuity anchor.
    Persisted(PersistStats),
    /// Any prefix may already have committed. Never reapply raw removals after
    /// this outcome; reconcile canonically, including later queued events.
    RecoveryRequired(LiveWriteWindow),
}

pub enum DurableCommitOutcome {
    Committed(PersistStats),
    RecoveryRequired(LiveWriteWindow),
}

pub struct DurableEventApplier {
    inbox: Arc<DurableInbox>,
    fence: DurableConsumerFence,
    writer: PgPersister,
    network: String,
}

impl DurableEventApplier {
    pub fn new(
        inbox: Arc<DurableInbox>,
        fence: DurableConsumerFence,
        network: String,
    ) -> Result<Self> {
        // The writer and intent always share a database and generation fence.
        let writer = PgPersister::for_wrpc(inbox.pool.clone(), network.clone())?
            .with_durable_consumer_fence(fence.clone());
        Ok(Self {
            inbox,
            fence,
            writer,
            network,
        })
    }

    pub async fn commit(
        &self,
        sequence: i64,
        plan: &ContiguousEventPlan,
    ) -> Result<DurableCommitOutcome> {
        ensure!(
            plan.previous_anchor().network == self.network
                && plan.next_anchor().network == self.network,
            "event proof belongs to another writer network"
        );
        let journal = InboxEffectJournal::new(self.inbox.clone(), sequence, self.fence.clone());
        let result = apply_ordered_inner(
            &self.writer,
            &journal,
            plan.event(),
            Some(plan.previous_anchor()),
        )
        .await?;
        let stats = match result {
            DurableApplyOutcome::RecoveryRequired(old) => {
                return Ok(DurableCommitOutcome::RecoveryRequired(old))
            }
            DurableApplyOutcome::NoEffects => {
                self.inbox
                    .acknowledge_contiguous(
                        sequence,
                        plan.previous_anchor(),
                        plan.next_anchor(),
                        &self.fence,
                    )
                    .await?;
                PersistStats::default()
            }
            DurableApplyOutcome::Persisted(stats) => {
                journal
                    .finish_contiguous(
                        plan.event()
                            .window
                            .as_ref()
                            .expect("persisted event has intent"),
                        plan.previous_anchor(),
                        plan.next_anchor(),
                    )
                    .await?;
                stats
            }
        };
        Ok(DurableCommitOutcome::Committed(stats))
    }
}

#[cfg(test)]
async fn apply_ordered<P: Persister>(
    writer: &P,
    journal: &InboxEffectJournal,
    plan: &DurableEventPlan,
) -> Result<DurableApplyOutcome> {
    apply_ordered_inner(writer, journal, plan, None).await
}

async fn apply_ordered_inner<P: Persister>(
    writer: &P,
    journal: &InboxEffectJournal,
    plan: &DurableEventPlan,
    previous: Option<&super::ChainAnchor>,
) -> Result<DurableApplyOutcome> {
    let Some(window) = &plan.window else {
        ensure!(
            plan.removed.is_empty() && plan.last_added.is_none(),
            "chain change lacks intent"
        );
        return Ok(match journal.load().await? {
            Some(old) => DurableApplyOutcome::RecoveryRequired(old),
            None => DurableApplyOutcome::NoEffects,
        });
    };
    window.validate()?;
    ensure!(
        plan.removed.len() <= 4096,
        "removal list exceeds metadata budget"
    );
    let mut unique = BTreeSet::new();
    for hash in &plan.removed {
        ensure!(unique.insert(hash), "duplicate removal");
        ensure!(
            window
                .observed_blocks
                .values()
                .any(|hashes| hashes.contains(hash)),
            "removal is not covered by durable intent"
        );
    }
    if let Some(last) = &plan.last_added {
        ensure!(
            !unique.contains(&last.hash),
            "anchor is removed by this event"
        );
        let width = u64::from(window.window_width.unwrap_or(100));
        ensure!(
            window
                .observed_blocks
                .get(&(last.blue_score / width * width))
                .is_some_and(|hashes| hashes.contains(&last.hash)),
            "last addition is outside intent"
        );
    }
    for tx in &window.transactions {
        ensure!(
            !unique.contains(tx.accepting_block_hash.as_ref().expect("validated")),
            "acceptance belongs to removed block"
        );
    }
    let start = match previous {
        Some(previous) => journal.start_contiguous(window, previous).await?,
        None => journal.start(window).await?,
    };
    match start {
        EffectStart::RecoveryRequired(old) => {
            return Ok(DurableApplyOutcome::RecoveryRequired(old))
        }
        EffectStart::Fresh => {}
    }
    // No acknowledgement or local retry on any error or cancellation. The
    // intent covers every removal before the first mutating database call.
    for hash in &plan.removed {
        writer.revert_block(&hex::decode(hash)?).await?;
    }
    let stats = writer.persist_batch(&window.transactions).await?;
    Ok(DurableApplyOutcome::Persisted(stats))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tn12_indexer_core::RestTransaction;
    use tn12_indexer_db::RevertStats;

    fn linked_plan(empty: bool) -> ContiguousEventPlan {
        use crate::durable_join::DurableJoin;
        use kaspa_wrpc_client::prelude::{
            RpcBlock, RpcBlockVerboseData, RpcHeader, VirtualChainChangedNotification,
        };
        let hash = |n: u8| format!("{n:02x}").repeat(32).parse().unwrap();
        let mut cache = DurableJoin::new(8192).unwrap();
        for n in [1, 2] {
            let block = RpcBlock {
                header: RpcHeader {
                    hash: hash(n),
                    version: 1,
                    parents_by_level: vec![vec![hash(n - 1)]],
                    hash_merkle_root: hash(0),
                    accepted_id_merkle_root: hash(0),
                    utxo_commitment: hash(0),
                    timestamp: n as u64,
                    bits: 0,
                    nonce: 0,
                    daa_score: n as u64,
                    blue_work: Default::default(),
                    blue_score: n as u64 * 10,
                    pruning_point: hash(0),
                },
                transactions: vec![],
                verbose_data: Some(RpcBlockVerboseData {
                    hash: hash(n),
                    difficulty: 0.0,
                    selected_parent_hash: hash(n - 1),
                    transaction_ids: vec![],
                    is_header_only: false,
                    blue_score: n as u64 * 10,
                    children_hashes: vec![],
                    merge_set_blues_hashes: vec![],
                    merge_set_reds_hashes: vec![],
                    is_chain_block: true,
                }),
            };
            cache
                .remember_block(&block, kaspa_addresses::Prefix::Testnet)
                .unwrap();
        }
        let previous = super::super::ChainAnchor {
            network: "testnet-10".into(),
            block_hash: "01".repeat(32),
            blue_score: 10,
        };
        cache
            .prepare_contiguous_change(
                "testnet-10",
                &previous,
                &VirtualChainChangedNotification {
                    removed_chain_block_hashes: Arc::new(vec![]),
                    added_chain_block_hashes: Arc::new(if empty { vec![] } else { vec![hash(2)] }),
                    accepted_transaction_ids: Arc::new(vec![]),
                },
            )
            .unwrap()
            .unwrap()
    }

    async fn commit_setup(
        pool: &sqlx::PgPool,
        empty: bool,
    ) -> (DurableEventApplier, ContiguousEventPlan, Arc<DurableInbox>) {
        let plan = linked_plan(empty);
        let inbox = Arc::new(
            DurableInbox::open(pool.clone(), "testnet-10:commit".into(), 4096)
                .await
                .unwrap(),
        );
        inbox.append(1, b"receipt", 1).await.unwrap();
        sqlx::query("UPDATE wrpc_inbox_streams SET anchor=$1 WHERE stream='testnet-10:commit'")
            .bind(serde_json::to_value(plan.previous_anchor()).unwrap())
            .execute(pool)
            .await
            .unwrap();
        let fence = DurableConsumerFence::claim(pool, "testnet-10:commit")
            .await
            .unwrap();
        (
            DurableEventApplier::new(inbox.clone(), fence, "testnet-10".into()).unwrap(),
            plan,
            inbox,
        )
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn public_commit_advances_receipt_and_verified_anchor_together(pool: sqlx::PgPool) {
        let (writer, plan, inbox) = commit_setup(&pool, false).await;
        assert!(matches!(
            writer.commit(1, &plan).await.unwrap(),
            DurableCommitOutcome::Committed(_)
        ));
        assert!(inbox.oldest().await.unwrap().is_none());
        let (seq,anchor,bytes):(i64,serde_json::Value,i64)=sqlx::query_as("SELECT committed_sequence,anchor,effect_bytes FROM wrpc_inbox_streams WHERE stream='testnet-10:commit'").fetch_one(&pool).await.unwrap();
        assert_eq!((seq, bytes), (1, 0));
        assert_eq!(anchor, serde_json::to_value(plan.next_anchor()).unwrap());
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn failed_final_commit_requires_recovery_without_acknowledgement(pool: sqlx::PgPool) {
        let (writer, plan, inbox) = commit_setup(&pool, false).await;
        sqlx::raw_sql("CREATE FUNCTION reject_effect_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'simulated final commit failure'; END $$; CREATE TRIGGER reject_effect_delete BEFORE DELETE ON wrpc_inbox_effects FOR EACH ROW EXECUTE FUNCTION reject_effect_delete();").execute(&pool).await.unwrap();
        assert!(writer.commit(1, &plan).await.is_err());
        assert!(inbox.oldest().await.unwrap().is_some());
        assert!(matches!(
            writer.commit(1, &plan).await.unwrap(),
            DurableCommitOutcome::RecoveryRequired(_)
        ));
        let (seq,anchor):(i64,serde_json::Value)=sqlx::query_as("SELECT committed_sequence,anchor FROM wrpc_inbox_streams WHERE stream='testnet-10:commit'").fetch_one(&pool).await.unwrap();
        assert_eq!(seq, 0);
        assert_eq!(
            anchor,
            serde_json::to_value(plan.previous_anchor()).unwrap()
        );
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn empty_notification_commits_only_on_the_matching_writer_network(pool: sqlx::PgPool) {
        let (mut writer, plan, inbox) = commit_setup(&pool, true).await;
        writer.network = "testnet-11".into();
        assert!(writer.commit(1, &plan).await.is_err());
        assert!(inbox.oldest().await.unwrap().is_some());
        writer.network = "testnet-10".into();
        assert!(matches!(
            writer.commit(1, &plan).await.unwrap(),
            DurableCommitOutcome::Committed(_)
        ));
        assert!(inbox.oldest().await.unwrap().is_none());
    }

    struct Writer {
        calls: Mutex<Vec<String>>,
        fail_at: Option<usize>,
        block_at: Option<usize>,
        journal: Arc<InboxEffectJournal>,
    }
    impl Writer {
        async fn record(&self, call: String) -> Result<()> {
            assert!(
                self.journal.load().await?.is_some(),
                "effect preceded durable intent"
            );
            let count = {
                let mut calls = self.calls.lock().unwrap();
                calls.push(call);
                calls.len()
            };
            ensure!(self.fail_at != Some(count), "simulated uncertain write");
            if self.block_at == Some(count) {
                std::future::pending::<()>().await;
            }
            Ok(())
        }
    }
    #[async_trait::async_trait]
    impl Persister for Writer {
        async fn has_utxo(&self, _: &str, _: i32) -> Result<bool> {
            unreachable!("preparation owns lookup work")
        }
        async fn persist_tx(&self, _: &RestTransaction) -> Result<PersistStats> {
            unreachable!("must use existing batch persister")
        }
        async fn persist_batch(&self, _: &[RestTransaction]) -> Result<PersistStats> {
            self.record("persist".into()).await?;
            Ok(PersistStats::default())
        }
        async fn revert_block(&self, hash: &[u8]) -> Result<RevertStats> {
            self.record(hex::encode(hash)).await?;
            Ok(RevertStats::default())
        }
    }
    async fn setup(
        pool: &sqlx::PgPool,
        fail_at: Option<usize>,
    ) -> (Writer, DurableEventPlan, Arc<DurableInbox>) {
        let stream = fail_at.map_or_else(
            || "testnet-10:apply".to_owned(),
            |n| format!("testnet-10:apply:{n}"),
        );
        let inbox = Arc::new(
            DurableInbox::open(pool.clone(), stream.clone(), 4096)
                .await
                .unwrap(),
        );
        inbox.append(1, b"receipt", 1).await.unwrap();
        let fence = DurableConsumerFence::claim(pool, &stream).await.unwrap();
        let journal = Arc::new(InboxEffectJournal::new(inbox.clone(), 1, fence));
        let plan = DurableEventPlan {
            window: Some(LiveWriteWindow {
                unresolved_blocks: Vec::new(),
                transactions: vec![],
                affected_transaction_ids: vec![],
                rejected_transactions: vec![],
                window_width: Some(10),
                observed_blocks: std::collections::BTreeMap::from([(
                    10,
                    BTreeSet::from(["02".repeat(32), "01".repeat(32)]),
                )]),
            }),
            removed: vec!["02".repeat(32), "01".repeat(32)],
            last_added: None,
        };
        (
            Writer {
                calls: Mutex::new(vec![]),
                fail_at,
                block_at: None,
                journal,
            },
            plan,
            inbox,
        )
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn intent_precedes_ordered_removals_and_success_does_not_ack(pool: sqlx::PgPool) {
        let (writer, plan, inbox) = setup(&pool, None).await;
        assert!(matches!(
            apply_ordered(&writer, &writer.journal, &plan)
                .await
                .unwrap(),
            DurableApplyOutcome::Persisted(_)
        ));
        assert_eq!(
            *writer.calls.lock().unwrap(),
            vec!["02".repeat(32), "01".repeat(32), "persist".into()]
        );
        assert_eq!(inbox.oldest().await.unwrap().unwrap().sequence, 1);
        assert!(writer.journal.load().await.unwrap().is_some());
        assert!(matches!(
            apply_ordered(&writer, &writer.journal, &plan)
                .await
                .unwrap(),
            DurableApplyOutcome::RecoveryRequired(_)
        ));
        assert_eq!(writer.calls.lock().unwrap().len(), 3);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn every_partial_write_failure_retains_receipt_and_never_reapplies(pool: sqlx::PgPool) {
        for fail_at in 1..=3 {
            let (writer, plan, inbox) = setup(&pool, Some(fail_at)).await;
            assert!(apply_ordered(&writer, &writer.journal, &plan)
                .await
                .is_err());
            assert_eq!(writer.calls.lock().unwrap().len(), fail_at);
            assert!(matches!(
                apply_ordered(&writer, &writer.journal, &plan)
                    .await
                    .unwrap(),
                DurableApplyOutcome::RecoveryRequired(_)
            ));
            assert_eq!(writer.calls.lock().unwrap().len(), fail_at);
            assert!(inbox.oldest().await.unwrap().is_some());
        }
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn missing_intent_and_stale_generation_cannot_start_writes(pool: sqlx::PgPool) {
        let (writer, mut plan, _) = setup(&pool, None).await;
        plan.removed.push("03".repeat(32));
        assert!(apply_ordered(&writer, &writer.journal, &plan)
            .await
            .is_err());
        assert!(writer.journal.load().await.unwrap().is_none());
        plan.removed.pop();
        DurableConsumerFence::claim(&pool, "testnet-10:apply")
            .await
            .unwrap();
        assert!(apply_ordered(&writer, &writer.journal, &plan)
            .await
            .is_err());
        assert!(writer.calls.lock().unwrap().is_empty());
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn cancelled_write_keeps_intent_for_recovery_before_any_retry(pool: sqlx::PgPool) {
        let (mut writer, plan, inbox) = setup(&pool, None).await;
        writer.block_at = Some(1);
        let writer = Arc::new(writer);
        let plan = Arc::new(plan);
        let task_writer = writer.clone();
        let task_plan = plan.clone();
        let task = tokio::spawn(async move {
            apply_ordered(task_writer.as_ref(), &task_writer.journal, &task_plan).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while writer.calls.lock().unwrap().is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        assert!(inbox.oldest().await.unwrap().is_some());
        assert!(matches!(
            apply_ordered(writer.as_ref(), &writer.journal, &plan)
                .await
                .unwrap(),
            DurableApplyOutcome::RecoveryRequired(_)
        ));
        assert_eq!(writer.calls.lock().unwrap().len(), 1);
    }
}
