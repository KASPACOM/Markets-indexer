//! Resolve immutable current-event cache misses without consuming later
//! notifications or assigning acceptance from a current node snapshot.
use super::*;
use anyhow::ensure;

const BLOCK_LIMIT: usize = 32;
const BYTE_LIMIT: usize = 8 * 1024 * 1024;

#[async_trait::async_trait]
pub(super) trait BlockSource: Send + Sync {
    async fn verify_network(&self) -> Result<()>;
    async fn block(&self, hash: &str) -> Result<RpcBlock>;
}

pub(super) struct RpcBlocks {
    pub rpc: Arc<KaspaRpcClient>,
    pub network: NetworkId,
}

#[async_trait::async_trait]
impl BlockSource for RpcBlocks {
    async fn verify_network(&self) -> Result<()> {
        let info = self.rpc.get_server_info().await?;
        ensure!(
            info.is_synced && info.network_id == self.network,
            "live cache source is unsynced or on another network"
        );
        Ok(())
    }
    async fn block(&self, hash: &str) -> Result<RpcBlock> {
        Ok(self.rpc.get_block(hash.parse()?, true).await?)
    }
}

pub(super) fn current_ready(
    cache: &LiveTransactionCache,
    groups: &[RpcAcceptedTransactionIds],
) -> bool {
    groups.iter().all(|g| {
        g.accepted_transaction_ids.is_empty()
            || (cache
                .blocks
                .contains_key(&g.accepting_block_hash.to_string())
                && g.accepted_transaction_ids
                    .iter()
                    .all(|id| cache.transactions.contains_key(&id.to_string())))
    })
}

pub(super) async fn hydrate(
    cache: &mut LiveTransactionCache,
    groups: &[RpcAcceptedTransactionIds],
    source: &dyn BlockSource,
) -> Result<()> {
    if current_ready(cache, groups) {
        return Ok(());
    }
    source.verify_network().await?;
    let accepting: BTreeSet<_> = groups
        .iter()
        .filter(|g| !current_ready(cache, std::slice::from_ref(*g)))
        .map(|g| g.accepting_block_hash.to_string())
        .collect();
    let mut queue: VecDeque<_> = accepting.iter().cloned().collect();
    let mut fetched = HashSet::new();
    let mut bytes = 0usize;
    while !current_ready(cache, groups) {
        let Some(hash) = queue.pop_front() else { break };
        if !fetched.insert(hash.clone()) {
            continue;
        }
        ensure!(
            fetched.len() <= BLOCK_LIMIT,
            "live cache source block budget exceeded"
        );
        let block = source.block(&hash).await?;
        ensure!(
            block.header.hash.to_string() == hash,
            "live cache source returned another block"
        );
        let verbose = block
            .verbose_data
            .as_ref()
            .context("live cache source omitted block evidence")?;
        ensure!(
            verbose.hash == block.header.hash
                && verbose.blue_score == block.header.blue_score
                && !verbose.is_header_only,
            "live cache source block evidence disagrees"
        );
        bytes = bytes
            .checked_add(serde_json::to_vec(&block)?.len())
            .context("live cache byte overflow")?;
        ensure!(
            bytes <= BYTE_LIMIT,
            "live cache source byte budget exceeded"
        );
        // Expand only current accepting blocks, not arbitrary ancestors.
        // Their accepted transactions can originate in merge-set bodies.
        if accepting.contains(&hash) {
            let missing_body = groups
                .iter()
                .filter(|g| g.accepting_block_hash.to_string() == hash)
                .any(|g| {
                    g.accepted_transaction_ids
                        .iter()
                        .any(|id| !cache.transactions.contains_key(&id.to_string()))
                });
            if missing_body {
                for parent in std::iter::once(&verbose.selected_parent_hash)
                    .chain(verbose.merge_set_blues_hashes.iter())
                    .chain(verbose.merge_set_reds_hashes.iter())
                {
                    if queue.len() + fetched.len() >= BLOCK_LIMIT {
                        break;
                    }
                    let parent = parent.to_string();
                    if !fetched.contains(&parent) && !queue.contains(&parent) {
                        queue.push_back(parent);
                    }
                }
            }
        }
        cache.remember_block(&block)?;
    }
    ensure!(
        current_ready(cache, groups),
        "live source did not supply all current acceptance bodies"
    );
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use kaspa_wrpc_client::prelude::{RpcBlockVerboseData, RpcHeader};
    use std::sync::Mutex;

    pub(crate) fn block(n: u8) -> RpcBlock {
        let hash = hex::encode([n; 32]).parse().unwrap();
        RpcBlock {
            header: RpcHeader {
                hash,
                version: 1,
                parents_by_level: vec![],
                hash_merkle_root: hash,
                accepted_id_merkle_root: hash,
                utxo_commitment: hash,
                timestamp: 1000,
                bits: 0,
                nonce: 0,
                daa_score: 106,
                blue_work: Default::default(),
                blue_score: 106,
                pruning_point: hash,
            },
            transactions: vec![],
            verbose_data: Some(RpcBlockVerboseData {
                hash,
                difficulty: 0.0,
                selected_parent_hash: hash,
                transaction_ids: vec![],
                is_header_only: false,
                blue_score: 106,
                children_hashes: vec![],
                merge_set_blues_hashes: vec![],
                merge_set_reds_hashes: vec![],
                is_chain_block: false,
            }),
        }
    }

    pub(crate) struct FixtureSource(pub Vec<RpcBlock>, pub Mutex<Vec<String>>);
    #[async_trait::async_trait]
    impl BlockSource for FixtureSource {
        async fn verify_network(&self) -> Result<()> {
            Ok(())
        }
        async fn block(&self, hash: &str) -> Result<RpcBlock> {
            self.1.lock().unwrap().push(hash.to_owned());
            self.0
                .iter()
                .find(|b| b.header.hash.to_string() == hash)
                .cloned()
                .context("fixture source block missing")
        }
    }
    fn transaction() -> RpcTransaction {
        RpcTransaction {
            version: 0,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            subnetwork_id: Default::default(),
            gas: 0,
            payload: vec![],
            storage_mass: 0,
            verbose_data: None,
        }
    }
    fn groups(id: &str) -> Vec<RpcAcceptedTransactionIds> {
        vec![RpcAcceptedTransactionIds {
            accepting_block_hash: hex::encode([0x22; 32]).parse().unwrap(),
            accepted_transaction_ids: vec![id.parse().unwrap()],
        }]
    }

    #[tokio::test]
    async fn current_body_in_red_merge_is_cached_without_applying_acceptance() {
        let mut accepting = block(0x22);
        let mut red = block(0x33);
        red.transactions.push(transaction());
        accepting
            .verbose_data
            .as_mut()
            .unwrap()
            .merge_set_reds_hashes
            .push(red.header.hash);
        let body = rpc_transaction_to_rest(&red.transactions[0], &red, Prefix::Testnet).unwrap();
        let groups = groups(&body.transaction_id);
        let mut cache = LiveTransactionCache::new(64, Prefix::Testnet);
        cache
            .pending
            .insert(body.transaction_id.clone(), hex::encode([0x44; 32]));
        cache.pending_order.push_back(body.transaction_id.clone());
        let source = FixtureSource(vec![accepting, red], Mutex::new(vec![]));
        hydrate(&mut cache, &groups, &source).await.unwrap();
        assert!(current_ready(&cache, &groups));
        assert_eq!(cache.pending[&body.transaction_id], hex::encode([0x44; 32]));
        assert!(!cache.transactions[&body.transaction_id].is_accepted);
        let ready = cache.accept(&groups);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].accepting_block_hash, Some(hex::encode([0x22; 32])));
        assert_eq!(source.1.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn source_budget_never_walks_an_unbounded_merge_set() {
        let mut accepting = block(0x22);
        let others: Vec<_> = (40..100).map(block).collect();
        accepting
            .verbose_data
            .as_mut()
            .unwrap()
            .merge_set_blues_hashes = others.iter().map(|b| b.header.hash).collect();
        let mut blocks = vec![accepting];
        blocks.extend(others);
        let source = FixtureSource(blocks, Mutex::new(vec![]));
        let mut cache = LiveTransactionCache::new(128, Prefix::Testnet);
        assert!(
            hydrate(&mut cache, &groups(&hex::encode([0xaa; 32])), &source)
                .await
                .is_err()
        );
        assert!(source.1.lock().unwrap().len() <= BLOCK_LIMIT);
        assert!(cache.pending.is_empty());
    }

    #[tokio::test]
    async fn oversized_source_body_is_not_retained() {
        let mut accepting = block(0x22);
        let mut tx = transaction();
        tx.payload = vec![1; BYTE_LIMIT];
        accepting.transactions.push(tx);
        let source = FixtureSource(vec![accepting], Mutex::new(vec![]));
        let mut cache = LiveTransactionCache::new(64, Prefix::Testnet);
        assert!(
            hydrate(&mut cache, &groups(&hex::encode([0xaa; 32])), &source)
                .await
                .is_err()
        );
        assert!(cache.blocks.is_empty());
        assert!(cache.transactions.is_empty());
    }

    struct UnavailableSource(bool);
    #[async_trait::async_trait]
    impl BlockSource for UnavailableSource {
        async fn verify_network(&self) -> Result<()> {
            ensure!(!self.0, "wrong network");
            Ok(())
        }
        async fn block(&self, _: &str) -> Result<RpcBlock> {
            futures::future::pending().await
        }
    }
    #[tokio::test]
    async fn wrong_network_and_cancelled_fetch_do_not_apply_any_cache_effect() {
        let mut cache = LiveTransactionCache::new(64, Prefix::Testnet);
        let groups = groups(&hex::encode([0xaa; 32]));
        assert!(hydrate(&mut cache, &groups, &UnavailableSource(true))
            .await
            .is_err());
        assert!(tokio::time::timeout(
            Duration::from_millis(5),
            hydrate(&mut cache, &groups, &UnavailableSource(false))
        )
        .await
        .is_err());
        assert!(
            cache.blocks.is_empty() && cache.transactions.is_empty() && cache.pending.is_empty()
        );
    }
    #[tokio::test]
    async fn hydration_eviction_preserves_older_unresolved_acceptance() {
        let mut cache = LiveTransactionCache::new(1, Prefix::Testnet);
        let old = hex::encode([0xaa; 32]);
        cache.transactions.insert(
            old.clone(),
            RestTransaction {
                transaction_id: old.clone(),
                ..Default::default()
            },
        );
        cache.transaction_order.push_back(old.clone());
        cache.pending.insert(old.clone(), hex::encode([0xbb; 32]));
        cache.pending_order.push_back(old.clone());
        let mut accepting = block(0x22);
        accepting.transactions.push(transaction());
        let id = rpc_transaction_to_rest(&accepting.transactions[0], &accepting, Prefix::Testnet)
            .unwrap()
            .transaction_id;
        let source = FixtureSource(vec![accepting], Mutex::new(vec![]));
        hydrate(&mut cache, &groups(&id), &source).await.unwrap();
        assert!(!cache.transactions.contains_key(&old));
        assert!(cache.pending.contains_key(&old));
        assert_eq!(cache.pending_order, VecDeque::from([old]));
    }

    #[tokio::test]
    async fn ready_groups_do_not_exhaust_missing_group_fetch_budget() {
        let mut cache = LiveTransactionCache::new(128, Prefix::Testnet);
        let id = hex::encode([0xaa; 32]);
        cache.transactions.insert(
            id.clone(),
            RestTransaction {
                transaction_id: id.clone(),
                ..Default::default()
            },
        );
        let mut current = Vec::new();
        for n in 1..=40 {
            let b = block(n);
            cache.remember_block(&b).unwrap();
            current.push(RpcAcceptedTransactionIds {
                accepting_block_hash: b.header.hash,
                accepted_transaction_ids: vec![id.parse().unwrap()],
            });
        }
        let missing = block(0xff);
        current.push(RpcAcceptedTransactionIds {
            accepting_block_hash: missing.header.hash,
            accepted_transaction_ids: vec![id.parse().unwrap()],
        });
        let source = FixtureSource(vec![missing], Mutex::new(vec![]));
        hydrate(&mut cache, &current, &source).await.unwrap();
        assert_eq!(source.1.lock().unwrap().len(), 1);
    }
}
