//! Prepare source observations outside the writer lock, then bind every
//! acceptance to its durable local removal revision at commit.
use crate::RestClient;
use anyhow::{ensure, Context, Result};
use kaspa_wrpc_client::prelude::{ConnectOptions, KaspaRpcClient, NetworkId, RpcApi, WrpcEncoding};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tn12_indexer_core::RestTransaction;
use tn12_indexer_db::{
    persist::{
        AcceptingBlockEvidence, CanonicalBlockReplacement, HistoricalAcceptanceMapProof,
        StaleRestAcceptance,
    },
    PgPersister,
};

pub async fn for_blocks(
    writer: &PgPersister,
    rest: &RestClient,
    blocks: &[(Vec<u8>, u64)],
) -> Result<PgPersister> {
    let mut unique = BTreeMap::new();
    for (hash, score) in blocks {
        if let Some(previous) = unique.insert(hash.clone(), *score) {
            ensure!(previous == *score, StaleRestAcceptance);
        }
    }
    let hashes: Vec<_> = unique.keys().cloned().collect();
    let revisions = writer.rest_removal_revisions(&hashes).await?;
    let removed: Vec<_> = unique
        .into_iter()
        .filter(|(hash, _)| revisions.get(hash).copied().unwrap_or(0) > 0)
        .collect();
    if !removed.is_empty() {
        // REST can answer a fresh request from a lagging publication database.
        // Only the independently configured node may renew a removed hash.
        let verifier = rest
            .canonical_verifier
            .as_ref()
            .ok_or(StaleRestAcceptance)?;
        verifier.verify(&removed).await.map_err(|error| {
            anyhow::Error::new(StaleRestAcceptance)
                .context(format!("node acceptance proof unavailable: {error:#}"))
        })?;
    }
    Ok(writer.with_rest_removal_guard(revisions))
}
pub async fn for_transactions(
    writer: &PgPersister,
    rest: &RestClient,
    txs: &[RestTransaction],
) -> Result<PgPersister> {
    let blocks = txs
        .iter()
        .filter(|tx| tx.is_accepted)
        .map(|tx| {
            Ok((
                hex::decode(
                    tx.accepting_block_hash
                        .as_deref()
                        .ok_or(StaleRestAcceptance)?,
                )?,
                tx.accepting_block_blue_score.ok_or(StaleRestAcceptance)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    for_blocks(writer, rest, &blocks).await
}
pub async fn for_replacement(
    writer: &PgPersister,
    rest: &RestClient,
    proof: &CanonicalBlockReplacement,
) -> Result<PgPersister> {
    let block = proof.target_block();
    for_blocks(writer, rest, &[(block.hash.clone(), block.blue_score)]).await
}
pub async fn for_acceptance_map(
    writer: &PgPersister,
    rest: &RestClient,
    proof: &HistoricalAcceptanceMapProof,
) -> Result<PgPersister> {
    let blocks = proof
        .source()
        .window()
        .canonical
        .iter()
        .map(|b| (b.block.hash.clone(), b.block.blue_score))
        .collect::<Vec<_>>();
    for_blocks(writer, rest, &blocks).await
}

/// No REST response, including a freshly fetched one, grants this authority.
#[async_trait::async_trait]
pub(crate) trait CanonicalVerifier: std::fmt::Debug + Send + Sync {
    async fn verify(&self, blocks: &[(Vec<u8>, u64)]) -> Result<()>;
    async fn block_evidence(&self, _hash: &[u8]) -> Result<AcceptingBlockEvidence> {
        anyhow::bail!("node block evidence unavailable")
    }
    async fn coordinates(&self, _hashes: &[Vec<u8>]) -> Result<Vec<(Vec<u8>, u64)>> {
        anyhow::bail!("node coordinate lookup unavailable")
    }
}
#[derive(Debug)]
struct NodeVerifier {
    endpoint: String,
    network: NetworkId,
}

pub(crate) fn configured_verifier() -> Result<Option<Arc<dyn CanonicalVerifier>>> {
    match (
        std::env::var("TN12_REST_CANONICAL_WRPC_URL").ok(),
        std::env::var("TN12_REST_CANONICAL_NETWORK").ok(),
    ) {
        (None, None) => Ok(None),
        (Some(endpoint), Some(network)) => Ok(Some(Arc::new(NodeVerifier {
            endpoint,
            network: network.parse()?,
        }))),
        _ => anyhow::bail!(
            "configure both TN12_REST_CANONICAL_WRPC_URL and TN12_REST_CANONICAL_NETWORK"
        ),
    }
}
#[async_trait::async_trait]
impl CanonicalVerifier for NodeVerifier {
    async fn verify(&self, blocks: &[(Vec<u8>, u64)]) -> Result<()> {
        let hashes: Vec<_> = blocks.iter().map(|(hash, _)| hash.clone()).collect();
        let observed = self.observe(&hashes).await?;
        ensure!(observed.len() == blocks.len(), StaleRestAcceptance);
        for ((hash, score), actual) in blocks.iter().zip(observed) {
            ensure!(
                *hash == actual.hash && *score == actual.blue_score && actual.is_chain_block,
                StaleRestAcceptance
            );
        }
        Ok(())
    }
    async fn block_evidence(&self, hash: &[u8]) -> Result<AcceptingBlockEvidence> {
        self.observe(&[hash.to_vec()])
            .await?
            .pop()
            .context("node omitted block evidence")
    }
    async fn coordinates(&self, hashes: &[Vec<u8>]) -> Result<Vec<(Vec<u8>, u64)>> {
        Ok(self
            .observe(hashes)
            .await?
            .into_iter()
            .map(|block| (block.hash, block.blue_score))
            .collect())
    }
}
impl NodeVerifier {
    async fn observe(&self, hashes: &[Vec<u8>]) -> Result<Vec<AcceptingBlockEvidence>> {
        let endpoint = self.endpoint.clone();
        let network = self.network;
        let hashes = hashes.to_vec();
        let task = tokio::spawn(async move {
            let rpc = KaspaRpcClient::new_with_args(
                WrpcEncoding::Borsh,
                Some(&endpoint),
                None,
                Some(network),
                None,
            )?;
            let result = tokio::time::timeout(Duration::from_secs(10), async {
                rpc.connect(Some(ConnectOptions {
                    connect_timeout: Some(Duration::from_secs(3)),
                    ..ConnectOptions::blocking_fallback()
                }))
                .await?;
                let info = rpc.get_server_info().await?;
                ensure!(
                    info.is_synced && info.network_id == network,
                    StaleRestAcceptance
                );
                let mut observed = Vec::with_capacity(hashes.len());
                for bytes in hashes {
                    let hash = hex::encode(&bytes).parse()?;
                    let block = rpc.get_block(hash, false).await?;
                    let verbose = block.verbose_data.ok_or(StaleRestAcceptance)?;
                    ensure!(verbose.hash == hash, StaleRestAcceptance);
                    ensure!(
                        block.header.blue_score == verbose.blue_score,
                        StaleRestAcceptance
                    );
                    let mut parents: Vec<Vec<Vec<u8>>> = block
                        .header
                        .parents_by_level
                        .iter()
                        .map(|level| level.iter().map(|hash| hash.as_bytes().to_vec()).collect())
                        .collect();
                    for level in &mut parents {
                        level.sort();
                    }
                    observed.push(AcceptingBlockEvidence {
                        hash: bytes,
                        is_chain_block: verbose.is_chain_block,
                        blue_score: verbose.blue_score,
                        timestamp: block.header.timestamp,
                        selected_parent: verbose.selected_parent_hash.as_bytes().to_vec(),
                        parents,
                        accepted_id_merkle_root: block
                            .header
                            .accepted_id_merkle_root
                            .as_bytes()
                            .to_vec(),
                        utxo_commitment: block.header.utxo_commitment.as_bytes().to_vec(),
                    });
                }
                Ok::<_, anyhow::Error>(observed)
            })
            .await;
            // This task owns SDK cleanup even when its request is cancelled.
            rpc.disconnect().await?;
            result?
        });
        tokio::time::timeout(Duration::from_secs(13), task).await??
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn cancelled_verification_still_closes_sdk_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let verifier = NodeVerifier {
            endpoint: format!("ws://{}", listener.local_addr().unwrap()),
            network: "testnet-10".parse().unwrap(),
        };
        let request = tokio::spawn(async move { verifier.verify(&[(vec![0x11; 32], 100)]).await });
        let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        request.abort();
        let mut bytes = Vec::new();
        // The fake peer deliberately never completes the websocket handshake.
        // Cancellation must still lead to closure after the connect deadline.
        tokio::time::timeout(Duration::from_secs(15), socket.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "one-shot verification must not reconnect after its caller is gone"
        );
    }
    #[tokio::test]
    async fn unavailable_node_is_bounded() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        drop(listener);
        let verifier = NodeVerifier {
            endpoint,
            network: "testnet-10".parse().unwrap(),
        };
        assert!(tokio::time::timeout(
            Duration::from_secs(15),
            verifier.verify(&[(vec![0x11; 32], 100)])
        )
        .await
        .unwrap()
        .is_err());
    }
}
