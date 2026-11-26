//! Pull-based bounded wRPC adapter. The committed hash is the durable intake
//! cursor, so disconnects never require buffering an unbounded notification tail.
use crate::{
    durable_inbox::ChainAnchor,
    durable_join::{DurableJoin, JOIN_CACHE_BYTES},
};
use anyhow::{ensure, Context, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use futures::{SinkExt, StreamExt};
use kaspa_addresses::Prefix;
use kaspa_rpc_core::api::ops::RpcApiOps;
use kaspa_wrpc_client::prelude::*;
use serde_json::{json, Value};
use std::{
    collections::{BTreeSet, VecDeque},
    time::Duration,
};
use tokio_tungstenite::{
    tungstenite::{protocol::WebSocketConfig, Message},
    MaybeTlsStream, WebSocketStream,
};
use workflow_rpc::messages::borsh::{BorshReqHeader, BorshServerMessage, ServerMessageKind};
use workflow_serializer::prelude::Serializable;

const FRAME_BYTES: usize = 8 * 1024 * 1024;
const FETCH_BYTES: usize = 64 * 1024 * 1024;
const FETCH_BLOCKS: usize = 256;
type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

pub struct ShadowSource {
    socket: Socket,
    id: u64,
    network: String,
    bytes: usize,
}
pub struct ShadowPlan {
    pub target: ChainAnchor,
    pub steps: Value,
}

// Count scheduled bodies, not just completed fetches. Admission happens before
// converting hashes to strings, including for a large decoded merge set.
fn schedule_body(
    queue: &mut VecDeque<RpcHash>,
    scheduled: &mut BTreeSet<RpcHash>,
    hash: RpcHash,
) -> Result<()> {
    if !scheduled.contains(&hash) {
        ensure!(
            scheduled.len() < FETCH_BLOCKS,
            "shadow body hydration block budget exceeded"
        );
        scheduled.insert(hash);
        queue.push_back(hash);
    }
    Ok(())
}

impl ShadowSource {
    pub async fn connect(endpoint: &str, network: &str) -> Result<Self> {
        let (socket, _) = tokio::time::timeout(
            Duration::from_secs(10),
            tokio_tungstenite::connect_async_with_config(
                endpoint,
                Some(WebSocketConfig {
                    max_message_size: Some(FRAME_BYTES),
                    max_frame_size: Some(FRAME_BYTES),
                    max_write_buffer_size: 1024 * 1024,
                    ..Default::default()
                }),
                true,
            ),
        )
        .await
        .context("shadow node connect deadline")??;
        let mut source = Self {
            socket,
            id: 0,
            network: network.into(),
            bytes: 0,
        };
        let info: Serializable<GetServerInfoResponse> = source
            .call(
                RpcApiOps::GetServerInfo,
                Serializable(GetServerInfoRequest {}),
            )
            .await?;
        ensure!(
            info.0.network_id.to_string() == network && info.0.is_synced,
            "shadow source network mismatch or unsynced"
        );
        Ok(source)
    }

    async fn call<Q: BorshSerialize, R: BorshDeserialize>(
        &mut self,
        op: RpcApiOps,
        request: Q,
    ) -> Result<R> {
        self.id = self.id.checked_add(1).context("RPC id exhausted")?;
        let id = self.id;
        let mut request_bytes = borsh::to_vec(&BorshReqHeader::new(Some(id), op))?;
        request_bytes.extend(borsh::to_vec(&request)?);
        tokio::time::timeout(Duration::from_secs(15), async {
            self.socket.send(Message::Binary(request_bytes)).await?;
            loop {
                let frame = self
                    .socket
                    .next()
                    .await
                    .context("shadow node disconnected")??;
                let bytes = match frame {
                    Message::Binary(bytes) => bytes,
                    Message::Ping(_) => {
                        self.socket.flush().await?;
                        continue;
                    }
                    Message::Pong(_) => continue,
                    _ => anyhow::bail!("unexpected shadow RPC frame"),
                };
                self.bytes = self
                    .bytes
                    .checked_add(bytes.len())
                    .context("source byte overflow")?;
                ensure!(
                    self.bytes <= FETCH_BYTES,
                    "shadow source window byte budget exceeded"
                );
                let reply: BorshServerMessage<RpcApiOps, u64> = bytes.as_slice().try_into()?;
                ensure!(
                    matches!(reply.header.kind, ServerMessageKind::Success)
                        && reply.header.id == Some(id),
                    "shadow response identity mismatch"
                );
                crate::bounded_notification::validate_shadow_response(op, reply.payload)?;
                return Ok(
                    std::result::Result::<R, workflow_rpc::error::ServerError>::try_from_slice(
                        reply.payload,
                    )??,
                );
            }
        })
        .await
        .context("shadow RPC deadline exceeded")?
    }

    async fn block(&mut self, hash: &str) -> Result<RpcBlock> {
        let reply: Serializable<GetBlockResponse> = self
            .call(
                RpcApiOps::GetBlock,
                Serializable(GetBlockRequest::new(hash.parse()?, true)),
            )
            .await?;
        ensure!(
            reply.0.block.header.hash.to_string() == hash,
            "node returned another block"
        );
        Ok(reply.0.block)
    }

    /// Complete a bounded, source-ordered plan before its first state change.
    /// An oversized window stops safely; it never skips hashes to reach the tip.
    pub async fn prepare(
        &mut self,
        anchor: &ChainAnchor,
        confirmations: u64,
        batch_blocks: usize,
    ) -> Result<Option<ShadowPlan>> {
        self.bytes = 0;
        ensure!(anchor.network == self.network, "anchor network mismatch");
        let anchor_block = self.block(&anchor.block_hash).await?;
        ensure!(
            anchor_block.header.blue_score == anchor.blue_score,
            "source checkpoint score mismatch"
        );
        let response: Serializable<GetVirtualChainFromBlockResponse> = self
            .call(
                RpcApiOps::GetVirtualChainFromBlock,
                Serializable(GetVirtualChainFromBlockRequest::new(
                    anchor.block_hash.parse()?,
                    true,
                    Some(confirmations),
                )),
            )
            .await?;
        let mut r = response.0;
        ensure!(
            (1..=16).contains(&batch_blocks),
            "batch blocks must be 1..16"
        );
        if r.removed_chain_block_hashes.is_empty() && r.added_chain_block_hashes.is_empty() {
            ensure!(
                r.accepted_transaction_ids.is_empty(),
                "acceptance without chain change"
            );
            return Ok(None);
        }
        ensure!(
            r.removed_chain_block_hashes.len() <= 128,
            "shadow removal window block budget exceeded"
        );
        // Every addition needs an explicit acceptance group, including empty ones.
        ensure!(
            r.accepted_transaction_ids.len() == r.added_chain_block_hashes.len()
                && r.accepted_transaction_ids
                    .iter()
                    .zip(&r.added_chain_block_hashes)
                    .all(|(g, h)| g.accepting_block_hash == *h),
            "node acceptance groups missing or unordered"
        );
        // Consume a canonical prefix, then request the next page from its hash.
        // Never discard removals or infer progress from the unprocessed suffix.
        r.added_chain_block_hashes.truncate(batch_blocks);
        r.accepted_transaction_ids.truncate(batch_blocks);
        let event = VirtualChainChangedNotification {
            removed_chain_block_hashes: r.removed_chain_block_hashes.into(),
            added_chain_block_hashes: r.added_chain_block_hashes.into(),
            accepted_transaction_ids: r.accepted_transaction_ids.into(),
        };
        let prefix: Prefix = self.network.parse::<NetworkId>()?.into();
        let mut cache = DurableJoin::new(JOIN_CACHE_BYTES)?;
        let mut queue = VecDeque::new();
        let mut scheduled = BTreeSet::new();
        let anchor_hash: RpcHash = anchor.block_hash.parse()?;
        schedule_body(&mut queue, &mut scheduled, anchor_hash)?;
        for hash in event
            .removed_chain_block_hashes
            .iter()
            .chain(event.added_chain_block_hashes.iter())
        {
            schedule_body(&mut queue, &mut scheduled, *hash)?;
        }
        let mut headers = Vec::new();
        while let Some(rpc_hash) = queue.pop_front() {
            let hash = rpc_hash.to_string();
            let block = if rpc_hash == anchor_hash {
                anchor_block.clone()
            } else {
                self.block(&hash).await?
            };
            let verbose = block
                .verbose_data
                .as_ref()
                .context("node omitted selected parent evidence")?;
            ensure!(!verbose.is_header_only, "node omitted transaction bodies");
            // Expand only selected chain blocks. Their merge set holds the
            // accepted bodies; recursively traversing all ancestors is forbidden.
            let on_path = event
                .added_chain_block_hashes
                .iter()
                .chain(event.removed_chain_block_hashes.iter())
                .any(|h| *h == rpc_hash);
            if on_path {
                schedule_body(&mut queue, &mut scheduled, verbose.selected_parent_hash)?;
                if event
                    .added_chain_block_hashes
                    .iter()
                    .any(|h| *h == rpc_hash)
                {
                    for hash in verbose
                        .merge_set_blues_hashes
                        .iter()
                        .chain(verbose.merge_set_reds_hashes.iter())
                    {
                        schedule_body(&mut queue, &mut scheduled, *hash)?;
                    }
                    headers.push(json!({"hash":hash,"score":block.header.blue_score,"time":block.header.timestamp,"daa":block.header.daa_score,"parents":block.header.parents_by_level.first().map(|v|v.iter().map(ToString::to_string).collect::<Vec<_>>()).unwrap_or_default()}));
                }
            }
            cache.remember_block(&block, prefix)?;
            if queue.is_empty() {
                break;
            }
        }
        let proof = cache
            .prepare_contiguous_change(&self.network, anchor, &event)?
            .context("node window lacks continuous selected-parent path or accepted bodies")?;
        let target = proof.next_anchor().clone();
        let mut steps = Vec::new();
        for hash in &proof.event().removed {
            steps.push(json!({"kind":"remove","evidence":{"hash":hash}}));
        }
        // Empty chain blocks must also become durable before checkpoint advance.
        for header in headers {
            steps.push(json!({"kind":"anchor","evidence":header}));
        }
        if let Some(window) = &proof.event().window {
            for tx in &window.transactions {
                steps.push(json!({"kind":"apply","evidence":tx}));
            }
        }
        let steps = Value::Array(steps);
        ensure!(
            serde_json::to_vec(&steps)?.len() <= 32 * 1024 * 1024,
            "shadow prepared plan exceeds budget"
        );
        Ok(Some(ShadowPlan { target, steps }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use workflow_rpc::messages::borsh::BorshServerMessageHeader;

    fn hash(n: u8) -> RpcHash {
        hex::encode([n; 32]).parse().unwrap()
    }
    fn block(n: u8) -> RpcBlock {
        let h = hash(n);
        let parent = hash(n.saturating_sub(1));
        RpcBlock {
            header: RpcHeader {
                hash: h,
                version: 1,
                parents_by_level: vec![vec![parent]],
                hash_merkle_root: h,
                accepted_id_merkle_root: h,
                utxo_commitment: h,
                timestamp: u64::from(n) * 1000,
                bits: 0,
                nonce: 0,
                daa_score: u64::from(n),
                blue_work: Default::default(),
                blue_score: u64::from(n),
                pruning_point: hash(0),
            },
            transactions: vec![],
            verbose_data: Some(RpcBlockVerboseData {
                hash: h,
                difficulty: 0.0,
                selected_parent_hash: parent,
                transaction_ids: vec![],
                is_header_only: false,
                blue_score: u64::from(n),
                children_hashes: vec![],
                merge_set_blues_hashes: vec![],
                merge_set_reds_hashes: vec![],
                is_chain_block: true,
            }),
        }
    }
    fn info(network: &str) -> GetServerInfoResponse {
        GetServerInfoResponse {
            rpc_api_version: 1,
            rpc_api_revision: 0,
            server_version: "synthetic".into(),
            network_id: network.parse().unwrap(),
            has_utxo_index: true,
            is_synced: true,
            virtual_daa_score: 4,
        }
    }
    fn response<R: BorshSerialize>(id: u64, op: RpcApiOps, body: R) -> Vec<u8> {
        let mut bytes = borsh::to_vec(&BorshServerMessageHeader::new(
            Some(id),
            ServerMessageKind::Success,
            Some(op),
        ))
        .unwrap();
        bytes.extend(
            borsh::to_vec(&std::result::Result::<R, workflow_rpc::error::ServerError>::Ok(body))
                .unwrap(),
        );
        bytes
    }
    #[test]
    fn shadow_hydration_admission_is_bounded_before_fetch() {
        let mut queue = VecDeque::new();
        let mut scheduled = BTreeSet::new();
        for n in 0..FETCH_BLOCKS {
            schedule_body(&mut queue, &mut scheduled, hash(n as u8)).unwrap();
        }
        // Duplicates consume no additional capacity, including after dequeue.
        queue.pop_front();
        schedule_body(&mut queue, &mut scheduled, hash(0)).unwrap();
        assert_eq!(queue.len(), FETCH_BLOCKS - 1);
        let extra: RpcHash = hex::encode([1u8; 31].into_iter().chain([2]).collect::<Vec<_>>())
            .parse()
            .unwrap();
        assert!(schedule_body(&mut queue, &mut scheduled, extra).is_err());
        assert_eq!(scheduled.len(), FETCH_BLOCKS);
        assert_eq!(queue.len(), FETCH_BLOCKS - 1);
    }

    #[test]
    fn shadow_response_preflight_accepts_pinned_serializers_and_rejects_truncation() {
        let chain = GetVirtualChainFromBlockResponse::new(
            vec![hash(1)],
            vec![hash(2)],
            vec![RpcAcceptedTransactionIds {
                accepting_block_hash: hash(2),
                accepted_transaction_ids: vec![hash(3)],
            }],
        );
        for (op, payload) in [
            (
                RpcApiOps::GetServerInfo,
                borsh::to_vec(&Ok::<_, workflow_rpc::error::ServerError>(Serializable(
                    info("testnet-10"),
                )))
                .unwrap(),
            ),
            (
                RpcApiOps::GetBlock,
                borsh::to_vec(&Ok::<_, workflow_rpc::error::ServerError>(Serializable(
                    GetBlockResponse { block: block(1) },
                )))
                .unwrap(),
            ),
            (
                RpcApiOps::GetVirtualChainFromBlock,
                borsh::to_vec(&Ok::<_, workflow_rpc::error::ServerError>(Serializable(
                    chain,
                )))
                .unwrap(),
            ),
        ] {
            crate::bounded_notification::validate_shadow_response(op, &payload).unwrap();
            for end in 0..payload.len() {
                assert!(
                    crate::bounded_notification::validate_shadow_response(op, &payload[..end])
                        .is_err()
                );
            }
            let mut trailing = payload;
            trailing.push(0);
            assert!(crate::bounded_notification::validate_shadow_response(op, &trailing).is_err());
        }
    }
    async fn node(network: &str) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let network = network.to_owned();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(Message::Binary(bytes))) = socket.next().await {
                let mut wire = bytes.as_slice();
                let header = BorshReqHeader::<RpcApiOps, u64>::deserialize(&mut wire).unwrap();
                let id = header.id.unwrap();
                let op = header.op;
                let bytes = match op {
                    RpcApiOps::GetServerInfo => response(id, op, Serializable(info(&network))),
                    RpcApiOps::GetVirtualChainFromBlock => {
                        let request =
                            Serializable::<GetVirtualChainFromBlockRequest>::try_from_slice(wire)
                                .unwrap();
                        assert_eq!(request.0.start_hash, hash(1));
                        response(
                            id,
                            op,
                            Serializable(GetVirtualChainFromBlockResponse::new(
                                vec![],
                                vec![hash(2), hash(3), hash(4)],
                                (2..=4)
                                    .map(|n| RpcAcceptedTransactionIds {
                                        accepting_block_hash: hash(n),
                                        accepted_transaction_ids: vec![],
                                    })
                                    .collect(),
                            )),
                        )
                    }
                    RpcApiOps::GetBlock => {
                        let request =
                            Serializable::<GetBlockRequest>::try_from_slice(wire).unwrap();
                        let n = (0..=4).find(|n| hash(*n) == request.0.hash).unwrap();
                        response(id, op, Serializable(GetBlockResponse { block: block(n) }))
                    }
                    _ => panic!("unexpected source operation"),
                };
                socket.send(Message::Binary(bytes)).await.unwrap();
            }
        });
        (url, task)
    }
    #[tokio::test]
    async fn shadow_source_consumes_only_a_continuous_bounded_prefix() {
        let (url, server) = node("testnet-10").await;
        let mut source = ShadowSource::connect(&url, "testnet-10").await.unwrap();
        let plan = source
            .prepare(
                &ChainAnchor {
                    network: "testnet-10".into(),
                    block_hash: hash(1).to_string(),
                    blue_score: 1,
                },
                0,
                2,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(plan.target.block_hash, hash(3).to_string());
        assert_eq!(plan.steps.as_array().unwrap().len(), 2);
        assert!(plan
            .steps
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["kind"] == "anchor"));
        drop(source);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn shadow_source_rejects_wrong_seed_checkpoint_score() {
        let (url, server) = node("testnet-10").await;
        let mut source = ShadowSource::connect(&url, "testnet-10").await.unwrap();
        let error = source
            .prepare(
                &ChainAnchor {
                    network: "testnet-10".into(),
                    block_hash: hash(1).to_string(),
                    blue_score: 999,
                },
                0,
                2,
            )
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("checkpoint score mismatch"));
        drop(source);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn shadow_source_rejects_another_network() {
        let (url, server) = node("testnet-11").await;
        assert!(ShadowSource::connect(&url, "testnet-10").await.is_err());
        server.await.unwrap();
    }
}
