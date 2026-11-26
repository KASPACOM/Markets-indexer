//! Bounded, same-source observations for historical acceptance splits/merges.
use super::{RestClient, RestHealth};
use anyhow::{ensure, Context, Result};
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet};
use tn12_indexer_core::VirtualChainBlock;
use tn12_indexer_db::persist::{
    AcceptanceConflict, AcceptedInputEvidence, AcceptedOutputEvidence, AcceptingBlockEvidence,
    HistoricalAcceptanceBlock, HistoricalAcceptanceCohort, HistoricalAcceptanceMapProof,
    HistoricalAcceptanceWindow,
};

const MAX_BYTES: usize = 64 * 1024 * 1024;
struct ResponseBudget {
    used: usize,
}
impl RestClient {
    async fn map_response<T: DeserializeOwned>(
        &self,
        path: &str,
        budget: &mut ResponseBudget,
    ) -> Result<T> {
        let request = if path == "/info/health" {
            self.source_health_request()
        } else {
            self.http.get(format!("{}{}", self.base_url, path))
        };
        let mut response = request
            .send()
            .await
            .context("fetch historical acceptance evidence")?;
        if path == "/info/health" {
            crate::source_observation::validate_health_headers(
                response.headers(),
                chrono::Utc::now().timestamp_millis(),
            )?;
        }
        // The source marks health 503 while its database is behind, but still
        // returns its database score. All evidence endpoints must return 200.
        if !(path == "/info/health" && response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE) {
            super::require_success(response.status(), path)?;
        }
        let response_limit = if path == "/info/health" {
            super::MAX_OBSERVATION_BYTES
        } else {
            MAX_BYTES
        };
        let remaining = MAX_BYTES.saturating_sub(budget.used).min(response_limit);
        ensure!(
            response
                .content_length()
                .is_none_or(|n| n <= remaining as u64),
            "historical acceptance cumulative response budget exceeded"
        );
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                chunk.len()
                    <= MAX_BYTES
                        .saturating_sub(budget.used)
                        .min(response_limit.saturating_sub(body.len())),
                "historical acceptance cumulative response budget exceeded"
            );
            budget.used += chunk.len();
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).context("decode historical acceptance evidence")
    }
    async fn map_block(
        &self,
        hash: &[u8],
        budget: &mut ResponseBudget,
    ) -> Result<AcceptingBlockEvidence> {
        ensure!(
            hash.len() == 32,
            "invalid historical acceptance block identity"
        );
        let text = hex::encode(hash);
        let raw = self
            .map_response(&format!("/blocks/{text}?includeTransactions=false"), budget)
            .await?;
        super::acceptance::parse_block(&raw, &text)
    }
    async fn map_page(
        &self,
        start: u64,
        budget: &mut ResponseBudget,
    ) -> Result<Vec<VirtualChainBlock>> {
        let end = start
            .checked_add(10)
            .context("historical acceptance range overflow")?;
        let blocks: Vec<VirtualChainBlock> = self
            .map_response(
                &format!("/virtual-chain?blueScoreGte={start}&limit=10&resolveInputs=true"),
                budget,
            )
            .await?;
        ensure!(
            blocks
                .iter()
                .all(|b| b.blue_score >= start && b.blue_score < end),
            "historical acceptance response escaped its requested page"
        );
        Ok(blocks)
    }
    async fn map_observation(
        &self,
        old_hashes: &[Vec<u8>],
        wanted: &BTreeSet<Vec<u8>>,
        incoming: &[u8],
        fixed: Option<(u64, u64)>,
        budget: &mut ResponseBudget,
    ) -> Result<HistoricalAcceptanceWindow> {
        let tip: RestHealth = self.map_response("/info/health", budget).await?;
        if !self.allow_degraded_snapshot {
            tip.database
                .require_current_transactions(chrono::Utc::now().timestamp_millis())?;
        }
        let mut removed = Vec::new();
        for hash in old_hashes {
            let block = self.map_block(hash, budget).await?;
            ensure!(
                !block.is_chain_block,
                "historical acceptance old block is still canonical"
            );
            removed.push(block);
        }
        let incoming_block = self.map_block(incoming, budget).await?;
        ensure!(
            incoming_block.is_chain_block,
            "historical acceptance incoming block is not canonical"
        );
        let origin = (incoming_block.blue_score / 10) * 10;
        let mut pages = BTreeMap::new();
        let mut seen = BTreeSet::new();
        let mut tx_count = 0usize;
        let mut io_count = 0usize;
        let mut low = origin;
        let mut high = origin;
        let mut next = origin;
        let mut right = true;
        if let Some((start, end)) = fixed {
            low = start;
            high = end - 9;
            next = start;
        }
        loop {
            let page = self.map_page(next, budget).await?;
            for block in &page {
                tx_count = tx_count
                    .checked_add(block.transactions.len())
                    .context("historical acceptance transaction count overflow")?;
                for tx in &block.transactions {
                    ensure!(
                        tx.is_accepted,
                        "historical acceptance page contains an unaccepted transaction"
                    );
                    io_count = io_count
                        .checked_add(tx.inputs.len())
                        .and_then(|n| n.checked_add(tx.outputs.len()))
                        .context("historical acceptance I/O count overflow")?;
                    let id = hex::decode(&tx.transaction_id)?;
                    ensure!(
                        id.len() == 32 && seen.insert(id),
                        "historical acceptance has invalid or repeated transaction membership"
                    );
                }
            }
            ensure!(
                tx_count <= 50_000 && io_count <= 200_000,
                "historical acceptance source window exceeds transaction or I/O bounds"
            );
            ensure!(
                pages.insert(next, page).is_none(),
                "historical acceptance page repeated"
            );
            if fixed.is_some() {
                if next == high {
                    break;
                }
                next = next
                    .checked_add(10)
                    .context("historical acceptance range overflow")?;
                continue;
            }
            low = low.min(next);
            high = high.max(next);
            let end = high
                .checked_add(9)
                .context("historical acceptance range overflow")?;
            if wanted.is_subset(&seen)
                && removed
                    .iter()
                    .all(|b| b.blue_score >= low && b.blue_score <= end)
            {
                break;
            }
            ensure!(
                high - low + 10 < 1000,
                "historical acceptance cohort is incomplete at source window bound"
            );
            let expand_left = removed.iter().any(|b| b.blue_score < low)
                || (!removed.iter().any(|b| b.blue_score > end) && !right && low >= 10);
            next = if expand_left {
                low.checked_sub(10)
                    .context("historical acceptance lower bound exhausted")?
            } else {
                high.checked_add(10)
                    .context("historical acceptance upper bound overflow")?
            };
            right = !right;
        }
        ensure!(
            wanted.is_subset(&seen),
            "historical acceptance repeat is missing a cohort transaction"
        );
        let mut canonical = Vec::new();
        for block in pages.into_values().flatten() {
            let hash = hex::decode(&block.hash)?;
            let evidence = if hash == incoming_block.hash {
                incoming_block.clone()
            } else {
                self.map_block(&hash, budget).await?
            };
            ensure!(
                evidence.is_chain_block
                    && evidence.blue_score == block.blue_score
                    && evidence.timestamp == block.timestamp,
                "historical acceptance page disagrees with node block evidence"
            );
            let mut accepted = HistoricalAcceptanceBlock {
                block: evidence,
                transaction_ids: vec![],
                inputs: vec![],
                outputs: vec![],
            };
            for tx in block.transactions {
                let tx = tx.with_normalized_missing_output_indexes();
                let id = hex::decode(&tx.transaction_id)?;
                accepted.transaction_ids.push(id.clone());
                for input in tx.inputs {
                    accepted.inputs.push(AcceptedInputEvidence {
                        transaction_id: id.clone(),
                        previous_txid: hex::decode(&input.previous_outpoint_hash)?,
                        previous_vout: input.previous_outpoint_index.parse()?,
                        previous_amount: input.previous_outpoint_amount,
                        previous_script: input
                            .previous_outpoint_script
                            .as_deref()
                            .map(hex::decode)
                            .transpose()?,
                    });
                }
                for output in tx.outputs {
                    accepted.outputs.push(AcceptedOutputEvidence {
                        transaction_id: id.clone(),
                        vout: i32::try_from(output.index)?,
                        amount: output.amount,
                        script: hex::decode(&output.script_public_key)?,
                    });
                }
            }
            canonical.push(accepted);
        }
        Ok(HistoricalAcceptanceWindow {
            source_tip: tip.database.blue_score,
            start_score: low,
            end_score: high + 9,
            removed,
            canonical,
        })
    }

    async fn historical_acceptance_observations(
        &self,
        old_hashes: &[Vec<u8>],
        transactions: &[(Vec<u8>, Vec<u8>)],
        incoming: &[u8],
    ) -> Result<(HistoricalAcceptanceWindow, HistoricalAcceptanceWindow)> {
        let mut budget = ResponseBudget { used: 0 };
        let wanted = transactions.iter().map(|(_, txid)| txid.clone()).collect();
        let mut first = self
            .map_observation(old_hashes, &wanted, incoming, None, &mut budget)
            .await?;
        let mut second = self
            .map_observation(
                old_hashes,
                &wanted,
                incoming,
                Some((first.start_score, first.end_score)),
                &mut budget,
            )
            .await?;
        // Both observed tips support this common floor. Advancing tips do not
        // invalidate otherwise identical, already settled historical evidence.
        let floor = first.source_tip.min(second.source_tip);
        first.source_tip = floor;
        second.source_tip = floor;
        Ok((first, second))
    }

    pub async fn verify_historical_acceptance_map(
        &self,
        cohort: HistoricalAcceptanceCohort,
        conflict: &AcceptanceConflict,
    ) -> Result<HistoricalAcceptanceMapProof> {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let incoming = hex::decode(&conflict.incoming_hash)?;
            let conflict_id = hex::decode(&conflict.transaction_id)?;
            let old = hex::decode(&conflict.persisted_hash)?;
            let transactions = cohort.transactions();
            ensure!(
                transactions.contains(&(old, conflict_id.clone())),
                "acceptance conflict is outside captured cohort"
            );
            let (first, second) = self
                .historical_acceptance_observations(cohort.old_hashes(), &transactions, &incoming)
                .await?;
            let proof = HistoricalAcceptanceMapProof::verify(cohort, first, second)?;
            ensure!(
                proof
                    .source()
                    .targets()
                    .iter()
                    .any(|t| t.transaction_id == conflict_id && t.target_hash == incoming),
                "historical acceptance proof disagrees with incoming conflict"
            );
            Ok(proof)
        })
        .await
        .context("historical acceptance source proof exceeded30seconds")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn observed(
        mode: &'static str,
    ) -> Result<tn12_indexer_db::persist::HistoricalAcceptanceSourceProof> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut observations = 0;
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let mut bytes = [0; 2048];
                    let n = socket.read(&mut bytes).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    request.extend_from_slice(&bytes[..n]);
                }
                let path = std::str::from_utf8(&request)
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap();
                let score2 = if mode == "expand" { 115 } else { 106 };
                let body=if path.split('?').next()==Some("/info/health") {
                    observations+=1;
                    let snapshot = mode.starts_with("snapshot_");
                    serde_json::json!({"database":{"blueScore":2000+observations,"isSynced":!snapshot,
                        "acceptedTxBlockTime":if snapshot {0} else {chrono::Utc::now().timestamp_millis()},
                        "acceptedTxBlockTimeDiff":if snapshot {1_000_000} else {0}}})
                }
                else if path.starts_with("/blocks/") {
                    let old=path.contains(&"11".repeat(32));let first=path.contains(&"22".repeat(32));
                    let byte=if old {"11"} else if first {"22"} else {"23"};let score=if old {102} else if first {103} else {score2};
                    serde_json::json!({"header":{"blueScore":score.to_string(),"timestamp":(score*100+if mode=="wrong_metadata" && !old && !first {1} else {0}).to_string(),"parents":[{"parentHashes":["33".repeat(32)]}],"acceptedIdMerkleRoot":"44".repeat(32),"utxoCommitment":"55".repeat(32)},"verboseData":{"hash":byte.repeat(32),"blueScore":score.to_string(),"isChainBlock":!old || mode=="old_canonical","selectedParentHash":"33".repeat(32)}})
                } else {
                    let start:u64=path.split("blueScoreGte=").nth(1).unwrap().split('&').next().unwrap().parse().unwrap();
                    let mut blocks=Vec::new();
                    for (byte,id,score,amount) in [("22","66",103,100),("23",if mode=="duplicate" {"66"} else {"77"},score2,200)] {
                        if score>=start && score<start+10 && !(mode=="missing" && byte=="23") {
                            blocks.push(serde_json::json!({"hash":byte.repeat(32),"blue_score":score,"timestamp":score*100,"transactions":[{"transaction_id":id.repeat(32),"is_accepted":mode!="unaccepted","inputs":[],"outputs":[{"index":0,"amount":amount+if mode=="changed" && observations>1 {1} else {0},"script_public_key":"51"}]}]}));
                        }
                    }
                    serde_json::json!(blocks)
                }.to_string();
                let length = if mode == "health_oversize"
                    && path.split('?').next() == Some("/info/health")
                {
                    super::super::MAX_OBSERVATION_BYTES + 1
                } else if mode == "oversize" {
                    MAX_BYTES + 1
                } else {
                    body.len()
                };
                let status = if ((mode == "health_503" || mode.starts_with("snapshot_"))
                    && path.split('?').next() == Some("/info/health"))
                    || (mode == "block_503" && path.starts_with("/blocks/"))
                {
                    "503 Service Unavailable"
                } else {
                    "200 OK"
                };
                let response=crate::source_observation::fresh_test_response(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{body}"));
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        let client = RestClient::new(format!("http://{address}")).unwrap();
        let client = if mode == "snapshot_optin" {
            client.allow_degraded_snapshot()
        } else {
            client
        };
        let members = vec![
            (vec![0x11; 32], vec![0x66; 32]),
            (vec![0x11; 32], vec![0x77; 32]),
        ];
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.historical_acceptance_observations(&[vec![0x11; 32]], &members, &vec![0x22; 32]),
        )
        .await;
        server.abort();
        let (first, second) = result.context("mock observation deadline")??;
        tn12_indexer_db::persist::HistoricalAcceptanceSourceProof::verify(first, second, &members)
    }
    #[tokio::test]
    async fn historical_source_rejects_truncated_http_frames() {
        for response in [
            "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nnull",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nnu",
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let mut bytes = [0; 2048];
                    let n = socket.read(&mut bytes).await.unwrap();
                    assert_ne!(n, 0);
                    request.extend_from_slice(&bytes[..n]);
                }
                socket.write_all(response.as_bytes()).await.unwrap();
            });
            let client = RestClient::new(format!("http://{address}")).unwrap();
            let mut budget = ResponseBudget { used: 0 };
            let result = client
                .map_response::<serde_json::Value>("/truncated", &mut budget)
                .await;
            assert!(
                result.is_err(),
                "truncated HTTP framing must not produce evidence"
            );
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn historical_source_counts_chunked_bytes_across_requests() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let mut bytes = [0; 2048];
                    let n = socket.read(&mut bytes).await.unwrap();
                    assert_ne!(n, 0);
                    request.extend_from_slice(&bytes[..n]);
                }
                socket.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nnull\r\n0\r\n\r\n").await.unwrap();
            }
        });
        let client = RestClient::new(format!("http://{address}")).unwrap();
        let mut budget = ResponseBudget {
            used: MAX_BYTES - 4,
        };
        let first: serde_json::Value = client.map_response("/first", &mut budget).await.unwrap();
        assert!(first.is_null());
        assert_eq!(budget.used, MAX_BYTES);
        let error = client
            .map_response::<serde_json::Value>("/second", &mut budget)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("cumulative response budget"));
        assert_eq!(budget.used, MAX_BYTES);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn historical_source_rejects_oversized_health_observation() {
        let error = observed("health_oversize").await.unwrap_err();
        assert!(format!("{error:#}").contains("response budget exceeded"));
    }

    #[tokio::test]
    async fn historical_source_verifies_split_with_advancing_tip() {
        let proof = observed("stable").await.unwrap();
        assert_eq!(proof.targets().len(), 2);
        assert_eq!(proof.window().source_tip, 2001);
    }
    #[tokio::test]
    async fn historical_source_uses_health_body_while_rest_is_catching_up() {
        let proof = observed("health_503").await.unwrap();
        assert_eq!(proof.targets().len(), 2);
        assert_eq!(proof.window().source_tip, 2001);
    }
    #[tokio::test]
    async fn historical_source_requires_explicit_optin_for_frozen_publication() {
        assert!(observed("snapshot_current").await.is_err());
        let proof = observed("snapshot_optin").await.unwrap();
        assert_eq!(proof.targets().len(), 2);
    }

    #[tokio::test]
    async fn historical_source_expands_adjacent_windows_without_gaps() {
        let proof = observed("expand").await.unwrap();
        assert_eq!(
            (proof.window().start_score, proof.window().end_score),
            (100, 119)
        );
    }
    #[tokio::test]
    async fn historical_source_rejects_unstable_incomplete_or_invalid_evidence() {
        for mode in [
            "changed",
            "missing",
            "duplicate",
            "unaccepted",
            "old_canonical",
            "wrong_metadata",
            "oversize",
            "block_503",
        ] {
            assert!(observed(mode).await.is_err(), "accepted {mode}");
        }
    }
}
