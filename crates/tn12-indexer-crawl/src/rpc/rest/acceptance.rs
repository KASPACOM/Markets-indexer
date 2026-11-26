//! Verify a settled, equivalent accepting-block replacement from one source.

use anyhow::{Context, Result};
use serde_json::Value;
use tn12_indexer_db::persist::{
    AcceptanceConflict, AcceptedInputEvidence, AcceptedOutputEvidence, AcceptingBlockEvidence,
    CanonicalBlockReplacement,
};

use super::{RestClient, MAX_FULL_BLOCK_RESPONSE_BYTES};

fn hash(value: &Value) -> Result<Vec<u8>> {
    let text = value.as_str().context("missing block proof hash")?;
    let bytes = hex::decode(text).context("invalid block proof hash")?;
    anyhow::ensure!(bytes.len() == 32, "invalid block proof hash length");
    Ok(bytes)
}

fn number(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .context("missing or invalid block proof number")
}

pub(super) fn parse_block(value: &Value, expected: &str) -> Result<AcceptingBlockEvidence> {
    let header = &value["header"];
    let verbose = &value["verboseData"];
    let block_hash = hash(&verbose["hash"])?;
    anyhow::ensure!(
        block_hash == hex::decode(expected)?,
        "block proof returned a different hash"
    );
    let mut parents = Vec::new();
    for level in header["parents"]
        .as_array()
        .context("missing block parents")?
    {
        let mut hashes = level["parentHashes"]
            .as_array()
            .context("missing block parent level")?
            .iter()
            .map(hash)
            .collect::<Result<Vec<_>>>()?;
        hashes.sort();
        anyhow::ensure!(
            !hashes.is_empty() && !hashes.windows(2).any(|pair| pair[0] == pair[1]),
            "invalid block parent set"
        );
        parents.push(hashes);
    }
    let blue_score = number(&header["blueScore"])?;
    anyhow::ensure!(
        blue_score == number(&verbose["blueScore"])?,
        "conflicting block scores"
    );
    Ok(AcceptingBlockEvidence {
        hash: block_hash,
        is_chain_block: verbose["isChainBlock"]
            .as_bool()
            .context("missing canonical block flag")?,
        blue_score,
        timestamp: number(&header["timestamp"])?,
        selected_parent: hash(&verbose["selectedParentHash"])?,
        parents,
        accepted_id_merkle_root: hash(&header["acceptedIdMerkleRoot"])?,
        utxo_commitment: hash(&header["utxoCommitment"])?,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct ProofSnapshot {
    old: AcceptingBlockEvidence,
    new: AcceptingBlockEvidence,
    members: Vec<Vec<u8>>,
    inputs: Vec<AcceptedInputEvidence>,
    outputs: Vec<AcceptedOutputEvidence>,
}

impl RestClient {
    /// Fresh same-source evidence for a retained decoding obligation. This is
    /// observed before replay and again after semantic effects commit.
    pub async fn deferred_decode_proof(&self, retained:&tn12_indexer_core::RestTransaction,
        network:&str)->Result<tn12_indexer_db::deferred_decode::CanonicalDecodeProof> {
        let observed=chrono::Utc::now().timestamp_millis();
        let publication=self.observe_publication(network).await?;
        publication.database.require_current_transactions(chrono::Utc::now().timestamp_millis())?;
        let tip=self.get_rest_database_blue_score().await?;
        let source=self.get_fresh_acceptance_transaction(&retained.transaction_id).await?;
        let block=self.accepting_block_evidence(retained.accepting_block_hash.as_deref().context("retained transaction lacks acceptance")?).await?;
        tn12_indexer_db::deferred_decode::CanonicalDecodeProof::verify(retained,&source,&block,tip,observed)
    }

    pub(crate) async fn accepting_block_evidence(
        &self,
        block_hash: &str,
    ) -> Result<AcceptingBlockEvidence> {
        anyhow::ensure!(
            hex::decode(block_hash).is_ok_and(|bytes| bytes.len() == 32),
            "invalid accepting block hash"
        );
        // No fallback sources: old/new canonicality and acceptance membership
        // must come from the same configured source.
        let url = format!(
            "{}/blocks/{block_hash}?includeTransactions=false",
            self.base_url
        );
        let mut response = self
            .http
            .get(&url)
            .header(reqwest::header::CACHE_CONTROL, "no-cache, no-store, max-age=0")
            .header(reqwest::header::PRAGMA, "no-cache")
            .query(&[("source_observation", chrono::Utc::now().timestamp_millis().to_string())])
            .send()
            .await
            .context("fetch accepting block evidence")?;
        // Preserve typed transient HTTP failures before validating successful
        // observations. Error responses need not carry freshness evidence.
        super::require_success(response.status(), &url)?;
        crate::source_observation::validate_health_headers(
            response.headers(), chrono::Utc::now().timestamp_millis(),
        ).context("stale accepting block evidence")?;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("read accepting block evidence")?
        {
            anyhow::ensure!(
                body.len().saturating_add(chunk.len()) <= MAX_FULL_BLOCK_RESPONSE_BYTES,
                "accepting block evidence exceeds byte limit"
            );
            body.extend_from_slice(&chunk);
        }
        parse_block(
            &serde_json::from_slice(&body).context("parse accepting block evidence")?,
            block_hash,
        )
    }

    async fn acceptance_snapshot(&self, conflict: &AcceptanceConflict) -> Result<ProofSnapshot> {
        let old = self
            .accepting_block_evidence(&conflict.persisted_hash)
            .await?;
        let new = self
            .accepting_block_evidence(&conflict.incoming_hash)
            .await?;
        anyhow::ensure!(
            !old.is_chain_block && new.is_chain_block,
            "source acceptance is stale or canonical replacement is unproven"
        );
        let start = (new.blue_score / 10) * 10;
        let blocks = self
            .get_virtual_chain_bounded(start, 10, MAX_FULL_BLOCK_RESPONSE_BYTES)
            .await?;
        anyhow::ensure!(
            blocks
                .iter()
                .all(|block| start <= block.blue_score && block.blue_score < start + 10),
            "canonical acceptance page is outside its requested window"
        );
        let matching = blocks
            .iter()
            .filter(|block| block.hash == conflict.incoming_hash)
            .collect::<Vec<_>>();
        anyhow::ensure!(
            matching.len() == 1,
            "canonical acceptance page is missing or ambiguous"
        );
        let block = matching[0];
        anyhow::ensure!(
            hex::decode(&block.hash)? == new.hash
                && block.blue_score == new.blue_score
                && block.timestamp == new.timestamp,
            "canonical acceptance page disagrees with node evidence"
        );
        let mut members = Vec::new();
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        for tx in &block.transactions {
            let tx = tx.with_normalized_missing_output_indexes();
            let txid =
                hex::decode(&tx.transaction_id).context("invalid accepted transaction identity")?;
            members.push(txid.clone());
            for input in &tx.inputs {
                inputs.push(AcceptedInputEvidence {
                    transaction_id: txid.clone(),
                    previous_txid: hex::decode(&input.previous_outpoint_hash)
                        .context("invalid canonical input identity")?,
                    previous_vout: input
                        .previous_outpoint_index
                        .parse()
                        .context("invalid canonical input position")?,
                    previous_amount: input.previous_outpoint_amount,
                    previous_script: input
                        .previous_outpoint_script
                        .as_deref()
                        .map(hex::decode)
                        .transpose()
                        .context("invalid canonical input script")?,
                });
            }
            for output in &tx.outputs {
                outputs.push(AcceptedOutputEvidence {
                    transaction_id: txid.clone(),
                    vout: i32::try_from(output.index)
                        .context("canonical output position exceeds database range")?,
                    amount: output.amount,
                    script: hex::decode(&output.script_public_key)
                        .context("invalid canonical output script")?,
                });
            }
        }
        members.sort();
        inputs.sort_by(|a, b| {
            (&a.transaction_id, &a.previous_txid, a.previous_vout).cmp(&(
                &b.transaction_id,
                &b.previous_txid,
                b.previous_vout,
            ))
        });
        outputs.sort_by(|a, b| (&a.transaction_id, a.vout).cmp(&(&b.transaction_id, b.vout)));
        anyhow::ensure!(
            members.contains(&hex::decode(&conflict.transaction_id)?),
            "conflicting transaction is absent from canonical acceptance membership"
        );
        Ok(ProofSnapshot {
            old,
            new,
            members,
            inputs,
            outputs,
        })
    }

    /// Re-fetch both facts and membership to reject an unstable source snapshot.
    /// The resulting proof is used immediately by the bounded DB transaction.
    pub async fn verify_canonical_block_replacement(
        &self,
        conflict: &AcceptanceConflict,
    ) -> Result<CanonicalBlockReplacement> {
        self.verify_canonical_block_replacement_with_policy(conflict, false)
            .await
    }

    pub async fn verify_recent_canonical_block_replacement(
        &self,
        conflict: &AcceptanceConflict,
    ) -> Result<CanonicalBlockReplacement> {
        self.verify_canonical_block_replacement_with_policy(conflict, true)
            .await
    }

    async fn verify_canonical_block_replacement_with_policy(
        &self,
        conflict: &AcceptanceConflict,
        recent: bool,
    ) -> Result<CanonicalBlockReplacement> {
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.verify_replacement_within_deadline(conflict, recent),
        )
        .await
        .context("canonical acceptance proof deadline exceeded")?
    }

    async fn verify_replacement_within_deadline(
        &self,
        conflict: &AcceptanceConflict,
        recent: bool,
    ) -> Result<CanonicalBlockReplacement> {
        let source_tip = self.get_rest_database_blue_score().await?;
        let first = self.acceptance_snapshot(conflict).await?;
        let verify = if recent {
            CanonicalBlockReplacement::verify_recent
        } else {
            CanonicalBlockReplacement::verify
        };
        verify(
            first.old.clone(),
            first.new.clone(),
            source_tip,
            first.members.clone(),
            first.inputs.clone(),
            first.outputs.clone(),
        )?;
        let second = self.acceptance_snapshot(conflict).await?;
        if first != second {
            return Err(tn12_indexer_db::persist::AcceptanceEvidenceChanged.into());
        }
        verify(
            second.old,
            second.new,
            source_tip,
            second.members,
            second.inputs,
            second.outputs,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deferred_and_recovery_acceptance_require_uncached_evidence() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for recovery in [false,true] {
        for cache in ["", "Age: 30\r\n", "CF-Cache-Status: HIT\r\n"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let mut chunk = [0; 4096];
                    let n = stream.read(&mut chunk).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&chunk[..n]);
                }
                let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                assert!(request.contains("source_observation="));
                assert!(request.contains("cache-control: no-cache, no-store, max-age=0"));
                let body = serde_json::json!({"transaction_id":"11".repeat(32),
                    "is_accepted":true,"accepting_block_hash":"22".repeat(32),
                    "accepting_block_blue_score":100}).to_string();
                let response = crate::source_observation::fresh_test_response(format!(
                    "HTTP/1.1 200 OK\r\n{cache}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()));
                stream.write_all(response.as_bytes()).await.unwrap();
            });
            let client = RestClient::new(format!("http://{address}")).unwrap();
            let result = if recovery {
                client.get_transaction_with_explicit_acceptance(&"11".repeat(32)).await
            } else { client.get_fresh_acceptance_transaction(&"11".repeat(32)).await };
            server.await.unwrap();
            assert_eq!(result.is_ok(), cache.is_empty(), "{cache}: {result:?}");
        }
        }
    }

    async fn verify_against_mock(mode: &'static str) -> Result<CanonicalBlockReplacement> {
        verify_against_mock_at_depth(mode, 5000, false).await
    }

    async fn verify_against_mock_at_depth(
        mode: &'static str,
        source_tip: u64,
        recent: bool,
    ) -> Result<CanonicalBlockReplacement> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = requests.clone();
        let server = tokio::spawn(async move {
            let mut page_requests = 0;
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let mut chunk = [0; 4096];
                    let n = stream.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..n]);
                }
                let path = std::str::from_utf8(&request)
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .to_string();
                seen.lock().unwrap().push(path.clone());
                let body = if path.split('?').next() == Some("/info/health") {
                    serde_json::json!({"database":{"blueScore":source_tip,"isSynced":true,"acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),"acceptedTxBlockTimeDiff":0}})
                } else if path.starts_with("/blocks/") {
                    let url = reqwest::Url::parse(&format!("http://source{path}")).unwrap();
                    assert!(url.query_pairs().any(|(k,v)| k == "includeTransactions" && v == "false"));
                    assert!(url.query_pairs().any(|(k,v)| k == "source_observation" && v.parse::<i64>().is_ok()));
                    let old = path.contains(&"11".repeat(32));
                    serde_json::json!({
                        "header":{"blueScore":"1524","timestamp":if mode=="different_timestamp" && !old { "12405" } else { "12345" },
                            "parents":[{"parentHashes":["33".repeat(32)]}],
                            "acceptedIdMerkleRoot":if mode=="different_root" && !old { "99".repeat(32) } else { "44".repeat(32) },
                            "utxoCommitment":"55".repeat(32)},
                        "verboseData":{"hash":if old { "11".repeat(32) } else { "22".repeat(32) },
                            "blueScore":"1524","selectedParentHash":"33".repeat(32),
                            "isChainBlock":if mode=="stale" { old } else { !old }}
                    })
                } else {
                    assert_eq!(path, "/virtual-chain?blueScoreGte=1520&limit=10&resolveInputs=true");
                    page_requests += 1;
                    let mut txs = vec![serde_json::json!({"transaction_id":if mode=="missing_tx" { "77".repeat(32) } else { "66".repeat(32) },
                        "outputs":[{"amount":100,"index":0,"script_public_key":format!("aa20{}87","88".repeat(32))}]
                    })];
                    if mode == "changed_membership" && page_requests == 2 {
                        txs.push(serde_json::json!({"transaction_id":"77".repeat(32),"outputs":[]}));
                    }
                    serde_json::json!([
                        {"hash":"aa".repeat(32),"blue_score":1520,"timestamp":12340,"transactions":[]},
                        {"hash":"22".repeat(32),"blue_score":1524,"timestamp":if mode=="different_timestamp" { 12405 } else { 12345 },"transactions":txs}
                    ])
                }.to_string();
                stream.write_all(crate::source_observation::fresh_test_response(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len())).as_bytes()).await.unwrap();
            }
        });
        let client = RestClient::new(format!("http://{address}")).unwrap();
        let result = client
            .verify_canonical_block_replacement_with_policy(
                &AcceptanceConflict {
                    transaction_id: "66".repeat(32),
                    persisted_hash: "11".repeat(32),
                    incoming_hash: "22".repeat(32),
                },
                recent,
            )
            .await;
        server.abort();
        if (mode == "stable" || mode == "different_timestamp")
            && source_tip.saturating_sub(1524) >= if recent { 20 } else { 1_000 }
        {
            assert_eq!(requests.lock().unwrap().len(), 7);
        }
        result
    }

    #[tokio::test]
    async fn canonical_proof_uses_aligned_window_and_rechecks_membership() {
        verify_against_mock("stable").await.unwrap();
        let error = verify_against_mock("changed_membership").await.unwrap_err();
        assert!(error.to_string().contains("changed during verification"));
    }

    #[tokio::test]
    async fn live_proof_requires_published_depth_and_stable_membership() {
        let too_close = verify_against_mock_at_depth("stable", 1543, true)
            .await
            .unwrap_err();
        assert!(too_close.is::<tn12_indexer_db::persist::AcceptanceWindowPending>());
        verify_against_mock_at_depth("stable", 1544, true)
            .await
            .unwrap();
        let changing = verify_against_mock_at_depth("changed_membership", 1544, true)
            .await
            .unwrap_err();
        assert!(changing.to_string().contains("changed during verification"));
        let historical = verify_against_mock_at_depth("stable", 1544, false)
            .await
            .unwrap_err();
        assert!(historical.is::<tn12_indexer_db::persist::AcceptanceWindowPending>());
    }

    #[tokio::test]
    async fn canonical_proof_accepts_equivalent_commitments_with_different_timestamps() {
        verify_against_mock("different_timestamp").await.unwrap();
    }

    #[tokio::test]
    async fn canonical_proof_rejects_stale_source_and_unequal_commitments() {
        let stale = verify_against_mock("stale").await.unwrap_err();
        assert!(stale.to_string().contains("source acceptance is stale"));
        let root = verify_against_mock("different_root").await.unwrap_err();
        assert!(root.to_string().contains("equivalent chain evidence"));
        let missing = verify_against_mock("missing_tx").await.unwrap_err();
        assert!(missing
            .to_string()
            .contains("absent from canonical acceptance membership"));
    }

    #[test]
    fn block_proof_rejects_missing_canonicality_and_wrong_identity() {
        let value =
            serde_json::json!({"header":{"parents":[]},"verboseData":{"hash":"11".repeat(32)}});
        assert!(parse_block(&value, &"22".repeat(32)).is_err());
        assert!(parse_block(&value, &"11".repeat(32)).is_err());
    }
}
