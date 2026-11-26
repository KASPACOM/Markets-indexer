//! Binds source membership/content to an immutable full-row database snapshot.
use super::{
    HistoricalAcceptanceCohort, HistoricalAcceptanceSourceProof, HistoricalAcceptanceWindow,
};
use anyhow::{ensure, Result};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct HistoricalAcceptanceMapProof {
    pub(super) cohort: HistoricalAcceptanceCohort,
    pub(super) source: HistoricalAcceptanceSourceProof,
    pub(super) proof_hash: [u8; 32],
}
impl HistoricalAcceptanceMapProof {
    pub fn verify(
        cohort: HistoricalAcceptanceCohort,
        first: HistoricalAcceptanceWindow,
        second: HistoricalAcceptanceWindow,
    ) -> Result<Self> {
        let source =
            HistoricalAcceptanceSourceProof::verify(first, second, &cohort.transactions())?;
        validate_content(&cohort, &source)?;
        let proof_hash = tn12_indexer_core::blake2b_256(&serde_json::to_vec(&serde_json::json!({
            "version":1,"cohort":cohort.digest(),"window":source.window_digest(),"targets":source.targets(),
        }))?);
        Ok(Self {
            cohort,
            source,
            proof_hash,
        })
    }
    pub fn proof_hash(&self) -> &[u8; 32] {
        &self.proof_hash
    }
    pub fn cohort(&self) -> &HistoricalAcceptanceCohort {
        &self.cohort
    }
    pub fn source(&self) -> &HistoricalAcceptanceSourceProof {
        &self.source
    }
}

fn bytes(row: &Value, key: &str) -> Result<Vec<u8>> {
    let s = row[key]
        .as_str()
        .and_then(|s| s.strip_prefix("\\x"))
        .ok_or_else(|| anyhow::anyhow!("invalid persisted bytea field: {key}"))?;
    Ok(hex::decode(s)?)
}
fn index(row: &Value, key: &str) -> Result<i32> {
    row[key]
        .as_i64()
        .and_then(|n| i32::try_from(n).ok())
        .filter(|n| *n >= 0)
        .ok_or_else(|| anyhow::anyhow!("invalid persisted output index: {key}"))
}
fn amount(row: &Value, key: &str) -> Result<u64> {
    row[key]
        .as_u64()
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or_else(|| anyhow::anyhow!("invalid persisted amount: {key}"))
}
pub(super) fn validate_content(
    cohort: &HistoricalAcceptanceCohort,
    source: &HistoricalAcceptanceSourceProof,
) -> Result<()> {
    let outputs: BTreeMap<_, _> = source
        .window()
        .canonical
        .iter()
        .flat_map(|b| b.outputs.iter())
        .map(|o| ((o.transaction_id.clone(), o.vout), o))
        .collect();
    let inputs: BTreeMap<_, _> = source
        .window()
        .canonical
        .iter()
        .flat_map(|b| b.inputs.iter())
        .map(|i| {
            (
                (
                    i.transaction_id.clone(),
                    i.previous_txid.clone(),
                    i.previous_vout,
                ),
                i,
            )
        })
        .collect();
    for reference in &cohort.references {
        let row = &reference.row;
        match reference.kind.as_str() {
            "created" => {
                let output = outputs
                    .get(&(reference.transaction_id.clone(), index(row, "vout")?))
                    .ok_or_else(|| {
                        anyhow::anyhow!("stored output absent from canonical evidence")
                    })?;
                ensure!(
                    output.amount == amount(row, "amount_sompi")?
                        && output.script == bytes(row, "script_pubkey")?,
                    "stored output content differs from canonical evidence"
                );
            }
            "spent" => {
                let input = inputs
                    .get(&(
                        reference.transaction_id.clone(),
                        bytes(row, "txid")?,
                        index(row, "vout")?,
                    ))
                    .ok_or_else(|| {
                        anyhow::anyhow!("stored spend absent from canonical evidence")
                    })?;
                ensure!(
                    row["status"] == "spent"
                        && bytes(row, "spent_by_txid")? == reference.transaction_id
                        && input.previous_amount == Some(amount(row, "amount_sompi")?)
                        && input.previous_script.as_ref() == Some(&bytes(row, "script_pubkey")?),
                    "stored spend content differs from canonical evidence"
                );
            }
            "action" => match row["action"].as_str() {
                Some("spend") => {
                    let previous = &row["inputs"]["previousOutpoint"];
                    let previous_id = hex::decode(previous["hash"].as_str().ok_or_else(|| {
                        anyhow::anyhow!("spend action lacks previous transaction")
                    })?)?;
                    ensure!(
                        inputs.contains_key(&(
                            reference.transaction_id.clone(),
                            previous_id,
                            index(previous, "index")?
                        )),
                        "stored spend action absent from canonical evidence"
                    );
                }
                Some("continuation" | "deploy") => {
                    let stored = &row["outputs"];
                    let output = outputs
                        .get(&(reference.transaction_id.clone(), index(stored, "vout")?))
                        .ok_or_else(|| {
                            anyhow::anyhow!("stored output action absent from canonical evidence")
                        })?;
                    let script = hex::decode(
                        stored["scriptPubKeyHex"]
                            .as_str()
                            .ok_or_else(|| anyhow::anyhow!("output action lacks script"))?,
                    )?;
                    ensure!(
                        output.amount == amount(stored, "amountSompi")? && output.script == script,
                        "stored output action content differs from canonical evidence"
                    );
                }
                _ => anyhow::bail!("unsupported historical action evidence"),
            },
            "genesis" => {
                let output = outputs
                    .get(&(
                        reference.transaction_id.clone(),
                        index(row, "genesis_vout")?,
                    ))
                    .ok_or_else(|| {
                        anyhow::anyhow!("stored genesis absent from canonical output evidence")
                    })?;
                let script_hash =
                    tn12_indexer_core::p2sh_script_hash(&output.script).ok_or_else(|| {
                        anyhow::anyhow!("stored genesis has non-covenant canonical output")
                    })?;
                ensure!(
                    script_hash.to_vec() == bytes(row, "script_hash")?,
                    "stored genesis script differs from canonical evidence"
                );
            }
            _ => anyhow::bail!("unknown historical acceptance reference kind"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod captured_trace_tests {
    use super::super::acceptance_cohort::HistoricalAcceptanceReference;
    use super::super::{
        AcceptedInputEvidence, AcceptedOutputEvidence, AcceptingBlockEvidence,
        HistoricalAcceptanceBlock,
    };
    use super::*;
    fn node_block(v: &Value) -> AcceptingBlockEvidence {
        let h = &v["header"];
        let b = &v["verboseData"];
        let hash = |v: &Value| hex::decode(v.as_str().unwrap()).unwrap();
        AcceptingBlockEvidence {
            hash: hash(&b["hash"]),
            is_chain_block: b["isChainBlock"].as_bool().unwrap(),
            blue_score: h["blueScore"].as_str().unwrap().parse().unwrap(),
            timestamp: h["timestamp"].as_str().unwrap().parse().unwrap(),
            selected_parent: hash(&b["selectedParentHash"]),
            parents: h["parents"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| {
                    p["parentHashes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(hash)
                        .collect()
                })
                .collect(),
            accepted_id_merkle_root: hash(&h["acceptedIdMerkleRoot"]),
            utxo_commitment: hash(&h["utxoCommitment"]),
        }
    }
    /// Explicit offline trace replay. The settlement tip is synthetic; this
    /// checks all captured content/mappings, not current RPC freshness or writes.
    fn captured_proof() -> HistoricalAcceptanceMapProof {
        let dir = std::path::PathBuf::from(
            std::env::var("TN10_ACCEPTANCE_TRACE_DIR").expect("captured trace directory"),
        );
        let read = |name: &str| -> Value {
            serde_json::from_slice(&std::fs::read(dir.join(name)).unwrap()).unwrap()
        };
        let repeat = read("acceptance-conflict-0937-source-repeat.json");
        let first = read("acceptance-conflict-0934-source-window.json");
        assert_eq!(
            first, repeat["responses"]["window"],
            "recorded windows differ"
        );
        let attribution = read("acceptance-conflict-split-attribution.json");
        let old_hex = attribution["old_hash"].as_str().unwrap();
        let old_hash = hex::decode(old_hex).unwrap();
        let old = node_block(&repeat["responses"][old_hex]);
        let state = read("acceptance-conflict-0937-old-state.json");
        let mut references = Vec::new();
        for row in state["utxos"].as_array().unwrap() {
            for (kind, block, tx) in [
                ("created", "created_block", "txid"),
                ("spent", "spent_block", "spent_by_txid"),
            ] {
                if row[block].as_str() == Some(&format!("\\x{old_hex}")) {
                    references.push(HistoricalAcceptanceReference {
                        kind: kind.into(),
                        old_hash: old_hash.clone(),
                        transaction_id: bytes(row, tx).unwrap(),
                        row: row.clone(),
                    });
                }
            }
        }
        for row in state["actions"].as_array().unwrap() {
            assert_eq!(bytes(row, "block_hash").unwrap(), old_hash);
            references.push(HistoricalAcceptanceReference {
                kind: "action".into(),
                old_hash: old_hash.clone(),
                transaction_id: bytes(row, "txid").unwrap(),
                row: row.clone(),
            });
        }
        assert_eq!(references.len(), 906);
        references.sort_by_cached_key(|r| serde_json::to_vec(r).unwrap());
        let old_hashes = vec![old_hash];
        let normalized_rows = serde_json::to_vec(&(&old_hashes, &references)).unwrap();
        let digest = tn12_indexer_core::blake2b_256(&normalized_rows);
        let cohort = HistoricalAcceptanceCohort {
            old_hashes,
            references,
            digest,
            normalized_rows,
            comparison_rows: None, // Offline source proof only; cannot enter a DB transition.
        };
        assert_eq!(cohort.transactions().len(), 451);
        let mut canonical = Vec::new();
        // The captured response includes the preceding canonical block. This
        // complete subwindow starts at the removed block's score instead.
        for raw in first
            .as_array()
            .unwrap()
            .iter()
            .filter(|b| b["blue_score"].as_u64().unwrap() >= old.blue_score)
        {
            let hash = raw["hash"].as_str().unwrap();
            let block = node_block(&repeat["responses"][hash]);
            assert_eq!(block.blue_score, raw["blue_score"].as_u64().unwrap());
            assert_eq!(block.timestamp, raw["timestamp"].as_u64().unwrap());
            let mut accepted = HistoricalAcceptanceBlock {
                block,
                transaction_ids: vec![],
                inputs: vec![],
                outputs: vec![],
            };
            for tx in raw["transactions"].as_array().unwrap() {
                assert_eq!(tx["is_accepted"], true);
                let txid = hex::decode(tx["transaction_id"].as_str().unwrap()).unwrap();
                accepted.transaction_ids.push(txid.clone());
                let empty_inputs = Vec::new();
                for i in tx
                    .get("inputs")
                    .map(|v| v.as_array().expect("input array"))
                    .unwrap_or(&empty_inputs)
                {
                    accepted.inputs.push(AcceptedInputEvidence {
                        transaction_id: txid.clone(),
                        previous_txid: hex::decode(i["previous_outpoint_hash"].as_str().unwrap())
                            .unwrap(),
                        previous_vout: i["previous_outpoint_index"].as_i64().unwrap() as i32,
                        previous_amount: i["previous_outpoint_amount"].as_u64(),
                        previous_script: i["previous_outpoint_script"]
                            .as_str()
                            .map(|s| hex::decode(s).unwrap()),
                    });
                }
                for (index, o) in tx["outputs"].as_array().unwrap().iter().enumerate() {
                    accepted.outputs.push(AcceptedOutputEvidence {
                        transaction_id: txid.clone(),
                        vout: o["index"].as_i64().unwrap_or(index as i64) as i32,
                        amount: o["amount"].as_u64().unwrap(),
                        script: hex::decode(o["script_public_key"].as_str().unwrap()).unwrap(),
                    });
                }
            }
            canonical.push(accepted);
        }
        let window = HistoricalAcceptanceWindow {
            source_tip: old.blue_score + 2000,
            start_score: old.blue_score,
            end_score: old.blue_score + 10,
            removed: vec![old],
            canonical,
        };
        let proof = HistoricalAcceptanceMapProof::verify(cohort, window.clone(), window).unwrap();
        let mut counts = BTreeMap::new();
        for target in proof.source().targets() {
            let id = hex::encode(&target.transaction_id);
            let hash = hex::encode(&target.target_hash);
            assert_eq!(attribution["transaction_targets"][id], hash);
            *counts.entry(hash).or_insert(0usize) += 1;
        }
        assert_eq!(
            serde_json::to_value(counts).unwrap(),
            attribution["canonical_target_counts"]
        );
        proof
    }
    #[test]
    #[ignore = "requires TN10_ACCEPTANCE_TRACE_DIR with the recorded incident files"]
    fn captured_451_transaction_split_proof_matches_all_906_references() {
        captured_proof();
    }

    #[sqlx::test(migrations = "./migrations")]
    #[ignore = "requires captured incident data; partial DB context, not production performance parity"]
    async fn captured_451_transaction_database_commit_recovery_and_lineage(pool: sqlx::PgPool) {
        let dir = std::path::PathBuf::from(std::env::var("TN10_ACCEPTANCE_TRACE_DIR").unwrap());
        let read = |name: &str| -> Value {
            serde_json::from_slice(&std::fs::read(dir.join(name)).unwrap()).unwrap()
        };
        let context = read("split-acceptance-fixture-context.json");
        let state = read("acceptance-conflict-0937-old-state.json");
        let db = read("acceptance-conflict-0932-db.json");
        let window = read("acceptance-conflict-0934-source-window.json");
        let offline = captured_proof();
        let mut blocks = context["data"]["genesis_blocks"]
            .as_array()
            .unwrap()
            .clone();
        blocks.extend(db["blocks"].as_array().unwrap().clone());
        for block in window.as_array().unwrap() {
            blocks.push(serde_json::json!({"hash":format!("\\x{}",block["hash"].as_str().unwrap()),"blue_score":block["blue_score"],"daa_score":block["daa_score"],"parent_hashes":[],"timestamp_ms":block["timestamp"],"is_chain_block":true,"indexed_at_ms":0}));
        }
        sqlx::query("INSERT INTO blocks SELECT * FROM jsonb_populate_recordset(NULL::blocks,$1) ON CONFLICT(hash) DO NOTHING").bind(serde_json::json!(blocks)).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO covenants SELECT * FROM jsonb_populate_recordset(NULL::covenants,$1)",
        )
        .bind(&context["data"]["covenants"])
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO covenant_utxos SELECT * FROM jsonb_populate_recordset(NULL::covenant_utxos,$1)").bind(&state["utxos"]).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO covenant_actions SELECT * FROM jsonb_populate_recordset(NULL::covenant_actions,$1)").bind(&state["actions"]).execute(&pool).await.unwrap();
        // Do not import captured summaries: they include 61,837 active outputs
        // absent from this fixture. All local summaries derive from seeded rows.
        let writer = super::super::PgPersister::new(pool.clone());
        let cohort = writer
            .historical_acceptance_cohort(offline.cohort().old_hashes())
            .await
            .unwrap();
        assert_eq!(cohort.reference_count(), 906);
        let mut without_metadata = cohort.clone();
        without_metadata.comparison_rows = None;
        let original_proof = HistoricalAcceptanceMapProof::verify(
            without_metadata,
            offline.source().window().clone(),
            offline.source().window().clone(),
        )
        .unwrap();
        let proof = HistoricalAcceptanceMapProof::verify(
            cohort,
            offline.source().window().clone(),
            offline.source().window().clone(),
        )
        .unwrap();
        assert_eq!(proof.proof_hash(), original_proof.proof_hash());
        assert_eq!(
            proof.cohort.normalized_rows(),
            original_proof.cohort.normalized_rows()
        );
        assert_eq!(proof.cohort.digest(), original_proof.cohort.digest());
        let snapshot_sql = r#"SELECT jsonb_build_object(
            'blocks',(SELECT jsonb_agg(to_jsonb(r) ORDER BY hash) FROM blocks r),
            'utxos',(SELECT jsonb_agg(to_jsonb(r) ORDER BY txid,vout) FROM covenant_utxos r),
            'actions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM covenant_actions r),
            'covenants',(SELECT jsonb_agg(to_jsonb(r) ORDER BY covenant_id) FROM covenants r),
            'summaries',(SELECT jsonb_agg(to_jsonb(r) ORDER BY covenant_id) FROM covenant_summaries r),
            'action_summaries',(SELECT jsonb_agg(to_jsonb(r) ORDER BY covenant_id) FROM covenant_action_summaries r),
            'templates',(SELECT jsonb_agg(to_jsonb(r) ORDER BY template) FROM covenant_template_summaries r),
            'maps',(SELECT jsonb_agg(to_jsonb(r) ORDER BY proof_hash) FROM historical_acceptance_maps r))"#;
        let before: Value = sqlx::query_scalar(snapshot_sql)
            .fetch_one(&pool)
            .await
            .unwrap();
        let started = std::time::Instant::now();
        let stats = writer
            .preview_historical_acceptance_map(&proof)
            .await
            .unwrap();
        eprintln!(
            "captured 906-reference preview, partial context, including rollback: {}us",
            started.elapsed().as_micros()
        );
        assert_eq!(
            (
                stats.created_outputs,
                stats.spent_inputs,
                stats.actions,
                stats.covenants
            ),
            (451, 2, 453, 0)
        );
        let after: Value = sqlx::query_scalar(snapshot_sql)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            before, after,
            "captured preview must leave no committed repair or summary changes"
        );
        // Paired control/batch measurements on the same captured fixture. The
        // fixed pseudorandom order reduces order bias; this is not a loaded-DB
        // acceptance gate. Measure from lock acquisition through rollback.
        let prepared_pair = super::super::acceptance_map_apply::PreparedTransition::new(&proof);
        let mut order_seed = 0x5a17_u64;
        for pair in 0..4 {
            order_seed = order_seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let first_batch = (order_seed >> 32) & 1 == 1;
            for batch in [first_batch, !first_batch] {
                let mut tx = pool.begin().await.unwrap();
                super::super::PgPersister::set_persist_query_limits(&mut tx)
                    .await
                    .unwrap();
                super::super::acceptance_map_apply::set_comparison_work_limits(&mut tx)
                    .await
                    .unwrap();
                if batch {
                    super::super::acceptance_map_apply::stage_transition(
                        &mut tx,
                        &proof,
                        &prepared_pair,
                    )
                    .await
                    .unwrap();
                }
                writer.acquire_persist_writer_lock(&mut tx).await.unwrap();
                let locked = tokio::time::Instant::now();
                let deadline = locked + std::time::Duration::from_millis(350);
                let stats = if batch {
                    super::super::acceptance_map_apply::transition(
                        &mut tx,
                        &proof,
                        &prepared_pair,
                        deadline,
                    )
                    .await
                    .unwrap()
                } else {
                    super::super::acceptance_map_apply::reference::transition_reference(
                        &mut tx,
                        &proof,
                        &prepared_pair,
                        deadline,
                    )
                    .await
                    .unwrap()
                };
                assert_eq!(
                    (
                        stats.created_outputs,
                        stats.spent_inputs,
                        stats.actions,
                        stats.covenants
                    ),
                    (451, 2, 453, 0)
                );
                tx.rollback().await.unwrap();
                let held = locked.elapsed();
                eprintln!(
                    "captured paired transition pair={pair} batch={batch} writer_hold_us={}",
                    held.as_micros()
                );
                assert!(held <= std::time::Duration::from_millis(400));
                let after: Value = sqlx::query_scalar(snapshot_sql)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
                assert_eq!(
                    before, after,
                    "paired transition must roll back every write"
                );
            }
        }
        // Inspect the same transition before rollback to verify exact per-tx
        // destinations/times and preservation of every other stored column.
        let prepared = super::super::acceptance_map_apply::PreparedTransition::new(&proof);
        let mut conn = pool.begin().await.unwrap();
        super::super::PgPersister::set_persist_query_limits(&mut conn)
            .await
            .unwrap();
        super::super::acceptance_map_apply::stage_transition(&mut conn, &proof, &prepared)
            .await
            .unwrap();
        writer.acquire_persist_writer_lock(&mut conn).await.unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(350);
        super::super::acceptance_map_apply::transition(&mut conn, &proof, &prepared, deadline)
            .await
            .unwrap();
        let classified = super::super::acceptance_map_state::classify_applied(
            &mut conn,
            &proof,
            tokio::time::Instant::now() + std::time::Duration::from_millis(350),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(classified.already_reconciled);

        let targets: Vec<_> = proof
            .source()
            .targets()
            .iter()
            .map(|t| t.target_hash.clone())
            .collect();
        let actual = super::super::acceptance_cohort::read_cohort(
            &mut conn,
            &targets,
            false,
            Some(tokio::time::Instant::now() + std::time::Duration::from_millis(350)),
        )
        .await
        .unwrap();
        assert_eq!(actual.reference_count(), 906);
        let mut expected = Vec::new();
        for reference in &proof.cohort.references {
            let target = proof
                .source
                .targets()
                .iter()
                .find(|t| {
                    t.old_hash == reference.old_hash && t.transaction_id == reference.transaction_id
                })
                .unwrap();
            let mut row = reference.row.clone();
            let bytea = Value::String(format!("\\x{}", hex::encode(&target.target_hash)));
            match reference.kind.as_str() {
                "created" => row["created_block"] = bytea,
                "spent" => row["spent_block"] = bytea,
                "action" => {
                    row["block_hash"] = bytea;
                    row["block_time_ms"] = Value::from(target.target_time_ms);
                }
                _ => panic!("unexpected reference in captured fixture"),
            }
            expected.push(
                serde_json::to_vec(&(
                    &reference.kind,
                    &reference.transaction_id,
                    &target.target_hash,
                    row,
                ))
                .unwrap(),
            );
        }
        let mut observed: Vec<_> = actual
            .references
            .iter()
            .map(|r| {
                serde_json::to_vec(&(&r.kind, &r.transaction_id, &r.old_hash, &r.row)).unwrap()
            })
            .collect();
        expected.sort();
        observed.sort();
        assert_eq!(
            expected, observed,
            "retags must exactly match every target and preserve all remaining columns"
        );
        let bad_summary:bool=sqlx::query_scalar(r#"SELECT EXISTS(
            SELECT 1 FROM covenant_summaries s
            CROSS JOIN LATERAL (SELECT count(*) n,coalesce(sum(amount_sompi),0) amount FROM covenant_utxos u WHERE u.covenant_id=s.covenant_id AND u.status='active') totals
            LEFT JOIN LATERAL (SELECT u.txid,u.vout,u.created_block,u.address,b.blue_score FROM covenant_utxos u JOIN blocks b ON b.hash=u.created_block WHERE u.covenant_id=s.covenant_id AND u.status='active' ORDER BY b.blue_score DESC,u.txid DESC,u.vout DESC LIMIT 1) latest ON TRUE
            WHERE s.active_utxos IS DISTINCT FROM totals.n OR s.total_amount_sompi IS DISTINCT FROM totals.amount
               OR (totals.n>0 AND (s.latest_active_txid IS DISTINCT FROM latest.txid OR s.latest_active_vout IS DISTINCT FROM latest.vout OR s.latest_active_block IS DISTINCT FROM latest.created_block OR s.latest_active_blue_score IS DISTINCT FROM latest.blue_score OR s.current_address IS DISTINCT FROM latest.address)))"#).fetch_one(&mut *conn).await.unwrap();
        assert!(
            !bad_summary,
            "retagged summaries must match the partial fixture's actual UTXOs and ordering"
        );
        let dirty:i64=sqlx::query_scalar("SELECT count(DISTINCT txid) FROM kcc20_projection_dirty WHERE reason='historical_acceptance_map'").fetch_one(&mut *conn).await.unwrap();
        assert_eq!(dirty, 451);
        let entries: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT txid,target_hash FROM historical_acceptance_map_entries ORDER BY txid",
        )
        .fetch_all(&mut *conn)
        .await
        .unwrap();
        let wanted: Vec<_> = proof
            .source
            .targets()
            .iter()
            .map(|t| (t.transaction_id.clone(), t.target_hash.clone()))
            .collect();
        assert_eq!(
            entries, wanted,
            "sealed audit entries must record every exact transaction destination"
        );
        let audit:(Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>)=sqlx::query_as("SELECT proof_hash,cohort_digest,window_digest,cohort_evidence,window_evidence FROM historical_acceptance_maps").fetch_one(&mut *conn).await.unwrap();
        assert_eq!(audit.0.as_slice(), original_proof.proof_hash());
        assert_eq!(audit.3.as_slice(), original_proof.cohort.normalized_rows());
        assert_eq!(
            tn12_indexer_core::blake2b_256(&audit.3).as_slice(),
            audit.1.as_slice()
        );
        assert_eq!(
            tn12_indexer_core::blake2b_256(&audit.4).as_slice(),
            audit.2.as_slice()
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&audit.3).unwrap(),
            serde_json::from_slice::<Value>(proof.cohort.normalized_rows()).unwrap()
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&audit.4).unwrap(),
            serde_json::to_value(proof.source.window()).unwrap()
        );
        let recorded:Vec<(Vec<u8>,Vec<u8>,Vec<u8>,i64,i64)>=sqlx::query_as("SELECT old_hash,txid,target_hash,target_score,target_time_ms FROM historical_acceptance_map_entries ORDER BY txid").fetch_all(&mut *conn).await.unwrap();
        let recorded: Vec<_> = recorded
            .into_iter()
            .map(|(old_hash, transaction_id, target_hash, score, time)| {
                super::super::HistoricalAcceptanceTarget {
                    old_hash,
                    transaction_id,
                    target_hash,
                    target_score: score as u64,
                    target_time_ms: time as u64,
                }
            })
            .collect();
        let reconstructed=tn12_indexer_core::blake2b_256(&serde_json::to_vec(&serde_json::json!({"version":1,"cohort":audit.1,"window":audit.2,"targets":recorded})).unwrap());
        assert_eq!(
            reconstructed.as_slice(),
            audit.0.as_slice(),
            "sealed data must independently reconstruct the proof hash"
        );
        eprintln!(
            "sealed audit evidence bytes: cohort={}, source={}",
            audit.3.len(),
            audit.4.len()
        );
        conn.rollback().await.unwrap();
        use super::super::{CanonicalBlockReplacement, HistoricalAcceptanceOutcome, Persister};
        assert_eq!(
            writer
                .classify_historical_acceptance_outcome(&proof)
                .await
                .unwrap(),
            HistoricalAcceptanceOutcome::NotApplied
        );
        // Restart after the tentative transition rolled back: use a new
        // persister with no process-local outcome state.
        let restarted_before_commit = super::super::PgPersister::new(pool.clone());
        let uncommitted = restarted_before_commit
            .recover_historical_acceptance_commit(&proof, Default::default())
            .await
            .unwrap_err();
        assert!(
            uncommitted
                .downcast_ref::<super::super::HistoricalAcceptanceCommitNotApplied>()
                .is_some(),
            "lost request with original rows intact must classify as not applied"
        );
        let committed = writer
            .reconcile_historical_acceptance_map(&proof)
            .await
            .unwrap();
        assert_eq!(
            (
                committed.created_outputs,
                committed.spent_inputs,
                committed.actions
            ),
            (451, 2, 453)
        );
        assert!(!committed.already_reconciled);
        // Exercise the same recovery branch as a lost acknowledgement, against
        // a real committed transaction rather than a mocked database result.
        let targets:Vec<_>=proof.source().targets().iter().map(|target|target.target_hash.clone()).collect();
        let observed=writer.rest_removal_revisions(&targets).await.unwrap();
        let guarded=writer.with_rest_removal_guard(observed);
        // A subsequent local removal observation expires mutation authority,
        // but must not prevent inspecting an already committed transition.
        let mut marker=pool.begin().await.unwrap();
        super::super::PgPersister::record_rest_removals(&mut marker,&targets).await.unwrap();
        marker.commit().await.unwrap();
        assert!(guarded.reconcile_historical_acceptance_map(&proof).await.unwrap_err()
            .is::<super::super::StaleRestAcceptance>());
        assert_eq!(guarded.classify_historical_acceptance_outcome(&proof).await.unwrap(),HistoricalAcceptanceOutcome::Applied);
        let restarted_after_commit = super::super::PgPersister::new(pool.clone());
        let recovered = restarted_after_commit
            .recover_historical_acceptance_commit(&proof, committed.clone())
            .await
            .unwrap();
        assert!(recovered.already_reconciled);
        let unavailable = sqlx::postgres::PgPoolOptions::new()
            .connect_with(pool.connect_options().as_ref().clone())
            .await
            .unwrap();
        unavailable.close().await;
        let unavailable_writer = super::super::PgPersister::new(unavailable);
        let unknown = unavailable_writer
            .recover_historical_acceptance_commit(&proof, committed.clone())
            .await
            .unwrap_err();
        assert!(
            unknown
                .downcast_ref::<super::super::HistoricalAcceptanceOutcomeUnknown>()
                .is_some(),
            "unavailable classification must preserve an explicit unknown outcome"
        );
        assert_eq!(
            writer
                .classify_historical_acceptance_outcome(&proof)
                .await
                .unwrap(),
            HistoricalAcceptanceOutcome::Applied
        );
        assert!(
            writer
                .reconcile_historical_acceptance_map(&proof)
                .await
                .unwrap()
                .already_reconciled
        );
        assert!(
            writer
                .preview_historical_acceptance_map(&proof)
                .await
                .unwrap()
                .already_reconciled
        );
        let source = &proof.source.window().canonical[0];
        let mut alias_old = source.block.clone();
        alias_old.is_chain_block = false;
        let mut alias_new = source.block.clone();
        alias_new.hash = vec![0x99; 32];
        alias_new.timestamp += 1;
        let equivalent = CanonicalBlockReplacement::verify(
            alias_old,
            alias_new.clone(),
            proof.source.window().source_tip,
            source.transaction_ids.clone(),
            source.inputs.clone(),
            source.outputs.clone(),
        )
        .unwrap();
        writer.reconcile_accepting_block(&equivalent).await.unwrap();
        assert!(
            writer
                .reconcile_historical_acceptance_map(&proof)
                .await
                .unwrap()
                .already_reconciled,
            "idempotence must follow the equivalent successor and its timestamp"
        );
        writer.revert_blocks(&[alias_new.hash]).await.unwrap();
        assert!(writer
            .reconcile_historical_acceptance_map(&proof)
            .await
            .unwrap_err()
            .to_string()
            .contains("lost a canonical target"));
        let state: String =
            sqlx::query_scalar("SELECT status FROM historical_acceptance_maps WHERE proof_hash=$1")
                .bind(proof.proof_hash().as_slice())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(state, "target_lost");
    }
}
