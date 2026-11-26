//! Identity decisions and repairs share the serialized persistence transaction.
//! A relocated output is not evidence that its accepting block was removed.
use super::PgPersister;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use tn12_indexer_core::{
    compute_genesis_covenant_id_for_output, p2sh_script_hash, RestTransaction,
};

#[derive(Debug, thiserror::Error)]
#[error(
    "missing_identity_dependency: {txid}:{vout}; retain transaction and hydrate its P2SH parent"
)]
pub struct MissingIdentityDependency {
    pub txid: String,
    pub vout: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct IdentityCorrection {
    pub old_covenant_id: String,
    pub new_covenant_id: String,
    pub txid: String,
    pub vout: i32,
    pub accepting_block: String,
    pub retired_family: bool,
}

impl PgPersister {
    /// Preview and apply use the same checks. Preview performs SELECTs only.
    /// No network request is made while the writer lock is held.
    pub async fn repair_output_identities(
        &self,
        source: &RestTransaction,
        ancestors: &[RestTransaction],
        apply: bool,
    ) -> Result<Vec<IdentityCorrection>> {
        anyhow::ensure!(
            source.is_accepted,
            "identity repair requires accepted source evidence"
        );
        let mut tx = self.pool.begin().await?;
        Self::set_persist_query_limits(&mut tx).await?;
        self.acquire_persist_writer_lock(&mut tx).await?;
        sqlx::query("SET LOCAL statement_timeout='250ms'")
            .execute(&mut *tx)
            .await?;
        let work = async {
            verify_source_lineage(&mut tx, source, ancestors).await?;
            let tid = hex::decode(&source.transaction_id)?;
            let block = hex::decode(
                source
                    .accepting_block_hash
                    .as_deref()
                    .context("missing accepting block")?,
            )?;
            let canonical: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM blocks WHERE hash=$1 AND is_chain_block AND blue_score=$2 AND timestamp_ms=$3)")
                .bind(&block).bind(source.accepting_block_blue_score.context("missing acceptance score")? as i64)
                .bind(source.accepting_block_time.context("missing acceptance time")? as i64).fetch_one(&mut *tx).await?;
            anyhow::ensure!(
                canonical,
                "identity repair source anchor differs from current canonical database"
            );
            Self::check_transaction_acceptance(&mut tx, &tid, &block).await?;
            let mut corrections = Vec::new();
            for output in &source.outputs {
                let Some((owner, script, amount, created)): Option<(Vec<u8>,Vec<u8>,i64,Vec<u8>)> =
                    sqlx::query_as("SELECT covenant_id,script_pubkey,amount_sompi,created_block FROM covenant_utxos WHERE txid=$1 AND vout=$2")
                    .bind(&tid).bind(output.index as i32).fetch_optional(&mut *tx).await? else { continue; };
                anyhow::ensure!(
                    script == hex::decode(&output.script_public_key)?
                        && amount == output.amount as i64
                        && created == block,
                    "identity repair output differs from accepted source evidence"
                );
                // The incident has one P2SH input and one P2SH output. Require the
                // same deterministic continuation rule as normal persistence.
                let mut inputs = Vec::new();
                for input in &source.inputs {
                    let previous = hex::decode(&input.previous_outpoint_hash)?;
                    let index: i32 = input.previous_outpoint_index.parse()?;
                    let row: Option<(Vec<u8>,Option<Vec<u8>>,Option<Vec<u8>>,bool)> = sqlx::query_as(
                        "SELECT u.covenant_id,u.spent_by_txid,u.spent_block,b.is_chain_block FROM covenant_utxos u JOIN blocks b ON b.hash=u.created_block WHERE u.txid=$1 AND u.vout=$2")
                        .bind(previous).bind(index).fetch_optional(&mut *tx).await?;
                    if let Some((cid, spender, spent_block, current)) = row {
                        anyhow::ensure!(
                            current
                                && spender.as_ref() == Some(&tid)
                                && spent_block.as_ref() == Some(&block),
                            "identity repair input lineage differs from canonical acceptance"
                        );
                        inputs.push(cid);
                    } else if source.needs_input_identity(input) {
                        return Err(MissingIdentityDependency {
                            txid: input.previous_outpoint_hash.clone(),
                            vout: index,
                        }
                        .into());
                    }
                }
                let p2sh_outputs = source
                    .outputs
                    .iter()
                    .filter(|o| {
                        hex::decode(&o.script_public_key)
                            .ok()
                            .is_some_and(|s| p2sh_script_hash(&s).is_some())
                    })
                    .count();
                anyhow::ensure!(
                    source.version != 0
                        && inputs.len() == 1
                        && p2sh_outputs == 1
                        && inputs[0] == owner,
                    "identity repair requires unambiguous continuation lineage"
                );
                anyhow::ensure!(
                    output
                        .canonical_covenant_id()
                        .is_none_or(|id| id.eq_ignore_ascii_case(&hex::encode(&owner))),
                    "explicit covenant identity conflicts with continuation lineage"
                );
                corrections.extend(
                    reconcile_output_actions(&mut tx, source, output.index as i32, &owner, apply)
                        .await?,
                );
            }
            Ok::<_, anyhow::Error>(corrections)
        };
        let result = tokio::time::timeout(std::time::Duration::from_millis(350), work).await;
        match result {
            Ok(Ok(report)) if apply => {
                tx.commit().await?;
                Ok(report)
            }
            Ok(Ok(report)) => {
                tx.rollback().await?;
                Ok(report)
            }
            other => {
                tx.rollback().await?;
                Err(match other {
                    Ok(Err(e)) => e,
                    _ => anyhow::anyhow!("identity repair exceeded 350-ms writer budget"),
                })
            }
        }
    }
}

/// Prove a bounded ancestor chain from source bodies instead of trusting an
/// existing database family ID. All P2SH ancestors must terminate in a source
/// genesis with resolved funding inputs. Ambiguous splits remain unrepaired.
async fn verify_source_lineage(
    tx: &mut Transaction<'_, Postgres>,
    source: &RestTransaction,
    ancestors: &[RestTransaction],
) -> Result<()> {
    anyhow::ensure!(
        ancestors.len() <= 256,
        "identity proof exceeds 256 ancestors"
    );
    anyhow::ensure!(
        serde_json::to_vec(ancestors)?.len() <= 16 * 1024 * 1024,
        "identity proof exceeds 16 MiB"
    );
    let mut bodies = ancestors.to_vec();
    bodies.push(source.clone());
    let ordered = super::transactions_in_dependency_order(&bodies)?;
    let mut outputs: std::collections::HashMap<
        (String, u64),
        (tn12_indexer_core::RestTxOutput, Option<Vec<u8>>),
    > = std::collections::HashMap::new();
    for body in ordered.iter() {
        anyhow::ensure!(body.is_accepted, "identity proof ancestor is not accepted");
        let tid = hex::decode(&body.transaction_id)?;
        let block = hex::decode(
            body.accepting_block_hash
                .as_deref()
                .context("proof acceptance missing")?,
        )?;
        let score = i64::try_from(
            body.accepting_block_blue_score
                .context("proof score missing")?,
        )?;
        let time = i64::try_from(body.accepting_block_time.context("proof time missing")?)?;
        let mut input_ids = Vec::new();
        for input in &body.inputs {
            let index: u64 = input.previous_outpoint_index.parse()?;
            if let Some((previous, owner)) =
                outputs.get(&(input.previous_outpoint_hash.clone(), index))
            {
                let previous: &tn12_indexer_core::RestTxOutput = previous;
                anyhow::ensure!(
                    input
                        .previous_outpoint_amount
                        .is_none_or(|v| v == previous.amount)
                        && input
                            .previous_outpoint_script
                            .as_deref()
                            .is_none_or(|v| v.strip_prefix("0000").unwrap_or(v)
                                == previous.script_public_key)
                        && input
                            .previous_outpoint_address
                            .as_ref()
                            .is_none_or(|v| Some(v) == previous.script_public_key_address.as_ref()),
                    "identity proof input conflicts with source parent output"
                );
                if let Some(owner) = owner {
                    input_ids.push(owner.clone());
                }
            } else {
                anyhow::ensure!(
                    !input.requires_covenant_identity()
                        && (input.previous_outpoint_script.is_some()
                            || input.previous_outpoint_address.is_some()),
                    "identity proof is missing a required ancestor or funding evidence"
                );
            }
        }
        let count = body
            .outputs
            .iter()
            .filter(|o| {
                hex::decode(&o.script_public_key)
                    .ok()
                    .is_some_and(|s| p2sh_script_hash(&s).is_some())
            })
            .count();
        for output in &body.outputs {
            let script = hex::decode(&output.script_public_key)?;
            let owner = if let Some(script_id) = p2sh_script_hash(&script) {
                let expected = if body.version == 0 {
                    script_id.to_vec()
                } else if input_ids.is_empty() {
                    hex::decode(
                        compute_genesis_covenant_id_for_output(body, output.index)
                            .context("proof genesis cannot be derived")?,
                    )?
                } else {
                    anyhow::ensure!(
                        input_ids.len() == 1 && count == 1,
                        "identity proof continuation is ambiguous"
                    );
                    input_ids[0].clone()
                };
                anyhow::ensure!(
                    output
                        .canonical_covenant_id()
                        .is_none_or(|v| v.eq_ignore_ascii_case(&hex::encode(&expected))),
                    "source binding disagrees with proven ancestry"
                );
                let matches: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM covenant_utxos u JOIN blocks b ON b.hash=u.created_block WHERE u.txid=$1 AND u.vout=$2 AND u.covenant_id=$3 AND u.script_pubkey=$4 AND u.amount_sompi=$5 AND u.address=$6 AND b.hash=$7 AND b.is_chain_block AND b.blue_score=$8 AND b.timestamp_ms=$9)")
                    .bind(&tid).bind(i32::try_from(output.index)?).bind(&expected).bind(&script).bind(i64::try_from(output.amount)?).bind(output.script_public_key_address.as_deref().context("proof address missing")?)
                    .bind(&block).bind(score).bind(time).fetch_one(&mut **tx).await?;
                anyhow::ensure!(
                    matches,
                    "database parent/output identity or contents disagree with source ancestry"
                );
                Some(expected)
            } else {
                None
            };
            outputs.insert(
                (body.transaction_id.clone(), output.index),
                (output.clone(), owner),
            );
        }
    }
    Ok(())
}

/// Correct only an output action whose former identity is demonstrably the
/// fallback for this exact outpoint. Never wholesale rekey a shared family.
pub(super) async fn reconcile_output_actions(
    tx: &mut Transaction<'_, Postgres>,
    source: &RestTransaction,
    vout: i32,
    owner: &[u8],
    apply: bool,
) -> Result<Vec<IdentityCorrection>> {
    let tid = hex::decode(&source.transaction_id)?;
    let block = hex::decode(
        source
            .accepting_block_hash
            .as_deref()
            .context("missing acceptance")?,
    )?;
    let output = source
        .outputs
        .iter()
        .find(|o| o.index == vout as u64)
        .context("missing source output")?;
    let script = hex::decode(&output.script_public_key)?;
    let fallback = compute_genesis_covenant_id_for_output(source, vout as u64)
        .and_then(|id| hex::decode(id).ok());
    let script_id = p2sh_script_hash(&script).map(|s| s.to_vec());
    let rows = sqlx::query("SELECT a.id,a.covenant_id,to_jsonb(a) old_action,to_jsonb(c) old_family,c.template_name,c.claimed_template,c.genesis_txid,c.genesis_vout FROM covenant_actions a JOIN covenants c USING(covenant_id) WHERE a.txid=$1 AND a.covenant_id<>$2 AND a.action IN ('deploy','continuation') AND a.outputs->>'vout'=$3 LIMIT 17")
        .bind(&tid).bind(owner).bind(vout.to_string()).fetch_all(&mut **tx).await?;
    anyhow::ensure!(
        rows.len() <= 16,
        "identity correction exceeds bounded output action limit"
    );
    let mut report = Vec::new();
    for row in rows {
        let old: Vec<u8> = row.get("covenant_id");
        let action: Value = row.get("old_action");
        anyhow::ensure!(
            Some(&old) == fallback.as_ref() || Some(&old) == script_id.as_ref(),
            "conflicting output identity is not a verified fallback"
        );
        anyhow::ensure!(
            row.get::<Option<String>, _>("template_name").is_none()
                && row.get::<Option<String>, _>("claimed_template").is_none()
                && row.get::<Value, _>("old_family")["constructor_args"].is_null()
                && row.get::<Value, _>("old_family")["claimed_args"].is_null(),
            "classified identity requires protocol-specific reconciliation"
        );
        anyhow::ensure!(
            row.get::<Vec<u8>, _>("genesis_txid") == tid
                && row.get::<i32, _>("genesis_vout") == vout,
            "old family is not the fallback genesis for this outpoint"
        );
        let contents: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM covenant_actions old JOIN covenant_actions current ON current.txid=old.txid AND current.outputs->>'vout'=old.outputs->>'vout' JOIN blocks b ON b.hash=old.block_hash AND b.is_chain_block WHERE old.id=$1 AND current.covenant_id=$2 AND current.action IN ('deploy','continuation') AND old.block_hash=$3 AND current.block_hash=$3 AND old.outputs->>'scriptPubKeyHex'=current.outputs->>'scriptPubKeyHex' AND old.outputs->>'amountSompi'=current.outputs->>'amountSompi' AND old.outputs->>'scriptPubKeyHex'=$4 AND (old.outputs->>'amountSompi')::bigint=$5 AND old.decoded_args IS NULL AND old.entrypoint IS NULL AND old.outputs->'state' IS NOT DISTINCT FROM current.outputs->'state')")
            .bind(row.get::<i64,_>("id")).bind(owner).bind(&block).bind(&output.script_public_key).bind(output.amount as i64).fetch_one(&mut **tx).await?;
        anyhow::ensure!(
            contents,
            "superseded action differs from accepted replacement"
        );
        let empty: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM covenant_utxos WHERE covenant_id=$1) AND NOT EXISTS(SELECT 1 FROM covenant_actions WHERE covenant_id=$1 AND id<>$3) AND NOT EXISTS(SELECT 1 FROM covenant_identity_corrections WHERE old_covenant_id=$1 AND new_covenant_id<>$2)")
            .bind(&old).bind(owner).bind(row.get::<i64,_>("id")).fetch_one(&mut **tx).await?;
        let existing: Option<Vec<u8>> = sqlx::query_scalar("SELECT new_covenant_id FROM covenant_identity_corrections WHERE old_covenant_id=$1 AND txid=$2 AND vout=$3 AND accepting_block=$4")
            .bind(&old).bind(&tid).bind(vout).bind(&block).fetch_optional(&mut **tx).await?;
        anyhow::ensure!(
            existing.as_deref().is_none_or(|id| id == owner),
            "existing identity audit disagrees with proposed correction"
        );
        if empty {
            // Protocol projections do not all have foreign keys. An allegedly
            // unclassified family with such records needs a separate proof.
            let protocol_state: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kcc20_holders WHERE covenant_id=$1) OR EXISTS(SELECT 1 FROM kcc20_activity_feed WHERE token_id=$1) OR EXISTS(SELECT 1 FROM kcc20_token_summaries WHERE token_id=$1 OR wrapper_id=$1) OR EXISTS(SELECT 1 FROM kcc20_wrapper_summaries WHERE wrapper_id=$1 OR canonical_token_id=$1) OR EXISTS(SELECT 1 FROM kcc20_market_summaries WHERE token_id=$1) OR EXISTS(SELECT 1 FROM kcc20_owner_orders WHERE token_id=$1 OR order_id=encode($1,'hex')) OR EXISTS(SELECT 1 FROM kcc20_owner_portfolio_assets WHERE canonical_token_id=$1 OR wrapper_id=$1) OR EXISTS(SELECT 1 FROM api_payment_channels WHERE channel_id=encode($1,'hex')) OR EXISTS(SELECT 1 FROM covenant_participants WHERE covenant_id=$1)")
                .bind(&old).fetch_one(&mut **tx).await?;
            anyhow::ensure!(
                !protocol_state,
                "fallback has protocol state; explicit projection reconciliation required"
            );
        }
        if apply {
            sqlx::query("INSERT INTO covenant_identity_corrections(old_covenant_id,new_covenant_id,txid,vout,accepting_block,old_action,old_family,corrected_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(old_covenant_id,txid,vout,accepting_block) DO NOTHING")
            .bind(&old).bind(owner).bind(&tid).bind(vout).bind(&block).bind(action).bind(row.get::<Value,_>("old_family")).bind(chrono::Utc::now().timestamp_millis()).execute(&mut **tx).await?;
            sqlx::query("DELETE FROM covenant_actions WHERE id=$1")
                .bind(row.get::<i64, _>("id"))
                .execute(&mut **tx)
                .await?;
            if empty {
                // Audit is outside the family FK cascade. There are no child actions
                // or outputs left to discard, and only unclassified fallbacks qualify.
                sqlx::query("UPDATE covenant_identity_corrections SET retired_family=TRUE WHERE old_covenant_id=$1 AND new_covenant_id=$2").bind(&old).bind(owner).execute(&mut **tx).await?;
                sqlx::query("DELETE FROM covenants WHERE covenant_id=$1")
                    .bind(&old)
                    .execute(&mut **tx)
                    .await?;
            }
            sqlx::query("UPDATE covenant_genesis_progress SET baseline_complete=FALSE,scan_txid=NULL,scan_vout=NULL,best_txid=NULL,best_vout=NULL,best_block=NULL,best_score=NULL,best_time=NULL,version=version+1,retry_at_ms=0,blocker=NULL WHERE covenant_id=$1 OR covenant_id=$2")
            .bind(&old).bind(owner).execute(&mut **tx).await?;
            super::repo::mark_kcc20_projection_dirty_txids_tx(
                tx,
                "identity_reconciliation",
                std::slice::from_ref(&tid),
            )
            .await?;
        }
        report.push(IdentityCorrection {
            old_covenant_id: hex::encode(old),
            new_covenant_id: hex::encode(owner),
            txid: source.transaction_id.clone(),
            vout,
            accepting_block: hex::encode(&block),
            retired_family: empty,
        });
    }
    Ok(report)
}

/// Resolve only a still-canonical, still-owned audited alias; a reorg or changed
/// owner makes the old lookup unavailable until fresh reconciliation proves it.
pub async fn resolve_alias(pool: &sqlx::PgPool, id: &[u8]) -> Result<Vec<u8>> {
    Ok(sqlx::query_scalar("SELECT r.new_covenant_id FROM covenant_identity_corrections r JOIN blocks b ON b.hash=r.accepting_block AND b.is_chain_block JOIN covenant_utxos u ON u.txid=r.txid AND u.vout=r.vout AND u.covenant_id=r.new_covenant_id AND u.created_block=r.accepting_block JOIN covenants c ON c.covenant_id=r.new_covenant_id WHERE r.old_covenant_id=$1 AND r.retired_family ORDER BY r.id DESC LIMIT 1")
        .bind(id).fetch_optional(pool).await?.unwrap_or_else(|| id.to_vec()))
}

#[derive(Debug, thiserror::Error)]
#[error("{reason}: family {family_id}, outpoint {txid}:{vout}; retain recovery window")]
pub struct GenesisIdentityBlocked {
    pub reason: &'static str,
    pub family_id: String,
    pub txid: String,
    pub vout: i32,
    pub replacement: Option<String>,
    pub version: i64,
}
impl GenesisIdentityBlocked {
    pub fn details(&self) -> Value {
        serde_json::json!({"reason":self.reason,"familyId":self.family_id,"txid":self.txid,"vout":self.vout,"proposedReplacementIdentity":self.replacement,"version":self.version})
    }
}

pub(super) async fn missing_genesis(
    tx: &mut Transaction<'_, Postgres>,
    family: &[u8],
) -> Result<GenesisIdentityBlocked> {
    let row=sqlx::query("SELECT c.genesis_txid,c.genesis_vout,u.covenant_id owner,b.is_chain_block,p.version FROM covenants c JOIN covenant_genesis_progress p USING(covenant_id) LEFT JOIN covenant_utxos u ON u.txid=c.genesis_txid AND u.vout=c.genesis_vout LEFT JOIN blocks b ON b.hash=c.genesis_block WHERE c.covenant_id=$1")
        .bind(family).fetch_one(&mut **tx).await?;
    let owner: Option<Vec<u8>> = row.get("owner");
    let reason = if owner.as_ref().is_some_and(|id| id != family) {
        "inconsistent_identity"
    } else if row.get::<Option<bool>, _>("is_chain_block") == Some(false) {
        "canonical_removal_requires_proof"
    } else {
        "missing_dependency_evidence"
    };
    Ok(GenesisIdentityBlocked {
        reason,
        family_id: hex::encode(family),
        txid: hex::encode(row.get::<Vec<u8>, _>("genesis_txid")),
        vout: row.get("genesis_vout"),
        replacement: owner.map(hex::encode),
        version: row.get("version"),
    })
}

/// Scan one primary-key page, including clean rows in the checkpoint. Empty
/// candidate pages still advance the inventory; no OFFSET or full-table join.
pub async fn inventory(pool: &sqlx::PgPool, after: Option<&str>, page_size: i64) -> Result<Value> {
    anyhow::ensure!(
        (1..=512).contains(&page_size),
        "inventory page size must be 1..=512"
    );
    let after = after.map(hex::decode).transpose()?;
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='2s'")
        .execute(&mut *tx)
        .await?;
    let rows=sqlx::query("WITH page AS MATERIALIZED (SELECT covenant_id,genesis_txid,genesis_vout FROM covenants WHERE covenant_id>COALESCE($1::bytea,''::bytea) ORDER BY covenant_id LIMIT $2) SELECT encode(c.covenant_id,'hex') family_id,encode(c.genesis_txid,'hex') txid,c.genesis_vout vout,encode(u.covenant_id,'hex') owner FROM page c LEFT JOIN covenant_utxos u ON u.txid=c.genesis_txid AND u.vout=c.genesis_vout ORDER BY c.covenant_id")
        .bind(after).bind(page_size).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    let next = rows.last().map(|r| r.get::<String, _>("family_id"));
    let candidates: Vec<Value>=rows.iter().filter_map(|r| {
        let family:String=r.get("family_id"); let owner:Option<String>=r.get("owner");
        if owner.as_ref()==Some(&family) {None} else {Some(serde_json::json!({"familyId":family,"txid":r.get::<String,_>("txid"),"vout":r.get::<i32,_>("vout"),"outputOwner":owner}))}
    }).collect();
    Ok(
        serde_json::json!({"scannedFamilies":rows.len(),"nextAfter":next,"complete":rows.len()<page_size as usize,"candidates":candidates}),
    )
}
