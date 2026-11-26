//! Decoding deferral is decided before semantic writes, under the writer fence.
//! No SQL, identity, acceptance, or authenticated-state errors are swallowed.
use super::*;

pub(super) fn unsupported_reason(
    tx: &RestTransaction,
    decoders: &DecoderRegistry,
) -> Option<String> {
    tx.inputs.iter().find_map(|input| {
        let signature = hex::decode(&input.signature_script).ok()?;
        let reveal = extract_last_push(&signature)?;
        if decoders.find_for_reveal(&reveal).is_some() {
            return None;
        }
        decoders.iter().find_map(|decoder| {
            decoder
                .unsupported_reveal_reason(&reveal)
                .map(|reason| format!("{}: {reason}", decoder.name()))
        })
    })
}

pub(super) async fn families(
    conn: &mut sqlx::PgConnection,
    txs: &[RestTransaction],
) -> Result<Vec<Vec<u8>>> {
    let parents: Vec<Vec<u8>> = txs
        .iter()
        .flat_map(|tx| tx.inputs.iter())
        .map(|input| hex::decode(&input.previous_outpoint_hash))
        .collect::<std::result::Result<_, _>>()?;
    let vouts: Vec<i32> = txs
        .iter()
        .flat_map(|tx| tx.inputs.iter())
        .map(|input| input.previous_outpoint_index.parse::<i32>())
        .collect::<std::result::Result<_, _>>()?;
    let mut ids: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT DISTINCT u.covenant_id FROM covenant_utxos u JOIN unnest($1::bytea[],$2::int[]) AS p(txid,vout) ON u.txid=p.txid AND u.vout=p.vout")
            .bind(parents)
            .bind(vouts)
            .fetch_all(conn)
            .await?;
    for tx in txs {
        for output in &tx.outputs {
            if let Some(id) = output.canonical_covenant_id() {
                ids.push(hex::decode(id)?);
            }
        }
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
}

/// Must run under the existing writer lock, including generic batch routing.
pub(super) async fn pending_dependency(
    conn: &mut sqlx::PgConnection,
    txs: &[RestTransaction],
    family_ids: &[Vec<u8>],
    before_sequence: Option<i64>,
) -> Result<bool> {
    let txids: Vec<Vec<u8>> = txs
        .iter()
        .map(|tx| hex::decode(&tx.transaction_id))
        .collect::<std::result::Result<_, _>>()?;
    let parents: Vec<Vec<u8>> = txs
        .iter()
        .flat_map(|tx| tx.inputs.iter())
        .map(|input| hex::decode(&input.previous_outpoint_hash))
        .collect::<std::result::Result<_, _>>()?;
    let vouts: Vec<i32> = txs
        .iter()
        .flat_map(|tx| tx.inputs.iter())
        .map(|input| input.previous_outpoint_index.parse::<i32>())
        .collect::<std::result::Result<_, _>>()?;
    let mut ids = family_ids.to_vec();
    for output in txs.iter().flat_map(|tx| &tx.outputs) {
        if let Some(id) = output.canonical_covenant_id() {
            ids.push(hex::decode(id)?);
        }
    }
    Ok(sqlx::query_scalar(
        "SELECT CASE WHEN (SELECT pending_count FROM indexer_deferred_decode_capacity WHERE singleton)=0 \
         THEN FALSE ELSE EXISTS(SELECT 1 FROM indexer_deferred_decodes d WHERE status='pending' \
         AND ($4::bigint IS NULL OR sequence<$4) \
         AND (txid=ANY($1) OR txid=ANY($2) OR covenant_ids && $3 OR covenant_ids && ARRAY( \
             SELECT u.covenant_id FROM covenant_utxos u JOIN unnest($2::bytea[],$5::int[]) AS p(txid,vout) \
             ON u.txid=p.txid AND u.vout=p.vout))) END",
    )
    .bind(txids)
    .bind(parents)
    .bind(ids)
    .bind(before_sequence)
    .bind(vouts)
    .fetch_one(conn)
    .await?)
}

pub(super) async fn prepare(
    conn: &mut sqlx::PgConnection,
    tx: &RestTransaction,
    decoders: &DecoderRegistry,
    replay: bool,
    forced_reason: Option<&str>,
) -> Result<(Option<String>, Vec<Vec<u8>>)> {
    let unsupported = forced_reason.map(str::to_owned).or_else(|| unsupported_reason(tx, decoders));
    // Ordinary traffic with no obligations must not read every input family.
    // Query the pending index first; derive retained families only on deferral.
    if !replay
        && unsupported.is_none()
        && !pending_dependency(conn, std::slice::from_ref(tx), &[], None).await?
    {
        return Ok((None, Vec::new()));
    }
    let ids = families(conn, std::slice::from_ref(tx)).await?;
    if replay {
        let saved: Option<(i64, Value)> = sqlx::query_as(
            "SELECT d.sequence,d.raw_transaction FROM indexer_deferred_decodes d \
             JOIN blocks b ON b.hash=d.block_hash AND b.is_chain_block \
             WHERE d.txid=$1 AND d.block_hash=$2 AND d.status='pending' FOR UPDATE OF d",
        )
        .bind(hex::decode(&tx.transaction_id)?)
        .bind(hex::decode(
            tx.accepting_block_hash
                .as_deref()
                .context("missing acceptance")?,
        )?)
        .fetch_optional(&mut *conn)
        .await?;
        let (sequence, raw) = saved.context("no canonical deferred transaction to replay")?;
        let retained: RestTransaction = serde_json::from_value(raw)?;
        anyhow::ensure!(
            crate::deferred_decode::evidence_identity(&retained)
                == crate::deferred_decode::evidence_identity(tx),
            "replay differs from retained transaction evidence"
        );
        anyhow::ensure!(
            unsupported.is_none(),
            "decoder still does not support retained transaction"
        );
        anyhow::ensure!(
            !pending_dependency(conn, std::slice::from_ref(tx), &ids, Some(sequence)).await?,
            "earlier deferred dependency must be replayed first"
        );
        return Ok((None, ids));
    }
    let reason = if let Some(reason) = unsupported {
        Some(reason)
    } else {
        Some("pending_decoder_dependency".into())
    };
    // Unsupported classification is only a routing hint. Authenticate the
    // revealed input against the stored chain output before archiving it.
    if reason.is_some() {
        for input in &tx.inputs {
            let signature = hex::decode(&input.signature_script)?;
            let Some(reveal) = extract_last_push(&signature) else {
                continue;
            };
            let script: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT script_pubkey FROM covenant_utxos WHERE txid=$1 AND vout=$2",
            )
            .bind(hex::decode(&input.previous_outpoint_hash)?)
            .bind(input.previous_outpoint_index.parse::<i32>()?)
            .fetch_optional(&mut *conn)
            .await?;
            let triggering = (forced_reason.is_some() && decoders.find_for_reveal(&reveal).is_some())
                || (decoders.find_for_reveal(&reveal).is_none()
                && decoders
                    .iter()
                    .any(|d| d.unsupported_reveal_reason(&reveal).is_some()));
            anyhow::ensure!(
                !triggering || script.as_deref().and_then(p2sh_script_hash).is_some(),
                "unsupported reveal requires an authenticated P2SH input"
            );
            anyhow::ensure!(
                script.is_some() || !input.requires_covenant_identity(),
                "deferred input identity must be hydrated before ingestion"
            );
            if let Some(script) = script {
                if let Some(expected) = p2sh_script_hash(&script) {
                    anyhow::ensure!(
                        expected == blake2b_256(&reveal),
                        "deferred reveal does not match authenticated input"
                    );
                }
            }
        }
    }
    Ok((reason, ids))
}

pub(super) async fn finish(
    conn: &mut sqlx::PgConnection,
    tx: &RestTransaction,
    reason: Option<&str>,
    ids: &[Vec<u8>],
    replay: bool,
) -> Result<()> {
    let txid = hex::decode(&tx.transaction_id)?;
    let block = hex::decode(
        tx.accepting_block_hash
            .as_deref()
            .context("missing accepting block")?,
    )?;
    if let Some(reason) = reason {
        let raw = serde_json::to_value(tx)?;
        let existing: Option<Value> = sqlx::query_scalar(
            "SELECT raw_transaction FROM indexer_deferred_decodes WHERE txid=$1 AND block_hash=$2",
        )
        .bind(&txid)
        .bind(&block)
        .fetch_optional(&mut *conn)
        .await?;
        if let Some(existing) = existing {
            let retained: RestTransaction = serde_json::from_value(existing)?;
            anyhow::ensure!(
                crate::deferred_decode::evidence_identity(&retained)
                    == crate::deferred_decode::evidence_identity(tx),
                "deferred transaction evidence changed"
            );
        }
        sqlx::query("INSERT INTO indexer_deferred_decodes(txid,block_hash,blue_score,covenant_ids,raw_transaction,reason,status,decoder_revision) \
            VALUES($1,$2,$3,$4,$5,$6,'pending',$7) ON CONFLICT(txid,block_hash) DO UPDATE SET status='pending',resolved_at_ms=NULL,decoded_at_ms=NULL")
            .bind(&txid).bind(&block).bind(i64::try_from(tx.accepting_block_blue_score.context("missing accepting score")?)?)
            .bind(ids).bind(raw).bind(reason).bind(tn12_indexer_decoder::revision()).execute(conn).await?;
    } else if replay {
        sqlx::query("UPDATE indexer_deferred_decodes SET decoded_at_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint \
            WHERE txid=$1 AND block_hash=$2 AND status='pending'")
            .bind(txid).bind(block).execute(conn).await?;
    }
    Ok(())
}
