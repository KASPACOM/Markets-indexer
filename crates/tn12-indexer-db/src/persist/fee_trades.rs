//! Per-fill accounting derived only after fee-role successor verification.
//! Keep actual ABI entrypoints intact; one leader action owns the ordered fills.
use anyhow::{Context, Result};
use serde_json::{json, Value};
use tn12_indexer_core::RestTransaction;

pub(super) fn records(
    entrypoint: &str,
    taker: Option<&Value>,
    sources: &[(usize, Value)],
    outputs: &[(i32, Value)],
) -> Result<Value> {
    let holders = outputs
        .iter()
        .filter(|(_, state)| state["mode"] == "0")
        .collect::<Vec<_>>();
    let count = if entrypoint == "crossWithBid" {
        1
    } else {
        sources.len()
    };
    anyhow::ensure!(
        count > 0 && holders.len() >= count,
        "missing authenticated trade holders"
    );
    let mut result = Vec::with_capacity(count);
    for (slot, (input, source)) in sources.iter().take(count).enumerate() {
        let (output, buyer) = holders[slot];
        let amount = buyer["amount"]
            .as_str()
            .context("trade amount")?
            .parse::<u128>()?;
        let available = source["amount"]
            .as_str()
            .context("source amount")?
            .parse::<u128>()?;
        let price = source["unitPrice"]
            .as_str()
            .context("trade price")?
            .parse::<u128>()?;
        let scale = source["priceScale"]
            .as_str()
            .context("trade price scale")?
            .parse::<u128>()?;
        anyhow::ensure!(
            amount > 0 && amount <= available && scale > 0,
            "invalid verified trade amount"
        );
        let product = amount.checked_mul(price).context("trade gross overflows")?;
        anyhow::ensure!(product % scale == 0, "trade gross is not exact");
        let (side, trader) = match entrypoint {
            "buyAsks" => ("buy", &buyer["owner"]),
            "sellIntoBids" => ("sell", &taker.context("seller authority")?["owner"]),
            "crossWithBid" => ("cross", &buyer["owner"]),
            _ => anyhow::bail!("unsupported fee trade leader"),
        };
        for owner in [&source["owner"], trader] {
            let text = owner.as_str().context("trade owner")?;
            anyhow::ensure!(
                text.len() == 64 && hex::decode(text)?.len() == 32,
                "invalid trade owner"
            );
        }
        result.push(
            json!({"slot":slot, "inputIndex":input, "buyerOutputIndex":output,
            "side":side, "maker":source["owner"], "taker":trader,
            "makerScheme":source["owner_scheme"], "takerScheme":if entrypoint == "sellIntoBids" { &taker.context("seller authority")?["owner_scheme"] } else { &buyer["owner_scheme"] },
            "canonicalTokenId":source["canonicalTokenId"], "amount":amount.to_string(),
            "unitPriceSompi":price.to_string(), "priceScale":scale.to_string(),
            "priceSompi":(product / scale).to_string()}),
        );
    }
    Ok(Value::Array(result))
}

pub(super) async fn annotate(
    conn: &mut sqlx::PgConnection,
    tx: &RestTransaction,
    block: &[u8],
    market: &[u8],
    leader: usize,
    mut records: Value,
) -> Result<bool> {
    for record in records.as_array_mut().context("fee trade record array")? {
        let index = usize::try_from(record["inputIndex"].as_u64().context("trade input")?)?;
        let input = tx.inputs.get(index).context("trade order input")?;
        record["orderId"] = json!(format!(
            "{}:{}",
            input.previous_outpoint_hash, input.previous_outpoint_index
        ));
    }
    let source = tx.inputs.get(leader).context("fee trade leader input")?;
    let changed = sqlx::query(
        "UPDATE covenant_actions SET decoded_args=decoded_args || jsonb_build_object('feeTrades',$1::jsonb) \
         WHERE covenant_id=$2 AND txid=$3 AND block_hash=$4 AND action='spend' \
         AND inputs->'previousOutpoint'->>'hash'=$5 AND inputs->'previousOutpoint'->>'index'=$6 \
         AND decoded_args->'feeTrades' IS DISTINCT FROM $1::jsonb")
        .bind(&records).bind(market).bind(hex::decode(&tx.transaction_id)?).bind(block)
        .bind(&source.previous_outpoint_hash).bind(&source.previous_outpoint_index)
        .execute(&mut *conn).await.context("annotate verified fee trade fills")?.rows_affected();
    anyhow::ensure!(changed <= 1, "fee trade leader matched duplicate actions");
    // This bounded materialization is part of the same commit as the verified
    // fill annotation. Source-action deletion cascades through both parties.
    let owners = sqlx::query(r#"
        INSERT INTO kcc20_fee_owner_trades
          (source_action_id,fill_index,party,owner,owner_scheme,address,txid_hex,block_time_ms,
           canonical_token_id,market_id,amount,direction,entrypoint,input_outpoints,output_outpoints)
        SELECT f.source_action_id,f.fill_index,p.party,p.owner,p.scheme,c.address,f.txid_hex,f.block_time_ms,
               f.token_id_hex,encode(f.market_id,'hex'),f.token_amount,
               CASE WHEN (f.side='sell') = (p.party='maker') THEN 'in' ELSE 'out' END,
               f.entrypoint,jsonb_build_array(jsonb_build_object('hash',split_part(f.order_id,':',1),
                   'index',split_part(f.order_id,':',2))),
               jsonb_build_array(jsonb_build_object('txidHex',f.txid_hex,'vout',
                   (a.decoded_args->'feeTrades'->((f.fill_index-1)::INT)->>'buyerOutputIndex')::INT))
        FROM kcc20_fee_trade_executions f
        JOIN covenant_actions a ON a.id=f.source_action_id
        JOIN covenants c ON c.covenant_id=f.market_id
        CROSS JOIN LATERAL (VALUES ('maker',f.maker,f.maker_scheme),('taker',f.taker,f.taker_scheme)) p(party,owner,scheme)
        WHERE f.market_id=$1 AND f.txid=$2 AND f.block_hash=$3
          AND a.inputs->'previousOutpoint'->>'hash'=$4 AND a.inputs->'previousOutpoint'->>'index'=$5
        ON CONFLICT (source_action_id,fill_index,party) DO UPDATE SET
          owner=EXCLUDED.owner,
          owner_scheme=EXCLUDED.owner_scheme,
          address=EXCLUDED.address,
          txid_hex=EXCLUDED.txid_hex,
          block_time_ms=EXCLUDED.block_time_ms,
          canonical_token_id=EXCLUDED.canonical_token_id,
          market_id=EXCLUDED.market_id,
          amount=EXCLUDED.amount,
          direction=EXCLUDED.direction,
          entrypoint=EXCLUDED.entrypoint,
          input_outpoints=EXCLUDED.input_outpoints,
          output_outpoints=EXCLUDED.output_outpoints
        WHERE (kcc20_fee_owner_trades.owner,kcc20_fee_owner_trades.owner_scheme,kcc20_fee_owner_trades.address,kcc20_fee_owner_trades.txid_hex,kcc20_fee_owner_trades.block_time_ms,kcc20_fee_owner_trades.canonical_token_id,kcc20_fee_owner_trades.market_id,kcc20_fee_owner_trades.amount,kcc20_fee_owner_trades.direction,kcc20_fee_owner_trades.entrypoint,kcc20_fee_owner_trades.input_outpoints,kcc20_fee_owner_trades.output_outpoints)
          IS DISTINCT FROM (EXCLUDED.owner,EXCLUDED.owner_scheme,EXCLUDED.address,EXCLUDED.txid_hex,EXCLUDED.block_time_ms,EXCLUDED.canonical_token_id,EXCLUDED.market_id,EXCLUDED.amount,EXCLUDED.direction,EXCLUDED.entrypoint,EXCLUDED.input_outpoints,EXCLUDED.output_outpoints)
        "#).bind(market).bind(hex::decode(&tx.transaction_id)?).bind(block)
        .bind(&source.previous_outpoint_hash).bind(&source.previous_outpoint_index)
        .execute(&mut *conn).await.context("persist fee trade owner history")?.rows_affected();
    Ok(changed > 0 || owners > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn order(amount: &str, owner: &str) -> Value {
        json!({"amount":amount,"owner":owner.repeat(32),"owner_scheme":0,"unitPrice":"30000000000000000",
            "priceScale":"100000000","canonicalTokenId":"33".repeat(32)})
    }
    fn holder(amount: &str, owner: &str) -> Value {
        let mut state = order(amount, owner);
        state["mode"] = json!("0");
        state
    }
    #[test]
    fn grouped_buy_records_each_seller_once_at_display_price() {
        let fills = records(
            "buyAsks",
            None,
            &[(0, order("3", "11")), (1, order("1", "22"))],
            &[(0, holder("2", "44")), (3, holder("1", "44"))],
        )
        .unwrap();
        assert_eq!(fills[0]["priceSompi"], "600000000");
        assert_eq!(fills[1]["priceSompi"], "300000000");
        assert_eq!(fills[0]["maker"], "11".repeat(32));
        assert_eq!(fills[1]["maker"], "22".repeat(32));
        assert_eq!(fills[1]["taker"], "44".repeat(32));
    }
    #[test]
    fn seller_change_is_not_an_extra_fill_and_cross_counts_once() {
        let seller = order("10", "11");
        let outputs = vec![(0, holder("2", "22")), (2, holder("8", "11"))];
        let fills = records(
            "sellIntoBids",
            Some(&seller),
            &[(1, order("2", "22"))],
            &outputs,
        )
        .unwrap();
        assert_eq!(fills.as_array().unwrap().len(), 1);
        assert_eq!(fills[0]["taker"], seller["owner"]);
        let cross = records(
            "crossWithBid",
            None,
            &[(0, order("2", "11")), (1, order("2", "22"))],
            &outputs[..1],
        )
        .unwrap();
        assert_eq!(cross.as_array().unwrap().len(), 1);
        assert_eq!(cross[0]["side"], "cross");
        assert!(records("buyAsks", None, &[(0, order("1", "11"))], &outputs[..1]).is_err());
    }
}
