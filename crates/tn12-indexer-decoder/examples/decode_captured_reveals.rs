//! Decode revealed programs from captured REST transactions without a database.
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use tn12_indexer_decoder::{
    default_registry,
    kcc20::{script_items, ScriptItem},
};

fn main() -> Result<()> {
    let registry = default_registry();
    let mut decoded = Vec::new();
    for path in std::env::args().skip(1) {
        let tx: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        ensure!(
            tx["is_accepted"] == true,
            "transaction is not accepted: {path}"
        );
        let inputs = tx
            .get("inputs")
            .and_then(Value::as_array)
            .with_context(|| format!("transaction inputs are missing or invalid: {path}"))?;
        for (index, input) in inputs.iter().enumerate() {
            let signature_script = input
                .get("signature_script")
                .and_then(Value::as_str)
                .with_context(|| format!("input {index} is missing signature_script: {path}"))?;
            let sig = hex::decode(signature_script)
                .with_context(|| format!("decode signature_script for input {index}: {path}"))?;
            let items = script_items(&sig);
            let Some(ScriptItem::Data(reveal)) = items.last() else {
                continue;
            };
            if let Some(decoder) = registry.find_for_reveal(reveal) {
                decoded.push(json!({
                    "transactionId": tx["transaction_id"], "input": index,
                    "template": decoder.name(), "action": decoder.decode_action(&sig),
                    "state": decoder.decode_constructor(reveal)?,
                }));
            }
        }
    }
    ensure!(!decoded.is_empty(), "no recognized revealed programs");
    println!("{}", serde_json::to_string_pretty(&decoded)?);
    Ok(())
}
