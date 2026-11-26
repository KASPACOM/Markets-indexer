//! Cache metadata is a hint only when its identity and every supplied field agree.
use tn12_indexer_core::{RestTransaction, RestTxInput, RestTxOutput};

pub(crate) fn compatible<'a>(
    input: &RestTxInput,
    parent: &'a RestTransaction,
) -> Option<&'a RestTxOutput> {
    if parent.transaction_id != input.previous_outpoint_hash {
        return None;
    }
    let index = input.previous_outpoint_index.parse::<usize>().ok()?;
    let output = parent.outputs.get(index)?;
    if output.index != index as u64
        || output.transaction_id != parent.transaction_id
        || input
            .previous_outpoint_script
            .as_ref()
            .is_some_and(|v| v != &output.script_public_key)
        || input
            .previous_outpoint_amount
            .is_some_and(|v| v != output.amount)
        || input
            .previous_outpoint_address
            .as_ref()
            .is_some_and(|v| Some(v) != output.script_public_key_address.as_ref())
    {
        return None;
    }
    Some(output)
}

pub(crate) fn added_bytes(input: &RestTxInput, output: &RestTxOutput) -> usize {
    usize::from(input.previous_outpoint_script.is_none()) * output.script_public_key.capacity()
        + if input.previous_outpoint_address.is_none() {
            output
                .script_public_key_address
                .as_ref()
                .map_or(0, String::capacity)
        } else {
            0
        }
}

pub(crate) fn hydrate(input: &mut RestTxInput, output: &RestTxOutput) {
    input
        .previous_outpoint_script
        .get_or_insert_with(|| output.script_public_key.clone());
    input.previous_outpoint_amount.get_or_insert(output.amount);
    if input.previous_outpoint_address.is_none() {
        input.previous_outpoint_address = output.script_public_key_address.clone();
    }
}
