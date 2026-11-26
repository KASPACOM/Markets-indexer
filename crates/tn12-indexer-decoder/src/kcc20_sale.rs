//! KCC20 fixed-price sale escrow decoder.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use tn12_indexer_core::{parse_minimal_int, read_push, template_fingerprint, KnownTemplate};

use crate::TemplateDecoder;

pub struct Kcc20SaleDecoder {
    fingerprint: [u8; 32],
}

const MIN_KCC20_SALE_SCRIPT_LEN: usize = 190;
const TOKEN_ID_PUSH_LEN_OFFSET: usize = 9;
const TOKEN_ID_OFFSET: usize = 10;
const TOKEN_AMOUNT_OFFSET: usize = 44;
const PRICE_MARKER: &[u8] = &[0xa0, 0x69, 0x00, 0xc2];
const SELLER_MARKER: &[u8] = &[0xa2, 0x69, 0x00, 0xc3, 0x20];

impl Kcc20SaleDecoder {
    pub fn new(fingerprint: [u8; 32]) -> Self {
        Self { fingerprint }
    }

    pub fn fingerprint_of_compiled_script(script: &[u8]) -> [u8; 32] {
        template_fingerprint(script)
    }
}

impl TemplateDecoder for Kcc20SaleDecoder {
    fn template(&self) -> KnownTemplate {
        KnownTemplate::Kcc20Sale
    }

    fn name(&self) -> &'static str {
        "KCC20Sale"
    }

    fn script_hash(&self) -> [u8; 32] {
        self.fingerprint
    }

    fn matches_reveal_script(&self, reveal: &[u8]) -> bool {
        Self::fingerprint_of_compiled_script(reveal) == self.fingerprint
            || self.decode_constructor(reveal).is_ok()
    }

    fn decode_constructor(&self, payload: &[u8]) -> Result<Value> {
        if payload.len() < MIN_KCC20_SALE_SCRIPT_LEN {
            return Err(anyhow!(
                "reveal script is {} bytes, expected at least {}",
                payload.len(),
                MIN_KCC20_SALE_SCRIPT_LEN
            ));
        }
        expect_push_len(payload, TOKEN_ID_PUSH_LEN_OFFSET, 32)?;
        let token_id = payload
            .get(TOKEN_ID_OFFSET..TOKEN_ID_OFFSET + 32)
            .ok_or_else(|| anyhow!("KCC20Sale tokenId is truncated"))?;

        let (token_amount, after_token_amount) =
            read_script_number_at(payload, TOKEN_AMOUNT_OFFSET)?;
        let price_marker = find_bytes(payload, PRICE_MARKER, after_token_amount)
            .ok_or_else(|| anyhow!("KCC20Sale price marker not found"))?;
        let (price_sompi, after_price) =
            read_script_number_at(payload, price_marker + PRICE_MARKER.len())?;

        let seller_marker = find_bytes(payload, SELLER_MARKER, after_price)
            .ok_or_else(|| anyhow!("KCC20Sale seller marker not found"))?;
        let seller_start = seller_marker + SELLER_MARKER.len();
        let seller = payload
            .get(seller_start..seller_start + 32)
            .ok_or_else(|| anyhow!("KCC20Sale seller is truncated"))?;

        Ok(json!({
            "seller": hex::encode(seller),
            "tokenId": hex::encode(token_id),
            "tokenAmount": token_amount.to_string(),
            "priceSompi": price_sompi.to_string(),
        }))
    }

    fn decode_state(&self, _payload: &[u8]) -> Result<Value> {
        Ok(Value::Null)
    }

    fn decode_action(&self, signature_script: &[u8]) -> Option<String> {
        let prefix = args_prefix_before_reveal(signature_script);
        match prefix.last().copied() {
            Some(0x00) => Some("buy".into()),
            Some(0x51) => Some("cancel".into()),
            _ => None,
        }
    }
}

fn expect_push_len(payload: &[u8], offset: usize, expected: usize) -> Result<()> {
    let actual = payload
        .get(offset)
        .copied()
        .ok_or_else(|| anyhow!("missing KCC20Sale push length at offset {offset}"))?
        as usize;
    if actual != expected {
        return Err(anyhow!(
            "unexpected KCC20Sale push length {actual} at offset {offset}, expected {expected}"
        ));
    }
    Ok(())
}

fn read_script_number_at(payload: &[u8], offset: usize) -> Result<(i128, usize)> {
    let op = *payload
        .get(offset)
        .ok_or_else(|| anyhow!("missing script number at offset {offset}"))?;

    match op {
        0x00 => Ok((0, offset + 1)),
        0x4f => Ok((-1, offset + 1)),
        0x51..=0x60 => Ok(((op - 0x50) as i128, offset + 1)),
        0x01..=0x4b => {
            let start = offset + 1;
            let end = start + op as usize;
            let bytes = payload
                .get(start..end)
                .ok_or_else(|| anyhow!("truncated script number at offset {offset}"))?;
            Ok((parse_minimal_int(bytes), end))
        }
        0x4c => {
            let len = *payload
                .get(offset + 1)
                .ok_or_else(|| anyhow!("missing PUSHDATA1 length at offset {offset}"))?
                as usize;
            let start = offset + 2;
            let end = start + len;
            let bytes = payload
                .get(start..end)
                .ok_or_else(|| anyhow!("truncated PUSHDATA1 number at offset {offset}"))?;
            Ok((parse_minimal_int(bytes), end))
        }
        0x4d => {
            let len_bytes = payload
                .get(offset + 1..offset + 3)
                .ok_or_else(|| anyhow!("missing PUSHDATA2 length at offset {offset}"))?;
            let len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
            let start = offset + 3;
            let end = start + len;
            let bytes = payload
                .get(start..end)
                .ok_or_else(|| anyhow!("truncated PUSHDATA2 number at offset {offset}"))?;
            Ok((parse_minimal_int(bytes), end))
        }
        _ => Err(anyhow!(
            "unsupported script number opcode 0x{op:02x} at offset {offset}"
        )),
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    haystack
        .get(start..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|pos| start + pos)
}

fn args_prefix_before_reveal(script: &[u8]) -> &[u8] {
    let mut cursor = script;
    let mut offset = 0usize;
    let mut last_push_start = None;
    while !cursor.is_empty() {
        if let Some((_data, rest)) = read_push(cursor) {
            last_push_start = Some(offset);
            let consumed = cursor.len() - rest.len();
            offset += consumed;
            cursor = rest;
        } else {
            offset += 1;
            cursor = &cursor[1..];
        }
    }
    &script[..last_push_start.unwrap_or(script.len())]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn placeholder_script() -> Vec<u8> {
        let artifact: Value = serde_json::from_str(include_str!(
            "../fixtures/kcc20-sale/KCC20Sale.placeholder.json"
        ))
        .unwrap();
        artifact["script"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect()
    }

    #[test]
    fn matches_vendored_placeholder_script() {
        let script = placeholder_script();
        let decoder =
            Kcc20SaleDecoder::new(Kcc20SaleDecoder::fingerprint_of_compiled_script(&script));
        assert!(decoder.matches_reveal_script(&script));
    }

    #[test]
    fn decodes_constructor_from_vendored_placeholder_script() {
        let script = placeholder_script();
        let decoder =
            Kcc20SaleDecoder::new(Kcc20SaleDecoder::fingerprint_of_compiled_script(&script));
        let v = decoder.decode_constructor(&script).unwrap();
        assert_eq!(
            v["seller"],
            "d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5"
        );
        assert_eq!(v["tokenId"], "00".repeat(32));
        assert_eq!(v["tokenAmount"], "1000000");
        assert_eq!(v["priceSompi"], "100000000");
    }

    #[test]
    fn decodes_constructor_with_short_script_numbers() {
        let script = placeholder_script();
        let mut dynamic = Vec::new();
        dynamic.extend_from_slice(&script[..44]);
        dynamic.extend_from_slice(&[0x01, 100]);
        dynamic.extend_from_slice(&[0x00, 0xa0, 0x69, 0x00, 0xc2]);
        dynamic.extend_from_slice(&[0x03, 0xa0, 0x86, 0x01]);
        dynamic.extend_from_slice(&script[58..]);

        let decoder =
            Kcc20SaleDecoder::new(Kcc20SaleDecoder::fingerprint_of_compiled_script(&dynamic));
        let v = decoder.decode_constructor(&dynamic).unwrap();
        assert_eq!(
            v["seller"],
            "d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5"
        );
        assert_eq!(v["tokenId"], "00".repeat(32));
        assert_eq!(v["tokenAmount"], "100");
        assert_eq!(v["priceSompi"], "100000");

        let placeholder_decoder =
            Kcc20SaleDecoder::new(Kcc20SaleDecoder::fingerprint_of_compiled_script(&script));
        assert!(placeholder_decoder.matches_reveal_script(&dynamic));
    }

    #[test]
    fn decodes_live_dynamic_sale_reveal() {
        let reveal = hex::decode(concat!(
            "6b6c76009c637576cf2019f02af56c89ee13fd6320a4f30ee867bc723d92e957ee5695",
            "a340ed6e2d8e118769016400a06900c203a08601a26900c3203a45f49d274878c84a",
            "ec501cdb8dca6699bf6495eb31ccc0e349ec567f4be732030000207c7e01ac7e876",
            "975516776519c637578203a45f49d274878c84aec501cdb8dca6699bf6495eb31cc",
            "c0e349ec567f4be732ac6976cf2019f02af56c89ee13fd6320a4f30ee867bc723d92e",
            "957ee5695a340ed6e2d8e118769016400a069757551677500696868"
        ))
        .unwrap();
        let decoder = Kcc20SaleDecoder::new([0u8; 32]);

        assert!(decoder.matches_reveal_script(&reveal));
        let v = decoder.decode_constructor(&reveal).unwrap();
        assert_eq!(
            v["seller"],
            "3a45f49d274878c84aec501cdb8dca6699bf6495eb31ccc0e349ec567f4be732"
        );
        assert_eq!(
            v["tokenId"],
            "19f02af56c89ee13fd6320a4f30ee867bc723d92e957ee5695a340ed6e2d8e11"
        );
        assert_eq!(v["tokenAmount"], "100");
        assert_eq!(v["priceSompi"], "100000");
    }

    #[test]
    fn decodes_action_selector_before_reveal() {
        let decoder = Kcc20SaleDecoder::new([0u8; 32]);
        assert_eq!(
            decoder.decode_action(&[0x51, 0x00, 0x01, 0xaa]).as_deref(),
            Some("buy")
        );

        let mut cancel = vec![65];
        cancel.extend([0x11; 65]);
        cancel.extend([0x51, 0x51, 0x01, 0xaa]);
        assert_eq!(decoder.decode_action(&cancel).as_deref(), Some("cancel"));
    }
}
