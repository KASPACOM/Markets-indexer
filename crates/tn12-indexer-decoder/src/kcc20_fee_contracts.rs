//! KCC20 V2 market-side contract decoders.

use anyhow::Result;
use serde_json::Value;
use tn12_indexer_core::{read_push, template_fingerprint, KnownTemplate};

use crate::TemplateDecoder;

pub struct StaticKcc20TemplateDecoder {
    template: KnownTemplate,
    name: &'static str,
    fingerprint: [u8; 32],
    actions: &'static [&'static str],
}

impl StaticKcc20TemplateDecoder {
    pub fn new(
        template: KnownTemplate,
        name: &'static str,
        fingerprint: [u8; 32],
        actions: &'static [&'static str],
    ) -> Self {
        Self {
            template,
            name,
            fingerprint,
            actions,
        }
    }

    pub fn fingerprint_of_compiled_script(script: &[u8]) -> [u8; 32] {
        template_fingerprint(script)
    }
}

impl TemplateDecoder for StaticKcc20TemplateDecoder {
    fn template(&self) -> KnownTemplate {
        self.template
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn script_hash(&self) -> [u8; 32] {
        self.fingerprint
    }

    fn matches_reveal_script(&self, reveal: &[u8]) -> bool {
        Self::fingerprint_of_compiled_script(reveal) == self.fingerprint
    }

    fn decode_constructor(&self, _payload: &[u8]) -> Result<Value> {
        Ok(Value::Null)
    }

    fn decode_state(&self, _payload: &[u8]) -> Result<Value> {
        Ok(Value::Null)
    }

    fn decode_action(&self, signature_script: &[u8]) -> Option<String> {
        let prefix = args_prefix_before_reveal(signature_script);
        let selector = selector_from_prefix(prefix)?;
        self.actions.get(selector).map(|s| (*s).to_string())
    }
}

pub fn kcc20_sale_v2(fingerprint: [u8; 32]) -> StaticKcc20TemplateDecoder {
    StaticKcc20TemplateDecoder::new(
        KnownTemplate::Kcc20SaleV2,
        "KCC20SaleV2",
        fingerprint,
        &["activateListing", "buyListing", "cancelListing"],
    )
}

pub fn kcc20_buy_order(fingerprint: [u8; 32]) -> StaticKcc20TemplateDecoder {
    StaticKcc20TemplateDecoder::new(
        KnownTemplate::Kcc20BuyOrder,
        "KCC20BuyOrder",
        fingerprint,
        &["fillBuyOrder", "cancelBuyOrder"],
    )
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

fn selector_from_prefix(prefix: &[u8]) -> Option<usize> {
    match prefix.last().copied()? {
        0x00 => Some(0),
        0x51..=0x60 => Some((prefix.last().copied()? - 0x50) as usize),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact_script(raw: &str) -> Vec<u8> {
        let artifact: Value = serde_json::from_str(raw).unwrap();
        artifact["script"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect()
    }

    #[test]
    fn sale_v2_matches_placeholder_and_decodes_actions() {
        let script = artifact_script(include_str!(
            "../fixtures/kcc20-sale-v2/KCC20SaleV2.placeholder.json"
        ));
        let decoder = kcc20_sale_v2(StaticKcc20TemplateDecoder::fingerprint_of_compiled_script(
            &script,
        ));

        assert!(decoder.matches_reveal_script(&script));
        assert_eq!(decoder.name(), "KCC20SaleV2");
        assert_eq!(decoder.template(), KnownTemplate::Kcc20SaleV2);
        assert_eq!(
            decoder.decode_action(&[0x00, 0x01, 0xaa]).as_deref(),
            Some("activateListing")
        );
        assert_eq!(
            decoder.decode_action(&[0x51, 0x01, 0xaa]).as_deref(),
            Some("buyListing")
        );
        assert_eq!(
            decoder.decode_action(&[0x52, 0x01, 0xaa]).as_deref(),
            Some("cancelListing")
        );
        assert_eq!(decoder.decode_action(&[0x53, 0x01, 0xaa]), None);
    }

    #[test]
    fn buy_order_matches_placeholder_and_decodes_actions() {
        let script = artifact_script(include_str!(
            "../fixtures/kcc20-buy-order/KCC20BuyOrder.placeholder.json"
        ));
        let decoder = kcc20_buy_order(StaticKcc20TemplateDecoder::fingerprint_of_compiled_script(
            &script,
        ));

        assert!(decoder.matches_reveal_script(&script));
        assert_eq!(decoder.name(), "KCC20BuyOrder");
        assert_eq!(decoder.template(), KnownTemplate::Kcc20BuyOrder);
        assert_eq!(
            decoder.decode_action(&[0x00, 0x01, 0xaa]).as_deref(),
            Some("fillBuyOrder")
        );
        assert_eq!(
            decoder.decode_action(&[0x51, 0x01, 0xaa]).as_deref(),
            Some("cancelBuyOrder")
        );
        assert_eq!(decoder.decode_action(&[0x52, 0x01, 0xaa]), None);
    }
}
