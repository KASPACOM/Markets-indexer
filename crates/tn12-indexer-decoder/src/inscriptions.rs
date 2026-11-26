use serde::{Deserialize, Serialize};
use serde_json::Value;
use tn12_indexer_core::read_push;

const OP_FALSE: u8 = 0x00;
const OP_IF: u8 = 0x63;
const OP_CHECKSIG: u8 = 0xac;
const OP_ENDIF: u8 = 0x68;

const KASPLEX_LC: &[u8] = b"kasplex";
const KASPLEX_UC: &[u8] = b"KASPLEX";
const KSPR_LC: &[u8] = b"kspr";
const KSPR_UC: &[u8] = b"KSPR";
const KNS_LC: &[u8] = b"kns";
const KNS_UC: &[u8] = b"KNS";

const KSPR_STRICT_LC: &[u8] = &[OP_FALSE, OP_IF, 0x04, b'k', b's', b'p', b'r'];
const KSPR_STRICT_UC: &[u8] = &[OP_FALSE, OP_IF, 0x04, b'K', b'S', b'P', b'R'];
const KNS_STRICT_LC: &[u8] = &[OP_FALSE, OP_IF, 0x03, b'k', b'n', b's'];
const KNS_STRICT_UC: &[u8] = &[OP_FALSE, OP_IF, 0x03, b'K', b'N', b'S'];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InscriptionProtocol {
    Krc20,
    Krc721,
    Kns,
}

impl InscriptionProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Krc20 => "KRC-20",
            Self::Krc721 => "KRC-721",
            Self::Kns => "KNS",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Inscription {
    pub protocol: InscriptionProtocol,
    pub op: String,
    pub json: Value,
}

impl Inscription {
    pub fn template_name(&self) -> String {
        format!("{}-{}", self.protocol.as_str(), self.op)
    }
}

pub fn detect_inscription_from_reveal(reveal: &[u8]) -> Option<Inscription> {
    if !has_any_header(reveal) {
        return None;
    }

    parse_envelope(reveal).and_then(|env| classify_payload(env.protocol_header, env.json_payload))
}

pub fn detect_inscription_in_signature_script(signature_script: &[u8]) -> Option<Inscription> {
    extract_last_push(signature_script).and_then(|reveal| detect_inscription_from_reveal(&reveal))
}

fn has_any_header(reveal: &[u8]) -> bool {
    window_find(reveal, KASPLEX_LC).is_some()
        || window_find(reveal, KASPLEX_UC).is_some()
        || window_find(reveal, KSPR_STRICT_LC).is_some()
        || window_find(reveal, KSPR_STRICT_UC).is_some()
        || window_find(reveal, KNS_STRICT_LC).is_some()
        || window_find(reveal, KNS_STRICT_UC).is_some()
}

struct ParsedEnvelope<'a> {
    protocol_header: &'a [u8],
    json_payload: &'a [u8],
}

fn parse_envelope(mut script: &[u8]) -> Option<ParsedEnvelope<'_>> {
    let (pubkey, rest) = read_push(script)?;
    if pubkey.len() != 32 && pubkey.len() != 33 {
        return None;
    }
    script = rest;

    script = consume_opcode(script, OP_CHECKSIG)?;
    script = consume_opcode(script, OP_FALSE)?;
    script = consume_opcode(script, OP_IF)?;

    let (protocol_header, rest) = read_push(script)?;
    if !matches_protocol_header(protocol_header) {
        return None;
    }
    script = rest;

    script = consume_opcode(script, OP_FALSE)?;

    let (json_payload, rest) = read_push(script)?;
    script = consume_opcode(rest, OP_ENDIF)?;
    if !script.is_empty() {
        return None;
    }

    Some(ParsedEnvelope {
        protocol_header,
        json_payload,
    })
}

fn classify_payload(protocol_header: &[u8], json_payload: &[u8]) -> Option<Inscription> {
    let json: Value = serde_json::from_slice(json_payload).ok()?;
    let protocol_raw = json
        .get("p")
        .or_else(|| json.get("protocol"))
        .and_then(Value::as_str);
    let protocol = if is_kns_header(protocol_header) {
        if let Some(raw) = protocol_raw {
            if raw.to_ascii_lowercase() != "domain" {
                return None;
            }
        }
        InscriptionProtocol::Kns
    } else {
        match protocol_raw?.to_ascii_lowercase().as_str() {
            "krc-20" if is_kasplex_header(protocol_header) => InscriptionProtocol::Krc20,
            "krc-721" if is_kspr_header(protocol_header) => InscriptionProtocol::Krc721,
            _ => return None,
        }
    };

    let op = json.get("op").and_then(Value::as_str)?.to_ascii_lowercase();
    if !allowed_op(protocol, &op) {
        return None;
    }

    Some(Inscription { protocol, op, json })
}

fn allowed_op(protocol: InscriptionProtocol, op: &str) -> bool {
    match protocol {
        InscriptionProtocol::Krc20 => matches!(op, "deploy" | "mint" | "transfer"),
        InscriptionProtocol::Krc721 => {
            matches!(
                op,
                "deploy" | "mint" | "send" | "transfer" | "list" | "discount"
            )
        }
        InscriptionProtocol::Kns => matches!(op, "create" | "send" | "list" | "transfer"),
    }
}

fn consume_opcode(script: &[u8], expected: u8) -> Option<&[u8]> {
    let (op, rest) = script.split_first()?;
    (*op == expected).then_some(rest)
}

fn matches_protocol_header(header: &[u8]) -> bool {
    is_kasplex_header(header) || is_kspr_header(header) || is_kns_header(header)
}

fn is_kasplex_header(header: &[u8]) -> bool {
    header == KASPLEX_LC || header == KASPLEX_UC
}

fn is_kspr_header(header: &[u8]) -> bool {
    header == KSPR_LC || header == KSPR_UC
}

fn is_kns_header(header: &[u8]) -> bool {
    header == KNS_LC || header == KNS_UC
}

fn window_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn extract_last_push(script: &[u8]) -> Option<Vec<u8>> {
    let mut cursor = script;
    let mut last: Option<Vec<u8>> = None;
    while !cursor.is_empty() {
        match read_push(cursor) {
            Some((data, rest)) => {
                last = Some(data.to_vec());
                cursor = rest;
            }
            None => cursor = &cursor[1..],
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push(data: &[u8]) -> Vec<u8> {
        assert!(data.len() <= 0x4b);
        let mut out = Vec::with_capacity(data.len() + 1);
        out.push(data.len() as u8);
        out.extend_from_slice(data);
        out
    }

    fn pushdata1(data: &[u8]) -> Vec<u8> {
        assert!(data.len() <= u8::MAX as usize);
        let mut out = Vec::with_capacity(data.len() + 2);
        out.push(0x4c);
        out.push(data.len() as u8);
        out.extend_from_slice(data);
        out
    }

    fn envelope(header: &[u8], json: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(push(&[0x11; 32]));
        out.push(OP_CHECKSIG);
        out.push(OP_FALSE);
        out.push(OP_IF);
        out.extend(push(header));
        out.push(OP_FALSE);
        out.extend(pushdata1(json));
        out.push(OP_ENDIF);
        out
    }

    fn sigscript_for(reveal: &[u8]) -> Vec<u8> {
        let mut out = push(&[0x55; 65]);
        out.extend(pushdata1(reveal));
        out
    }

    #[test]
    fn detects_krc20_mint_from_extracted_reveal() {
        let reveal = envelope(KASPLEX_LC, br#"{"p":"krc-20","op":"mint","tick":"TEST"}"#);
        let inscription = detect_inscription_from_reveal(&reveal).expect("inscription");

        assert_eq!(inscription.protocol, InscriptionProtocol::Krc20);
        assert_eq!(inscription.op, "mint");
        assert_eq!(inscription.template_name(), "KRC-20-mint");
    }

    #[test]
    fn detects_krc721_uppercase_header() {
        let reveal = envelope(KSPR_UC, br#"{"p":"krc-721","op":"list","tick":"NFT"}"#);
        let inscription = detect_inscription_from_reveal(&reveal).expect("inscription");

        assert_eq!(inscription.protocol, InscriptionProtocol::Krc721);
        assert_eq!(inscription.op, "list");
    }

    #[test]
    fn detects_kns_domain_create() {
        let reveal = envelope(KNS_LC, br#"{"op":"create","p":"domain","v":"example"}"#);
        let inscription = detect_inscription_from_reveal(&reveal).expect("inscription");

        assert_eq!(inscription.protocol, InscriptionProtocol::Kns);
        assert_eq!(inscription.op, "create");
        assert_eq!(inscription.template_name(), "KNS-create");
    }

    #[test]
    fn detects_kns_send_without_protocol_field() {
        let reveal = envelope(KNS_UC, br#"{"op":"send","id":"787...i0"}"#);
        let inscription = detect_inscription_from_reveal(&reveal).expect("inscription");

        assert_eq!(inscription.protocol, InscriptionProtocol::Kns);
        assert_eq!(inscription.op, "send");
    }

    #[test]
    fn rejects_kns_domain_header_with_non_domain_protocol() {
        let reveal = envelope(KNS_LC, br#"{"op":"create","p":"krc-20","v":"example"}"#);

        assert!(detect_inscription_from_reveal(&reveal).is_none());
    }

    #[test]
    fn detects_full_signature_script_helper() {
        let reveal = envelope(KASPLEX_UC, br#"{"protocol":"krc-20","op":"transfer"}"#);
        let sigscript = sigscript_for(&reveal);

        let from_reveal = detect_inscription_from_reveal(&reveal);
        let from_sigscript = detect_inscription_in_signature_script(&sigscript);

        assert_eq!(from_sigscript, from_reveal);
    }

    #[test]
    fn rejects_header_bytes_in_json_value() {
        let reveal = envelope(KASPLEX_LC, br#"{"p":"note","op":"mint","memo":"kasplex"}"#);

        assert!(detect_inscription_from_reveal(&reveal).is_none());
    }

    #[test]
    fn rejects_wrong_opcode_position() {
        let mut reveal = Vec::new();
        reveal.extend(push(&[0x11; 32]));
        reveal.push(OP_CHECKSIG);
        reveal.push(OP_FALSE);
        reveal.push(OP_IF);
        reveal.push(OP_FALSE);
        reveal.extend(push(KASPLEX_LC));
        reveal.extend(pushdata1(br#"{"p":"krc-20","op":"mint"}"#));
        reveal.push(OP_ENDIF);

        assert!(detect_inscription_from_reveal(&reveal).is_none());
    }

    #[test]
    fn rejects_malformed_json() {
        let reveal = envelope(KSPR_LC, br#"{"p":"krc-721","op":"mint""#);

        assert!(detect_inscription_from_reveal(&reveal).is_none());
    }
}
