//! Kaspa-side script primitives + small helpers used by template decoders.
//!
//! We do not pull `kaspa-txscript` (which requires the full rusty-kaspa
//! workspace). Instead we re-derive the rules the indexer actually needs:
//!   * P2SH `script_public_key` detection: `OP_BLAKE2B(0xAA) PUSH32 <hash> OP_EQUAL(0x87)`.
//!   * Blake2b-256 of a redeem script (the value committed by P2SH).
//!   * Push-op reading for unpacking constructor args / state from reveal scripts.

use blake2::digest::consts::U32;
use blake2::digest::{Digest, FixedOutput};
use blake2::Blake2b;

const OP_BLAKE2B: u8 = 0xaa;
const OP_PUSH_32: u8 = 0x20;
const OP_EQUAL: u8 = 0x87;

pub fn is_p2sh_script_pubkey(spk: &[u8]) -> bool {
    spk.len() == 35 && spk[0] == OP_BLAKE2B && spk[1] == OP_PUSH_32 && spk[34] == OP_EQUAL
}

pub fn p2sh_script_hash(spk: &[u8]) -> Option<[u8; 32]> {
    if !is_p2sh_script_pubkey(spk) {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&spk[2..34]);
    Some(out)
}

/// Length-invariant template fingerprint.
///
/// Walks the script, emitting only the opcode bytes (push payloads stripped).
/// Two compiled SilverScript contracts of the same template but with different
/// constructor values produce identical opcode signatures, so
/// `blake2b_256(opcode_signature(script))` is a stable template id across
/// deploys regardless of push-data widths (pubkeys are always 32 B, but ints
/// can be 1..9 bytes depending on magnitude — that variation does not change
/// the opcode stream).
/// Sentinel byte we substitute for every push-class opcode in
/// `opcode_signature`. Keeps the signature invariant under push-data magnitude:
/// PUSH4 of `0xdeadbeef` and OP_PUSHDATA1 of an 80-byte value both collapse to
/// the same sentinel, so a template that takes a tiny int in one deploy and a
/// large int in another still produces the same fingerprint.
const PUSH_SENTINEL: u8 = 0xFF;

#[inline]
fn is_push_class(op: u8) -> bool {
    matches!(op, 0x00 | 0x01..=0x4e | 0x4f | 0x51..=0x60)
}

pub fn opcode_signature(script: &[u8]) -> Vec<u8> {
    let mut sig = Vec::with_capacity(script.len() / 2);
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        let consumed = if (0x01..=0x4b).contains(&op) {
            1 + op as usize
        } else if op == 0x4c {
            if i + 1 >= script.len() {
                break;
            }
            2 + script[i + 1] as usize
        } else if op == 0x4d {
            if i + 2 >= script.len() {
                break;
            }
            3 + u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize
        } else if op == 0x4e {
            if i + 4 >= script.len() {
                break;
            }
            5 + u32::from_le_bytes([script[i + 1], script[i + 2], script[i + 3], script[i + 4]])
                as usize
        } else {
            1
        };
        sig.push(if is_push_class(op) { PUSH_SENTINEL } else { op });
        i += consumed;
    }
    sig
}

/// `blake2b_256(opcode_signature(script))` — the template fingerprint.
pub fn template_fingerprint(script: &[u8]) -> [u8; 32] {
    blake2b_256(&opcode_signature(script))
}

pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut h: Blake2b<U32> = Blake2b::new();
    Digest::update(&mut h, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize_fixed());
    out
}

/// Read the next data push from a script. Returns (data, rest).
pub fn read_push(script: &[u8]) -> Option<(&[u8], &[u8])> {
    let (op, rest) = script.split_first()?;
    let op = *op;
    if (0x01..=0x4b).contains(&op) {
        let len = op as usize;
        if rest.len() < len {
            return None;
        }
        Some((&rest[..len], &rest[len..]))
    } else if op == 0x4c {
        // OP_PUSHDATA1
        let (lb, rest) = rest.split_first()?;
        let len = *lb as usize;
        if rest.len() < len {
            return None;
        }
        Some((&rest[..len], &rest[len..]))
    } else if op == 0x4d {
        // OP_PUSHDATA2 (little-endian length)
        if rest.len() < 2 {
            return None;
        }
        let len = u16::from_le_bytes([rest[0], rest[1]]) as usize;
        let rest = &rest[2..];
        if rest.len() < len {
            return None;
        }
        Some((&rest[..len], &rest[len..]))
    } else if op == 0x4e {
        // OP_PUSHDATA4
        if rest.len() < 4 {
            return None;
        }
        let len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        let rest = &rest[4..];
        if rest.len() < len {
            return None;
        }
        Some((&rest[..len], &rest[len..]))
    } else {
        None
    }
}

pub fn skip_one_push(script: &[u8]) -> Option<&[u8]> {
    let (_, rest) = read_push(script)?;
    Some(rest)
}

/// Reader state for sequentially consuming push ops.
pub struct ScriptReader<'a> {
    pub script: &'a [u8],
}

impl<'a> ScriptReader<'a> {
    pub fn new(script: &'a [u8]) -> Self {
        Self { script }
    }
    pub fn next_push(&mut self) -> anyhow::Result<&'a [u8]> {
        let (data, rest) =
            read_push(self.script).ok_or_else(|| anyhow::anyhow!("script truncated at push"))?;
        self.script = rest;
        Ok(data)
    }
}

/// Parse a Bitcoin/Kaspa Script-encoded little-endian signed integer.
pub fn parse_minimal_int(bytes: &[u8]) -> i128 {
    if bytes.is_empty() {
        return 0;
    }
    let mut result: i128 = 0;
    for (i, b) in bytes.iter().enumerate() {
        result |= (*b as i128) << (8 * i);
    }
    let last = *bytes.last().unwrap();
    if last & 0x80 != 0 {
        result &= !(1i128 << (8 * bytes.len() - 1));
        result = -result;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_real_timelock_spk() {
        let spk =
            hex::decode("aa2011f8924c7f0718634c684a96facacfdc38999073f0ce70c0d429b64c89596eb987")
                .unwrap();
        assert!(is_p2sh_script_pubkey(&spk));
        let hash = p2sh_script_hash(&spk).unwrap();
        assert_eq!(
            hex::encode(hash),
            "11f8924c7f0718634c684a96facacfdc38999073f0ce70c0d429b64c89596eb9"
        );
    }

    #[test]
    fn rejects_non_p2sh_spk() {
        let spk =
            hex::decode("2026cb3ff1d2275f7d5b9d960a6f5ec437bf15dfc099dacb199e8d35e8151562fcac")
                .unwrap();
        assert!(!is_p2sh_script_pubkey(&spk));
    }

    #[test]
    fn read_short_push() {
        let (data, rest) = read_push(&[0x02, 0xaa, 0xbb, 0xcc]).unwrap();
        assert_eq!(data, &[0xaa, 0xbb]);
        assert_eq!(rest, &[0xcc]);
    }

    #[test]
    fn read_pushdata1() {
        let (data, rest) = read_push(&[0x4c, 0x03, 0x11, 0x22, 0x33, 0x99]).unwrap();
        assert_eq!(data, &[0x11, 0x22, 0x33]);
        assert_eq!(rest, &[0x99]);
    }

    #[test]
    fn parses_minimal_int_positive_and_negative() {
        assert_eq!(parse_minimal_int(&[0x05]), 5);
        assert_eq!(parse_minimal_int(&[0x85]), -5);
        assert_eq!(parse_minimal_int(&[0xff, 0x7f]), 0x7fff);
    }
}
