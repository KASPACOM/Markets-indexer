use serde_json::Value;
use tn12_indexer_decoder::inscriptions::{
    detect_inscription_in_signature_script, InscriptionProtocol,
};

struct Fixture {
    name: &'static str,
    txid: &'static str,
    sigscript_hex: &'static str,
    protocol: InscriptionProtocol,
    op: &'static str,
    tick: &'static str,
}

fn decode_sigscript(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str.trim()).expect("fixture sigscript hex")
}

fn lower_json_str(json: &Value, key: &str) -> String {
    json.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase()
}

#[test]
fn detects_real_mainnet_krc_inscriptions() {
    let cases = [
        Fixture {
            name: "KRC-20 deploy DUKBUX",
            txid: "b8f44d7542daaf6718ff6cae531b4aeb3977ae62f7fb1e0d2fe0c67c7377ac6b",
            sigscript_hex: include_str!("fixtures/inscriptions/krc20-deploy-dukbux.sighex"),
            protocol: InscriptionProtocol::Krc20,
            op: "deploy",
            tick: "dukbux",
        },
        Fixture {
            name: "KRC-20 mint KSOC",
            txid: "02f1c3c6af73259d574afc9f58f08b030d469e36f248ce14b51626630336113b",
            sigscript_hex: include_str!("fixtures/inscriptions/krc20-mint-ksoc.sighex"),
            protocol: InscriptionProtocol::Krc20,
            op: "mint",
            tick: "ksoc",
        },
        Fixture {
            name: "KRC-20 transfer DUKBUX",
            txid: "551ca84d0362d49d7d536c20a791980e077dc82f2e4570aff4b197c3610be785",
            sigscript_hex: include_str!("fixtures/inscriptions/krc20-transfer-dukbux.sighex"),
            protocol: InscriptionProtocol::Krc20,
            op: "transfer",
            tick: "dukbux",
        },
        Fixture {
            name: "KRC-721 deploy KSPR",
            txid: "3b15799a3e3041fe692890352f9d60de5e487c6f6d63ee5c2310b872ba5b49af",
            sigscript_hex: include_str!("fixtures/inscriptions/krc721-deploy-kspr.sighex"),
            protocol: InscriptionProtocol::Krc721,
            op: "deploy",
            tick: "kspr",
        },
        Fixture {
            name: "KRC-721 mint KSPR",
            txid: "ea3d20f07e0b0886ab868c049ce72ac01efb711a06badfa4f817186459479a14",
            sigscript_hex: include_str!("fixtures/inscriptions/krc721-mint-kspr.sighex"),
            protocol: InscriptionProtocol::Krc721,
            op: "mint",
            tick: "kspr",
        },
        Fixture {
            name: "KRC-721 discount KSPR",
            txid: "afff01a80489f0440de86186ad1400d424432af0c81fcfe12e3d1518f7fce4d3",
            sigscript_hex: include_str!("fixtures/inscriptions/krc721-discount-kspr.sighex"),
            protocol: InscriptionProtocol::Krc721,
            op: "discount",
            tick: "kspr",
        },
        Fixture {
            name: "KRC-721 transfer KSPR",
            txid: "0ae19e397a094ebe4a283d9ca805bb4cb97491886f49457d26b4c02af1caba41",
            sigscript_hex: include_str!("fixtures/inscriptions/krc721-transfer-kspr.sighex"),
            protocol: InscriptionProtocol::Krc721,
            op: "transfer",
            tick: "kspr",
        },
    ];

    for case in cases {
        let sigscript = decode_sigscript(case.sigscript_hex);
        let inscription = detect_inscription_in_signature_script(&sigscript)
            .unwrap_or_else(|| panic!("detect {}", case.name));

        assert_eq!(inscription.protocol, case.protocol, "{}", case.txid);
        assert_eq!(inscription.op, case.op, "{}", case.txid);
        assert_eq!(
            inscription.template_name(),
            format!("{}-{}", case.protocol.as_str(), case.op),
            "{}",
            case.txid
        );
        assert_eq!(
            lower_json_str(&inscription.json, "tick"),
            case.tick,
            "{}",
            case.txid
        );
    }
}

#[test]
fn detects_kns_domain_fixture() {
    let sigscript = decode_sigscript(include_str!(
        "fixtures/inscriptions/kns-create-example.sighex"
    ));
    let inscription =
        detect_inscription_in_signature_script(&sigscript).expect("detect KNS create");

    assert_eq!(inscription.protocol, InscriptionProtocol::Kns);
    assert_eq!(inscription.op, "create");
    assert_eq!(inscription.template_name(), "KNS-create");
    assert_eq!(lower_json_str(&inscription.json, "p"), "domain");
    assert_eq!(lower_json_str(&inscription.json, "v"), "example");
}
