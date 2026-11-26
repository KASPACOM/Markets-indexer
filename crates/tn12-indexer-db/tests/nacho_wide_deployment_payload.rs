use tn12_indexer_db::claim;
use tn12_indexer_decoder::kcc20_standard::{
    decode_supply_claim, deploy_output_states_from_claimed_args,
};

const NACHO_PAYLOAD: &str = include_str!(
    "../../tn12-indexer-decoder/fixtures/kcc20/nacho-wide-deployment-payload.v1.json"
);

#[test]
fn exact_nacho_payload_crosses_envelope_and_deployment_decoders() {
    let payload_hex = hex::encode(NACHO_PAYLOAD.trim().as_bytes());
    let claimed = claim::parse_payload_envelope(&payload_hex).expect("Nacho deployment envelope");
    let claimed_args = claim::claimed_args_jsonb(&claimed);

    assert_eq!(claimed.tmpl, "KCC20");
    assert_eq!(
        decode_supply_claim(&claimed_args, "maxSupply"),
        Some(28_700_000_000_000_000_000)
    );
    assert_eq!(
        decode_supply_claim(&claimed_args, "premintSupply"),
        Some(28_700_000_000_000_000_000)
    );

    let outputs = deploy_output_states_from_claimed_args(&claimed_args)
        .expect("indexer accepts the builder's canonical wide deployment payload");
    assert_eq!(outputs.len(), 5);
    assert!(outputs.iter().all(|output| output.role == "reserve"));
    assert_eq!(
        outputs
            .iter()
            .map(|output| output.state["amount"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "6155259898638223950",
            "5951866420246839519",
            "5757775773333178726",
            "5919898242175782749",
            "4915199665605975056",
        ]
    );
    assert!(outputs.iter().all(|output| {
        output.state["extensionCommitment"]
            == "bd2bc17e17e2a7a6fdc4a557c80fa441760a8ce31f4d09a394bed240f7f9a6e3"
    }));
}
