-- Repair snapshot starts indexed while the former covenant+transaction deploy
-- key retained only the first reserve output. This is not compatibility for an
-- old contract or wire format: these are current snapshot genesis transactions
-- whose action history became incomplete under the superseded database key.
--
-- The covenant's immutable genesis transaction is the authority. Requiring the
-- current snapshot genesis projection schema additionally keeps this repair
-- away from ordinary deploys and from continuation transactions that happen to
-- contain a stale deploy action. The preceding migrations have already created
-- output-scoped uniqueness and retired the conflicting transaction-scoped key.
--
-- Do not substitute the bootstrap/controller `*-start/v2` or `*-start/v3`
-- schemas below. Those identify the input `spend` action decoded from the
-- snapshot start witness. `project_snapshot_start_kcc20()` separately annotates
-- the derived KCC20 `deploy` action with `kcc20-snapshot-token-genesis/v1` in
-- persist.rs; that deploy annotation is the seed this output repair requires.
WITH snapshot_genesis AS (
    SELECT DISTINCT ON (a.covenant_id, a.txid)
        a.covenant_id,
        a.txid,
        a.block_hash,
        a.block_time_ms
    FROM covenant_actions a
    JOIN covenants c
      ON c.covenant_id = a.covenant_id
     AND c.genesis_txid = a.txid
    WHERE a.action = 'deploy'
      AND a.decoded_args->>'projectionSchema' = 'kcc20-snapshot-token-genesis/v1'
    ORDER BY a.covenant_id, a.txid, a.id ASC
)
INSERT INTO covenant_actions (
    covenant_id,
    txid,
    block_hash,
    block_time_ms,
    action,
    entrypoint,
    inputs,
    outputs,
    decoded_args
)
SELECT
    seed.covenant_id,
    seed.txid,
    seed.block_hash,
    seed.block_time_ms,
    'deploy',
    NULL,
    NULL,
    jsonb_build_object(
        'vout', u.vout,
        'amountSompi', u.amount_sompi,
        'address', u.address,
        'scriptPubKeyHex', encode(u.script_pubkey, 'hex'),
        'state', u.state
    ),
    NULL
FROM snapshot_genesis seed
JOIN covenant_utxos u
  ON u.covenant_id = seed.covenant_id
 AND u.txid = seed.txid
WHERE NOT EXISTS (
    SELECT 1
    FROM covenant_actions exact
    WHERE exact.covenant_id = seed.covenant_id
      AND exact.txid = seed.txid
      AND exact.action = 'deploy'
      AND exact.outputs->>'vout' = u.vout::TEXT
)
ON CONFLICT DO NOTHING;
