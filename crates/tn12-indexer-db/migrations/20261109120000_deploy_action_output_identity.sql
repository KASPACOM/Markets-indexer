-- A snapshot start creates one reserve output per shard. Those outputs share
-- the token covenant ID and transaction ID, so deploy identity must include
-- vout just like continuation identity does. The previous covenant+tx key
-- silently kept only the first reserve action even though covenant_utxos
-- correctly retained every output.

-- Converge both supported predecessor schemas. Fully migrated databases have
-- the deploy/spend split from 20260709150000; older installations can still
-- carry the broad non-continuation key, which would otherwise reject vout 1.
DROP INDEX IF EXISTS covenant_actions_non_continuation_uniq;
DROP INDEX IF EXISTS covenant_actions_deploy_uniq;

CREATE UNIQUE INDEX covenant_actions_deploy_uniq
    ON covenant_actions (
        covenant_id,
        txid,
        action,
        ((outputs->>'vout'))
    )
    WHERE action = 'deploy' AND outputs ? 'vout';

-- Preserve replay idempotency for legacy/degraded deploy rows that do not
-- carry output identity.
CREATE UNIQUE INDEX covenant_actions_deploy_without_vout_uniq
    ON covenant_actions (covenant_id, txid, action)
    WHERE action = 'deploy'
      AND (outputs IS NULL OR NOT (outputs ? 'vout'));

CREATE UNIQUE INDEX IF NOT EXISTS covenant_actions_spend_outpoint_uniq
    ON covenant_actions (
        covenant_id,
        txid,
        action,
        ((inputs #>> '{previousOutpoint,hash}')),
        ((inputs #>> '{previousOutpoint,index}'))
    )
    WHERE action = 'spend'
      AND inputs #>> '{previousOutpoint,hash}' IS NOT NULL
      AND inputs #>> '{previousOutpoint,index}' IS NOT NULL;

-- Repair already indexed multi-output genesis transactions from the canonical
-- UTXO projection. The existing deploy row supplies the accepted block/time;
-- the UTXO row supplies exact output identity and decoded state. Payload-level
-- constructor arguments remain on the original deploy action. The covenant's
-- recorded genesis transaction is the authority: a stale deploy row attached
-- to a real continuation transaction must never make that UTXO a deployment.
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
    u.covenant_id,
    u.txid,
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
FROM covenant_utxos u
JOIN covenants c
  ON c.covenant_id = u.covenant_id
 AND c.genesis_txid = u.txid
JOIN LATERAL (
    SELECT a.block_hash, a.block_time_ms
    FROM covenant_actions a
    WHERE a.covenant_id = u.covenant_id
      AND a.txid = u.txid
      AND a.action = 'deploy'
    ORDER BY a.id ASC
    LIMIT 1
) seed ON TRUE
WHERE NOT EXISTS (
    SELECT 1
    FROM covenant_actions exact
    WHERE exact.covenant_id = u.covenant_id
      AND exact.txid = u.txid
      AND exact.action = 'deploy'
      AND exact.outputs->>'vout' = u.vout::TEXT
)
ON CONFLICT DO NOTHING;
