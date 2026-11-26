-- Event-sourced snapshot migration projection. Genesis rows come from the
-- wallet deployment claim and remain explicitly unverified until a spend
-- reveals the controller script. Claim rows always come from decoded spends.

CREATE VIEW kcc20_snapshot_claims AS
SELECT
    a.id AS action_id,
    a.covenant_id AS controller_id,
    decode(a.decoded_args->>'tokenId', 'hex') AS token_id,
    decode(a.decoded_args->>'manifestCommitment', 'hex') AS manifest_commitment,
    decode(a.decoded_args->>'snapshotContext', 'hex') AS snapshot_context,
    (a.decoded_args->>'shardIndex')::BIGINT AS shard_index,
    (a.decoded_args->>'globalIndex')::BIGINT AS global_index,
    (a.decoded_args->>'shardLeafIndex')::BIGINT AS shard_leaf_index,
    (a.decoded_args->>'ownerScheme')::SMALLINT AS owner_scheme,
    decode(a.decoded_args->>'owner', 'hex') AS owner_identifier,
    (a.decoded_args->>'claimAmount')::NUMERIC(78,0) AS claim_amount,
    decode(a.decoded_args->>'holderExtensionCommitment', 'hex') AS holder_extension_commitment,
    (a.decoded_args->>'recipientAmount')::NUMERIC(78,0) AS recipient_amount,
    decode(a.decoded_args->>'recipient', 'hex') AS recipient_identifier,
    (a.decoded_args->>'recipientOwnerScheme')::SMALLINT AS recipient_owner_scheme,
    (a.decoded_args->>'successorReserveAmount')::NUMERIC(78,0) AS successor_reserve_amount,
    decode(a.decoded_args->>'previousRoot', 'hex') AS previous_root,
    decode(a.decoded_args->>'nextRoot', 'hex') AS next_root,
    (a.decoded_args->>'remainingBefore')::NUMERIC(78,0) AS remaining_before,
    (a.decoded_args->>'remainingAfter')::NUMERIC(78,0) AS remaining_after,
    (a.decoded_args->>'claimsProcessedBefore')::BIGINT AS claims_processed_before,
    (a.decoded_args->>'claimsProcessedAfter')::BIGINT AS claims_processed_after,
    (a.decoded_args->>'holderCount')::BIGINT AS holder_count,
    (a.decoded_args->>'terminal')::BOOLEAN AS terminal,
    a.txid,
    a.block_hash,
    a.block_time_ms
FROM covenant_actions a
JOIN covenants c ON c.covenant_id = a.covenant_id
WHERE c.template_name = 'KCC20SnapshotController'
  AND a.action = 'spend'
  AND a.entrypoint = 'claim'
  AND a.decoded_args->>'projectionSchema' = 'kcc20-snapshot-claim/v1'
  AND a.decoded_args ?& ARRAY[
      'tokenId', 'manifestCommitment', 'snapshotContext', 'shardIndex',
      'globalIndex', 'shardLeafIndex', 'ownerScheme', 'owner', 'claimAmount',
      'holderExtensionCommitment', 'recipientAmount', 'recipient',
      'recipientOwnerScheme', 'successorReserveAmount', 'previousRoot',
      'nextRoot', 'remainingBefore', 'remainingAfter', 'claimsProcessedBefore',
      'claimsProcessedAfter', 'holderCount', 'terminal'
  ];

CREATE VIEW kcc20_snapshot_shards AS
WITH controllers AS (
    SELECT
        c.covenant_id AS controller_id,
        decode(u.state->>'tokenId', 'hex') AS token_id,
        decode(u.state->>'manifestCommitment', 'hex') AS manifest_commitment,
        decode(u.state->>'snapshotContext', 'hex') AS snapshot_context,
        decode(u.state->>'holderExtensionCommitment', 'hex') AS holder_extension_commitment,
        (u.state->>'shardIndex')::BIGINT AS shard_index,
        (u.state->>'globalIndexStart')::BIGINT AS global_index_start,
        (u.state->>'holderCount')::BIGINT AS holder_count,
        decode(u.state->>'remainingRoot', 'hex') AS initial_root,
        (u.state->>'remainingAmount')::NUMERIC(78,0) AS allocation_total,
        (u.state->>'claimsProcessed')::BIGINT AS initial_claims_processed,
        c.template_name = 'KCC20SnapshotController'
            AND c.claim_verified IS TRUE AS state_verified
    FROM covenants c
    JOIN LATERAL (
        SELECT candidate.state
        FROM covenant_utxos candidate
        JOIN blocks created ON created.hash = candidate.created_block
        WHERE candidate.covenant_id = c.covenant_id
          AND candidate.state ?& ARRAY[
              'tokenId', 'manifestCommitment', 'snapshotContext', 'shardIndex',
              'holderExtensionCommitment', 'globalIndexStart', 'holderCount',
              'remainingRoot', 'remainingAmount', 'claimsProcessed'
          ]
        ORDER BY created.blue_score ASC, candidate.txid ASC, candidate.vout ASC
        LIMIT 1
    ) u ON TRUE
    WHERE COALESCE(c.template_name, c.claimed_template) = 'KCC20SnapshotController'
), ranked AS (
    SELECT
        claim.*,
        row_number() OVER (
            PARTITION BY controller_id ORDER BY claims_processed_after ASC, action_id ASC
        ) AS first_rank,
        row_number() OVER (
            PARTITION BY controller_id ORDER BY claims_processed_after DESC, action_id DESC
        ) AS last_rank,
        lag(next_root) OVER (
            PARTITION BY controller_id ORDER BY claims_processed_after ASC, action_id ASC
        ) AS previous_chain_root,
        lag(remaining_after) OVER (
            PARTITION BY controller_id ORDER BY claims_processed_after ASC, action_id ASC
        ) AS previous_remaining_after,
        lag(claims_processed_after) OVER (
            PARTITION BY controller_id ORDER BY claims_processed_after ASC, action_id ASC
        ) AS previous_claims_processed_after,
        first_value(token_id) OVER (
            PARTITION BY controller_id ORDER BY claims_processed_after ASC, action_id ASC
        ) AS first_token_id,
        first_value(manifest_commitment) OVER (
            PARTITION BY controller_id ORDER BY claims_processed_after ASC, action_id ASC
        ) AS first_manifest_commitment,
        first_value(snapshot_context) OVER (
            PARTITION BY controller_id ORDER BY claims_processed_after ASC, action_id ASC
        ) AS first_snapshot_context,
        first_value(holder_extension_commitment) OVER (
            PARTITION BY controller_id ORDER BY claims_processed_after ASC, action_id ASC
        ) AS first_holder_extension_commitment,
        first_value(shard_index) OVER (
            PARTITION BY controller_id ORDER BY claims_processed_after ASC, action_id ASC
        ) AS first_shard_index,
        first_value(holder_count) OVER (
            PARTITION BY controller_id ORDER BY claims_processed_after ASC, action_id ASC
        ) AS first_holder_count,
        first_value(global_index - shard_leaf_index) OVER (
            PARTITION BY controller_id ORDER BY claims_processed_after ASC, action_id ASC
        ) AS first_global_index_start
    FROM kcc20_snapshot_claims claim
), folded AS (
    SELECT
        controller_id,
        (array_agg(token_id ORDER BY action_id))[1] AS token_id,
        (array_agg(manifest_commitment ORDER BY action_id))[1] AS manifest_commitment,
        (array_agg(snapshot_context ORDER BY action_id))[1] AS snapshot_context,
        (array_agg(holder_extension_commitment ORDER BY action_id))[1] AS holder_extension_commitment,
        max(shard_index) AS shard_index,
        max(holder_count) AS holder_count,
        min(global_index - shard_leaf_index) AS inferred_global_index_start,
        (array_agg(previous_root ORDER BY first_rank))[1] AS initial_root,
        max(remaining_before) FILTER (WHERE first_rank = 1) AS allocation_total,
        max(claims_processed_before) FILTER (WHERE first_rank = 1) AS initial_claims_processed,
        (array_agg(next_root ORDER BY last_rank))[1] AS current_root,
        max(remaining_after) FILTER (WHERE last_rank = 1) AS remaining_amount,
        max(claims_processed_after) AS claims_processed,
        bool_or(terminal) AS exhausted,
        bool_and(
            token_id = first_token_id
            AND manifest_commitment = first_manifest_commitment
            AND snapshot_context = first_snapshot_context
            AND holder_extension_commitment = first_holder_extension_commitment
            AND shard_index = first_shard_index
            AND holder_count = first_holder_count
            AND shard_leaf_index >= 0
            AND shard_leaf_index < holder_count
            AND global_index >= shard_leaf_index
            AND (global_index - shard_leaf_index) = first_global_index_start
            AND claim_amount > 0
            AND recipient_amount = claim_amount
            AND recipient_identifier = owner_identifier
            AND recipient_owner_scheme = owner_scheme
            AND successor_reserve_amount = remaining_after
            AND claims_processed_after = claims_processed_before + 1
            AND remaining_after = remaining_before - claim_amount
            AND terminal = (remaining_after = 0 AND claims_processed_after = holder_count)
            AND (
                (first_rank = 1 AND previous_chain_root IS NULL)
                OR (first_rank > 1 AND previous_root = previous_chain_root)
            )
            AND (
                (first_rank = 1 AND previous_remaining_after IS NULL)
                OR (first_rank > 1 AND remaining_before = previous_remaining_after)
            )
            AND (
                (first_rank = 1 AND previous_claims_processed_after IS NULL)
                OR (first_rank > 1 AND claims_processed_before = previous_claims_processed_after)
            )
        ) AS claim_chain_verified
    FROM ranked
    GROUP BY controller_id
)
SELECT
    controllers.controller_id,
    COALESCE(folded.token_id, controllers.token_id) AS token_id,
    COALESCE(folded.manifest_commitment, controllers.manifest_commitment) AS manifest_commitment,
    COALESCE(folded.snapshot_context, controllers.snapshot_context) AS snapshot_context,
    COALESCE(folded.holder_extension_commitment, controllers.holder_extension_commitment) AS holder_extension_commitment,
    COALESCE(folded.shard_index, controllers.shard_index) AS shard_index,
    COALESCE(folded.holder_count, controllers.holder_count) AS holder_count,
    COALESCE(folded.initial_root, controllers.initial_root) AS initial_root,
    COALESCE(folded.allocation_total, controllers.allocation_total) AS allocation_total,
    COALESCE(folded.current_root, controllers.initial_root) AS current_root,
    COALESCE(folded.remaining_amount, controllers.allocation_total) AS remaining_amount,
    COALESCE(folded.claims_processed, controllers.initial_claims_processed) AS claims_processed,
    COALESCE(folded.exhausted, FALSE) AS exhausted,
    controllers.state_verified
        AND active.active_outpoint_count <= 1
        AND COALESCE(folded.claim_chain_verified, TRUE)
        AND (
            folded.controller_id IS NULL
            OR (
                folded.token_id = controllers.token_id
                AND folded.manifest_commitment = controllers.manifest_commitment
                AND folded.snapshot_context = controllers.snapshot_context
                AND folded.holder_extension_commitment = controllers.holder_extension_commitment
                AND folded.shard_index = controllers.shard_index
                AND folded.holder_count = controllers.holder_count
                AND folded.inferred_global_index_start = controllers.global_index_start
                AND folded.initial_root = controllers.initial_root
                AND folded.allocation_total = controllers.allocation_total
                AND folded.initial_claims_processed = controllers.initial_claims_processed
                AND folded.claims_processed <= controllers.holder_count
            )
        ) AS state_verified,
    active.active_outpoint_count,
    active.active_outpoint_count > 1 AS active_outpoint_ambiguous,
    CASE WHEN active.active_outpoint_count = 1 THEN active.txids[1] END AS active_txid,
    CASE WHEN active.active_outpoint_count = 1 THEN active.vouts[1] END AS active_vout
FROM controllers
LEFT JOIN folded USING (controller_id)
LEFT JOIN LATERAL (
    SELECT
        count(*) AS active_outpoint_count,
        array_agg(txid ORDER BY txid, vout) AS txids,
        array_agg(vout ORDER BY txid, vout) AS vouts
    FROM covenant_utxos
    WHERE covenant_id = controllers.controller_id AND status = 'active'
) active ON TRUE;

CREATE VIEW kcc20_snapshot_global_totals AS
SELECT
    token_id,
    manifest_commitment,
    count(*) AS shard_count,
    sum(holder_count) AS holder_count,
    sum(allocation_total) AS allocation_total,
    sum(allocation_total - remaining_amount) AS claimed_total,
    sum(remaining_amount) AS remaining_total,
    sum(claims_processed)::BIGINT AS claims_processed,
    bool_and(exhausted) AS exhausted,
    bool_and(state_verified) AS state_verified
FROM kcc20_snapshot_shards
GROUP BY token_id, manifest_commitment;

CREATE UNIQUE INDEX IF NOT EXISTS covenant_actions_snapshot_claim_global_uniq
    ON covenant_actions (
        (lower(decoded_args->>'tokenId')),
        (lower(decoded_args->>'manifestCommitment')),
        ((decoded_args->>'globalIndex')::BIGINT)
    )
    WHERE entrypoint = 'claim'
      AND decoded_args->>'projectionSchema' = 'kcc20-snapshot-claim/v1'
      AND decoded_args ?& ARRAY['tokenId', 'manifestCommitment', 'globalIndex'];
