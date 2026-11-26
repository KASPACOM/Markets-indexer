WITH transfer_repairs AS (
    SELECT
        a.id,
        a.txid,
        jsonb_strip_nulls(jsonb_build_object(
            'recipientOwner', tickets.owner_identifier,
            'toOwner', tickets.owner_identifier,
            'recipientOwnerScheme', tickets.owner_scheme,
            'toOwnerScheme', tickets.owner_scheme
        )) AS patch
    FROM covenant_actions AS a
    JOIN covenants AS c
      ON c.covenant_id = a.covenant_id
    JOIN LATERAL (
        SELECT
            COUNT(*) AS output_count,
            MIN(COALESCE(u.state->>'ownerIdentifier', u.state->>'stateOwner', u.state->>'owner')) AS owner_identifier,
            MIN(COALESCE(u.state->>'ownerScheme', '0')) AS owner_scheme,
            COUNT(DISTINCT COALESCE(u.state->>'ownerIdentifier', u.state->>'stateOwner', u.state->>'owner')) AS owner_count,
            COUNT(DISTINCT COALESCE(u.state->>'ownerScheme', '0')) AS scheme_count
        FROM covenant_utxos AS u
        WHERE u.txid = a.txid
          AND u.covenant_id = a.covenant_id
          AND COALESCE(u.state->>'mode', u.state->>'stateMode') = '2'
    ) AS tickets
      ON tickets.output_count > 1
     AND tickets.owner_count = 1
     AND tickets.scheme_count = 1
     AND tickets.owner_identifier IS NOT NULL
    WHERE c.template_name = 'KCC20FeeTicket'
      AND a.entrypoint = 'transferByOwnerSig'
      AND NOT COALESCE(a.decoded_args, '{}'::JSONB) ? 'recipientOwner'
),
updated AS (
    UPDATE covenant_actions AS a
       SET decoded_args = COALESCE(a.decoded_args, '{}'::JSONB) || transfer_repairs.patch
      FROM transfer_repairs
     WHERE a.id = transfer_repairs.id
       AND transfer_repairs.patch <> '{}'::JSONB
    RETURNING a.txid
)
INSERT INTO kcc20_projection_dirty (reason, txid, created_at_ms)
SELECT DISTINCT
    'kcc20_fee_ticket_multi_transfer_owner_backfill',
    txid,
    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
FROM updated;
