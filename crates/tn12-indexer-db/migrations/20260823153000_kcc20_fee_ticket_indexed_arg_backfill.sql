WITH create_repairs AS (
    SELECT
        a.id,
        jsonb_strip_nulls(jsonb_build_object(
            'ticketOwner', ticket.owner_identifier,
            'ticketOwnerScheme', ticket.owner_scheme,
            'ticketOutputIndex', ticket.vout::TEXT,
            'rootOutputIndex', root.vout::TEXT,
            'quantity', 1
        )) AS patch
    FROM covenant_actions AS a
    JOIN covenants AS c
      ON c.covenant_id = a.covenant_id
    JOIN LATERAL (
        SELECT
            COUNT(*) AS output_count,
            MIN(u.vout) AS vout,
            MIN(COALESCE(u.state->>'ownerIdentifier', u.state->>'stateOwner', u.state->>'owner')) AS owner_identifier,
            MIN(COALESCE(u.state->>'ownerScheme', '0')) AS owner_scheme,
            COUNT(DISTINCT COALESCE(u.state->>'ownerIdentifier', u.state->>'stateOwner', u.state->>'owner')) AS owner_count,
            COUNT(DISTINCT COALESCE(u.state->>'ownerScheme', '0')) AS scheme_count
        FROM covenant_utxos AS u
        WHERE u.txid = a.txid
          AND u.covenant_id = a.covenant_id
          AND COALESCE(u.state->>'mode', u.state->>'stateMode') = '2'
    ) AS ticket
      ON ticket.output_count = 1
     AND ticket.owner_count = 1
     AND ticket.scheme_count = 1
     AND ticket.owner_identifier IS NOT NULL
    JOIN LATERAL (
        SELECT COUNT(*) AS output_count, MIN(u.vout) AS vout
        FROM covenant_utxos AS u
        WHERE u.txid = a.txid
          AND u.covenant_id = a.covenant_id
          AND COALESCE(u.state->>'mode', u.state->>'stateMode') = '1'
    ) AS root
      ON root.output_count = 1
    WHERE c.template_name = 'KCC20FeeTicket'
      AND a.entrypoint = 'createFromUtilityBurn'
      AND NOT COALESCE(a.decoded_args, '{}'::JSONB) ? 'ticketOwner'
),
batch_repairs AS (
    SELECT
        a.id,
        jsonb_strip_nulls(jsonb_build_object(
            'ticketOwner', tickets.owner_identifier,
            'ticketOwnerScheme', tickets.owner_scheme,
            'firstTicketOutputIndex', tickets.first_vout::TEXT,
            'rootOutputIndex', root.vout::TEXT,
            'quantity', tickets.output_count
        )) AS patch
    FROM covenant_actions AS a
    JOIN covenants AS c
      ON c.covenant_id = a.covenant_id
    JOIN LATERAL (
        SELECT
            COUNT(*) AS output_count,
            MIN(u.vout) AS first_vout,
            MAX(u.vout) AS last_vout,
            MIN(COALESCE(u.state->>'ownerIdentifier', u.state->>'stateOwner', u.state->>'owner')) AS owner_identifier,
            MIN(COALESCE(u.state->>'ownerScheme', '0')) AS owner_scheme,
            COUNT(DISTINCT COALESCE(u.state->>'ownerIdentifier', u.state->>'stateOwner', u.state->>'owner')) AS owner_count,
            COUNT(DISTINCT COALESCE(u.state->>'ownerScheme', '0')) AS scheme_count
        FROM covenant_utxos AS u
        WHERE u.txid = a.txid
          AND u.covenant_id = a.covenant_id
          AND COALESCE(u.state->>'mode', u.state->>'stateMode') = '2'
    ) AS tickets
      ON tickets.output_count BETWEEN 1 AND 10
     AND tickets.last_vout = tickets.first_vout + tickets.output_count - 1
     AND tickets.owner_count = 1
     AND tickets.scheme_count = 1
     AND tickets.owner_identifier IS NOT NULL
    JOIN LATERAL (
        SELECT COUNT(*) AS output_count, MIN(u.vout) AS vout
        FROM covenant_utxos AS u
        WHERE u.txid = a.txid
          AND u.covenant_id = a.covenant_id
          AND COALESCE(u.state->>'mode', u.state->>'stateMode') = '1'
    ) AS root
      ON root.output_count = 1
     AND root.vout = tickets.first_vout + tickets.output_count
    WHERE c.template_name = 'KCC20FeeTicket'
      AND a.entrypoint = 'createBatchFromUtilityBurn'
      AND NOT COALESCE(a.decoded_args, '{}'::JSONB) ?& ARRAY['ticketOwner', 'quantity', 'firstTicketOutputIndex']
),
transfer_repairs AS (
    SELECT
        a.id,
        jsonb_strip_nulls(jsonb_build_object(
            'recipientOwner', ticket.owner_identifier,
            'toOwner', ticket.owner_identifier,
            'recipientOwnerScheme', ticket.owner_scheme,
            'toOwnerScheme', ticket.owner_scheme,
            'ticketOutputIndex', ticket.vout::TEXT
        )) AS patch
    FROM covenant_actions AS a
    JOIN covenants AS c
      ON c.covenant_id = a.covenant_id
    JOIN LATERAL (
        SELECT
            COUNT(*) AS output_count,
            MIN(u.vout) AS vout,
            MIN(COALESCE(u.state->>'ownerIdentifier', u.state->>'stateOwner', u.state->>'owner')) AS owner_identifier,
            MIN(COALESCE(u.state->>'ownerScheme', '0')) AS owner_scheme,
            COUNT(DISTINCT COALESCE(u.state->>'ownerIdentifier', u.state->>'stateOwner', u.state->>'owner')) AS owner_count,
            COUNT(DISTINCT COALESCE(u.state->>'ownerScheme', '0')) AS scheme_count
        FROM covenant_utxos AS u
        WHERE u.txid = a.txid
          AND u.covenant_id = a.covenant_id
          AND COALESCE(u.state->>'mode', u.state->>'stateMode') = '2'
    ) AS ticket
      ON ticket.output_count = 1
     AND ticket.owner_count = 1
     AND ticket.scheme_count = 1
     AND ticket.owner_identifier IS NOT NULL
    WHERE c.template_name = 'KCC20FeeTicket'
      AND a.entrypoint = 'transferByOwnerSig'
      AND NOT COALESCE(a.decoded_args, '{}'::JSONB) ? 'recipientOwner'
),
repairs AS (
    SELECT * FROM create_repairs
    UNION ALL
    SELECT * FROM batch_repairs
    UNION ALL
    SELECT * FROM transfer_repairs
),
updated AS (
    UPDATE covenant_actions AS a
       SET decoded_args = COALESCE(a.decoded_args, '{}'::JSONB) || repairs.patch
      FROM repairs
     WHERE a.id = repairs.id
       AND repairs.patch <> '{}'::JSONB
    RETURNING a.txid
)
INSERT INTO kcc20_projection_dirty (reason, txid, created_at_ms)
SELECT DISTINCT
    'kcc20_fee_ticket_indexed_arg_backfill',
    txid,
    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
FROM updated;
