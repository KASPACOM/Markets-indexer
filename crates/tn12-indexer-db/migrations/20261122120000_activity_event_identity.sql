-- Projection serial IDs change on refresh. Public identities use chain coordinates.
ALTER TABLE kcc20_activity_feed ADD COLUMN event_id TEXT;

CREATE FUNCTION kcc20_activity_event_id(txid BYTEA, action TEXT, inputs JSONB, outputs JSONB)
RETURNS TEXT LANGUAGE SQL IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE
      WHEN action = 'spend'
       AND inputs->'previousOutpoint'->>'hash' ~ '^[0-9a-fA-F]{64}$'
       AND inputs->'previousOutpoint'->>'index' ~ '^(0|[1-9][0-9]*)$'
      THEN 'kcc20:' || encode(txid, 'hex') || ':input:' ||
           lower(inputs->'previousOutpoint'->>'hash') || ':' ||
           (inputs->'previousOutpoint'->>'index')
      WHEN action IN ('deploy', 'continuation')
       AND outputs->>'vout' ~ '^(0|[1-9][0-9]*)$'
      THEN 'kcc20:' || encode(txid, 'hex') || ':output:' || (outputs->>'vout')
      ELSE NULL
    END
$$;

CREATE FUNCTION kcc20_activity_fill_event_id(txid BYTEA, input_index TEXT)
RETURNS TEXT LANGUAGE SQL IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE WHEN input_index ~ '^(0|[1-9][0-9]*)$'
      THEN 'kcc20:' || encode(txid, 'hex') || ':fee-fill:' || input_index
      ELSE NULL END
$$;

-- Existing rows remain readable with null identity until the existing scoped
-- projector refreshes their transactions. Do not enqueue an unbounded rebuild
-- or invent identities from display fields during a schema migration.
