CREATE OR REPLACE FUNCTION refresh_covenant_participants(target_covenant_id BYTEA)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF target_covenant_id IS NULL THEN
        RETURN;
    END IF;

    DELETE FROM covenant_participants WHERE covenant_id = target_covenant_id;

    INSERT INTO covenant_participants (
        covenant_id,
        source,
        name,
        value,
        value_normalized,
        value_hash,
        type,
        created_at_ms
    )
    SELECT DISTINCT ON (covenant_id, source, normalized_name, normalized_value)
        covenant_id,
        source,
        normalized_name,
        value,
        normalized_value,
        md5(normalized_value),
        type,
        created_at_ms
    FROM (
        SELECT
            c.covenant_id,
            'claimed_args'::TEXT AS source,
            arg->>'name' AS name,
            value_item.value #>> '{}' AS value,
            arg->>'type' AS type,
            c.created_at_ms
        FROM covenants c
        CROSS JOIN LATERAL jsonb_array_elements(
            CASE
                WHEN jsonb_typeof(c.claimed_args->'args') = 'array' THEN c.claimed_args->'args'
                ELSE '[]'::jsonb
            END
        ) AS arg
        CROSS JOIN LATERAL jsonb_array_elements(
            CASE
                WHEN jsonb_typeof(arg->'value') = 'array' THEN arg->'value'
                ELSE jsonb_build_array(arg->'value')
            END
        ) AS value_item(value)
        WHERE c.covenant_id = target_covenant_id
          AND arg ? 'name'
          AND arg ? 'value'

        UNION ALL

        SELECT
            c.covenant_id,
            'claimed_args'::TEXT AS source,
            arg.name,
            value_item.value #>> '{}',
            NULL::TEXT AS type,
            c.created_at_ms
        FROM covenants c
        CROSS JOIN LATERAL jsonb_each(
            CASE
                WHEN jsonb_typeof(c.claimed_args) = 'object'
                  AND COALESCE(jsonb_typeof(c.claimed_args->'args'), 'null') <> 'array'
                THEN c.claimed_args
                ELSE '{}'::jsonb
            END
        ) AS arg(name, value)
        CROSS JOIN LATERAL jsonb_array_elements(
            CASE
                WHEN jsonb_typeof(arg.value) = 'array' THEN arg.value
                ELSE jsonb_build_array(arg.value)
            END
        ) AS value_item(value)
        WHERE c.covenant_id = target_covenant_id
          AND arg.name NOT IN ('tmpl', 'args', 'meta')

        UNION ALL

        SELECT
            c.covenant_id,
            'constructor_args'::TEXT AS source,
            arg.name,
            value_item.value #>> '{}',
            NULL::TEXT AS type,
            c.created_at_ms
        FROM covenants c
        CROSS JOIN LATERAL jsonb_each(
            CASE
                WHEN jsonb_typeof(c.constructor_args) = 'object' THEN c.constructor_args
                ELSE '{}'::jsonb
            END
        ) AS arg(name, value)
        CROSS JOIN LATERAL jsonb_array_elements(
            CASE
                WHEN jsonb_typeof(arg.value) = 'array' THEN arg.value
                ELSE jsonb_build_array(arg.value)
            END
        ) AS value_item(value)
        WHERE c.covenant_id = target_covenant_id
    ) raw
    CROSS JOIN LATERAL (
        SELECT
            lower(btrim(raw.name)) AS normalized_name,
            lower(btrim(raw.value)) AS normalized_value
    ) normalized
    WHERE normalized_name <> ''
      AND normalized_value <> ''
    ORDER BY covenant_id, source, normalized_name, normalized_value, type NULLS LAST;
END;
$$;

CREATE INDEX IF NOT EXISTS covenant_summaries_current_address_idx
    ON covenant_summaries (current_address);

INSERT INTO covenant_participants (
    covenant_id,
    source,
    name,
    value,
    value_normalized,
    value_hash,
    type,
    created_at_ms
)
SELECT DISTINCT ON (covenant_id, source, normalized_name, normalized_value)
    covenant_id,
    source,
    normalized_name,
    value,
    normalized_value,
    md5(normalized_value),
    type,
    created_at_ms
FROM (
    SELECT
        c.covenant_id,
        'claimed_args'::TEXT AS source,
        arg->>'name' AS name,
        value_item.value #>> '{}' AS value,
        arg->>'type' AS type,
        c.created_at_ms
    FROM covenants c
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE
            WHEN jsonb_typeof(c.claimed_args->'args') = 'array' THEN c.claimed_args->'args'
            ELSE '[]'::jsonb
        END
    ) AS arg
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE
            WHEN jsonb_typeof(arg->'value') = 'array' THEN arg->'value'
            ELSE '[]'::jsonb
        END
    ) AS value_item(value)
    WHERE arg ? 'name'
      AND arg ? 'value'

    UNION ALL

    SELECT
        c.covenant_id,
        'claimed_args'::TEXT AS source,
        arg.name,
        value_item.value #>> '{}',
        NULL::TEXT AS type,
        c.created_at_ms
    FROM covenants c
    CROSS JOIN LATERAL jsonb_each(
        CASE
            WHEN jsonb_typeof(c.claimed_args) = 'object'
              AND COALESCE(jsonb_typeof(c.claimed_args->'args'), 'null') <> 'array'
            THEN c.claimed_args
            ELSE '{}'::jsonb
        END
    ) AS arg(name, value)
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE
            WHEN jsonb_typeof(arg.value) = 'array' THEN arg.value
            ELSE '[]'::jsonb
        END
    ) AS value_item(value)
    WHERE arg.name NOT IN ('tmpl', 'args', 'meta')

    UNION ALL

    SELECT
        c.covenant_id,
        'constructor_args'::TEXT AS source,
        arg.name,
        value_item.value #>> '{}',
        NULL::TEXT AS type,
        c.created_at_ms
    FROM covenants c
    CROSS JOIN LATERAL jsonb_each(
        CASE
            WHEN jsonb_typeof(c.constructor_args) = 'object' THEN c.constructor_args
            ELSE '{}'::jsonb
        END
    ) AS arg(name, value)
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE
            WHEN jsonb_typeof(arg.value) = 'array' THEN arg.value
            ELSE '[]'::jsonb
        END
    ) AS value_item(value)
    WHERE jsonb_typeof(arg.value) = 'array'
) raw
CROSS JOIN LATERAL (
    SELECT
        lower(btrim(raw.name)) AS normalized_name,
        lower(btrim(raw.value)) AS normalized_value
) normalized
WHERE normalized_name <> ''
  AND normalized_value <> ''
  AND NOT EXISTS (
      SELECT 1
      FROM covenant_participants existing
      WHERE existing.covenant_id = raw.covenant_id
        AND existing.source = raw.source
        AND existing.name = normalized_name
        AND existing.value_hash = md5(normalized_value)
        AND existing.value_normalized = normalized_value
  )
ORDER BY covenant_id, source, normalized_name, normalized_value, type NULLS LAST;

ANALYZE covenant_participants;
