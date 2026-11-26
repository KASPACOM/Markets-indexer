CREATE TABLE covenant_participants (
    id                BIGSERIAL PRIMARY KEY,
    covenant_id       BYTEA NOT NULL REFERENCES covenants(covenant_id) ON UPDATE CASCADE ON DELETE CASCADE,
    source            TEXT NOT NULL CHECK (source IN ('claimed_args', 'constructor_args')),
    name              TEXT NOT NULL,
    value             TEXT NOT NULL,
    value_normalized  TEXT NOT NULL,
    value_hash        TEXT NOT NULL,
    type              TEXT,
    created_at_ms     BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS covenant_participants_value_time_idx
    ON covenant_participants (value_hash, created_at_ms DESC, covenant_id);

CREATE INDEX IF NOT EXISTS covenant_participants_name_value_time_idx
    ON covenant_participants (name, value_hash, created_at_ms DESC, covenant_id);

CREATE INDEX IF NOT EXISTS covenant_participants_name_time_idx
    ON covenant_participants (name, created_at_ms DESC, covenant_id);

CREATE INDEX IF NOT EXISTS covenant_participants_covenant_idx
    ON covenant_participants (covenant_id);

CREATE INDEX IF NOT EXISTS covenants_recent_idx
    ON covenants (created_at_ms DESC, covenant_id DESC);

CREATE INDEX IF NOT EXISTS covenants_template_recent_idx
    ON covenants ((COALESCE(template_name, claimed_template, 'Unknown')), created_at_ms DESC, covenant_id DESC);

CREATE INDEX IF NOT EXISTS covenants_classification_recent_idx
    ON covenants (classification_kind, classification_status, created_at_ms DESC, covenant_id DESC);

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
            arg->>'value' AS value,
            arg->>'type' AS type,
            c.created_at_ms
        FROM covenants c
        CROSS JOIN LATERAL jsonb_array_elements(
            CASE
                WHEN jsonb_typeof(c.claimed_args->'args') = 'array' THEN c.claimed_args->'args'
                ELSE '[]'::jsonb
            END
        ) AS arg
        WHERE c.covenant_id = target_covenant_id
          AND arg ? 'name'
          AND arg ? 'value'

        UNION ALL

        SELECT
            c.covenant_id,
            'claimed_args'::TEXT AS source,
            arg.name,
            arg.value #>> '{}',
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
        WHERE c.covenant_id = target_covenant_id
          AND arg.name NOT IN ('tmpl', 'args', 'meta')

        UNION ALL

        SELECT
            c.covenant_id,
            'constructor_args'::TEXT AS source,
            arg.name,
            arg.value #>> '{}',
            NULL::TEXT AS type,
            c.created_at_ms
        FROM covenants c
        CROSS JOIN LATERAL jsonb_each(
            CASE
                WHEN jsonb_typeof(c.constructor_args) = 'object' THEN c.constructor_args
                ELSE '{}'::jsonb
            END
        ) AS arg(name, value)
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

CREATE OR REPLACE FUNCTION refresh_covenant_participants_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM refresh_covenant_participants(NEW.covenant_id);
    RETURN NEW;
END;
$$;

CREATE TRIGGER covenants_refresh_participants
AFTER INSERT OR UPDATE OF claimed_args, constructor_args, created_at_ms ON covenants
FOR EACH ROW
EXECUTE FUNCTION refresh_covenant_participants_trigger();

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
        arg->>'value' AS value,
        arg->>'type' AS type,
        c.created_at_ms
    FROM covenants c
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE
            WHEN jsonb_typeof(c.claimed_args->'args') = 'array' THEN c.claimed_args->'args'
            ELSE '[]'::jsonb
        END
    ) AS arg
    WHERE arg ? 'name'
      AND arg ? 'value'

    UNION ALL

    SELECT
        c.covenant_id,
        'claimed_args'::TEXT AS source,
        arg.name,
        arg.value #>> '{}',
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
    WHERE arg.name NOT IN ('tmpl', 'args', 'meta')

    UNION ALL

    SELECT
        c.covenant_id,
        'constructor_args'::TEXT AS source,
        arg.name,
        arg.value #>> '{}',
        NULL::TEXT AS type,
        c.created_at_ms
    FROM covenants c
    CROSS JOIN LATERAL jsonb_each(
        CASE
            WHEN jsonb_typeof(c.constructor_args) = 'object' THEN c.constructor_args
            ELSE '{}'::jsonb
        END
    ) AS arg(name, value)
) raw
CROSS JOIN LATERAL (
    SELECT
        lower(btrim(raw.name)) AS normalized_name,
        lower(btrim(raw.value)) AS normalized_value
) normalized
WHERE normalized_name <> ''
  AND normalized_value <> ''
ORDER BY covenant_id, source, normalized_name, normalized_value, type NULLS LAST
;

ANALYZE covenant_participants;
ANALYZE covenants;
