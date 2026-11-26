-- Reconcile incident-containment drift after the trigger migration commits.
-- Numeric corrections are additive against the same statement snapshot, so
-- concurrent trigger deltas are preserved while this compact-state scan runs.
WITH actual AS MATERIALIZED (
    SELECT
        COALESCE(c.template_name, c.claimed_template, 'Unknown') AS template,
        COUNT(*)::BIGINT AS covenant_count,
        COUNT(*) FILTER (WHERE c.template_name IS NOT NULL)::BIGINT AS verified_count,
        COUNT(*) FILTER (
            WHERE c.template_name IS NULL AND c.claimed_template IS NOT NULL
        )::BIGINT AS claimed_only_count,
        COUNT(*) FILTER (WHERE COALESCE(s.active_utxos, 0) > 0)::BIGINT AS active_covenants,
        COALESCE(SUM(s.active_utxos), 0)::BIGINT AS active_utxos,
        COALESCE(SUM(s.total_amount_sompi), 0)::NUMERIC AS total_amount_sompi,
        COALESCE(SUM(a.action_count), 0)::BIGINT AS action_count,
        COUNT(*) FILTER (WHERE c.classification_status = 'matched')::BIGINT AS matched_count,
        COUNT(*) FILTER (WHERE c.classification_status = 'unrevealed')::BIGINT AS unrevealed_count,
        COUNT(*) FILTER (WHERE c.classification_status = 'unmatched')::BIGINT AS unmatched_count,
        MAX(c.created_at_ms) AS latest_created_at_ms,
        MAX(a.latest_action_time_ms) AS latest_action_time_ms
    FROM covenants c
    LEFT JOIN covenant_summaries s ON s.covenant_id = c.covenant_id
    LEFT JOIN covenant_action_summaries a ON a.covenant_id = c.covenant_id
    GROUP BY COALESCE(c.template_name, c.claimed_template, 'Unknown')
),
snapshot AS MATERIALIZED (
    SELECT * FROM covenant_template_summaries
),
inserted AS (
    INSERT INTO covenant_template_summaries (
        template,
        covenant_count,
        verified_count,
        claimed_only_count,
        active_covenants,
        active_utxos,
        total_amount_sompi,
        action_count,
        matched_count,
        unrevealed_count,
        unmatched_count,
        latest_created_at_ms,
        latest_action_time_ms,
        updated_at_ms
    )
    SELECT
        actual.template,
        actual.covenant_count,
        actual.verified_count,
        actual.claimed_only_count,
        actual.active_covenants,
        actual.active_utxos,
        actual.total_amount_sompi,
        actual.action_count,
        actual.matched_count,
        actual.unrevealed_count,
        actual.unmatched_count,
        actual.latest_created_at_ms,
        actual.latest_action_time_ms,
        EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
    FROM actual
    LEFT JOIN snapshot ON snapshot.template = actual.template
    WHERE snapshot.template IS NULL
    ON CONFLICT (template) DO UPDATE SET
        covenant_count = covenant_template_summaries.covenant_count + EXCLUDED.covenant_count,
        verified_count = covenant_template_summaries.verified_count + EXCLUDED.verified_count,
        claimed_only_count = covenant_template_summaries.claimed_only_count + EXCLUDED.claimed_only_count,
        active_covenants = covenant_template_summaries.active_covenants + EXCLUDED.active_covenants,
        active_utxos = covenant_template_summaries.active_utxos + EXCLUDED.active_utxos,
        total_amount_sompi = covenant_template_summaries.total_amount_sompi + EXCLUDED.total_amount_sompi,
        action_count = covenant_template_summaries.action_count + EXCLUDED.action_count,
        matched_count = covenant_template_summaries.matched_count + EXCLUDED.matched_count,
        unrevealed_count = covenant_template_summaries.unrevealed_count + EXCLUDED.unrevealed_count,
        unmatched_count = covenant_template_summaries.unmatched_count + EXCLUDED.unmatched_count,
        latest_created_at_ms = GREATEST(
            covenant_template_summaries.latest_created_at_ms,
            EXCLUDED.latest_created_at_ms
        ),
        latest_action_time_ms = GREATEST(
            covenant_template_summaries.latest_action_time_ms,
            EXCLUDED.latest_action_time_ms
        ),
        updated_at_ms = EXCLUDED.updated_at_ms
    RETURNING template
)
UPDATE covenant_template_summaries current
   SET covenant_count = GREATEST(
           current.covenant_count + actual.covenant_count - COALESCE(snapshot.covenant_count, 0),
           0
       ),
       verified_count = GREATEST(
           current.verified_count + actual.verified_count - COALESCE(snapshot.verified_count, 0),
           0
       ),
       claimed_only_count = GREATEST(
           current.claimed_only_count + actual.claimed_only_count - COALESCE(snapshot.claimed_only_count, 0),
           0
       ),
       active_covenants = GREATEST(
           current.active_covenants + actual.active_covenants - COALESCE(snapshot.active_covenants, 0),
           0
       ),
       active_utxos = GREATEST(
           current.active_utxos + actual.active_utxos - COALESCE(snapshot.active_utxos, 0),
           0
       ),
       total_amount_sompi = GREATEST(
           current.total_amount_sompi + actual.total_amount_sompi - COALESCE(snapshot.total_amount_sompi, 0),
           0
       ),
       action_count = GREATEST(
           current.action_count + actual.action_count - COALESCE(snapshot.action_count, 0),
           0
       ),
       matched_count = GREATEST(
           current.matched_count + actual.matched_count - COALESCE(snapshot.matched_count, 0),
           0
       ),
       unrevealed_count = GREATEST(
           current.unrevealed_count + actual.unrevealed_count - COALESCE(snapshot.unrevealed_count, 0),
           0
       ),
       unmatched_count = GREATEST(
           current.unmatched_count + actual.unmatched_count - COALESCE(snapshot.unmatched_count, 0),
           0
       ),
       latest_created_at_ms = CASE
           WHEN current.latest_created_at_ms IS NOT DISTINCT FROM snapshot.latest_created_at_ms
               THEN actual.latest_created_at_ms
           ELSE GREATEST(current.latest_created_at_ms, actual.latest_created_at_ms)
       END,
       latest_action_time_ms = CASE
           WHEN current.latest_action_time_ms IS NOT DISTINCT FROM snapshot.latest_action_time_ms
               THEN actual.latest_action_time_ms
           ELSE GREATEST(current.latest_action_time_ms, actual.latest_action_time_ms)
       END,
       updated_at_ms = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
  FROM actual
  LEFT JOIN snapshot ON snapshot.template = actual.template
 WHERE current.template = actual.template
   AND NOT EXISTS (
       SELECT 1 FROM inserted WHERE inserted.template = current.template
   );

DELETE FROM covenant_template_summaries summary
WHERE NOT EXISTS (
    SELECT 1
    FROM covenants covenant
    WHERE COALESCE(
              covenant.template_name,
              covenant.claimed_template,
              'Unknown'
          ) = summary.template
);
