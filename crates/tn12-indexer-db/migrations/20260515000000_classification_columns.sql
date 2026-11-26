ALTER TABLE covenants
    ADD COLUMN classification_kind TEXT NOT NULL DEFAULT 'unknown'
        CHECK (classification_kind IN ('covenant', 'inscription', 'unknown')),
    ADD COLUMN classification_status TEXT NOT NULL DEFAULT 'unrevealed'
        CHECK (classification_status IN ('unrevealed', 'matched', 'unmatched'));

UPDATE covenants
SET classification_kind = 'covenant',
    classification_status = 'matched'
WHERE template_name IS NOT NULL;

UPDATE covenants c
SET classification_kind = 'unknown',
    classification_status = 'unmatched'
WHERE c.template_name IS NULL
  AND (
      EXISTS (
          SELECT 1 FROM covenant_actions a
          WHERE a.covenant_id = c.covenant_id
            AND a.action = 'spend'
      )
      OR EXISTS (
          SELECT 1 FROM covenant_utxos u
          WHERE u.covenant_id = c.covenant_id
            AND u.status = 'spent'
      )
  );

CREATE INDEX covenants_classification_idx
    ON covenants(classification_kind, classification_status);
