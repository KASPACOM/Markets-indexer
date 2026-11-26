-- Keep verified replacements even if an operator later removes a blocks row.
-- Ordinary replay must never restore references to a replaced accepting block.
CREATE TABLE canonical_block_replacements (
    old_hash BYTEA PRIMARY KEY CHECK (octet_length(old_hash) = 32),
    new_hash BYTEA NOT NULL CHECK (octet_length(new_hash) = 32 AND new_hash <> old_hash),
    evidence JSONB NOT NULL,
    source_tip BIGINT NOT NULL CHECK (source_tip >= 0),
    verified_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX canonical_block_replacements_new_hash_idx ON canonical_block_replacements (new_hash);
