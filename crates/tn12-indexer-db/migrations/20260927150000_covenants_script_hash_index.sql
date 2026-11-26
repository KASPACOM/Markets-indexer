-- no-transaction

-- Resolve covenant IDs from script hashes without scanning the full covenant table.
CREATE INDEX CONCURRENTLY IF NOT EXISTS covenants_script_hash_idx
    ON covenants (script_hash);
