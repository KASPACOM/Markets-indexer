-- no-transaction

CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_actions_output_address_time_idx
    ON covenant_actions ((outputs->>'address'), block_time_ms DESC, id DESC)
    WHERE outputs ? 'address';
