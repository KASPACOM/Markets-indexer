-- Keep the address action history small and keyed by the source action.
-- The API remains on its original query until a bounded backfill is complete.
CREATE TABLE kcc20_owner_action_history (
    action_id BIGINT PRIMARY KEY REFERENCES covenant_actions(id) ON DELETE CASCADE,
    txid BYTEA NOT NULL,
    txid_hex TEXT NOT NULL,
    block_time_ms BIGINT NOT NULL,
    owner TEXT,
    address TEXT NOT NULL,
    normalized_action TEXT NOT NULL,
    token_id TEXT,
    canonical_token_id TEXT,
    wrapped_token_id TEXT,
    amount TEXT,
    direction TEXT,
    status TEXT NOT NULL,
    input_outpoints JSONB NOT NULL,
    output_outpoints JSONB NOT NULL,
    covenant_id_hex TEXT NOT NULL,
    wrapper_covenant_id TEXT,
    entrypoint TEXT,
    template_name TEXT
);

CREATE INDEX kcc20_owner_action_history_owner_time_idx
    ON kcc20_owner_action_history (owner, block_time_ms DESC, txid_hex DESC, action_id DESC)
    WHERE owner IS NOT NULL;
CREATE INDEX kcc20_owner_action_history_address_time_idx
    ON kcc20_owner_action_history (address, block_time_ms DESC, txid_hex DESC, action_id DESC);
CREATE INDEX kcc20_owner_action_history_txid_idx
    ON kcc20_owner_action_history (txid);

-- This row is initialized by the backfill after the new projector owns the
-- dirty queue. Its absence keeps the old API query active.
CREATE TABLE kcc20_owner_action_backfill (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    dirty_start_id BIGINT NOT NULL,
    max_action_id BIGINT NOT NULL,
    target_covenant_id BYTEA,
    covenant_cursor BYTEA,
    action_cursor BIGINT NOT NULL DEFAULT 0,
    scan_template_name TEXT,
    scan_address TEXT,
    scan_template_initialized BOOLEAN NOT NULL DEFAULT FALSE,
    complete BOOLEAN NOT NULL DEFAULT FALSE,
    ready BOOLEAN NOT NULL DEFAULT FALSE
);

-- Remember each covenant's classification at the end of the source scan.
-- A later classification change invalidates historical actions, not just
-- the dirty transaction that revealed the new template.
CREATE TABLE kcc20_owner_action_covenant_state (
    covenant_id BYTEA PRIMARY KEY REFERENCES covenants(covenant_id) ON DELETE CASCADE,
    template_name TEXT NOT NULL,
    address TEXT NOT NULL
);
