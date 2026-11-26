-- Fast read models for KCC20 token-page and wallet-position surfaces.
--
-- These tables move expensive token-page reads out of request-time CTE scans.
-- They are rebuilt by the indexer refresh path after KCC20 writes/reverts and
-- at API startup.

CREATE TABLE kcc20_activity_feed (
    id                 BIGSERIAL PRIMARY KEY,
    token_id           BYTEA NOT NULL,
    txid               BYTEA NOT NULL,
    block_time_ms      BIGINT NOT NULL,
    entrypoint         TEXT,
    kind               TEXT NOT NULL,
    side               TEXT,
    order_id           TEXT,
    owner_identifier   TEXT,
    token_amount       TEXT,
    unit_price_sompi   TEXT,
    price_sompi        TEXT
);

CREATE INDEX kcc20_activity_feed_token_time_idx
    ON kcc20_activity_feed (token_id, block_time_ms DESC, txid DESC);

CREATE INDEX kcc20_activity_feed_kind_idx
    ON kcc20_activity_feed (kind, token_id, block_time_ms DESC);

CREATE TABLE kcc20_wrapper_summaries (
    wrapper_id              BYTEA PRIMARY KEY,
    canonical_token_id      BYTEA NOT NULL,
    address                 TEXT,
    genesis_txid            BYTEA,
    active_utxos            BIGINT NOT NULL DEFAULT 0,
    pending_reveal          BOOLEAN NOT NULL DEFAULT FALSE,
    enabled                 BOOLEAN NOT NULL DEFAULT TRUE,
    fee_ticket_id           BYTEA,
    wrapped_root_amount     NUMERIC(78,0),
    classification_kind     TEXT,
    classification_status   TEXT,
    claim_source            TEXT,
    refreshed_at_ms         BIGINT NOT NULL,
    source_blue_score       BIGINT
);

CREATE INDEX kcc20_wrapper_summaries_canonical_idx
    ON kcc20_wrapper_summaries (canonical_token_id, active_utxos DESC, wrapper_id);

CREATE TABLE kcc20_token_summaries (
    token_id                BYTEA PRIMARY KEY,
    holder_count            BIGINT NOT NULL DEFAULT 0,
    holder_supply           NUMERIC(78,0) NOT NULL DEFAULT 0,
    minter_supply           NUMERIC(78,0) NOT NULL DEFAULT 0,
    wrapper_reserve_supply  NUMERIC(78,0) NOT NULL DEFAULT 0,
    v3_tradeable_supply     NUMERIC(78,0) NOT NULL DEFAULT 0,
    top_holders             JSONB NOT NULL DEFAULT '[]'::jsonb,
    wrapper_id              BYTEA,
    refreshed_at_ms         BIGINT NOT NULL,
    source_blue_score       BIGINT
);

CREATE INDEX kcc20_token_summaries_wrapper_idx
    ON kcc20_token_summaries (wrapper_id)
    WHERE wrapper_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS kcc20_holders_owner_idx
    ON kcc20_holders (owner_identifier, amount_total DESC, covenant_id);

CREATE INDEX IF NOT EXISTS blocks_chain_blue_desc_idx
    ON blocks (blue_score DESC)
    WHERE is_chain_block;

CREATE INDEX IF NOT EXISTS covenant_actions_block_time_desc_idx
    ON covenant_actions (block_time_ms DESC, txid DESC);
