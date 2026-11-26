-- Owner-scoped KCC20 portfolio read model.
--
-- The projector performs the expensive balance/order/market normalization once.
-- API reads then filter, sort, count, and paginate directly in Postgres.

CREATE TABLE kcc20_owner_portfolio_assets (
    owner_identifier            BYTEA NOT NULL CHECK (octet_length(owner_identifier) = 32),
    canonical_token_id          BYTEA NOT NULL CHECK (octet_length(canonical_token_id) = 32),
    wrapper_id                  BYTEA CHECK (wrapper_id IS NULL OR octet_length(wrapper_id) = 32),
    wrapped_market_id           BYTEA CHECK (wrapped_market_id IS NULL OR octet_length(wrapped_market_id) = 32),
    v2_balance                  NUMERIC NOT NULL DEFAULT 0 CHECK (v2_balance >= 0),
    v3_balance                  NUMERIC NOT NULL DEFAULT 0 CHECK (v3_balance >= 0),
    total_balance               NUMERIC NOT NULL DEFAULT 0 CHECK (total_balance >= 0),
    asset_utxo_count            BIGINT NOT NULL DEFAULT 0 CHECK (asset_utxo_count >= 0),
    open_ask_amount             NUMERIC NOT NULL DEFAULT 0 CHECK (open_ask_amount >= 0),
    open_bid_amount             NUMERIC NOT NULL DEFAULT 0 CHECK (open_bid_amount >= 0),
    open_order_count            BIGINT NOT NULL DEFAULT 0 CHECK (open_order_count >= 0),
    best_ask_unit_price_sompi   NUMERIC CHECK (best_ask_unit_price_sompi IS NULL OR best_ask_unit_price_sompi >= 0),
    best_bid_unit_price_sompi   NUMERIC CHECK (best_bid_unit_price_sompi IS NULL OR best_bid_unit_price_sompi >= 0),
    value_sompi                 NUMERIC CHECK (value_sompi IS NULL OR value_sompi >= 0),
    fee_ticket_supported        BOOLEAN NOT NULL DEFAULT FALSE,
    last_change_ms              BIGINT NOT NULL DEFAULT 0 CHECK (last_change_ms >= 0),
    ticker                      TEXT,
    token_name                  TEXT,
    decimals                    SMALLINT NOT NULL DEFAULT 0 CHECK (decimals BETWEEN 0 AND 18),
    refreshed_at_ms             BIGINT NOT NULL CHECK (refreshed_at_ms > 0),
    source_blue_score           BIGINT CHECK (source_blue_score IS NULL OR source_blue_score >= 0),
    PRIMARY KEY (owner_identifier, canonical_token_id)
);

ALTER TABLE kcc20_owner_portfolio_assets SET (
    autovacuum_vacuum_scale_factor = 0.02,
    autovacuum_analyze_scale_factor = 0.01,
    autovacuum_vacuum_threshold = 1000,
    autovacuum_analyze_threshold = 1000
);

-- Force the projector to populate the new table even when the previous
-- token-page watermark was already clean before this migration ran.
INSERT INTO kcc20_projection_dirty (reason, created_at_ms)
VALUES ('owner_portfolio_assets_projection_added', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000);

CREATE INDEX kcc20_projection_dirty_owner_portfolio_init_idx
    ON kcc20_projection_dirty (id DESC)
    WHERE reason = 'owner_portfolio_assets_projection_added';
