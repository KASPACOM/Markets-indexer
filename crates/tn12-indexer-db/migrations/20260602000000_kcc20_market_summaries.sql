-- Materialized KCC20 market discovery rows.
--
-- Discovery endpoints must read this table directly so limit/sort/filter are
-- applied by Postgres before API response shaping. Raw covenant activity is
-- used only by the refresh path during indexing/startup.

CREATE TABLE kcc20_market_summaries (
    token_id                  BYTEA PRIMARY KEY,
    best_ask_unit_price_sompi NUMERIC(78,0),
    best_bid_unit_price_sompi NUMERIC(78,0),
    spread_sompi              NUMERIC(78,0),
    open_ask_count            BIGINT NOT NULL DEFAULT 0,
    open_bid_count            BIGINT NOT NULL DEFAULT 0,
    total_volume_sompi        NUMERIC(78,0) NOT NULL DEFAULT 0,
    total_trades              BIGINT NOT NULL DEFAULT 0,
    last_trade_txid           BYTEA,
    last_trade_time_ms        BIGINT,
    refreshed_at_ms           BIGINT NOT NULL,
    source_blue_score         BIGINT,
    volume_24h_sompi          NUMERIC(78,0),
    volume_7d_sompi           NUMERIC(78,0),
    trade_count_24h           BIGINT,
    trade_count_7d            BIGINT
);

CREATE INDEX kcc20_market_summaries_last_trade_idx
    ON kcc20_market_summaries (last_trade_time_ms DESC NULLS LAST);
CREATE INDEX kcc20_market_summaries_volume_idx
    ON kcc20_market_summaries (total_volume_sompi DESC, token_id ASC);
CREATE INDEX kcc20_market_summaries_trades_idx
    ON kcc20_market_summaries (total_trades DESC, token_id ASC);
CREATE INDEX kcc20_market_summaries_best_ask_idx
    ON kcc20_market_summaries (best_ask_unit_price_sompi ASC NULLS LAST);
CREATE INDEX kcc20_market_summaries_best_bid_idx
    ON kcc20_market_summaries (best_bid_unit_price_sompi DESC NULLS LAST);
CREATE INDEX kcc20_market_summaries_spread_idx
    ON kcc20_market_summaries (spread_sompi ASC NULLS LAST);

-- Keep summary refresh bounded to indexed raw tables. The discovery endpoint
-- never reads these raw tables, but the indexer refresh path does.
CREATE INDEX kcc20_market_refresh_covenants_template_idx
    ON covenants (COALESCE(template_name, claimed_template));
CREATE INDEX kcc20_market_refresh_utxos_covenant_status_idx
    ON covenant_utxos (covenant_id, status);
CREATE INDEX kcc20_market_refresh_actions_market_idx
    ON covenant_actions (action, entrypoint, block_time_ms DESC, txid);
