-- Add indexed windowed discovery sorts for the already-materialized 24h/7d
-- summary columns.

CREATE INDEX IF NOT EXISTS kcc20_market_summaries_volume_24h_idx
    ON kcc20_market_summaries (volume_24h_sompi DESC NULLS LAST, token_id ASC);
CREATE INDEX IF NOT EXISTS kcc20_market_summaries_volume_7d_idx
    ON kcc20_market_summaries (volume_7d_sompi DESC NULLS LAST, token_id ASC);
CREATE INDEX IF NOT EXISTS kcc20_market_summaries_trades_24h_idx
    ON kcc20_market_summaries (trade_count_24h DESC NULLS LAST, token_id ASC);
CREATE INDEX IF NOT EXISTS kcc20_market_summaries_trades_7d_idx
    ON kcc20_market_summaries (trade_count_7d DESC NULLS LAST, token_id ASC);
