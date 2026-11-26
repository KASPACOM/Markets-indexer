-- Keep cold startup pricing loads bounded as the catalog grows.
-- The API loads active pricing rows by effective time before constructing
-- its in-memory route policy catalog.
CREATE INDEX IF NOT EXISTS api_payment_pricing_active_time_idx
    ON api_payment_pricing (
        effective_from_ms,
        effective_to_ms,
        method,
        path_pattern,
        pricing_id
    );
