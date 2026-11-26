-- Owner-scoped KCC20 order detail read model.
--
-- `/addresses/{address}/kcc20/orders` was reconstructing order state from
-- covenants, actions, UTXOs, and JSONB arguments on every request. Keep that
-- work in the projector and make the hot API path a keyed read.

CREATE TABLE kcc20_owner_orders (
    order_id                 TEXT PRIMARY KEY,
    side                     TEXT NOT NULL CHECK (side IN ('ask', 'bid')),
    status                   TEXT NOT NULL CHECK (status IN ('open', 'waitingForLock', 'filled', 'cancelled', 'closed')),
    token_id                 BYTEA NOT NULL CHECK (octet_length(token_id) = 32),
    owner                    TEXT,
    token_amount             TEXT,
    remaining_token_amount   TEXT,
    price_sompi              TEXT,
    unit_price_sompi         TEXT,
    min_fill_amount          TEXT,
    template_name            TEXT,
    address                  TEXT NOT NULL,
    txid                     BYTEA CHECK (txid IS NULL OR octet_length(txid) = 32),
    vout                     INT,
    close_txid               BYTEA CHECK (close_txid IS NULL OR octet_length(close_txid) = 32),
    close_entrypoint         TEXT,
    created_at_ms            BIGINT NOT NULL,
    refreshed_at_ms          BIGINT NOT NULL CHECK (refreshed_at_ms > 0)
);

ALTER TABLE kcc20_owner_orders SET (
    autovacuum_vacuum_scale_factor = 0.02,
    autovacuum_analyze_scale_factor = 0.01,
    autovacuum_vacuum_threshold = 1000,
    autovacuum_analyze_threshold = 1000
);

CREATE INDEX kcc20_owner_orders_owner_time_idx
    ON kcc20_owner_orders (owner, created_at_ms DESC, order_id DESC);

CREATE INDEX kcc20_owner_orders_owner_status_time_idx
    ON kcc20_owner_orders (owner, status, created_at_ms DESC, order_id DESC);

CREATE INDEX kcc20_owner_orders_owner_token_status_time_idx
    ON kcc20_owner_orders (owner, token_id, status, created_at_ms DESC, order_id DESC);

CREATE INDEX kcc20_owner_orders_token_time_idx
    ON kcc20_owner_orders (token_id, created_at_ms DESC, order_id DESC);

-- Force a first projector pass even if all older KCC20 projections were clean.
INSERT INTO kcc20_projection_dirty (reason, created_at_ms)
VALUES ('owner_orders_projection_added', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000);

CREATE INDEX kcc20_projection_dirty_owner_orders_init_idx
    ON kcc20_projection_dirty (id DESC)
    WHERE reason = 'owner_orders_projection_added';
