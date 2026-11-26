-- KaspaCom API payment state.
--
-- These tables support the first backend-local payment-channel path. The
-- indexer still classifies on-chain opens/settles/refunds separately; these
-- rows track HTTP request payment credentials and provider settlement state.

CREATE TABLE api_payment_pricing (
    pricing_id       TEXT PRIMARY KEY,
    method           TEXT NOT NULL,
    path_pattern     TEXT NOT NULL,
    base_sompi       BIGINT NOT NULL CHECK (base_sompi >= 0),
    per_row_sompi    BIGINT NOT NULL DEFAULT 0 CHECK (per_row_sompi >= 0),
    max_limit        BIGINT CHECK (max_limit IS NULL OR max_limit >= 0),
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    effective_from_ms BIGINT NOT NULL,
    effective_to_ms   BIGINT
);
CREATE INDEX api_payment_pricing_route_idx
    ON api_payment_pricing (method, path_pattern, enabled);

CREATE TABLE api_payment_channels (
    channel_id         TEXT PRIMARY KEY,
    network_id         TEXT NOT NULL,
    payer_identifier   TEXT NOT NULL,
    payer_pubkey       TEXT NOT NULL,
    provider_pubkey    TEXT NOT NULL,
    provider_identifier TEXT,
    scope              TEXT,
    deposit_sompi      BIGINT NOT NULL CHECK (deposit_sompi >= 0),
    reserve_sompi      BIGINT NOT NULL DEFAULT 0 CHECK (reserve_sompi >= 0),
    spent_sompi        BIGINT NOT NULL DEFAULT 0 CHECK (spent_sompi >= 0),
    latest_sequence    BIGINT NOT NULL DEFAULT 0 CHECK (latest_sequence >= 0),
    status             TEXT NOT NULL CHECK (status IN (
        'opening',
        'usable',
        'settlement_pending',
        'settled',
        'refund_pending',
        'refunded',
        'failed',
        'disabled'
    )),
    open_txid          BYTEA,
    settlement_txid    BYTEA,
    refund_txid        BYTEA,
    refund_after_daa   BIGINT,
    pricing_policy_id  TEXT,
    indexed_at_ms      BIGINT,
    created_at_ms      BIGINT NOT NULL,
    updated_at_ms      BIGINT NOT NULL,
    CHECK (spent_sompi <= deposit_sompi),
    CHECK (reserve_sompi <= deposit_sompi)
);
CREATE INDEX api_payment_channels_payer_idx
    ON api_payment_channels (payer_identifier, status);
CREATE INDEX api_payment_channels_status_idx
    ON api_payment_channels (status, updated_at_ms DESC);

CREATE TABLE api_payment_vouchers (
    id                         BIGSERIAL PRIMARY KEY,
    channel_id                 TEXT NOT NULL REFERENCES api_payment_channels(channel_id) ON DELETE CASCADE,
    sequence                   BIGINT NOT NULL CHECK (sequence > 0),
    total_spent_sompi          BIGINT NOT NULL CHECK (total_spent_sompi >= 0),
    incremental_amount_sompi   BIGINT NOT NULL CHECK (incremental_amount_sompi >= 0),
    pricing_id                 TEXT NOT NULL,
    request_hash               BYTEA NOT NULL,
    route                      TEXT NOT NULL,
    credential_hash            BYTEA NOT NULL,
    signature                  TEXT NOT NULL,
    accepted_at_ms             BIGINT NOT NULL,
    served_status              INT,
    settlement_txid            BYTEA,
    UNIQUE (channel_id, sequence),
    UNIQUE (credential_hash)
);
CREATE INDEX api_payment_vouchers_channel_idx
    ON api_payment_vouchers (channel_id, sequence DESC);
CREATE INDEX api_payment_vouchers_pricing_idx
    ON api_payment_vouchers (pricing_id, accepted_at_ms DESC);

CREATE TABLE api_payment_usage_events (
    id                 BIGSERIAL PRIMARY KEY,
    request_id         TEXT NOT NULL UNIQUE,
    channel_id         TEXT REFERENCES api_payment_channels(channel_id) ON DELETE SET NULL,
    wallet_or_api_key_hash BYTEA,
    route              TEXT NOT NULL,
    pricing_id         TEXT NOT NULL,
    amount_sompi       BIGINT NOT NULL CHECK (amount_sompi >= 0),
    voucher_sequence   BIGINT,
    receipt_id         TEXT,
    response_status    INT,
    duration_ms        BIGINT CHECK (duration_ms IS NULL OR duration_ms >= 0),
    created_at_ms      BIGINT NOT NULL
);
CREATE INDEX api_payment_usage_events_channel_idx
    ON api_payment_usage_events (channel_id, created_at_ms DESC);
CREATE INDEX api_payment_usage_events_pricing_idx
    ON api_payment_usage_events (pricing_id, created_at_ms DESC);

CREATE TABLE api_payment_settlements (
    txid                    BYTEA PRIMARY KEY,
    channel_id              TEXT NOT NULL REFERENCES api_payment_channels(channel_id) ON DELETE CASCADE,
    settled_sequence        BIGINT NOT NULL CHECK (settled_sequence >= 0),
    settled_total_sompi     BIGINT NOT NULL CHECK (settled_total_sompi >= 0),
    provider_amount_sompi   BIGINT NOT NULL CHECK (provider_amount_sompi >= 0),
    payer_refund_sompi      BIGINT NOT NULL DEFAULT 0 CHECK (payer_refund_sompi >= 0),
    indexer_status          TEXT NOT NULL,
    created_at_ms           BIGINT NOT NULL,
    indexed_at_ms           BIGINT
);
CREATE INDEX api_payment_settlements_channel_idx
    ON api_payment_settlements (channel_id, created_at_ms DESC);
