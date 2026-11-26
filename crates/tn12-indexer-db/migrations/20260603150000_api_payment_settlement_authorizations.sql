-- Provider-held settlement authorizations for covenant-backed API channels.
--
-- Request vouchers are backend-local usage credentials. These rows track the
-- latest payer-signed close-on-settle transaction/PSKT metadata that the
-- provider can actually use to enforce accumulated spend.

CREATE TABLE api_payment_settlement_authorizations (
    id                              BIGSERIAL PRIMARY KEY,
    channel_id                      TEXT NOT NULL REFERENCES api_payment_channels(channel_id) ON DELETE CASCADE,
    sequence                        BIGINT NOT NULL CHECK (sequence > 0),
    total_spent_sompi               BIGINT NOT NULL CHECK (total_spent_sompi >= 0),
    provider_amount_sompi           BIGINT NOT NULL CHECK (provider_amount_sompi >= 0),
    payer_refund_sompi              BIGINT NOT NULL CHECK (payer_refund_sompi >= 0),
    settlement_fee_sompi            BIGINT NOT NULL CHECK (settlement_fee_sompi >= 0),
    settlement_txid                 BYTEA NOT NULL,
    settlement_template_hash        BYTEA NOT NULL,
    metadata_hash                   BYTEA NOT NULL,
    payer_settlement_signature      TEXT NOT NULL,
    refund_after_ms                 BIGINT NOT NULL,
    expires_at_ms                   BIGINT NOT NULL,
    status                          TEXT NOT NULL CHECK (status IN (
        'available',
        'submitted',
        'spent',
        'expired',
        'rejected'
    )),
    created_at_ms                   BIGINT NOT NULL,
    updated_at_ms                   BIGINT NOT NULL,
    UNIQUE (channel_id, sequence),
    UNIQUE (settlement_txid),
    UNIQUE (metadata_hash)
);

CREATE INDEX api_payment_settlement_auth_channel_idx
    ON api_payment_settlement_authorizations (channel_id, sequence DESC);
CREATE INDEX api_payment_settlement_auth_status_idx
    ON api_payment_settlement_authorizations (status, updated_at_ms DESC);
