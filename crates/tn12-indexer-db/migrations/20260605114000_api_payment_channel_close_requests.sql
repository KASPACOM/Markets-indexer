-- Payer-signed channel close/finalize requests.
--
-- A close request is not a refund. It is the payer asking the provider to stop
-- serving the channel and settle the latest payer-signed authorization so the
-- remaining balance returns in the settlement transaction.

ALTER TABLE api_payment_channels
    DROP CONSTRAINT IF EXISTS api_payment_channels_status_check;

ALTER TABLE api_payment_channels
    ADD CONSTRAINT api_payment_channels_status_check CHECK (status IN (
        'opening',
        'usable',
        'close_requested',
        'settlement_pending',
        'settled',
        'refund_pending',
        'refunded',
        'failed',
        'disabled'
    ));

CREATE TABLE IF NOT EXISTS api_payment_channel_close_requests (
    id                 BIGSERIAL PRIMARY KEY,
    channel_id         TEXT NOT NULL REFERENCES api_payment_channels(channel_id) ON DELETE CASCADE,
    credential_hash    BYTEA NOT NULL UNIQUE,
    payer_pubkey       TEXT NOT NULL,
    provider_pubkey    TEXT NOT NULL,
    requested_at_ms    BIGINT NOT NULL,
    expires_at_ms      BIGINT NOT NULL,
    nonce              TEXT NOT NULL,
    reason             TEXT,
    signature          TEXT NOT NULL,
    status             TEXT NOT NULL CHECK (status IN (
        'requested',
        'claimed',
        'rejected'
    )),
    created_at_ms      BIGINT NOT NULL,
    updated_at_ms      BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS api_payment_channel_close_requests_channel_idx
    ON api_payment_channel_close_requests (channel_id, requested_at_ms DESC);

CREATE INDEX IF NOT EXISTS api_payment_channels_close_requested_idx
    ON api_payment_channels (status, updated_at_ms ASC)
    WHERE status = 'close_requested';
