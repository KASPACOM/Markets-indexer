-- On-chain ApiPaymentChannel projection metadata.
--
-- The original api_payment_channels table was created for backend-local
-- voucher state. These nullable columns let the indexer project decoded
-- covenant opens/spends into the same lifecycle row without breaking existing
-- backend tests or rows.

ALTER TABLE api_payment_channels
    ADD COLUMN IF NOT EXISTS provider_payout_pubkey TEXT,
    ADD COLUMN IF NOT EXISTS voucher_domain_hash BYTEA,
    ADD COLUMN IF NOT EXISTS refund_after_ms BIGINT,
    ADD COLUMN IF NOT EXISTS max_spend_sompi BIGINT CHECK (
        max_spend_sompi IS NULL OR max_spend_sompi >= 0
    );

UPDATE api_payment_channels
SET refund_after_ms = refund_after_daa
WHERE refund_after_ms IS NULL
  AND refund_after_daa IS NOT NULL;

CREATE INDEX IF NOT EXISTS api_payment_channels_open_txid_idx
    ON api_payment_channels (open_txid)
    WHERE open_txid IS NOT NULL;

CREATE INDEX IF NOT EXISTS api_payment_channels_settlement_txid_idx
    ON api_payment_channels (settlement_txid)
    WHERE settlement_txid IS NOT NULL;

CREATE INDEX IF NOT EXISTS api_payment_channels_refund_txid_idx
    ON api_payment_channels (refund_txid)
    WHERE refund_txid IS NOT NULL;
