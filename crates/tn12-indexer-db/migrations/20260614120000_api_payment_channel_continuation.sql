-- Track the live ApiPaymentChannel outpoint separately from the genesis/open
-- transaction so same-channel top-ups can renew the refund window without
-- losing the original channel identity.

ALTER TABLE api_payment_channels
    ADD COLUMN IF NOT EXISTS current_txid BYTEA,
    ADD COLUMN IF NOT EXISTS current_vout INT;

UPDATE api_payment_channels
SET current_txid = open_txid,
    current_vout = COALESCE(current_vout, 0)
WHERE current_txid IS NULL
  AND open_txid IS NOT NULL;

CREATE INDEX IF NOT EXISTS api_payment_channels_current_outpoint_idx
    ON api_payment_channels (current_txid, current_vout)
    WHERE current_txid IS NOT NULL;
