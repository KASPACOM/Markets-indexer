-- Durable receipt lookup for paid API usage.
--
-- Receipts are emitted only after voucher acceptance. This index makes
-- support/debug lookup deterministic without scanning usage history.

CREATE UNIQUE INDEX IF NOT EXISTS api_payment_usage_events_receipt_id_idx
    ON api_payment_usage_events (receipt_id)
    WHERE receipt_id IS NOT NULL;
