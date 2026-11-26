CREATE INDEX IF NOT EXISTS api_payment_channels_settlement_candidates_idx
    ON api_payment_channels (
        status,
        refund_after_ms,
        spent_sompi DESC,
        latest_sequence DESC,
        updated_at_ms
    )
    WHERE spent_sompi > 0;

CREATE INDEX IF NOT EXISTS api_payment_settlement_auth_latest_idx
    ON api_payment_settlement_authorizations (channel_id, sequence DESC, id DESC);
