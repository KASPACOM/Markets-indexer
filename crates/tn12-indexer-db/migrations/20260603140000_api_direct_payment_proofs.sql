-- Replay-safe direct Kaspa payment proof state.
--
-- Direct payments are intentionally not the hot path. A client broadcasts a
-- payment tx, submits the txid plus the challenge binding, and the backend
-- stores a pending proof until a verifier/indexer confirms the tx paid the
-- exact route/request/recipient.

CREATE TABLE api_payment_direct_proofs (
    id                  BIGSERIAL PRIMARY KEY,
    challenge_id        TEXT NOT NULL UNIQUE,
    network_id          TEXT NOT NULL,
    txid                BYTEA NOT NULL UNIQUE,
    payer_identifier    TEXT,
    recipient_address   TEXT NOT NULL,
    amount_sompi        BIGINT NOT NULL CHECK (amount_sompi >= 0),
    pricing_id          TEXT NOT NULL,
    route               TEXT NOT NULL,
    request_hash        BYTEA NOT NULL,
    status              TEXT NOT NULL CHECK (status IN (
        'submitted',
        'verified',
        'accepted',
        'rejected'
    )),
    failure_reason      TEXT,
    raw_status_snapshot JSONB,
    submitted_at_ms     BIGINT NOT NULL,
    verified_at_ms      BIGINT,
    indexed_at_ms       BIGINT
);

CREATE INDEX api_payment_direct_proofs_status_idx
    ON api_payment_direct_proofs (status, submitted_at_ms DESC);
CREATE INDEX api_payment_direct_proofs_pricing_idx
    ON api_payment_direct_proofs (pricing_id, submitted_at_ms DESC);
