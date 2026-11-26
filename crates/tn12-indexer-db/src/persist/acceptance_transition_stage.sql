SET LOCAL search_path = pg_catalog, public;
CREATE TEMP TABLE historical_transition_input (
    singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    mapping jsonb NOT NULL, block_evidence jsonb NOT NULL, inputs jsonb NOT NULL,
    comparison jsonb NOT NULL, old_hashes bytea[] NOT NULL,
    target_hashes bytea[] NOT NULL, ids bytea[] NOT NULL, acceptance_blocks bytea[] NOT NULL,
    proof bytea NOT NULL CHECK (octet_length(proof)=32),
    source_tip bigint NOT NULL, window_start bigint NOT NULL, window_end bigint NOT NULL,
    cohort_digest bytea NOT NULL CHECK (octet_length(cohort_digest)=32),
    window_digest bytea NOT NULL CHECK (octet_length(window_digest)=32),
    audit jsonb NOT NULL,
    window_evidence bytea COMPRESSION lz4 NOT NULL CHECK (octet_length(window_evidence) BETWEEN 1 AND 67108864),
    cohort_evidence bytea COMPRESSION lz4 NOT NULL CHECK (octet_length(cohort_evidence) BETWEEN 1 AND 16777216),
    expected_created bigint NOT NULL CHECK (expected_created>=0),
    expected_spent bigint NOT NULL CHECK (expected_spent>=0),
    expected_actions bigint NOT NULL CHECK (expected_actions>=0),
    expected_genesis bigint NOT NULL CHECK (expected_genesis>=0),
    CHECK (expected_created+expected_spent+expected_actions+expected_genesis BETWEEN 1 AND 8192)
) ON COMMIT DROP;
CREATE TEMP TABLE historical_transition_mapping (
    old bytea NOT NULL CHECK (octet_length(old)=32),
    txid bytea PRIMARY KEY CHECK (octet_length(txid)=32),
    target bytea NOT NULL CHECK (octet_length(target)=32 AND target<>old),
    score bigint NOT NULL CHECK (score>=0), time bigint NOT NULL CHECK (time>=0)
) ON COMMIT DROP;
CREATE TEMP TABLE historical_transition_result (
    proof bytea PRIMARY KEY, created bigint NOT NULL, spent bigint NOT NULL,
    actions bigint NOT NULL, genesis bigint NOT NULL
) ON COMMIT DROP;
