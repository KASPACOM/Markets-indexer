-- Match the transport and decoder limit, including inserts from other clients.
-- Never discard an oversized receipt: an existing violation stops migration.
ALTER TABLE wrpc_inbox_entries ADD CONSTRAINT wrpc_inbox_payload_bound
    CHECK (octet_length(payload) BETWEEN 1 AND 8388608);
