-- no-transaction

CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_active_script_pubkey_idx
ON covenant_utxos (script_pubkey)
WHERE status = 'active';
