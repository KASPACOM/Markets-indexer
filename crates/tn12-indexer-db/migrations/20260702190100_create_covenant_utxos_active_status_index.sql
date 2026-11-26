-- no-transaction

CREATE INDEX CONCURRENTLY covenant_utxos_status_active_idx
ON covenant_utxos(status)
WHERE status = 'active';
