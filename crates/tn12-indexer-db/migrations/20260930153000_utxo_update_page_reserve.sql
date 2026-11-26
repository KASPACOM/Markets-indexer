-- Reserve space for future UTXO row versions and avoid scattering small updates
-- across mostly full heap pages. This changes allocation policy without a rewrite.
-- Keep every existing autovacuum option. Reverting the option is metadata-only;
-- it does not compact pages already allocated with the reserve.
-- A busy vacuum or DDL operation must fail this migration for a later retry.
SET LOCAL lock_timeout = '2s';
ALTER TABLE covenant_utxos SET (fillfactor = 80);
