-- no-transaction

-- Token summary refreshes only need active KCC20 mint authorities with a
-- supported policy. Keep this lookup independent of the full UTXO table.
CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_kcc20_active_mint_policy_idx
    ON covenant_utxos (covenant_id)
    WHERE status = 'active'
      AND state->>'isMintAuthority' = 'true'
      AND state->>'mintPolicy' ~ '^[12]$';
