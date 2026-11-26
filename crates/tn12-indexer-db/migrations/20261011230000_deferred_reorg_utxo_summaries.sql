-- Only the ordered reorg persister enables this transaction-local setting.
-- It captures all affected covenant IDs before mutating UTXOs and recounts
-- their summaries before commit. Other writers retain incremental triggers.
DROP TRIGGER covenant_utxos_refresh_summary ON covenant_utxos;
CREATE TRIGGER covenant_utxos_refresh_summary
AFTER INSERT OR UPDATE OR DELETE ON covenant_utxos
FOR EACH ROW
WHEN (COALESCE(current_setting('tn12.defer_reorg_utxo_summaries', TRUE), 'off') <> 'on')
EXECUTE FUNCTION refresh_covenant_summary_from_utxo_trigger();
