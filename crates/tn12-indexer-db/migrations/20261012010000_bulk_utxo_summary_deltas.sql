-- Ordered bulk persistence derives deltas only from actual RETURNING rows and
-- updates each affected summary once before committing under the writer lock.
DROP TRIGGER covenant_utxos_refresh_summary ON covenant_utxos;
CREATE TRIGGER covenant_utxos_refresh_summary
AFTER INSERT OR UPDATE OR DELETE ON covenant_utxos
FOR EACH ROW
WHEN (COALESCE(current_setting('tn12.defer_reorg_utxo_summaries', TRUE), 'off') <> 'on'
  AND COALESCE(current_setting('tn12.defer_bulk_utxo_summaries', TRUE), 'off') <> 'on')
EXECUTE FUNCTION refresh_covenant_summary_from_utxo_trigger();

-- Pointer-only changes do not change template totals. Avoid rewriting the
-- shared template row when every aggregate delta is zero.
-- Keep the existing statement-level delete trigger unchanged.
DROP TRIGGER covenant_summaries_refresh_template_summary ON covenant_summaries;
CREATE TRIGGER covenant_summaries_refresh_template_summary
AFTER INSERT ON covenant_summaries
FOR EACH ROW EXECUTE FUNCTION refresh_covenant_template_summary_from_summary_trigger();
CREATE TRIGGER covenant_summaries_refresh_template_summary_update
AFTER UPDATE ON covenant_summaries
FOR EACH ROW
WHEN (ROW(OLD.covenant_id, OLD.active_utxos, OLD.total_amount_sompi)
  IS DISTINCT FROM ROW(NEW.covenant_id, NEW.active_utxos, NEW.total_amount_sompi))
EXECUTE FUNCTION refresh_covenant_template_summary_from_summary_trigger();
