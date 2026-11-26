ALTER TABLE covenant_utxos SET (
  autovacuum_vacuum_scale_factor = 0.02,
  autovacuum_analyze_scale_factor = 0.01,
  autovacuum_vacuum_threshold = 5000,
  autovacuum_analyze_threshold = 5000
);

ALTER TABLE covenant_actions SET (
  autovacuum_vacuum_scale_factor = 0.02,
  autovacuum_analyze_scale_factor = 0.01,
  autovacuum_vacuum_threshold = 5000,
  autovacuum_analyze_threshold = 5000
);
