-- Migration 20261109120000 already replaced the transaction-scoped deploy key
-- with an output-scoped key on databases that applied it. Preserve that index
-- while giving it the name expected by current schema checks.
--
-- Keep the rename transactional with the migration record. A busy database
-- can retry after a short lock timeout without losing its uniqueness rule.
SET LOCAL lock_timeout = '250ms';
ALTER INDEX covenant_actions_deploy_uniq
    RENAME TO covenant_actions_deploy_vout_uniq;
