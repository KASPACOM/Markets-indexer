-- Multi-leg KCC20V3 sweeps spend several UTXOs from the same wrapper covenant
-- in one transaction. The previous non-continuation key collapsed those spend
-- rows into one action and hid partial-fill activity. Keep deploy rows unique
-- by covenant+tx, but key spend rows by their previous outpoint.

DROP INDEX IF EXISTS covenant_actions_non_continuation_uniq;

CREATE UNIQUE INDEX IF NOT EXISTS covenant_actions_deploy_uniq
    ON covenant_actions (covenant_id, txid, action)
    WHERE action = 'deploy';

CREATE UNIQUE INDEX IF NOT EXISTS covenant_actions_spend_outpoint_uniq
    ON covenant_actions (
        covenant_id,
        txid,
        action,
        ((inputs #>> '{previousOutpoint,hash}')),
        ((inputs #>> '{previousOutpoint,index}'))
    )
    WHERE action = 'spend'
      AND inputs #>> '{previousOutpoint,hash}' IS NOT NULL
      AND inputs #>> '{previousOutpoint,index}' IS NOT NULL;
