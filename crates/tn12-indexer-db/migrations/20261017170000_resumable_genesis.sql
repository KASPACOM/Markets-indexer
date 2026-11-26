-- Empty until a repair requests a family. No historical backfill in migration.
CREATE TABLE covenant_genesis_progress (
  covenant_id BYTEA PRIMARY KEY,
  scan_txid BYTEA,
  scan_vout INTEGER,
  scanned_outputs BIGINT NOT NULL DEFAULT 0,
  baseline_complete BOOLEAN NOT NULL DEFAULT FALSE,
  best_txid BYTEA,
  best_vout INTEGER,
  best_block BYTEA,
  best_score BIGINT,
  best_time BIGINT,
  version BIGINT NOT NULL DEFAULT 0,
  applied_version BIGINT NOT NULL DEFAULT -1,
  CHECK ((scan_txid IS NULL) = (scan_vout IS NULL)),
  CHECK ((best_txid IS NULL) = (best_score IS NULL))
);
CREATE INDEX covenant_genesis_progress_pending_idx ON covenant_genesis_progress(covenant_id) WHERE NOT baseline_complete OR applied_version<>version;
CREATE INDEX covenant_genesis_progress_block_idx ON covenant_genesis_progress(best_block);

CREATE TABLE settled_repair_jobs (
  cursor_key TEXT PRIMARY KEY,
  window_start BIGINT NOT NULL,
  width INTEGER NOT NULL CHECK (width BETWEEN 1 AND 100),
  epoch BIGINT NOT NULL DEFAULT 0,
  phase TEXT NOT NULL DEFAULT 'replay' CHECK (phase IN ('replay','discover','reconcile','complete')),
  discovery_after BYTEA,
  discovery_action_id BIGINT NOT NULL DEFAULT 0,
  batch_size INTEGER NOT NULL DEFAULT 512 CHECK (batch_size BETWEEN 1 AND 512),
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  attempts BIGINT NOT NULL DEFAULT 0,
  last_error TEXT,
  next_retry_at_ms BIGINT NOT NULL DEFAULT 0,
  updated_at_ms BIGINT NOT NULL,
  scanned_outputs BIGINT NOT NULL DEFAULT 0,
  normalized_covenants BIGINT NOT NULL DEFAULT 0,
  normalized_actions BIGINT NOT NULL DEFAULT 0,
  last_step_ms BIGINT NOT NULL DEFAULT 0,
  last_lock_held_ms BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE settled_repair_members (
  cursor_key TEXT NOT NULL REFERENCES settled_repair_jobs(cursor_key) ON DELETE CASCADE,
  covenant_id BYTEA NOT NULL REFERENCES covenant_genesis_progress(covenant_id),
  normalized_version BIGINT,
  PRIMARY KEY (cursor_key,covenant_id)
);

-- A candidate offer is cheap for untracked families and unchanged later outputs.
-- All canonical writers already serialize on the persister advisory lock.
CREATE FUNCTION tn10_genesis_offer(cid BYTEA, tid BYTEA, output_index INTEGER, block BYTEA)
RETURNS VOID LANGUAGE SQL AS $$
  UPDATE covenant_genesis_progress p SET
    best_txid=tid,best_vout=output_index,best_block=block,
    best_score=b.blue_score,best_time=b.timestamp_ms,version=p.version+1
  FROM blocks b WHERE p.covenant_id=cid AND b.hash=block AND b.is_chain_block
    AND (p.best_txid IS NULL OR ROW(b.blue_score,output_index,tid)<ROW(p.best_score,p.best_vout,p.best_txid));
$$;

CREATE FUNCTION tn10_genesis_forget(cid BYTEA, tid BYTEA, output_index INTEGER)
RETURNS VOID LANGUAGE SQL AS $$
  UPDATE covenant_genesis_progress SET
    best_txid=NULL,best_vout=NULL,best_block=NULL,best_score=NULL,best_time=NULL,
    scan_txid=NULL,scan_vout=NULL,scanned_outputs=0,baseline_complete=FALSE,version=version+1
  WHERE covenant_id=cid AND best_txid=tid AND best_vout=output_index;
$$;

-- Statement transition tables avoid a nested SQL call for every live output.
CREATE FUNCTION tn10_genesis_outputs_inserted() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM new_outputs) THEN RETURN NULL; END IF;
  WITH candidates AS MATERIALIZED (
    SELECT DISTINCT ON(u.covenant_id) u.covenant_id,u.txid,u.vout,u.created_block,b.blue_score,b.timestamp_ms
    FROM new_outputs u JOIN covenant_genesis_progress p USING(covenant_id)
    JOIN blocks b ON b.hash=u.created_block AND b.is_chain_block
    ORDER BY u.covenant_id,b.blue_score,u.vout,u.txid
  )
  UPDATE covenant_genesis_progress p SET best_txid=c.txid,best_vout=c.vout,
    best_block=c.created_block,best_score=c.blue_score,best_time=c.timestamp_ms,version=p.version+1
  FROM candidates c WHERE p.covenant_id=c.covenant_id
    AND (p.best_txid IS NULL OR ROW(c.blue_score,c.vout,c.txid)<ROW(p.best_score,p.best_vout,p.best_txid));
  UPDATE settled_repair_jobs j SET phase='replay',epoch=epoch+1,next_retry_at_ms=0,discovery_after=NULL,discovery_action_id=0
  WHERE EXISTS(SELECT 1 FROM new_outputs u JOIN blocks b ON b.hash=u.created_block
    WHERE b.blue_score>=j.window_start AND b.blue_score<j.window_start+j.width);
  RETURN NULL;
END $$;
CREATE FUNCTION tn10_genesis_outputs_deleted() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM old_outputs) THEN RETURN NULL; END IF;
  UPDATE covenant_genesis_progress p SET best_txid=NULL,best_vout=NULL,best_block=NULL,
    best_score=NULL,best_time=NULL,scan_txid=NULL,scan_vout=NULL,scanned_outputs=0,baseline_complete=FALSE,version=p.version+1
  WHERE EXISTS(SELECT 1 FROM old_outputs u WHERE u.covenant_id=p.covenant_id AND u.txid=p.best_txid AND u.vout=p.best_vout);
  UPDATE settled_repair_jobs j SET phase='replay',epoch=epoch+1,next_retry_at_ms=0,discovery_after=NULL,discovery_action_id=0
  WHERE EXISTS(SELECT 1 FROM old_outputs u JOIN blocks b ON b.hash=u.created_block
    WHERE b.blue_score>=j.window_start AND b.blue_score<j.window_start+j.width);
  RETURN NULL;
END $$;
CREATE FUNCTION tn10_genesis_outputs_updated() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM old_outputs o FULL JOIN new_outputs n USING(txid,vout)
    WHERE ROW(o.covenant_id,o.created_block) IS DISTINCT FROM ROW(n.covenant_id,n.created_block)) THEN RETURN NULL; END IF;
  UPDATE covenant_genesis_progress p SET best_txid=NULL,best_vout=NULL,best_block=NULL,
    best_score=NULL,best_time=NULL,scan_txid=NULL,scan_vout=NULL,scanned_outputs=0,baseline_complete=FALSE,version=p.version+1
  WHERE EXISTS(SELECT 1 FROM old_outputs o LEFT JOIN new_outputs n USING(txid,vout)
    WHERE ROW(o.covenant_id,o.created_block) IS DISTINCT FROM ROW(n.covenant_id,n.created_block)
    AND o.covenant_id=p.covenant_id AND o.txid=p.best_txid AND o.vout=p.best_vout);
  WITH candidates AS MATERIALIZED (
    SELECT DISTINCT ON(u.covenant_id) u.covenant_id,u.txid,u.vout,u.created_block,b.blue_score,b.timestamp_ms
    FROM new_outputs u JOIN covenant_genesis_progress p USING(covenant_id)
    JOIN blocks b ON b.hash=u.created_block AND b.is_chain_block
    ORDER BY u.covenant_id,b.blue_score,u.vout,u.txid
  )
  UPDATE covenant_genesis_progress p SET best_txid=c.txid,best_vout=c.vout,
    best_block=c.created_block,best_score=c.blue_score,best_time=c.timestamp_ms,version=p.version+1
  FROM candidates c WHERE p.covenant_id=c.covenant_id
    AND (p.best_txid IS NULL OR ROW(c.blue_score,c.vout,c.txid)<ROW(p.best_score,p.best_vout,p.best_txid));
  UPDATE settled_repair_jobs j SET phase='replay',epoch=epoch+1,next_retry_at_ms=0,discovery_after=NULL,discovery_action_id=0
  WHERE EXISTS(SELECT 1 FROM (SELECT created_block FROM old_outputs UNION SELECT created_block FROM new_outputs) u
    JOIN blocks b ON b.hash=u.created_block WHERE b.blue_score>=j.window_start AND b.blue_score<j.window_start+j.width);
  RETURN NULL;
END $$;
CREATE TRIGGER tn10_genesis_insert AFTER INSERT ON covenant_utxos REFERENCING NEW TABLE AS new_outputs
FOR EACH STATEMENT EXECUTE FUNCTION tn10_genesis_outputs_inserted();
CREATE TRIGGER tn10_genesis_delete AFTER DELETE ON covenant_utxos REFERENCING OLD TABLE AS old_outputs
FOR EACH STATEMENT EXECUTE FUNCTION tn10_genesis_outputs_deleted();
CREATE TRIGGER tn10_genesis_update AFTER UPDATE ON covenant_utxos REFERENCING OLD TABLE AS old_outputs NEW TABLE AS new_outputs
FOR EACH STATEMENT EXECUTE FUNCTION tn10_genesis_outputs_updated();

CREATE FUNCTION tn10_genesis_block_changed() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE item RECORD;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    UPDATE covenant_genesis_progress SET
      best_txid=NULL,best_vout=NULL,best_block=NULL,best_score=NULL,best_time=NULL,
      scan_txid=NULL,scan_vout=NULL,scanned_outputs=0,baseline_complete=FALSE,version=version+1
    WHERE best_block=OLD.hash;
    UPDATE settled_repair_jobs SET phase='replay',epoch=epoch+1,next_retry_at_ms=0,discovery_after=NULL,discovery_action_id=0
    WHERE OLD.blue_score>=window_start AND OLD.blue_score<window_start+width;
  END IF;
  IF TG_OP <> 'DELETE' THEN
    UPDATE settled_repair_jobs SET phase='replay',epoch=epoch+1,next_retry_at_ms=0,discovery_after=NULL,discovery_action_id=0
    WHERE NEW.blue_score>=window_start AND NEW.blue_score<window_start+width;
    IF NEW.is_chain_block AND EXISTS(SELECT 1 FROM covenant_genesis_progress) THEN
      FOR item IN SELECT DISTINCT ON (u.covenant_id) u.covenant_id,u.txid,u.vout
        FROM covenant_utxos u JOIN covenant_genesis_progress p USING(covenant_id)
        WHERE u.created_block=NEW.hash ORDER BY u.covenant_id,u.vout,u.txid
      LOOP
        PERFORM tn10_genesis_offer(item.covenant_id,item.txid,item.vout,NEW.hash);
      END LOOP;
    END IF;
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER tn10_genesis_block_insert AFTER INSERT ON blocks
FOR EACH ROW EXECUTE FUNCTION tn10_genesis_block_changed();
CREATE TRIGGER tn10_genesis_block_delete AFTER DELETE ON blocks
FOR EACH ROW EXECUTE FUNCTION tn10_genesis_block_changed();
CREATE TRIGGER tn10_genesis_block_update AFTER UPDATE ON blocks
FOR EACH ROW WHEN (ROW(OLD.hash,OLD.blue_score,OLD.timestamp_ms,OLD.is_chain_block)
 IS DISTINCT FROM ROW(NEW.hash,NEW.blue_score,NEW.timestamp_ms,NEW.is_chain_block))
EXECUTE FUNCTION tn10_genesis_block_changed();
