-- Applied explicitly only after provisioning a dedicated shadow database.
-- Deliberately outside the V1 SQLx migration directory.
CREATE SCHEMA shadow_v2;
CREATE TABLE shadow_v2.identity (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    network text NOT NULL CHECK (length(network) > 0),
    instance_id uuid NOT NULL,
    format_version integer NOT NULL DEFAULT 1 CHECK (format_version = 1)
);
CREATE TABLE shadow_v2.control (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    epoch bigint NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    owner_id text,
    heartbeat_at timestamptz,
    active_plan bigint,
    completed_plan bigint,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    retained_bytes bigint NOT NULL DEFAULT 0,
    max_retained_bytes bigint NOT NULL DEFAULT 21474836480 CHECK (max_retained_bytes > 0),
    CHECK (retained_bytes BETWEEN 0 AND max_retained_bytes),
    ready boolean NOT NULL DEFAULT false,
    generation bigint NOT NULL DEFAULT 0,
    checkpoint_hash bytea,
    checkpoint_score bigint,
    history_start_hash bytea,
    history_start_score bigint,
    history_start_ms bigint,
    seed_manifest jsonb,
    source_checked_at timestamptz,
    source_validated boolean NOT NULL DEFAULT false,
    CHECK ((owner_id IS NULL) = (heartbeat_at IS NULL)),
    CHECK (NOT ready OR (source_validated AND checkpoint_hash IS NOT NULL AND active_plan IS NULL))
);
INSERT INTO shadow_v2.control DEFAULT VALUES;
CREATE TABLE shadow_v2.plans (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    archive_digest bytea UNIQUE,
    base_hash bytea NOT NULL CHECK (octet_length(base_hash) = 32),
    target_hash bytea NOT NULL CHECK (octet_length(target_hash) = 32),
    target_score bigint NOT NULL CHECK (target_score >= 0),
    required_consumers text[] NOT NULL,
    cursor bigint NOT NULL DEFAULT 0,
    step_count bigint NOT NULL CHECK (step_count >= 0 AND step_count <= 65536),
    evidence_bytes bigint NOT NULL CHECK (evidence_bytes BETWEEN 0 AND 67108864),
    sealed_revision bigint,
    published_epoch bigint,
    status text NOT NULL DEFAULT 'applying' CHECK (status IN ('applying','sealed','completed')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (cursor BETWEEN 0 AND step_count),
    CHECK (cardinality(required_consumers) > 0),
    CHECK (array_position(required_consumers, NULL) IS NULL),
    CHECK (array_position(required_consumers, '') IS NULL)
);
ALTER TABLE shadow_v2.control ADD FOREIGN KEY (active_plan) REFERENCES shadow_v2.plans;
ALTER TABLE shadow_v2.control ADD FOREIGN KEY (completed_plan) REFERENCES shadow_v2.plans;
CREATE TABLE shadow_v2.steps (
    plan_id bigint NOT NULL REFERENCES shadow_v2.plans,
    ordinal bigint NOT NULL CHECK (ordinal >= 0),
    kind text NOT NULL CHECK (kind IN ('apply','remove','anchor')),
    evidence jsonb NOT NULL CHECK (octet_length(evidence::text) <= 8388608),
    PRIMARY KEY (plan_id, ordinal)
);
CREATE TABLE shadow_v2.consumers (
    plan_id bigint NOT NULL REFERENCES shadow_v2.plans,
    consumer text NOT NULL,
    cursor bigint NOT NULL,
    target_hash bytea NOT NULL,
    revision bigint NOT NULL,
    epoch bigint NOT NULL,
    PRIMARY KEY (plan_id, consumer)
);
CREATE TABLE shadow_v2.journal (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    plan_id bigint NOT NULL REFERENCES shadow_v2.plans,
    epoch bigint NOT NULL,
    revision bigint NOT NULL,
    cursor bigint NOT NULL,
    phase text NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
-- Full preimages, including scripts and payloads, not just evidence hashes.
CREATE TABLE shadow_v2.undo (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    plan_id bigint NOT NULL REFERENCES shadow_v2.plans,
    cursor bigint NOT NULL,
    table_name text NOT NULL,
    operation text NOT NULL,
    before_row jsonb,
    after_row jsonb
);
CREATE INDEX ON shadow_v2.undo (plan_id, cursor, id);
CREATE TABLE shadow_v2.acceptance_events (
    plan_id bigint NOT NULL REFERENCES shadow_v2.plans,
    cursor bigint NOT NULL,
    kind text NOT NULL CHECK (kind IN ('accepted','removed')),
    txid bytea,
    block_hash bytea NOT NULL,
    PRIMARY KEY(plan_id,cursor)
);
CREATE TABLE shadow_v2.guarded_tables (table_name text PRIMARY KEY);

CREATE FUNCTION shadow_v2.acquire(p_owner text, p_lease_seconds integer DEFAULT 30)
RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE c shadow_v2.control;
BEGIN
    IF p_owner IS NULL OR length(p_owner) = 0 OR p_lease_seconds NOT BETWEEN 1 AND 300 THEN
        RAISE EXCEPTION 'invalid ownership parameters';
    END IF;
    SELECT * INTO STRICT c FROM shadow_v2.control FOR UPDATE;
    IF c.owner_id IS NOT NULL AND c.heartbeat_at >= clock_timestamp() - make_interval(secs => p_lease_seconds) THEN
        RAISE EXCEPTION 'ownership held' USING ERRCODE = '55000';
    END IF;
    -- Preserve unfinished AND sealed plans, including their exact cursor.
    UPDATE shadow_v2.control SET epoch = epoch + 1, owner_id = p_owner,
        heartbeat_at = clock_timestamp() RETURNING epoch INTO c.epoch;
    RETURN c.epoch;
END $$;

CREATE FUNCTION shadow_v2.fence(p_epoch bigint, p_plan bigint)
RETURNS shadow_v2.plans LANGUAGE plpgsql AS $$
DECLARE c shadow_v2.control; p shadow_v2.plans;
BEGIN
    SELECT * INTO STRICT c FROM shadow_v2.control FOR UPDATE;
    IF p_epoch IS NULL OR p_plan IS NULL OR c.epoch <> p_epoch OR c.owner_id IS NULL
        OR c.active_plan IS DISTINCT FROM p_plan THEN
        RAISE EXCEPTION 'stale owner or plan' USING ERRCODE = '55000';
    END IF;
    SELECT * INTO STRICT p FROM shadow_v2.plans WHERE id = p_plan;
    IF p.status <> 'applying' THEN
        RAISE EXCEPTION 'plan sealed' USING ERRCODE = '55000';
    END IF;
    PERFORM set_config('shadow_v2.epoch', p_epoch::text, true);
    PERFORM set_config('shadow_v2.plan', p_plan::text, true);
    UPDATE shadow_v2.control SET heartbeat_at = clock_timestamp();
    RETURN p;
END $$;

CREATE FUNCTION shadow_v2.begin_plan(p_epoch bigint, p_base bytea, p_target bytea,
    p_score bigint, p_consumers text[], p_steps jsonb)
RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE c shadow_v2.control; v_plan bigint; v_bytes bigint;
BEGIN
    SELECT * INTO STRICT c FROM shadow_v2.control FOR UPDATE;
    IF p_epoch IS NULL OR c.epoch <> p_epoch OR c.owner_id IS NULL THEN
        RAISE EXCEPTION 'stale owner' USING ERRCODE = '55000';
    END IF;
    IF c.active_plan IS NOT NULL THEN
        RAISE EXCEPTION 'unfinished plan must be resumed' USING ERRCODE = '55000';
    END IF;
    IF c.checkpoint_hash IS DISTINCT FROM p_base THEN
        RAISE EXCEPTION 'base checkpoint mismatch';
    END IF;
    IF p_consumers IS NULL OR cardinality(p_consumers) = 0
       OR array_position(p_consumers, NULL) IS NOT NULL OR array_position(p_consumers, '') IS NOT NULL
       OR NOT ('ingestor' = ANY(p_consumers)) OR NOT ('projection' = ANY(p_consumers)) THEN
        RAISE EXCEPTION 'invalid required consumers';
    END IF;
    IF p_steps IS NULL OR jsonb_typeof(p_steps) <> 'array' THEN
        RAISE EXCEPTION 'steps must be an array';
    END IF;
    v_bytes := octet_length(p_steps::text);
    INSERT INTO shadow_v2.plans(base_hash,target_hash,target_score,required_consumers,step_count,evidence_bytes)
        VALUES(p_base,p_target,p_score,p_consumers,jsonb_array_length(p_steps),v_bytes) RETURNING id INTO v_plan;
    INSERT INTO shadow_v2.steps(plan_id,ordinal,kind,evidence)
        SELECT v_plan, ord - 1, item->>'kind', item->'evidence'
        FROM jsonb_array_elements(p_steps) WITH ORDINALITY AS s(item,ord);
    UPDATE shadow_v2.control SET active_plan = v_plan, ready = false, heartbeat_at = clock_timestamp(), retained_bytes=retained_bytes+v_bytes;
    INSERT INTO shadow_v2.journal(plan_id,epoch,revision,cursor,phase)
        VALUES(v_plan,p_epoch,c.revision,0,'begin');
    RETURN v_plan;
END $$;

CREATE FUNCTION shadow_v2.finish_step(p_epoch bigint, p_plan bigint, p_cursor bigint)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE p shadow_v2.plans; v_revision bigint;
BEGIN
    p := shadow_v2.fence(p_epoch,p_plan);
    IF p_cursor IS NULL OR p.cursor <> p_cursor OR p.cursor >= p.step_count THEN
        RAISE EXCEPTION 'cursor mismatch';
    END IF;
    UPDATE shadow_v2.control SET revision = revision + 1 RETURNING revision INTO v_revision;
    UPDATE shadow_v2.plans SET cursor = cursor + 1 WHERE id = p_plan;
    INSERT INTO shadow_v2.journal(plan_id,epoch,revision,cursor,phase)
        VALUES(p_plan,p_epoch,v_revision,p_cursor + 1,'step');
END $$;

CREATE FUNCTION shadow_v2.consumer_done(p_epoch bigint, p_plan bigint, p_consumer text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE p shadow_v2.plans; v_revision bigint;
BEGIN
    p := shadow_v2.fence(p_epoch,p_plan);
    IF p.cursor <> p.step_count OR p_consumer IS NULL OR NOT (p_consumer = ANY(p.required_consumers)) THEN
        RAISE EXCEPTION 'consumer or cursor mismatch';
    END IF;
    SELECT revision INTO v_revision FROM shadow_v2.control;
    INSERT INTO shadow_v2.consumers(plan_id,consumer,cursor,target_hash,revision,epoch)
        VALUES(p_plan,p_consumer,p.cursor,p.target_hash,v_revision,p_epoch)
        ON CONFLICT(plan_id,consumer) DO UPDATE SET cursor=excluded.cursor,
        target_hash=excluded.target_hash,revision=excluded.revision,epoch=excluded.epoch;
END $$;

CREATE FUNCTION shadow_v2.publish(p_epoch bigint, p_plan bigint, p_revision bigint)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE p shadow_v2.plans; c shadow_v2.control;
BEGIN
    p := shadow_v2.fence(p_epoch,p_plan);
    SELECT * INTO STRICT c FROM shadow_v2.control;
    IF p_revision IS NULL OR c.revision <> p_revision OR p.cursor <> p.step_count THEN
        RAISE EXCEPTION 'verification revision or cursor mismatch';
    END IF;
    IF EXISTS (SELECT 1 FROM unnest(p.required_consumers) AS req(name)
        WHERE NOT EXISTS (SELECT 1 FROM shadow_v2.consumers m
            WHERE m.plan_id=p_plan AND m.consumer=req.name AND m.epoch=p_epoch
              AND m.cursor=p.cursor AND m.target_hash=p.target_hash AND m.revision=p_revision)) THEN
        RAISE EXCEPTION 'consumer watermark missing or stale';
    END IF;
    UPDATE shadow_v2.plans SET status='sealed',sealed_revision=p_revision,published_epoch=p_epoch WHERE id=p_plan;
    -- Still unavailable until release. No new writes can pass the seal.
    INSERT INTO shadow_v2.journal(plan_id,epoch,revision,cursor,phase)
        VALUES(p_plan,p_epoch,p_revision,p.cursor,'sealed');
END $$;

CREATE FUNCTION shadow_v2.release(p_epoch bigint, p_plan bigint)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE c shadow_v2.control; p shadow_v2.plans;
BEGIN
    SELECT * INTO STRICT c FROM shadow_v2.control FOR UPDATE;
    IF p_epoch IS NULL OR p_plan IS NULL OR c.epoch <> p_epoch OR c.owner_id IS NULL
       OR c.active_plan IS DISTINCT FROM p_plan THEN
        RAISE EXCEPTION 'stale owner or plan' USING ERRCODE='55000';
    END IF;
    SELECT * INTO STRICT p FROM shadow_v2.plans WHERE id=p_plan;
    IF NOT c.source_validated THEN
        RAISE EXCEPTION 'seed requires live source validation';
    END IF;
    IF p.status <> 'sealed' OR p.sealed_revision IS NULL OR p.sealed_revision <> c.revision THEN
        RAISE EXCEPTION 'cannot release unverified plan';
    END IF;
    UPDATE shadow_v2.plans SET status='completed' WHERE id=p_plan;
    UPDATE shadow_v2.control SET completed_plan=p_plan,active_plan=NULL,owner_id=NULL,heartbeat_at=NULL,
        ready=true,generation=generation+1,checkpoint_hash=p.target_hash,checkpoint_score=p.target_score;
    INSERT INTO shadow_v2.journal(plan_id,epoch,revision,cursor,phase)
        VALUES(p_plan,p_epoch,c.revision,p.cursor,'released');
END $$;

-- A V1 writer pointed accidentally at a marked V2 database must fail closed.
-- Session credentials are set on V2 pools; every row write obtains the fence.
CREATE FUNCTION shadow_v2.guard_write() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p shadow_v2.plans; v_epoch bigint; v_plan bigint; v_bytes bigint;
BEGIN
    v_epoch := nullif(current_setting('shadow_v2.epoch',true),'')::bigint;
    v_plan := nullif(current_setting('shadow_v2.plan',true),'')::bigint;
    p := shadow_v2.fence(v_epoch,v_plan);
    v_bytes := COALESCE(octet_length(to_jsonb(OLD)::text),0) + COALESCE(octet_length(to_jsonb(NEW)::text),0) + 256;
    IF v_bytes > 8388608 THEN RAISE EXCEPTION 'shadow undo row exceeds byte budget'; END IF;
    UPDATE shadow_v2.control SET revision=revision+1,retained_bytes=retained_bytes+v_bytes;
    INSERT INTO shadow_v2.undo(plan_id,cursor,table_name,operation,before_row,after_row)
        VALUES(v_plan,p.cursor,TG_TABLE_NAME,TG_OP,
               CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END,
               CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END);
    RETURN NULL; -- AFTER trigger
END $$;
CREATE FUNCTION shadow_v2.guard_statement() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM shadow_v2.fence(nullif(current_setting('shadow_v2.epoch',true),'')::bigint,
                           nullif(current_setting('shadow_v2.plan',true),'')::bigint);
    RETURN NULL;
END $$;
CREATE FUNCTION shadow_v2.reject_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'truncate is prohibited on shadow state'; END $$;

CREATE FUNCTION shadow_v2.install_guards() RETURNS void LANGUAGE plpgsql AS $$
DECLARE t record;
BEGIN
    -- Called once after base schema and seed import. New public tables require
    -- another explicit installation before a new runtime/schema is published.
    FOR t IN SELECT tablename FROM pg_tables WHERE schemaname='public'
        AND tablename <> '_sqlx_migrations' ORDER BY tablename LOOP
        IF NOT EXISTS (SELECT 1 FROM shadow_v2.guarded_tables WHERE table_name=t.tablename) THEN
            EXECUTE format('CREATE TRIGGER shadow_v2_guard BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH STATEMENT EXECUTE FUNCTION shadow_v2.guard_statement()',t.tablename);
            EXECUTE format('CREATE TRIGGER shadow_v2_write AFTER INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION shadow_v2.guard_write()',t.tablename);
            EXECUTE format('CREATE TRIGGER shadow_v2_truncate BEFORE TRUNCATE ON public.%I EXECUTE FUNCTION shadow_v2.reject_truncate()',t.tablename);
            INSERT INTO shadow_v2.guarded_tables VALUES(t.tablename);
        END IF;
    END LOOP;
END $$;

CREATE FUNCTION shadow_v2.readiness()
RETURNS TABLE(ready boolean,generation bigint,reason text,checkpoint_hash bytea,checkpoint_score bigint)
LANGUAGE sql STABLE AS $$
    SELECT c.ready AND c.active_plan IS NULL AND c.checkpoint_hash IS NOT NULL,
        c.generation,CASE WHEN c.active_plan IS NOT NULL THEN 'recovery_in_progress'
        WHEN NOT c.ready THEN 'not_ready' ELSE 'ok' END,c.checkpoint_hash,c.checkpoint_score
    FROM shadow_v2.control c JOIN shadow_v2.identity i USING(singleton)
$$;

CREATE FUNCTION shadow_v2.immutable_record() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'shadow evidence is append only'; END $$;
CREATE TRIGGER immutable_steps BEFORE UPDATE OR DELETE ON shadow_v2.steps
    FOR EACH ROW EXECUTE FUNCTION shadow_v2.immutable_record();
CREATE TRIGGER immutable_acceptance BEFORE UPDATE OR DELETE ON shadow_v2.acceptance_events
    FOR EACH ROW EXECUTE FUNCTION shadow_v2.immutable_record();
CREATE TRIGGER immutable_journal BEFORE UPDATE OR DELETE ON shadow_v2.journal
    FOR EACH ROW EXECUTE FUNCTION shadow_v2.immutable_record();
CREATE TRIGGER immutable_undo BEFORE UPDATE OR DELETE ON shadow_v2.undo
    FOR EACH ROW EXECUTE FUNCTION shadow_v2.immutable_record();
CREATE FUNCTION shadow_v2.plan_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.archive_digest IS NOT NULL AND OLD.archive_digest IS DISTINCT FROM NEW.archive_digest THEN
        RAISE EXCEPTION 'archive receipt is immutable';
    END IF;
    IF (OLD.base_hash,OLD.target_hash,OLD.target_score,OLD.required_consumers,OLD.step_count,OLD.evidence_bytes)
       IS DISTINCT FROM (NEW.base_hash,NEW.target_hash,NEW.target_score,NEW.required_consumers,NEW.step_count,NEW.evidence_bytes) THEN
        RAISE EXCEPTION 'shadow plan identity is immutable';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER immutable_plan BEFORE UPDATE ON shadow_v2.plans
    FOR EACH ROW EXECUTE FUNCTION shadow_v2.plan_identity();
