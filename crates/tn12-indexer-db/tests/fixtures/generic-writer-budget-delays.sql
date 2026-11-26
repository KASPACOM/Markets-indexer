
CREATE SEQUENCE test_budget_attempts;
CREATE FUNCTION test_budget_blocks() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM nextval('test_budget_attempts'); PERFORM pg_sleep(0.05); RETURN NULL; END $$;
CREATE FUNCTION test_budget_rows() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE n bigint;
BEGIN SELECT count(*) INTO n FROM inserted_rows; PERFORM pg_sleep(n * 0.003125 / TG_ARGV[0]::float); RETURN NULL; END $$;
CREATE TRIGGER test_budget_blocks AFTER INSERT ON blocks FOR EACH STATEMENT EXECUTE FUNCTION test_budget_blocks();
CREATE TRIGGER test_budget_covenants AFTER INSERT ON covenants REFERENCING NEW TABLE AS inserted_rows FOR EACH STATEMENT EXECUTE FUNCTION test_budget_rows('1');
CREATE TRIGGER test_budget_outputs AFTER INSERT ON covenant_utxos REFERENCING NEW TABLE AS inserted_rows FOR EACH STATEMENT EXECUTE FUNCTION test_budget_rows('1');
CREATE TRIGGER test_budget_inputs AFTER UPDATE ON covenant_utxos REFERENCING NEW TABLE AS inserted_rows FOR EACH STATEMENT EXECUTE FUNCTION test_budget_rows('1');
CREATE TRIGGER test_budget_actions AFTER INSERT ON covenant_actions REFERENCING NEW TABLE AS inserted_rows FOR EACH STATEMENT EXECUTE FUNCTION test_budget_rows('2');
