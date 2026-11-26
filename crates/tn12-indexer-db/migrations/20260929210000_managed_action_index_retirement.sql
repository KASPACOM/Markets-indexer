-- Version barrier for guarded action-index convergence in migrate().
-- The retained tx/covenant/action/id index is created by the immutable
-- 20260804100000 migration. The official migrator repairs and exact-validates
-- it on every attempt before dropping the redundant continuation index with
-- a separate autocommit DROP INDEX CONCURRENTLY. Direct SQLx migration is safe
-- and leaves the redundant index in place until the official migrator runs.
SELECT 1;
