"""Real PostgreSQL assertions. Each test owns a disposable, uniquely named DB."""
import concurrent.futures
import os
from pathlib import Path
import threading
import unittest
import uuid

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

MIGRATION = Path(__file__).resolve().parents[2] / 'crates/tn12-indexer-db/shadow-migrations/001_coordination.sql'
DSN = os.environ['SHADOW_TEST_ADMIN_DSN']
H0, H1, H2 = bytes([0])*32, bytes([1])*32, bytes([2])*32

class Coordination(unittest.TestCase):
    def setUp(self):
        self.name = 'shadow_test_' + uuid.uuid4().hex
        self.admin = psycopg.connect(DSN, autocommit=True)
        self.admin.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(self.name)))
        self.c = self.connect()
        self.c.execute(MIGRATION.read_text())
        self.c.execute("INSERT INTO shadow_v2.identity(network,instance_id) VALUES ('testnet-10',%s)", (uuid.uuid4(),))
        self.c.execute("UPDATE shadow_v2.control SET checkpoint_hash=%s,checkpoint_score=10,history_start_hash=%s,history_start_score=10,ready=true,source_validated=true,seed_manifest='{}'", (H0,H0))
        self.c.execute('CREATE TABLE public.fixture (id int PRIMARY KEY, value text NOT NULL)')
        self.c.execute('SELECT shadow_v2.install_guards()')

    def connect(self):
        return psycopg.connect(DSN, dbname=self.name, autocommit=True)

    def tearDown(self):
        self.c.close()
        self.admin.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(self.name)))
        self.admin.close()

    def scalar(self, query, args=()):
        return self.c.execute(query, args).fetchone()[0]

    def acquire(self, owner='A'):
        return self.scalar('SELECT shadow_v2.acquire(%s)', (owner,))

    def begin(self, epoch, base=H0, target=H1, steps=None):
        return self.scalar("SELECT shadow_v2.begin_plan(%s,%s,%s,20,ARRAY['ingestor','projection'],%s)",
                           (epoch,base,target,Jsonb(steps if steps is not None else [])))

    def done(self,e,p):
        for consumer in ('ingestor','projection'):
            self.c.execute('SELECT shadow_v2.consumer_done(%s,%s,%s)',(e,p,consumer))
        revision=self.scalar('SELECT revision FROM shadow_v2.control')
        self.c.execute('SELECT shadow_v2.publish(%s,%s,%s)',(e,p,revision))

    def expect(self, message, query, args=()):
        with self.assertRaisesRegex(psycopg.Error,message):
            self.c.execute(query,args)

    def test_missing_consumer_and_null_requirements(self):
        e=self.acquire()
        self.expect('invalid required consumers','SELECT shadow_v2.begin_plan(%s,%s,%s,20,NULL,\'[]\')',(e,H0,H1))
        p=self.begin(e)
        self.c.execute("SELECT shadow_v2.consumer_done(%s,%s,'ingestor')",(e,p))
        self.expect('consumer watermark','SELECT shadow_v2.publish(%s,%s,0)',(e,p))
        self.assertFalse(self.scalar('SELECT ready FROM shadow_v2.readiness()'))

    def test_actual_effect_undo_and_cursor_rollback_together(self):
        e=self.acquire();p=self.begin(e,steps=[{'kind':'anchor','evidence':{'hash':H1.hex()}}])
        with self.assertRaisesRegex(RuntimeError,'kill'):
            with self.c.transaction():
                self.c.execute('SELECT shadow_v2.fence(%s,%s)',(e,p))
                self.c.execute("INSERT INTO fixture VALUES(1,'before crash')")
                self.c.execute('SELECT shadow_v2.finish_step(%s,%s,0)',(e,p))
                raise RuntimeError('kill before commit')
        self.assertEqual(self.scalar('SELECT count(*) FROM fixture'),0)
        self.assertEqual(self.scalar('SELECT count(*) FROM shadow_v2.undo'),0)
        self.assertEqual(self.scalar('SELECT cursor FROM shadow_v2.plans WHERE id=%s',(p,)),0)
        with self.c.transaction():
            self.c.execute('SELECT shadow_v2.fence(%s,%s)',(e,p))
            self.c.execute("INSERT INTO fixture VALUES(1,'committed')")
            self.c.execute('SELECT shadow_v2.finish_step(%s,%s,0)',(e,p))
        self.assertEqual(self.scalar("SELECT after_row->>'value' FROM shadow_v2.undo"),'committed')
        self.assertEqual(self.scalar('SELECT cursor FROM shadow_v2.plans WHERE id=%s',(p,)),1)
        self.done(e,p)

    def test_unvalidated_seed_cannot_be_published_ready(self):
        self.c.execute('UPDATE shadow_v2.control SET ready=false,source_validated=false')
        e=self.acquire();p=self.begin(e)
        for consumer in ('ingestor','projection'):
            self.c.execute('SELECT shadow_v2.consumer_done(%s,%s,%s)',(e,p,consumer))
        revision=self.scalar('SELECT revision FROM shadow_v2.control')
        self.c.execute('SELECT shadow_v2.publish(%s,%s,%s)',(e,p,revision))
        self.expect('live source validation','SELECT shadow_v2.release(%s,%s)',(e,p))
        self.assertFalse(self.scalar('SELECT ready FROM shadow_v2.control'))
        self.assertEqual(self.scalar('SELECT active_plan FROM shadow_v2.control'),p)

    def test_stale_owner_and_wrong_plan_cannot_write(self):
        e=self.acquire();p=self.begin(e)
        self.c.execute("UPDATE shadow_v2.control SET heartbeat_at=clock_timestamp()-interval '1 hour'")
        e2=self.acquire('B');self.assertGreater(e2,e)
        self.assertEqual(self.scalar('SELECT active_plan FROM shadow_v2.control'),p)
        self.expect('stale owner or plan','SELECT shadow_v2.fence(%s,%s)',(e,p))
        self.expect('stale owner or plan','SELECT shadow_v2.fence(%s,%s)',(e2,p+1))
        self.expect('unfinished plan','SELECT shadow_v2.begin_plan(%s,%s,%s,20,ARRAY[\'ingestor\',\'projection\'],\'[]\')',(e2,H0,H1))
        self.done(e2,p)
        self.expect('stale owner or plan','SELECT shadow_v2.release(%s,%s)',(e,p))
        self.c.execute('SELECT shadow_v2.release(%s,%s)',(e2,p))
        self.assertTrue(self.scalar('SELECT ready FROM shadow_v2.readiness()'))

    def test_sealed_takeover_release_and_second_cycle(self):
        e=self.acquire();p=self.begin(e);self.done(e,p)
        self.assertFalse(self.scalar('SELECT ready FROM shadow_v2.readiness()'))
        self.expect('plan sealed','SELECT shadow_v2.fence(%s,%s)',(e,p))
        self.c.execute("UPDATE shadow_v2.control SET heartbeat_at=clock_timestamp()-interval '1 hour'")
        e2=self.acquire('B')
        self.c.execute('SELECT shadow_v2.release(%s,%s)',(e2,p))
        e3=self.acquire('C');p2=self.begin(e3,H1,H2)
        self.done(e3,p2);self.c.execute('SELECT shadow_v2.release(%s,%s)',(e3,p2))
        self.assertEqual(self.scalar('SELECT generation FROM shadow_v2.control'),2)
        self.assertIsNone(self.scalar('SELECT active_plan FROM shadow_v2.control'))
        self.assertEqual(self.scalar('SELECT completed_plan FROM shadow_v2.control'),p2)
        self.assertGreater(e3,e2)

    def test_missing_fence_and_truncate_fail(self):
        self.expect('stale owner or plan',"INSERT INTO fixture VALUES(1,'rogue V1 writer')")
        self.expect('truncate is prohibited','TRUNCATE fixture')

    def test_changed_revision_rejects_previous_verification(self):
        e=self.acquire();p=self.begin(e)
        for consumer in ('ingestor','projection'):
            self.c.execute('SELECT shadow_v2.consumer_done(%s,%s,%s)',(e,p,consumer))
        with self.c.transaction():
            self.c.execute('SELECT shadow_v2.fence(%s,%s)',(e,p))
            self.c.execute("INSERT INTO fixture VALUES(1,'new revision')")
        self.expect('verification revision','SELECT shadow_v2.publish(%s,%s,0)',(e,p))
        self.expect('consumer watermark','SELECT shadow_v2.publish(%s,%s,1)',(e,p))
        self.done(e,p)

    def test_unpublished_release_rejected(self):
        e=self.acquire();p=self.begin(e)
        self.expect('cannot release unverified','SELECT shadow_v2.release(%s,%s)',(e,p))
        self.assertFalse(self.scalar('SELECT ready FROM shadow_v2.readiness()'))

    def test_concurrent_acquisition_has_one_winner(self):
        barrier=threading.Barrier(2)
        def acquire(owner):
            with self.connect() as c:
                barrier.wait(timeout=5)
                try:return c.execute('SELECT shadow_v2.acquire(%s)',(owner,)).fetchone()[0]
                except psycopg.errors.ObjectNotInPrerequisiteState:return None
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results=list(pool.map(acquire,['A','B']))
        self.assertEqual(sorted(x for x in results if x is not None),[1])

    def test_database_disconnect_rolls_back_effect_and_cursor(self):
        e=self.acquire();p=self.begin(e,steps=[{'kind':'anchor','evidence':{'hash':H1.hex()}}])
        worker=self.connect()
        try:
            pid=worker.execute('SELECT pg_backend_pid()').fetchone()[0]
            worker.execute('BEGIN')
            worker.execute('SELECT shadow_v2.fence(%s,%s)',(e,p))
            worker.execute("INSERT INTO fixture VALUES(1,'uncommitted')")
            worker.execute('SELECT shadow_v2.finish_step(%s,%s,0)',(e,p))
            self.c.execute('SELECT pg_terminate_backend(%s)',(pid,))
            with self.assertRaises(psycopg.OperationalError):worker.execute('COMMIT')
        finally:worker.close()
        self.assertEqual(self.scalar('SELECT count(*) FROM fixture'),0)
        self.assertEqual(self.scalar('SELECT count(*) FROM shadow_v2.undo'),0)
        self.assertEqual(self.scalar('SELECT cursor FROM shadow_v2.plans WHERE id=%s',(p,)),0)

    def test_retention_budget_and_plan_identity_fail_closed(self):
        e=self.acquire();p=self.begin(e)
        self.expect('identity is immutable','UPDATE shadow_v2.plans SET required_consumers=ARRAY[\'ingestor\'] WHERE id=%s',(p,))
        self.c.execute('UPDATE shadow_v2.control SET max_retained_bytes=retained_bytes+1')
        with self.assertRaises(psycopg.errors.CheckViolation):
            with self.c.transaction():
                self.c.execute('SELECT shadow_v2.fence(%s,%s)',(e,p))
                self.c.execute("INSERT INTO fixture VALUES(1,'too large for remaining capacity')")
        self.assertEqual(self.scalar('SELECT count(*) FROM fixture'),0)
        self.assertFalse(self.scalar('SELECT ready FROM shadow_v2.readiness()'))

    def test_two_connection_snapshot_and_read_lock(self):
        e=self.acquire()
        with self.connect() as api:
            api.execute('BEGIN ISOLATION LEVEL REPEATABLE READ')
            self.assertTrue(api.execute('SELECT ready FROM shadow_v2.readiness()').fetchone()[0])
            p=self.begin(e)
            self.assertTrue(api.execute('SELECT ready FROM shadow_v2.readiness()').fetchone()[0])
            api.execute('COMMIT')
            self.assertFalse(api.execute('SELECT ready FROM shadow_v2.readiness()').fetchone()[0])
            self.done(e,p);self.c.execute('SELECT shadow_v2.release(%s,%s)',(e,p))
            e2=self.acquire('B')
            api.execute('BEGIN')
            api.execute('SELECT * FROM shadow_v2.control FOR SHARE')
            with self.connect() as worker:
                worker.execute("SET lock_timeout='100ms'")
                with self.assertRaises(psycopg.errors.LockNotAvailable):
                    worker.execute("SELECT shadow_v2.begin_plan(%s,%s,%s,20,ARRAY['ingestor','projection'],'[]')",(e2,H1,H2))
            api.execute('COMMIT')
            self.begin(e2,H1,H2)

if __name__=='__main__':unittest.main(verbosity=2)
