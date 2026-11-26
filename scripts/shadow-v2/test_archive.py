"""Archive integrity and replay dispatch tests; Rust tests execute the decoder."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import psycopg
import archive
import test_snapshot as snapshot_tests
H=snapshot_tests.H


class Archives(unittest.TestCase):
    def setUp(self):
        self.fixture=snapshot_tests.Snapshots();self.fixture.setUp()
        self.fixture.export();self.fixture.import_()
        self.environment=patch.dict(os.environ,{
            'SHADOW_DATABASE_URL':os.environ['SHADOW_TEST_TARGET'],
            'SHADOW_INSTANCE_ID':self.fixture.instance})
        self.environment.start()
        with psycopg.connect(os.environ['SHADOW_DATABASE_URL']) as c:
            c.execute('UPDATE shadow_v2.control SET source_validated=true')
            e=c.execute("SELECT shadow_v2.acquire('archive-test')").fetchone()[0]
            self.plan=c.execute("SELECT shadow_v2.begin_plan(%s,%s,%s,10,ARRAY['ingestor','projection'],'[]')",(e,H,H)).fetchone()[0]
            for consumer in ('ingestor','projection'):
                c.execute('SELECT shadow_v2.consumer_done(%s,%s,%s)',(e,self.plan,consumer))
            c.execute('SELECT shadow_v2.publish(%s,%s,0)',(e,self.plan))
            c.execute('SELECT shadow_v2.release(%s,%s)',(e,self.plan))
        self.directory=Path(self.fixture.directory.name)/'archive'
        archive.export(argparse.Namespace(source_env='SHADOW_DATABASE_URL',after_plan=0,limit=100,
            output=str(self.directory),decoder_revision='synthetic-test'))
        self.args=argparse.Namespace(input=str(self.directory),decoder_revision='synthetic-test',binary='pinned-test-binary')

    def tearDown(self):
        self.environment.stop();self.fixture.tearDown()

    def manifest(self):return json.loads((self.directory/'manifest.json').read_text())

    def test_export_preserves_identity_and_validated_dispatch(self):
        m=self.manifest()
        self.assertEqual(m['instance_id'],self.fixture.instance)
        self.assertEqual(len(m['plans']),1)
        plan=json.loads((self.directory/m['plans'][0]['file']).read_text())
        self.assertEqual(plan['base_hash'],H.hex())
        self.assertEqual(plan['decoder_revision'],'synthetic-test')
        with patch.object(archive.subprocess,'run') as run:
            archive.replay(self.args)
            self.assertEqual(run.call_count,1)
            self.assertEqual(run.call_args.args[0][:3],['pinned-test-binary','replay','--plan'])

    def test_corrupt_evidence_stops_before_binary(self):
        m=self.manifest()
        with (self.directory/m['plans'][0]['file']).open('ab') as f:f.write(b'corrupt')
        with patch.object(archive.subprocess,'run') as run:
            with self.assertRaisesRegex(ValueError,'checksum'):archive.replay(self.args)
            run.assert_not_called()

    def test_wrong_snapshot_instance_stops_before_binary(self):
        m=self.manifest();m['instance_id']='wrong-instance'
        (self.directory/'manifest.json').write_text(json.dumps(m))
        with patch.object(archive.subprocess,'run') as run:
            with self.assertRaisesRegex(ValueError,'snapshot instance mismatch'):archive.replay(self.args)
            run.assert_not_called()

    def test_exact_completed_receipt_skips_replay(self):
        m=self.manifest();data=(self.directory/m['plans'][0]['file']).read_bytes()
        with psycopg.connect(os.environ['SHADOW_DATABASE_URL']) as c:
            c.execute('UPDATE shadow_v2.plans SET archive_digest=%s WHERE id=%s',
                (hashlib.blake2b(data,digest_size=32).digest(),self.plan))
        with patch.object(archive.subprocess,'run') as run:
            archive.replay(self.args);run.assert_not_called()


if __name__=='__main__':unittest.main(verbosity=2)
