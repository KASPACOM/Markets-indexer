import argparse
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid
import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('snapshot',HERE/'snapshot.py')
snapshot=importlib.util.module_from_spec(spec);spec.loader.exec_module(snapshot)
MIGRATION=(HERE.parents[1]/'crates/tn12-indexer-db/shadow-migrations/001_coordination.sql').read_text()
DSN=os.environ['SHADOW_TEST_ADMIN_DSN']
SCHEMA="""
CREATE TABLE source_identity(network text,genesis_hash bytea,decoder_revision text,source_id text);
CREATE TABLE blocks(hash bytea PRIMARY KEY,blue_score bigint,timestamp_ms bigint,is_chain_block boolean);
CREATE TABLE covenants(id int PRIMARY KEY,script bytea);
CREATE TABLE covenant_utxos(txid bytea,vout int,status text,amount bigint,script bytea,PRIMARY KEY(txid,vout));
CREATE TABLE covenant_actions(id bigserial PRIMARY KEY,payload bytea);
"""
H=bytes([1])*32

class Snapshots(unittest.TestCase):
    def setUp(self):
        self.admin=psycopg.connect(DSN,autocommit=True)
        self.names=[];self.directory=tempfile.TemporaryDirectory(prefix='shadow-snapshot-test-')
        self.source=self.database();self.target=self.database()
        os.environ['SHADOW_TEST_SOURCE']=make_conninfo(DSN,dbname=self.source)
        os.environ['SHADOW_TEST_TARGET']=make_conninfo(DSN,dbname=self.target)
        self.instance=str(uuid.uuid4())
        with psycopg.connect(os.environ['SHADOW_TEST_SOURCE']) as c:
            c.execute(SCHEMA)
            c.execute("INSERT INTO source_identity VALUES('testnet-10',%s,'synthetic-test','synthetic-source')",(bytes.fromhex(snapshot.TN10_GENESIS),))
            c.execute('INSERT INTO blocks VALUES(%s,10,1000,true)',(H,))
            c.execute("INSERT INTO covenants VALUES(1,'\\x01')")
            c.execute("INSERT INTO covenant_utxos VALUES(%s,0,'active',100,'\\x0102')",(H,))
            c.execute("INSERT INTO covenant_actions VALUES(8,'\\x0304')")
        with psycopg.connect(os.environ['SHADOW_TEST_TARGET']) as c:
            c.execute(SCHEMA);c.execute(MIGRATION)
            c.execute("INSERT INTO shadow_v2.identity(network,instance_id) VALUES('testnet-10',%s)",(self.instance,))
            c.execute('SELECT shadow_v2.install_guards()')
        self.inventory=Path(self.directory.name)/'inventory.json'
        self.inventory.write_text(json.dumps({'network':'testnet-10','decoder_revision':'synthetic-test',
            'source_identity_query':'SELECT network,genesis_hash,decoder_revision,source_id FROM source_identity',
            'checkpoint_query':"SELECT hash,blue_score,timestamp_ms FROM blocks WHERE is_chain_block",
            'evidence_contract':'Synthetic bytes only; verifies transport integrity, not covenant decoding.',
            'assertions':['SELECT count(*)=1 FROM covenant_utxos WHERE status=\'active\''],
            'tables':{table:{'query':'SELECT * FROM '+table,'purpose':'synthetic test','retention':'current-closure' if table in ('blocks','covenant_utxos') else 'full'} for table in ('source_identity','blocks','covenants','covenant_utxos','covenant_actions')}}))
        self.seed=Path(self.directory.name)/'seed'

    def database(self):
        name='shadow_snapshot_test_'+uuid.uuid4().hex;self.names.append(name)
        self.admin.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)));return name

    def tearDown(self):
        for name in self.names:self.admin.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(name)))
        self.admin.close();self.directory.cleanup()

    def export(self):
        snapshot.export_seed(argparse.Namespace(source_env='SHADOW_TEST_SOURCE',inventory=str(self.inventory),output=str(self.seed)))
    def import_(self):
        snapshot.import_seed(argparse.Namespace(target_env='SHADOW_TEST_TARGET',instance_id=self.instance,expected_source_id='synthetic-source',input=str(self.seed)))

    def test_seed_import_preserves_evidence_and_sequences(self):
        self.export();self.import_()
        with psycopg.connect(os.environ['SHADOW_TEST_TARGET']) as c:
            self.assertEqual(c.execute('SELECT amount,script FROM covenant_utxos').fetchone(),(100,b'\x01\x02'))
            self.assertEqual(c.execute('SELECT last_value FROM covenant_actions_id_seq').fetchone(),(8,))
            self.assertEqual(c.execute('SELECT ready,checkpoint_hash FROM shadow_v2.control').fetchone(),(False,H))
            with self.assertRaises(psycopg.Error):c.execute("UPDATE covenant_utxos SET amount=1")
        with self.assertRaisesRegex(ValueError,'already seeded'):self.import_()

    def test_checksum_corruption_rejected_before_target_changes(self):
        self.export()
        with (self.seed/'0000.copy').open('ab') as f:f.write(b'corrupt')
        with self.assertRaisesRegex(ValueError,'checksum'):self.import_()
        with psycopg.connect(os.environ['SHADOW_TEST_TARGET']) as c:
            self.assertEqual(c.execute('SELECT count(*) FROM blocks').fetchone(),(0,))

    def test_active_omission_rolls_back_entire_import(self):
        inventory=json.loads(self.inventory.read_text())
        inventory['tables']['covenant_utxos']['query']='SELECT * FROM covenant_utxos WHERE false'
        self.inventory.write_text(json.dumps(inventory));self.export()
        with self.assertRaisesRegex(ValueError,'omits or changes active'):self.import_()
        with psycopg.connect(os.environ['SHADOW_TEST_TARGET']) as c:
            self.assertEqual(c.execute('SELECT count(*) FROM blocks').fetchone(),(0,))
            self.assertEqual(c.execute('SELECT checkpoint_hash FROM shadow_v2.control').fetchone(),(None,))

    def test_missing_state_table_rejected(self):
        inventory=json.loads(self.inventory.read_text());del inventory['tables']['covenant_actions']
        self.inventory.write_text(json.dumps(inventory))
        with self.assertRaisesRegex(ValueError,'every public table'):self.export()

    def test_wrong_source_network_rejected(self):
        with psycopg.connect(os.environ['SHADOW_TEST_SOURCE']) as c:
            c.execute("UPDATE source_identity SET network='mainnet'")
        with self.assertRaisesRegex(ValueError,'source identity mismatch'):self.export()

    def test_wrong_genesis_rejected(self):
        with psycopg.connect(os.environ['SHADOW_TEST_SOURCE']) as c:
            c.execute('UPDATE source_identity SET genesis_hash=%s',(bytes(32),))
        with self.assertRaisesRegex(ValueError,'source identity mismatch'):self.export()

    def test_source_id_must_match_operator_expectation(self):
        self.export()
        with self.assertRaisesRegex(ValueError,'unexpected seed source'):
            snapshot.import_seed(argparse.Namespace(target_env='SHADOW_TEST_TARGET',instance_id=self.instance,
                expected_source_id='another-source',input=str(self.seed)))

    def test_filtered_required_state_rejected_on_import(self):
        inventory=json.loads(self.inventory.read_text())
        inventory['tables']['covenant_actions']['query']='SELECT * FROM covenant_actions WHERE false'
        self.inventory.write_text(json.dumps(inventory));self.export()
        with self.assertRaisesRegex(ValueError,'required state: covenant_actions'):self.import_()
        with psycopg.connect(os.environ['SHADOW_TEST_TARGET']) as c:
            self.assertFalse(c.execute('SELECT ready FROM shadow_v2.control').fetchone()[0])
            self.assertEqual(c.execute('SELECT count(*) FROM covenants').fetchone(),(0,))

    def test_backup_restore_without_source(self):
        self.export();self.import_()
        # Synthetic publication, independent of the live node verification test.
        with psycopg.connect(os.environ['SHADOW_TEST_TARGET']) as c:
            c.execute('UPDATE shadow_v2.control SET source_validated=true')
            e=c.execute("SELECT shadow_v2.acquire('test')").fetchone()[0]
            p=c.execute("SELECT shadow_v2.begin_plan(%s,%s,%s,10,ARRAY['ingestor','projection'],'[]')",(e,H,H)).fetchone()[0]
            for consumer in ('ingestor','projection'):c.execute('SELECT shadow_v2.consumer_done(%s,%s,%s)',(e,p,consumer))
            c.execute('SELECT shadow_v2.publish(%s,%s,0)',(e,p))
            c.execute('SELECT shadow_v2.release(%s,%s)',(e,p))
        backup=Path(self.directory.name)/'backup'
        snapshot.backup(argparse.Namespace(source_env='SHADOW_TEST_TARGET',output=str(backup),decoder_revision='synthetic-test'))
        # Remove both source databases: restore cannot fall back to either one.
        for name in (self.source,self.target):
            self.admin.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(name)))
            self.names.remove(name)
        restored=self.database();os.environ['SHADOW_TEST_RESTORE']=make_conninfo(DSN,dbname=restored)
        snapshot.restore(argparse.Namespace(target_env='SHADOW_TEST_RESTORE',input=str(backup),decoder_revision='synthetic-test'))
        with psycopg.connect(os.environ['SHADOW_TEST_RESTORE']) as c:
            self.assertEqual(c.execute('SELECT amount,script FROM covenant_utxos').fetchone(),(100,b'\x01\x02'))
            self.assertTrue(c.execute('SELECT ready FROM shadow_v2.control').fetchone()[0])

if __name__=='__main__':unittest.main(verbosity=2)
