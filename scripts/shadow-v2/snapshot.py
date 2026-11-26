#!/usr/bin/env python3
"""Consistent, streamed shadow seed and backup artifacts. No source writes.

Connection strings are read from named environment variables and never logged.
An inventory is mandatory: source checkpoint semantics and evidence retention
must be reviewed rather than guessed from a maximum score.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import re
import shutil
import uuid

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict
from psycopg.types.json import Jsonb

FORMAT = 'tn10-shadow-snapshot/1'
# TESTNET_GENESIS from the pinned rusty-kaspa SDK (98a4ccd), used by TN10.
TN10_GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'


def connect(env):
    return psycopg.connect(os.environ[env])


def pg_environment(env_name):
    # Keep credentials out of argv and remove inherited connection overrides.
    environment={k:v for k,v in os.environ.items() if not k.startswith('PG')}
    names={'host':'PGHOST','hostaddr':'PGHOSTADDR','port':'PGPORT','dbname':'PGDATABASE',
           'user':'PGUSER','password':'PGPASSWORD','sslmode':'PGSSLMODE',
           'sslrootcert':'PGSSLROOTCERT','sslcert':'PGSSLCERT','sslkey':'PGSSLKEY',
           'options':'PGOPTIONS','connect_timeout':'PGCONNECT_TIMEOUT','service':'PGSERVICE'}
    for key,value in conninfo_to_dict(os.environ[env_name]).items():
        if key not in names:raise ValueError('unsupported backup connection option: '+key)
        environment[names[key]]=value
    return environment


def pg_tool(name,major):
    configured=os.environ.get('SHADOW_PG_BIN')
    candidate=Path(configured)/name if configured else Path(f'/usr/lib/postgresql/{major}/bin')/name
    executable=str(candidate) if candidate.is_file() else shutil.which(name)
    if not executable:raise ValueError(f'PostgreSQL {major} client tools are required')
    version=subprocess.check_output([executable,'--version'],text=True)
    match=re.search(r'(\d+)\.\d+',version)
    if not match or int(match.group(1))!=major:
        raise ValueError(f'{name} must match PostgreSQL server major {major}; set SHADOW_PG_BIN')
    return executable


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def migrations(c):
    if not c.execute("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL").fetchone()[0]:return []
    return [list(row) for row in c.execute("SELECT version,encode(checksum,'hex') FROM public._sqlx_migrations WHERE success ORDER BY version")]


def columns(c,table):
    return c.execute("SELECT column_name,data_type,udt_name,is_generated FROM information_schema.columns WHERE table_schema='public' AND table_name=%s ORDER BY ordinal_position",(table,)).fetchall()


def copy_out(c,query,path):
    h=hashlib.sha256(); size=0
    with path.open('xb') as f, c.cursor() as cur:
        with cur.copy(sql.SQL('COPY ({}) TO STDOUT').format(sql.SQL(query))) as copy:
            for block in copy:
                f.write(block);h.update(block);size+=len(block)
        count=cur.rowcount
    return {'sha256':h.hexdigest(),'bytes':size,'rows':count}


def atomic_manifest(directory,manifest):
    temporary=directory/'manifest.pending.json'
    temporary.write_text(json.dumps(manifest,indent=2)+'\n')
    temporary.replace(directory/'manifest.json')


def public_tables(c):
    return {r[0] for r in c.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename<>'_sqlx_migrations'")}


def full_table_query(c,table):
    # A stable multiset digest checks all rows independently of the export query.
    return sql.SQL('SELECT to_jsonb(t) FROM public.{} t ORDER BY to_jsonb(t)::text COLLATE "C"').format(sql.Identifier(table)).as_string(c)


def source_identity(row,network,decoder):
    if len(row)!=4:raise ValueError('source identity needs network, genesis hash, decoder revision, source id')
    net,genesis,revision,source_id=row
    if isinstance(genesis,bytes):genesis=genesis.hex()
    if net!=network or revision!=decoder or not source_id or not isinstance(genesis,str) or genesis.lower()!=TN10_GENESIS:
        raise ValueError('source identity mismatch')
    return {'network':net,'genesis_hash':genesis.lower(),'decoder_revision':revision,'source_id':source_id}


def export_seed(args):
    inventory=json.loads(Path(args.inventory).read_text())
    if inventory.get('network')!='testnet-10' or not inventory.get('decoder_revision'):
        raise ValueError('inventory needs TN10 network and source decoder revision')
    # No default table filter: active state and required covenant evidence must
    # have an explicit retention inventory before this tool can create a seed.
    entries=inventory['tables']
    if not {'blocks','covenants','covenant_utxos'} <= entries.keys():
        raise ValueError('inventory omits core current-state tables')
    if not inventory.get('evidence_contract') or not inventory.get('checkpoint_query') or not inventory.get('source_identity_query'):
        raise ValueError('inventory needs evidence contract, source identity query and exact checkpoint query')
    directory=Path(args.output);directory.mkdir(parents=True,exist_ok=False)
    manifest={'format':FORMAT,'kind':'current-state-seed','network':inventory['network'],
              'decoder_revision':inventory['decoder_revision'],'history_complete':False,
              'evidence_contract':inventory['evidence_contract'],'tables':{}}
    with connect(args.source_env) as c:
        c.execute('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
        c.execute("SET LOCAL timezone='UTC'");c.execute("SET LOCAL bytea_output='hex'")
        manifest['migrations']=migrations(c)
        if set(entries)!=public_tables(c):raise ValueError('inventory must account for every public table')
        identities=c.execute(inventory['source_identity_query']).fetchall()
        if len(identities)!=1:raise ValueError('source identity query must return exactly one row')
        manifest['source_identity']=source_identity(identities[0],inventory['network'],inventory['decoder_revision'])
        checkpoints=c.execute(inventory['checkpoint_query']).fetchall()
        if len(checkpoints)!=1 or len(checkpoints[0])!=3:
            raise ValueError('checkpoint query must return exactly one hash, score, timestamp_ms')
        hash_,score,time=checkpoints[0]
        if isinstance(hash_,bytes):hash_=hash_.hex()
        if len(bytes.fromhex(hash_))!=32 or score<0 or time<0:raise ValueError('invalid checkpoint')
        manifest['checkpoint']={'hash':hash_,'score':score,'timestamp_ms':time}
        # All assertions run in precisely the same snapshot as the exports.
        assertions=inventory.get('assertions',[])
        if not assertions:raise ValueError('inventory must verify source readiness and retained evidence')
        for assertion in assertions:
            if c.execute(assertion).fetchone()!=(True,):raise ValueError('source inventory assertion failed')
        for number,(table,spec) in enumerate(entries.items()):
            shape=columns(c,table)
            if not shape or any(row[3]!='NEVER' for row in shape):raise ValueError(f'unsupported table shape: {table}')
            if not spec.get('purpose'):raise ValueError(f'missing retention purpose: {table}')
            retention=spec.get('retention')
            if retention not in ('full','current-closure') or (retention=='current-closure' and table not in ('blocks','covenant_utxos')):
                raise ValueError(f'table needs full retention, or supported current closure: {table}')
            filename=f'{number:04d}.copy'
            result=copy_out(c,spec['query'],directory/filename)
            manifest['tables'][table]={**result,'file':filename,'columns':shape,'purpose':spec['purpose'],'retention':retention}
            if retention=='full':
                proof_file=f'{number:04d}.full.copy'
                proof=copy_out(c,full_table_query(c,table),directory/proof_file)
                manifest['tables'][table]['full_state']={**proof,'file':proof_file}
        # Exact unspent set, independently exported, proves no age-filter loss.
        active=copy_out(c,"SELECT * FROM covenant_utxos WHERE status='active' ORDER BY txid,vout",directory/'active-utxos.copy')
        manifest['active_utxos']=active
    atomic_manifest(directory,manifest)


def safe_file(directory,name):
    path=(directory/name).resolve()
    if path.parent!=directory.resolve():raise ValueError('artifact path escapes snapshot')
    return path


def import_seed(args):
    directory=Path(args.input);m=json.loads((directory/'manifest.json').read_text())
    if m.get('format')!=FORMAT or m.get('kind')!='current-state-seed':raise ValueError('wrong seed format')
    identity=m.get('source_identity',{})
    source_identity(tuple(identity.get(k) for k in ('network','genesis_hash','decoder_revision','source_id')),m['network'],m['decoder_revision'])
    if identity['source_id']!=args.expected_source_id:raise ValueError('unexpected seed source id')
    for entry in m['tables'].values():
        if digest(safe_file(directory,entry['file']))!=entry['sha256']:raise ValueError('snapshot checksum mismatch')
    if digest(directory/'active-utxos.copy')!=m['active_utxos']['sha256']:raise ValueError('active UTXO checksum mismatch')
    with connect(args.target_env) as c:
        c.execute("SET LOCAL timezone='UTC'");c.execute("SET LOCAL bytea_output='hex'")
        c.execute("SET LOCAL lock_timeout='5s'")
        identity=c.execute('SELECT network,instance_id::text FROM shadow_v2.identity').fetchone()
        if identity!=(m['network'],args.instance_id):raise ValueError('target shadow identity mismatch')
        if migrations(c)!=m['migrations']:raise ValueError('seed migration identity mismatch')
        control=c.execute('SELECT checkpoint_hash,active_plan FROM shadow_v2.control FOR UPDATE').fetchone()
        if control!=(None,None):raise ValueError('target already seeded or active')
        all_tables=[r[0] for r in c.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename<>'_sqlx_migrations'")]
        if set(m['tables'])!=set(all_tables):raise ValueError('seed must account for every public table')
        for table,entry in m['tables'].items():
            if entry.get('retention')=='current-closure' and table in ('blocks','covenant_utxos'):continue
            if entry.get('retention')!='full' or 'full_state' not in entry:raise ValueError('missing full-state proof: '+table)
            proof=entry['full_state']
            if digest(safe_file(directory,proof['file']))!=proof['sha256']:raise ValueError('full-state proof checksum mismatch')
        # Owner-only, transactional trigger suppression in this empty V2 target.
        # Foreign-key constraints remain enabled and every COPY must satisfy them.
        for table in all_tables:
            c.execute(sql.SQL('ALTER TABLE public.{} DISABLE TRIGGER USER').format(sql.Identifier(table)))
        # Seed catalog defaults are allowed; no existing chain data is overwritten.
        for table in ('blocks','covenants','covenant_utxos','covenant_actions'):
            if c.execute(sql.SQL('SELECT EXISTS(SELECT 1 FROM public.{})').format(sql.Identifier(table))).fetchone()[0]:
                raise ValueError('target contains chain data before import')
        # Inventory order is dependency order. Existing migration defaults are
        # replaced only for named tables; constraints reject an incomplete seed.
        for table in reversed(list(m['tables'])):
            c.execute(sql.SQL('DELETE FROM public.{}').format(sql.Identifier(table)))
        for table,entry in m['tables'].items():
            if [list(row) for row in columns(c,table)]!=entry['columns']:raise ValueError(f'schema mismatch: {table}')
            with c.cursor() as cur, safe_file(directory,entry['file']).open('rb') as f:
                with cur.copy(sql.SQL('COPY public.{} FROM STDIN').format(sql.Identifier(table))) as copy:
                    for block in iter(lambda:f.read(1024*1024),b''):copy.write(block)
                if cur.rowcount!=entry['rows']:raise ValueError(f'row count mismatch: {table}')
        for table,entry in m['tables'].items():
            if entry['retention']!='full':continue
            h=hashlib.sha256()
            with c.cursor() as cur:
                with cur.copy(sql.SQL('COPY ({}) TO STDOUT').format(sql.SQL(full_table_query(c,table)))) as copy:
                    for block in copy:h.update(block)
                count=cur.rowcount
            if h.hexdigest()!=entry['full_state']['sha256'] or count!=entry['full_state']['rows']:
                raise ValueError('seed omits or changes required state: '+table)
        # Sequence positions must follow copied IDs, or the first live insert can collide.
        for table in m['tables']:
            for column,*_ in columns(c,table):
                sequence=c.execute('SELECT pg_get_serial_sequence(%s,%s)',('public.'+table,column)).fetchone()[0]
                if sequence:
                    maximum=c.execute(sql.SQL('SELECT max({}) FROM public.{}').format(sql.Identifier(column),sql.Identifier(table))).fetchone()[0]
                    c.execute('SELECT setval(%s,%s,%s)',(sequence,maximum or 1,maximum is not None))
        h=hashlib.sha256();count=0
        with c.cursor() as cur:
            with cur.copy("COPY (SELECT * FROM covenant_utxos WHERE status='active' ORDER BY txid,vout) TO STDOUT") as copy:
                for block in copy:h.update(block)
            count=cur.rowcount
        if h.hexdigest()!=m['active_utxos']['sha256'] or count!=m['active_utxos']['rows']:
            raise ValueError('seed omits or changes active UTXOs')
        for table in all_tables:
            c.execute(sql.SQL('ALTER TABLE public.{} ENABLE TRIGGER USER').format(sql.Identifier(table)))
        checkpoint=m['checkpoint'];hash_=bytes.fromhex(checkpoint['hash'])
        if c.execute('SELECT blue_score,timestamp_ms FROM blocks WHERE hash=%s AND is_chain_block',(hash_,)).fetchone()!=(checkpoint['score'],checkpoint['timestamp_ms']):
            raise ValueError('seed checkpoint absent or inconsistent')
        c.execute('UPDATE shadow_v2.control SET checkpoint_hash=%s,checkpoint_score=%s,history_start_hash=%s,history_start_score=%s,history_start_ms=%s,seed_manifest=%s,ready=false,source_validated=false',
                  (hash_,checkpoint['score'],hash_,checkpoint['score'],checkpoint['timestamp_ms'],Jsonb(m)))
        c.execute('SELECT shadow_v2.install_guards()')


def backup(args):
    directory=Path(args.output);directory.mkdir(parents=True,exist_ok=False)
    with connect(args.source_env) as c:
        c.execute('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
        c.execute("SET LOCAL timezone='UTC'");c.execute("SET LOCAL bytea_output='hex'")
        control=c.execute('SELECT ready,active_plan,generation,encode(checkpoint_hash,\'hex\'),checkpoint_score,COALESCE(completed_plan,0) FROM shadow_v2.control').fetchone()
        if not control or not control[0] or control[1] is not None:raise ValueError('backup requires a published generation')
        identity=c.execute('SELECT network,instance_id::text FROM shadow_v2.identity').fetchone()
        snapshot=c.execute('SELECT pg_export_snapshot()').fetchone()[0]
        major=c.info.server_version//10000
        environment=pg_environment(args.source_env)
        subprocess.run([pg_tool('pg_dump',major),'--format=custom','--no-owner','--snapshot='+snapshot,'--file='+str(directory/'database.dump')],env=environment,check=True)
        active=copy_out(c,"SELECT * FROM covenant_utxos WHERE status='active' ORDER BY txid,vout",directory/'active-utxos.copy')
        m={'format':FORMAT,'kind':'shadow-backup','network':identity[0],'instance_id':identity[1],
           'completed_plan':control[5],'generation':control[2],'checkpoint':{'hash':control[3],'score':control[4]},
           'decoder_revision':args.decoder_revision,'postgres_major':major,'active_utxos':active,'database_sha256':digest(directory/'database.dump')}
    atomic_manifest(directory,m)


def restore(args):
    directory=Path(args.input);m=json.loads((directory/'manifest.json').read_text())
    if m.get('format')!=FORMAT or m.get('kind')!='shadow-backup':raise ValueError('wrong backup format')
    if digest(directory/'database.dump')!=m['database_sha256']:raise ValueError('backup checksum mismatch')
    if args.decoder_revision!=m['decoder_revision']:raise ValueError('restore requires pinned decoder revision')
    with connect(args.target_env) as c:
        c.execute("SET LOCAL timezone='UTC'");c.execute("SET LOCAL bytea_output='hex'")
        if c.execute("SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname IN ('public','shadow_v2'))").fetchone()[0]:raise ValueError('restore requires empty target')
        major=c.info.server_version//10000
        if major!=m['postgres_major']:raise ValueError('restore requires matching PostgreSQL major')
    environment=pg_environment(args.target_env)
    subprocess.run([pg_tool('pg_restore',major),'--exit-on-error','--single-transaction','--no-owner','--dbname='+environment.get('PGDATABASE','postgres'),str(directory/'database.dump')],env=environment,check=True)
    with connect(args.target_env) as c:
        c.execute("SET LOCAL timezone='UTC'");c.execute("SET LOCAL bytea_output='hex'")
        restored=c.execute("SELECT generation,encode(checkpoint_hash,'hex'),checkpoint_score FROM shadow_v2.control").fetchone()
        if restored!=(m['generation'],m['checkpoint']['hash'],m['checkpoint']['score']):raise ValueError('restored checkpoint mismatch')
        h=hashlib.sha256()
        with c.cursor() as cur:
            with cur.copy("COPY (SELECT * FROM covenant_utxos WHERE status='active' ORDER BY txid,vout) TO STDOUT") as copy:
                for block in copy:h.update(block)
            count=cur.rowcount
        if h.hexdigest()!=m['active_utxos']['sha256'] or count!=m['active_utxos']['rows']:raise ValueError('restored UTXO set mismatch')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('seed-export');p.add_argument('--source-env',default='SHADOW_SEED_SOURCE_DSN');p.add_argument('--inventory',required=True);p.add_argument('--output',required=True)
    p=sub.add_parser('seed-import');p.add_argument('--target-env',default='SHADOW_DATABASE_URL');p.add_argument('--instance-id',required=True);p.add_argument('--expected-source-id',required=True);p.add_argument('--input',required=True)
    p=sub.add_parser('backup');p.add_argument('--source-env',default='SHADOW_DATABASE_URL');p.add_argument('--decoder-revision',required=True);p.add_argument('--output',required=True)
    p=sub.add_parser('restore');p.add_argument('--target-env',default='SHADOW_DATABASE_URL');p.add_argument('--decoder-revision',required=True);p.add_argument('--input',required=True)
    args=parser.parse_args()
    {'seed-export':export_seed,'seed-import':import_seed,'backup':backup,'restore':restore}[args.command](args)

if __name__=='__main__':main()
