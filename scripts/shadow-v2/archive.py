#!/usr/bin/env python3
"""Export completed ordered plans, then replay with a pinned Rust decoder."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import psycopg
from snapshot import atomic_manifest,digest,safe_file


def export(args):
    if not 1<=args.limit<=1000:raise ValueError('plan limit must be 1..1000')
    directory=Path(args.output);directory.mkdir(parents=True,exist_ok=False)
    manifest={'format':'tn10-shadow-archive/1','decoder_revision':args.decoder_revision,'plans':[]}
    with psycopg.connect(os.environ[args.source_env]) as c:
        c.execute('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
        network,instance=c.execute('SELECT network,instance_id::text FROM shadow_v2.identity').fetchone();manifest['network']=network;manifest['instance_id']=instance
        plans=c.execute("SELECT id,encode(base_hash,'hex'),encode(target_hash,'hex'),target_score FROM shadow_v2.plans WHERE id>%s AND status='completed' ORDER BY id LIMIT %s",(args.after_plan,args.limit)).fetchall()
        previous=None
        for plan,base,target,score in plans:
            if previous is not None and base!=previous:raise ValueError('archive plan chain is discontinuous')
            previous=target
            filename=f'{plan}.json';path=directory/filename
            header={'format':'tn10-shadow-plan/1','network':network,'decoder_revision':args.decoder_revision,
                    'instance_id':instance,'source_plan':plan,'base_hash':base,'target_hash':target,'target_score':score}
            # One server-side cursor and one bounded evidence row at a time.
            with path.open('x') as out,c.cursor(name='archive_steps') as cursor:
                out.write(json.dumps(header)[:-1]+',"steps":[')
                cursor.execute('SELECT kind,evidence FROM shadow_v2.steps WHERE plan_id=%s ORDER BY ordinal',(plan,))
                first=True
                for kind,evidence in cursor:
                    if not first:out.write(',')
                    first=False;json.dump({'kind':kind,'evidence':evidence},out)
                out.write(']}\n')
            if path.stat().st_size>64*1024*1024:raise ValueError('archive plan exceeds replay budget')
            # Preimages are retained separately for audit; replay derives effects
            # from the base snapshot and ordered source bytes using the decoder.
            undo=f'{plan}.undo.jsonl'
            with (directory/undo).open('x') as out,c.cursor(name='archive_undo') as cursor:
                cursor.execute('SELECT cursor,table_name,operation,before_row,after_row FROM shadow_v2.undo WHERE plan_id=%s ORDER BY id',(plan,))
                for row in cursor:out.write(json.dumps(row)+'\n')
            manifest['plans'].append({'file':filename,'sha256':digest(path),'base_hash':base,'target_hash':target,
                                      'source_plan':plan,'undo_file':undo,'undo_sha256':digest(directory/undo)})
    atomic_manifest(directory,manifest)


def replay(args):
    directory=Path(args.input);m=json.loads((directory/'manifest.json').read_text())
    if m.get('format')!='tn10-shadow-archive/1' or m.get('decoder_revision')!=args.decoder_revision:
        raise ValueError('archive format or decoder mismatch')
    previous=None
    for plan in m['plans']:
        if previous is not None and plan['base_hash']!=previous:raise ValueError('archive continuity mismatch')
        previous=plan['target_hash']
        if safe_file(directory,plan['file']).stat().st_size>64*1024*1024:raise ValueError('archive plan exceeds byte budget')
        for file_key,hash_key in [('file','sha256'),('undo_file','undo_sha256')]:
            if digest(safe_file(directory,plan[file_key]))!=plan[hash_key]:raise ValueError('archive checksum mismatch')
    for plan in m['plans']:
        with psycopg.connect(os.environ['SHADOW_DATABASE_URL']) as c:
            network,instance=c.execute('SELECT network,instance_id::text FROM shadow_v2.identity').fetchone()
            checkpoint=c.execute("SELECT encode(checkpoint_hash,'hex') FROM shadow_v2.control").fetchone()[0]
            receipt=hashlib.blake2b(safe_file(directory,plan['file']).read_bytes(),digest_size=32).digest()
            completed=c.execute("SELECT EXISTS(SELECT 1 FROM shadow_v2.plans WHERE archive_digest=%s AND status='completed')",(receipt,)).fetchone()[0]
        if (network,instance)!=(m['network'],m['instance_id']):raise ValueError('archive network or snapshot instance mismatch')
        if completed:continue
        if checkpoint!=plan['base_hash']:raise ValueError('archive does not continue target checkpoint')
        subprocess.run([args.binary,'replay','--plan',str(safe_file(directory,plan['file']))],check=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('export');p.add_argument('--source-env',default='SHADOW_DATABASE_URL');p.add_argument('--output',required=True);p.add_argument('--after-plan',type=int,required=True);p.add_argument('--limit',type=int,default=100);p.add_argument('--decoder-revision',required=True)
    p=sub.add_parser('replay');p.add_argument('--input',required=True);p.add_argument('--decoder-revision',required=True);p.add_argument('--binary',default='tn10-shadow-indexer')
    args=parser.parse_args();{'export':export,'replay':replay}[args.command](args)

if __name__=='__main__':main()
