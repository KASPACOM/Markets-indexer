#!/usr/bin/env python3
"""Read-only, resumable acceptance-set audit. Never certifies KCC20 projections."""
import argparse
import concurrent.futures
import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import subprocess
import time
import urllib.request


class SourceHistoryUnavailable(ValueError):
    """The independent source cannot prove a requested historical window."""


def next_window_end(start, target, batch_scores):
    if start < 0 or start % 100 or target <= start or target % 100:
        raise ValueError('audit bounds must increase and align to 100 scores')
    if batch_scores < 100 or batch_scores > 1000 or batch_scores % 100:
        raise ValueError('batch size must be 100–1000 scores in steps of 100')
    return min(start + batch_scores, target)


def follow_target(coverage):
    tip = coverage.get('sourceTipBlueScore')
    cursor = coverage.get('historyCursorBlueScore')
    if not isinstance(tip, int) or not isinstance(cursor, int) or tip < 1000 or cursor < 0:
        raise ValueError('fresh source tip and indexer history cursor are required')
    # The cursor is a reachability bound, not proof of parity. The audit below
    # performs its own independent comparison for every requested window.
    return min(tip - 1000, cursor) // 100 * 100


def parse_rows(text):
    result = {}
    for line in text.splitlines():
        if not line or line.startswith(('SET', 'BEGIN', 'COMMIT')):
            continue
        parts = line.split('|')
        if len(parts) != 3 or not parts[0].isdigit() or not parts[1].isdigit():
            raise ValueError('unexpected SQL audit output')
        key = int(parts[0])
        if key in result or len(parts[2]) != 64 or any(c not in '0123456789abcdef' for c in parts[2]):
            raise ValueError('duplicate window or invalid digest')
        result[key] = (int(parts[1]), parts[2])
    return result


def compare(source, target, start, end):
    if any(k < start or k >= end or k % 100 for k in source.keys() | target.keys()):
        raise ValueError('audit returned a window outside its range')
    if set(source) != set(range(start, end, 100)):
        raise SourceHistoryUnavailable('historical source block availability is unproven; retain range')
    empty = (0, hashlib.sha256(b'').hexdigest())
    return [{'window': w, 'source': source.get(w), 'indexer': target.get(w)}
            for w in sorted(source.keys() | target.keys()) if source.get(w, empty) != target.get(w, empty)]


def sql(start, end, source):
    assert isinstance(start, int) and isinstance(end, int) and 0 <= start < end <= start + 1000
    if source:
        script = "octet_length(script)=35 AND substring(script from 1 for 2)=decode('aa20','hex') AND substring(script from 35 for 1)=decode('87','hex')"
        output = script.replace('script', '(o).script_public_key')
        inp = script.replace('script', '(i).previous_outpoint_script')
        # Keep each lookup tied to the bounded block window. A flattened join
        # can scan the entire source tables when a dense window is overestimated.
        rows = f"""SELECT DISTINCT (b.blue_score/100)*100 win, encode(a.transaction_id,'hex')||':'||encode(b.hash,'hex') item
          FROM w b CROSS JOIN LATERAL (SELECT transaction_id FROM transactions_acceptances
          WHERE block_hash=b.hash OFFSET 0) a
          CROSS JOIN LATERAL (SELECT inputs,outputs FROM transactions
          WHERE transaction_id=a.transaction_id OFFSET 0) t
          WHERE EXISTS(SELECT 1 FROM unnest(t.outputs) o WHERE {output})
             OR EXISTS(SELECT 1 FROM unnest(t.inputs) i WHERE {inp})"""
        canonical = ''  # transactions_acceptances is the source's current acceptance mapping.
    else:
        rows = """SELECT DISTINCT (b.blue_score/100)*100 win,encode(a.txid,'hex')||':'||encode(b.hash,'hex') item
          FROM w b CROSS JOIN LATERAL (SELECT txid FROM covenant_actions WHERE block_hash=b.hash OFFSET 0) a"""
        canonical = 'AND is_chain_block'
    aggregate = "SELECT win,count(*) n,encode(sha256(convert_to(string_agg(item,'|' ORDER BY item),'UTF8')),'hex') digest FROM candidates GROUP BY win"
    output = "SELECT win,n,digest FROM digests ORDER BY win"
    if source:
        output = "SELECT win,coalesce(n,0),coalesce(digest,encode(sha256(''::bytea),'hex')) FROM (SELECT DISTINCT (blue_score/100)*100 win FROM w) windows LEFT JOIN digests USING(win) ORDER BY win"
    return f"""BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='500ms'; SET LOCAL jit=off;
      WITH w AS MATERIALIZED (SELECT hash,blue_score FROM blocks WHERE blue_score>={start} AND blue_score<{end} {canonical}),
      candidates AS ({rows}), digests AS ({aggregate})
      {output}; COMMIT;"""


def query(statement, source):
    if source:
        command = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', 'tn10-node',
                   'docker exec -i tn10_kaspa_db psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d tn10_source_v23_probe']
    else:
        command = ['kubectl', '--context', 'dev', '-n', 'graph-node', 'exec', '-i',
                   'tn10-canonical-standby-0', '-c', 'postgres', '--', 'sh', '-c',
                   'exec psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d tn10_indexer_dev']
    result = subprocess.run(command, input=statement, text=True, capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError(result.stderr[-500:])
    return parse_rows(result.stdout)


def get_json(url):
    request = urllib.request.Request(url + ('&' if '?' in url else '?') + 'audit_observation=' + str(time.time_ns()),
        headers={'User-Agent': 'Mozilla/5.0', 'Cache-Control': 'no-cache, no-store'})
    with urllib.request.urlopen(request, timeout=12) as response:
        age = int(response.headers.get('Age', '0'))
        if age > 15:
            raise RuntimeError('cached source observation')
        return json.load(response)


def healthy(end):
    live = get_json('https://tn10-indexer.kaspa.com/health/live')
    rest = get_json('https://tn10-node.kaspa.com/rest/info/health')
    if live.get('ok') is not True or not live.get('source', {}).get('synced'):
        raise RuntimeError('live indexing unavailable; audit paused')
    node = live['source']
    if node['network'] != 'testnet-10' or abs(time.time()*1000-node['observedAtMs']) > 15000:
        raise RuntimeError('node identity or freshness unavailable')
    db = rest['database']
    if not db['isSynced'] or db['blueScore'] < end or db['acceptedTxBlockTimeDiff'] > 15:
        raise RuntimeError('REST acceptance publication unavailable')
    scanner = live['scanner']
    indexed = scanner.get('latestBlockIndexedAtMs')
    accepted = scanner.get('latestBlockTimeMs')
    if indexed and accepted and indexed-accepted > 2000:
        raise RuntimeError('live latency exceeded budget; audit paused')


def resume_cursor(path, start, end):
    cursor = start
    if path.exists():
        for line in path.read_text().splitlines():
            row = json.loads(line)
            if row.get('status') == 'matched':
                if row.get('audit_version') != 2:
                    raise ValueError('audit version changed; retain old evidence and use a new output')
                if row['start'] != cursor or not cursor < row['end'] <= end:
                    raise ValueError('audit evidence is noncontiguous or belongs to another range')
                cursor = row['end']
    return cursor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--start', type=int, required=True)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--end', type=int)
    target.add_argument('--follow', action='store_true', help='audit windows reached by the history cursor and at least 1000 scores behind the source tip')
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--batch-scores', type=int, help='100–1000 aligned scores per bounded read (follow default: 100)')
    parser.add_argument('--max-hours', type=float, default=48)
    args = parser.parse_args()
    batch_scores = args.batch_scores if args.batch_scores is not None else (100 if args.follow else 1000)
    if args.start < 0 or args.start % 100 or (args.end is not None and (args.end <= args.start or args.end % 100)):
        parser.error('use increasing nonnegative bounds aligned to 100 scores')
    if batch_scores < 100 or batch_scores > 1000 or batch_scores % 100:
        parser.error('--batch-scores must be 100–1000 in steps of 100')
    if args.follow and args.max_hours != 48:
        parser.error('--max-hours is only for a fixed --end audit')
    deadline = None if args.follow else time.monotonic() + args.max_hours*3600
    with args.output.open('a') as log, concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
        fcntl.flock(log, fcntl.LOCK_EX | fcntl.LOCK_NB)
        cursor = resume_cursor(args.output, args.start, args.end if args.end is not None else 2**63-1)
        while deadline is None or time.monotonic() < deadline:
            try:
                target_end = follow_target(get_json('https://tn10-indexer.kaspa.com/health/history')['coverage']) if args.follow else args.end
            except Exception as error:
                if not args.follow:
                    raise
                print(json.dumps({'status':'waiting_for_source_or_history_cursor','next':cursor,'error':str(error)[:200]}),flush=True)
                time.sleep(30)
                continue
            if target_end <= cursor:
                if not args.follow:
                    break
                time.sleep(10)
                continue
            end = next_window_end(cursor,target_end,batch_scores)
            row = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'start': cursor, 'end': end,
                   'audit_version': 2, 'scope': 'canonical P2SH transaction/accepting-block sets only; projections unverified'}
            started = time.monotonic()
            try:
                healthy(end)
                source = workers.submit(query, sql(cursor,end,True), True)
                target = workers.submit(query, sql(cursor,end,False), False)
                source, target = source.result(), target.result()
                differences = compare(source,target,cursor,end)
                row['differences'] = differences
                row['status'] = 'different' if differences else 'matched'
                row['source_digest'] = hashlib.sha256(json.dumps(source,sort_keys=True).encode()).hexdigest()
                row['indexer_digest'] = hashlib.sha256(json.dumps(target,sort_keys=True).encode()).hexdigest()
                row['candidates'] = sum(v[0] for v in source.values())
                if not differences:
                    cursor = end
            except Exception as error:
                row.update(status='source_unavailable' if isinstance(error, SourceHistoryUnavailable) else 'error', error=str(error)[:500])
            row['seconds'] = round(time.monotonic()-started,3)
            log.write(json.dumps(row)+'\n'); log.flush(); os.fsync(log.fileno())
            if row['status']=='different':
                raise SystemExit('Parity mismatch recorded; cursor retained for investigation')
            if row['status']=='source_unavailable':
                raise SystemExit('Independent source history unavailable; checkpoint unchanged')
            time.sleep(1 if row['status']=='matched' else 30)
    print(json.dumps({'next':cursor,'target':args.end,'acceptance_sets_complete':not args.follow and cursor==args.end,'historical_coverage_verified':False}))

if __name__ == '__main__':
    main()
