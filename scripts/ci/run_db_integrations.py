#!/usr/bin/env python3
"""Partition every DB integration target exactly once, with isolated databases."""
import argparse
import json
import subprocess


def select(targets, shard):
    if shard not in ('heavy', 'other'):
        raise ValueError('Unknown DB integration shard')
    heavy = {'repo', 'reorg_batch'}
    return sorted(name for name in targets if (name in heavy) == (shard == 'heavy'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('shard', choices=['heavy', 'other'])
    args = parser.parse_args()
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1'], text=True))
    package = next(p for p in metadata['packages'] if p['name'] == 'tn12-indexer-db')
    targets = [t['name'] for t in package['targets'] if 'test' in t['kind']]
    selected = select(targets, args.shard)
    if not selected:
        raise SystemExit('DB integration shard unexpectedly empty')
    print(json.dumps({'shard': args.shard, 'targets': selected}), flush=True)
    command = ['cargo', 'test', '--locked', '-p', 'tn12-indexer-db']
    for target in selected:
        command += ['--test', target]
    subprocess.run(command, check=True)


if __name__ == '__main__':
    main()
