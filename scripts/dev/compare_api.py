#!/usr/bin/env python3
"""Bounded, read-only three-read API parity probe. Unstable data is not a pass."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_BODY = 2 * 1024 * 1024
MAX_PATHS = 32


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def base_url(value):
    parsed = urlsplit(value)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('base URL must be HTTP(S), without credentials, query or fragment')
    host = parsed.hostname.lower()
    host = '[' + host + ']' if ':' in host else host
    port = parsed.port
    if port is not None and port != (443 if parsed.scheme == 'https' else 80):
        host += ':' + str(port)
    return urlunsplit((parsed.scheme, host, parsed.path.rstrip('/'), '', ''))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def fetch(base, path, timeout=5):
    # Isolate DNS, connection and body reads behind a wall-clock deadline.
    # A socket inactivity timeout alone can be defeated by a slow stream.
    try:
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                 '--fetch', base, path, str(timeout), str(MAX_BODY)],
                                capture_output=True, timeout=timeout, check=True)
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {'error': 'request_deadline'}
    except (subprocess.CalledProcessError, OSError, ValueError):
        return {'error': 'request_failed'}


def reject_constant(value):
    raise ValueError('non-finite JSON constant')


def fetch_in_child(base, path, timeout, max_body):
    started = time.monotonic()
    req = Request(base + path, headers={'Cache-Control': 'no-cache, no-store', 'Accept': 'application/json'})
    try:
        try:
            # A target redirect to the source would manufacture a parity pass.
            response = build_opener(NoRedirect).open(req, timeout=timeout)
        except HTTPError as exc:
            response = exc
        with response:
            body = response.read(max_body + 1)
            if len(body) > max_body:
                return {'error': 'response_size_limit'}
            try:
                parsed = json.loads(body, parse_constant=reject_constant)
                digest = hashlib.sha256(canonical(parsed)).hexdigest()
            except (ValueError, UnicodeDecodeError):
                return {'error': 'invalid_json', 'status': response.status}
            return {'status': response.status, 'body': parsed,
                    'sha256': digest,
                    'generation': response.headers.get('x-shadow-generation'),
                    'duration_ms': round((time.monotonic() - started) * 1000, 2)}
    except (URLError, TimeoutError, OSError):
        return {'error': 'request_failed'}


def compare(before, target, after):
    if any('error' in item or item.get('status') != 200 for item in (before, target, after)):
        return 'unavailable'
    if canonical(before['body']) != canonical(after['body']):
        return 'source_changed'
    return 'matched' if canonical(before['body']) == canonical(target['body']) else 'mismatch'


def validate_paths(paths):
    if not isinstance(paths, list) or not 1 <= len(paths) <= MAX_PATHS:
        raise ValueError('paths must contain 1 through 32 relative API paths')
    for path in paths:
        if not isinstance(path, str) or not path.startswith('/') or path.startswith('//') or urlsplit(path).fragment or '\\' in path:
            raise ValueError('invalid relative API path')
        for key, value in parse_qsl(urlsplit(path).query, keep_blank_values=True, strict_parsing=True):
            if key not in ('limit', 'offset', 'from', 'to') or not value.isascii() or not value.isdigit() or len(value) > 19:
                raise ValueError('only numeric limit, offset, from and to query parameters are allowed')
            if key == 'limit' and not 1 <= int(value) <= 100:
                raise ValueError('limit must be between 1 and 100')
    if len(paths) != len(set(paths)):
        raise ValueError('duplicate paths do not count as independent samples')
    return paths


def run(source, target, paths, fetcher=fetch):
    source, target = base_url(source), base_url(target)
    if source == target:
        raise ValueError('source and target must be different endpoints')
    results = []
    for path in validate_paths(paths):
        before, candidate, after = fetcher(source, path), fetcher(target, path), fetcher(source, path)
        status = compare(before, candidate, after)
        results.append({'path': path, 'result': status,
                        'reads': [{k: v for k, v in row.items() if k != 'body'} for row in (before, candidate, after)]})
    counts = {name: sum(r['result'] == name for r in results)
              for name in ('matched', 'mismatch', 'source_changed', 'unavailable')}
    return {'format': 'markets-api-parity/1', 'observed_at_unix_ms': int(time.time() * 1000),
            'source': source, 'target': target, 'counts': counts, 'results': results,
            'passed': counts['matched'] == len(results),
            'scope': 'sampled HTTP response parity only; no full-state or historical certification'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--paths', required=True, help='JSON array of relative supported API routes')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = run(args.source, args.target, json.loads(Path(args.paths).read_text()))
    Path(args.output).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'passed': result['passed'], 'counts': result['counts']}))
    raise SystemExit(0 if result['passed'] else 1 if result['counts']['mismatch'] else 2)


if __name__ == '__main__':
    if sys.argv[1:2] == ['--fetch']:
        print(json.dumps(fetch_in_child(sys.argv[2], sys.argv[3], float(sys.argv[4]), int(sys.argv[5])), allow_nan=False))
    else:
        main()
