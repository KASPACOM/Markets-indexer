import importlib.util
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('parity', Path(__file__).resolve().parents[1] / 'dev/compare_api.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def response(body, status=200):
    return {'status': status, 'body': body}


class Parity(unittest.TestCase):
    def test_exact_match_accepts_object_key_order(self):
        self.assertEqual(p.compare(response({'a': 1, 'b': 2}), response({'b': 2, 'a': 1}), response({'a': 1, 'b': 2})), 'matched')

    def test_ordered_results_and_balances_are_not_normalized_away(self):
        self.assertEqual(p.compare(response([1, 2]), response([2, 1]), response([1, 2])), 'mismatch')
        self.assertEqual(p.compare(response({'balance': 1}), response({'balance': 2}), response({'balance': 1})), 'mismatch')

    def test_changing_source_is_inconclusive(self):
        self.assertEqual(p.compare(response([1]), response([1]), response([2])), 'source_changed')

    def test_equal_errors_are_never_parity(self):
        self.assertEqual(p.compare(response({}, 503), response({}, 503), response({}, 503)), 'unavailable')
        self.assertEqual(p.compare(response({}), {'error': 'invalid_json'}, response({})), 'unavailable')

    def test_all_unstable_is_not_success(self):
        reads = iter([response([1]), response([1]), response([2])])
        result = p.run('http://source', 'http://target', ['/utxos'], lambda *_: next(reads))
        self.assertFalse(result['passed'])
        self.assertEqual(result['counts']['source_changed'], 1)

    def test_reject_empty_and_duplicate_probe_sets(self):
        for paths in ([], ['/utxos', '/utxos'], ['//another-host/utxos'], ['/utxos'] * 33):
            with self.assertRaises(ValueError): p.validate_paths(paths)

    def test_same_endpoint_and_credentials_rejected(self):
        with self.assertRaises(ValueError): p.run('http://same/', 'http://same', ['/utxos'])
        with self.assertRaises(ValueError): p.base_url('https://user:secret@example.com')
        for source, target in [('http://HOST', 'http://host:80'), ('https://HOST/', 'https://host:443')]:
            with self.assertRaises(ValueError): p.run(source, target, ['/utxos'])

    def test_only_reviewed_numeric_query_parameters(self):
        self.assertEqual(p.validate_paths(['/utxos?limit=10&offset=0']), ['/utxos?limit=10&offset=0'])
        for path in ['/utxos?token=secret', '/utxos?limit=secret', '/utxos?limit=101', '/utxos?limit=0']:
            with self.assertRaises(ValueError): p.validate_paths([path])


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        status, body = 200, b'{"utxos":[{"amount":5}]}'
        if self.path.startswith('/changed/'): body = b'{"utxos":[{"amount":6}]}'
        if self.path == '/invalid': body = b'not JSON'
        if self.path == '/oversized': body = b'"' + b'x' * 1024 + b'"'
        if self.path == '/nan': body = b'{"amount":NaN}'
        if self.path == '/infinity': body = b'{"amount":Infinity}'
        if self.path == '/overflow': body = b'{"amount":1e9999}'
        if self.path == '/unready': status = 503
        if self.path == '/redirect': status = 302
        self.send_response(status)
        if status == 302: self.send_header('Location', '/utxos')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('x-shadow-generation', '7')
        self.end_headers()
        try:
            if self.path == '/slow':
                for byte in body:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.05)
            else:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError): pass

    def log_message(self, *_): pass


class HttpParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = [ThreadingHTTPServer(('127.0.0.1', 0), Handler) for _ in range(2)]
        cls.threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in cls.servers]
        for t in cls.threads: t.start()
        cls.source, cls.target = [f'http://127.0.0.1:{s.server_port}' for s in cls.servers]

    @classmethod
    def tearDownClass(cls):
        for s in cls.servers:
            s.shutdown()
            s.server_close()
        for t in cls.threads: t.join()

    def test_two_servers_record_hashes_without_bodies(self):
        report = p.run(self.source, self.target, ['/utxos'])
        self.assertTrue(report['passed'])
        for read in report['results'][0]['reads']:
            self.assertEqual(read['generation'], '7')
            self.assertEqual(len(read['sha256']), 64)
            self.assertNotIn('body', read)

    def test_http_error_redirect_and_invalid_json_fail_closed(self):
        for path in ('/unready', '/redirect', '/invalid'):
            report = p.run(self.source, self.target, [path])
            self.assertFalse(report['passed'])
            self.assertEqual(report['counts']['unavailable'], 1)

    def test_response_size_bound(self):
        with patch.object(p, 'MAX_BODY', 64):
            self.assertEqual(p.fetch(self.source, '/oversized'), {'error': 'response_size_limit'})

    def test_nonfinite_and_overflow_json_never_match(self):
        for path in ('/nan', '/infinity', '/overflow'):
            self.assertEqual(p.fetch(self.source, path)['error'], 'invalid_json')

    def test_slow_stream_has_wall_clock_deadline(self):
        start = time.monotonic()
        self.assertEqual(p.fetch(self.source, '/slow', timeout=0.3), {'error': 'request_deadline'})
        self.assertLess(time.monotonic() - start, 1.5)

    def test_cli_exit_status_and_evidence_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths, output = Path(tmp) / 'paths.json', Path(tmp) / 'report.json'
            for route, target, expected in (('/utxos', self.target, 0),
                                             ('/utxos', self.target + '/changed', 1),
                                             ('/unready', self.target, 2)):
                paths.write_text(json.dumps([route]))
                result = subprocess.run([sys.executable, p.__file__, '--source', self.source,
                                         '--target', target, '--paths', str(paths),
                                         '--output', str(output)], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr.decode())
                self.assertEqual(json.loads(output.read_text())['passed'], expected == 0)
