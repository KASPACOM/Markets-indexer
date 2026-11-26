import importlib.util
import pathlib
import sys
import tempfile
import unittest
from unittest import mock
spec=importlib.util.spec_from_file_location('audit',pathlib.Path(__file__).resolve().parents[1]/'tn10_recovery_audit.py')
audit=importlib.util.module_from_spec(spec); spec.loader.exec_module(audit)
class AuditTests(unittest.TestCase):
    def test_same_count_different_block_is_a_mismatch(self):
        self.assertTrue(audit.compare({100:(2,'a'*64)},{100:(2,'b'*64)},100,200))
    def test_missing_window_is_a_mismatch(self):
        self.assertTrue(audit.compare({100:(2,'a'*64)},{},100,200))
    def test_sql_output_cannot_silently_hide_an_error(self):
        with self.assertRaises(ValueError): audit.parse_rows('ERROR: timeout')
        with self.assertRaises(ValueError): audit.parse_rows(('100|1|'+'a'*64+'\n')*2)
    def test_duplicate_or_skipped_success_cannot_advance_resume(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'audit.jsonl'
            p.write_text('{"status":"matched","audit_version":2,"start":200,"end":300}\n')
            with self.assertRaises(ValueError): audit.resume_cursor(p,100,300)
    def test_errors_never_advance_cursor(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'audit.jsonl'
            p.write_text('{"status":"error","start":100,"end":200}\n')
            self.assertEqual(audit.resume_cursor(p,100,300),100)
    def test_source_availability_required_even_when_both_have_no_candidates(self):
        with self.assertRaises(audit.SourceHistoryUnavailable): audit.compare({}, {}, 100, 200)
        empty = (0, audit.hashlib.sha256(b'').hexdigest())
        self.assertEqual(audit.compare({100: empty}, {}, 100, 200), [])
    def test_source_unavailable_is_recorded_and_never_retried(self):
        with tempfile.TemporaryDirectory() as d:
            output = pathlib.Path(d)/'audit.jsonl'
            argv = ['audit.py','--start','100','--end','200','--output',str(output)]
            with mock.patch.object(sys,'argv',argv), \
                 mock.patch.object(audit,'healthy'), \
                 mock.patch.object(audit,'query',return_value={}), \
                 mock.patch.object(audit.time,'sleep') as sleep:
                with self.assertRaises(SystemExit): audit.main()
                sleep.assert_not_called()
            row = audit.json.loads(output.read_text().splitlines()[0])
            self.assertEqual(row['status'],'source_unavailable')
            self.assertEqual(audit.resume_cursor(output,100,200),100)
    def test_follow_target_waits_for_cursor_and_mature_source(self):
        coverage = {'sourceTipBlueScore': 10250,
                    'historyCursorBlueScore': 9400}
        self.assertEqual(audit.follow_target(coverage), 9200)
        coverage['historyCursorBlueScore'] = 8500
        self.assertEqual(audit.follow_target(coverage), 8500)
        with self.assertRaises(ValueError): audit.follow_target({'sourceTipBlueScore': 10250})
    def test_window_size_is_aligned_and_bounded(self):
        self.assertEqual(audit.next_window_end(100, 1000, 300), 400)
        self.assertEqual(audit.next_window_end(900, 1000, 300), 1000)
        for size in [0, 101, 1100]:
            with self.assertRaises(ValueError): audit.next_window_end(100, 1000, size)
    def test_old_evidence_cannot_certify_current_version(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'audit.jsonl'
            p.write_text('{"status":"matched","start":100,"end":200}\n')
            with self.assertRaises(ValueError): audit.resume_cursor(p,100,300)
    def test_queries_are_bounded_read_only(self):
        for source in [False,True]: self.assertIn('BEGIN READ ONLY',audit.sql(100,200,source))
        with self.assertRaises(AssertionError): audit.sql(100,2000,True)
    def test_follow_writes_only_reached_mature_window_and_never_certifies(self):
        class StopAfterFirstWindow(Exception): pass
        empty = (0, audit.hashlib.sha256(b'').hexdigest())
        coverage = {'coverage': {'sourceTipBlueScore': 3200,
                                 'historyCursorBlueScore': 2100}}
        with tempfile.TemporaryDirectory() as d:
            output = pathlib.Path(d)/'audit.jsonl'
            argv = ['audit.py','--start','100','--follow','--output',str(output)]
            with mock.patch.object(sys,'argv',argv), \
                 mock.patch.object(audit,'get_json',return_value=coverage), \
                 mock.patch.object(audit,'healthy'), \
                 mock.patch.object(audit,'query',return_value={100:empty}), \
                 mock.patch.object(audit.time,'sleep',side_effect=StopAfterFirstWindow):
                with self.assertRaises(StopAfterFirstWindow): audit.main()
            rows = [audit.json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual([(r['start'],r['end'],r['status']) for r in rows],[(100,200,'matched')])
            self.assertEqual(audit.resume_cursor(output,100,2100),200)
if __name__=='__main__': unittest.main()
