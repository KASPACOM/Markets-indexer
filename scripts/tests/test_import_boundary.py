"""Exercise provenance failures in a temporary synthetic repository, including -O."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ImportBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'scripts/ci').mkdir(parents=True)
        (self.root / 'crates/test/src').mkdir(parents=True)
        shutil.copyfile(ROOT / 'scripts/ci/verify_import.py', self.root / 'scripts/ci/verify_import.py')
        self.data = self.root / 'crates/test/src/lib.rs'
        self.data.write_text('pub fn example() {}\n')
        self.record()
        (self.root / 'decoder-compatibility.txt').write_text('synthetic\n')
        (self.root / 'extraction-changes.json').write_text('{}')

    def record(self):
        (self.root / 'upstream-files.json').write_text(json.dumps({
            'commit': 'synthetic', 'files': [{'path': str(self.data.relative_to(self.root)),
            'sha256': hashlib.sha256(self.data.read_bytes()).hexdigest()}]}))

    def run_check(self):
        return subprocess.run([sys.executable, '-O', 'scripts/ci/verify_import.py'],
                              cwd=self.root, capture_output=True, text=True)

    def test_clean_import_passes(self):
        self.assertEqual(self.run_check().returncode, 0)

    def test_modified_source_rejected_even_with_optimization(self):
        self.data.write_text('modified\n')
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unreviewed import change', result.stderr)

    def test_missing_embedded_asset_rejected(self):
        self.data.write_text('const DATA: &str = include_str!("missing.json");\n')
        self.record()
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('missing embedded asset', result.stderr)

    def test_changed_decoder_pin_rejected(self):
        (self.root / 'decoder-compatibility.txt').write_text('different')
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('decoder compatibility pin', result.stderr)
