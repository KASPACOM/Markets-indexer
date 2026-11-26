#!/usr/bin/env bash
set -euo pipefail
python3 scripts/ci/verify_import.py
python3 -m unittest discover -s scripts/tests -p test_import_boundary.py -v
python3 scripts/shadow-v2/test_coordination.py
python3 scripts/shadow-v2/test_snapshot.py
python3 scripts/shadow-v2/test_archive.py
