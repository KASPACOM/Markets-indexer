"""Check the imported boundary without reading the upstream repository."""
from pathlib import Path
import hashlib
import json
import re

root = Path(__file__).resolve().parents[2]
manifest = json.loads((root / 'upstream-files.json').read_text())
changes = json.loads((root / 'extraction-changes.json').read_text())
paths = {entry['path'] for entry in manifest['files']}


def require(condition, message):
    if not condition:
        raise SystemExit(message)


require(set(changes) <= paths, 'override outside import inventory')
for entry in manifest['files']:
    path = root / entry['path']
    expected = changes.get(entry['path'], entry['sha256'])
    require(path.is_file(), f'missing import: {path}')
    require(hashlib.sha256(path.read_bytes()).hexdigest() == expected,
            f'unreviewed import change: {path}')
for source in (root / 'crates').rglob('*.rs'):
    for relative in re.findall(r'include_(?:str|bytes)!\(\s*"([^"\n]+)"', source.read_text()):
        require((source.parent / relative).is_file(),
                f'missing embedded asset: {source}: {relative}')
require((root / 'decoder-compatibility.txt').read_text().strip() == manifest['commit'],
        'decoder compatibility pin differs from reviewed source')
require(not (root / '.gitmodules').exists(), 'unexpected submodule dependency')
print(f"Verified {len(paths)} imported files and embedded asset closure")
