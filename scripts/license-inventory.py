"""Record installed metadata; does not certify licence eligibility."""
import importlib.metadata
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
rows = []
for path in sorted((ROOT / 'node_modules').glob('**/package.json')):
    # Only package roots, not examples or embedded source manifests.
    relative = path.relative_to(ROOT / 'node_modules')
    parts = relative.parts
    if len(parts) != (3 if parts[0].startswith('@') else 2):
        continue
    data = json.loads(path.read_text())
    rows.append({'ecosystem': 'npm', 'name': data.get('name', str(relative)),
                 'version': data.get('version'), 'license': data.get('license', 'UNDECLARED'),
                 'source': str(path.relative_to(ROOT))})
for dist in sorted(importlib.metadata.distributions(), key=lambda d: d.metadata['Name'].lower()):
    metadata = dist.metadata
    licence = metadata.get('License-Expression') or metadata.get('License')
    if not licence:
        licence = '; '.join(c for c in metadata.get_all('Classifier', []) if c.startswith('License ::')) or 'UNDECLARED'
    rows.append({'ecosystem': 'python', 'name': metadata['Name'], 'version': dist.version,
                 'license': licence, 'source': 'installed distribution metadata'})
(ROOT / 'docs' / 'licenses.json').write_text(json.dumps(rows, indent=2) + '\n')
print(f'Recorded {len(rows)} installed distributions in docs/licenses.json')
