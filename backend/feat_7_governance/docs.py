"""Serve design-decision records and the latest interception-proof result."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DECISIONS = ROOT / 'docs' / 'decisions'
INTERCEPT_RESULT = ROOT / 'demo' / '.runtime' / 'last_result.json'

_HEADER = re.compile(r'^#\s*(\d{3})\s+(.+)$', re.M)
_STATUS = re.compile(r'Status:\s*(\w+)\s+Source status:\s*(\w+)', re.I)


def decisions():
    items = []
    for path in sorted(DECISIONS.glob('*.md')):
        try:
            text = path.read_text(encoding='utf-8')
        except OSError:
            continue
        header = _HEADER.search(text)
        status = _STATUS.search(text)
        items.append({
            'id': header.group(1) if header else path.stem[:3],
            'title': header.group(2).strip() if header else path.stem,
            'status': status.group(1).lower() if status else 'unknown',
            'source_status': status.group(2).lower() if status else 'unknown',
            'file': path.name,
            'body': text,
        })
    return {'count': len(items), 'decisions': items}


def intercept_result():
    try:
        return {'available': True, **json.loads(INTERCEPT_RESULT.read_text(encoding='utf-8'))}
    except (OSError, ValueError):
        return {'available': False,
                'message': 'Run `python demo/intercept_check.py` to produce a result.'}
