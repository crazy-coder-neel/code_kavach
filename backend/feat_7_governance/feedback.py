"""Contestability store. Feedback is metadata + a code hash; raw code is not stored."""
import json
import os
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from threading import Lock
from uuid import uuid4

DIRECTORY = Path(os.environ.get('CODEGUARD_FEEDBACK_DIR',
                                Path(__file__).resolve().parents[1] / '.local' / 'feedback'))
LOCK = Lock()
KINDS = frozenset(('false_positive', 'false_negative', 'other'))


def submit(request_id, kind, note='', code=None):
    if kind not in KINDS:
        raise ValueError('kind must be false_positive, false_negative or other')
    if not isinstance(request_id, str) or not 1 <= len(request_id) <= 128:
        raise ValueError('request_id is required')
    record = {
        'id': str(uuid4()),
        'request_id': request_id,
        'kind': kind,
        'note': (note or '')[:2000],
        'code_sha256': sha256(code.encode()).hexdigest() if isinstance(code, str) else None,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'status': 'triaged',
    }
    with LOCK:
        DIRECTORY.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = DIRECTORY / 'feedback.jsonl'
        fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        try:
            os.write(fd, (json.dumps(record, separators=(',', ':')) + '\n').encode())
            os.fsync(fd)
        finally:
            os.close(fd)
    return record


def summary():
    path = DIRECTORY / 'feedback.jsonl'
    try:
        rows = [json.loads(line) for line in path.read_bytes().splitlines() if line.strip()]
    except (OSError, ValueError):
        rows = []
    counts = {}
    for row in rows:
        counts[row.get('kind', 'other')] = counts.get(row.get('kind', 'other'), 0) + 1
    return {'total': len(rows), 'by_kind': counts,
            'raw_code_stored': False, 'latest': rows[-5:]}
