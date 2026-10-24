"""Local durable JSONL audit with a SHA-256 hash chain. No submitted source."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
from threading import Lock
from threading import Condition, Thread
from collections import deque

DIRECTORY = Path(os.environ.get('CODEGUARD_AUDIT_DIR', Path(__file__).resolve().parents[1] / '.local' / 'audit'))
MAX_BYTES = 5 * 1024 * 1024
LOCK = Lock()
GENESIS = '0' * 64


class AuditQueue:
    """One writer per worker; bounded memory and drop-oldest overflow."""
    def __init__(self, writer=None, capacity=1024):
        self.writer = writer or append_event
        self.capacity = capacity
        self.pending = deque()
        self.condition = Condition()
        self.thread = None
        self.stopping = False
        self.dropped = self.errors = self.written = 0

    def start(self):
        with self.condition:
            if self.thread and self.thread.is_alive():
                return
            self.stopping = False
            self.thread = Thread(target=self._run, name='codeguard-audit', daemon=True)
            self.thread.start()

    def enqueue(self, event):
        with self.condition:
            if self.stopping:
                self.dropped += 1
                return False
            if len(self.pending) >= self.capacity:
                self.pending.popleft()
                self.dropped += 1
            self.pending.append(event)
            self.condition.notify()
            return True

    def _run(self):
        while True:
            with self.condition:
                self.condition.wait_for(lambda: self.pending or self.stopping)
                if not self.pending:
                    return
                event = self.pending.popleft()
            try:
                self.writer(event)
                with self.condition:
                    self.written += 1
            except Exception:
                with self.condition:
                    self.errors += 1

    def close(self):
        with self.condition:
            self.stopping = True
            self.condition.notify_all()
        if self.thread:
            self.thread.join(timeout=2)

    def stats(self):
        with self.condition:
            return dict(queued=len(self.pending), dropped=self.dropped,
                        errors=self.errors, written=self.written)


def _canonical(event):
    return json.dumps(event, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def _last_hash():
    path = DIRECTORY / 'chain.json'
    try:
        return json.loads(path.read_text())['last_hash']
    except (OSError, ValueError, KeyError):
        return GENESIS


def append_event(event):
    """Append one event and extend the SHA-256 chain (hash over previous hash)."""
    with LOCK:
        DIRECTORY.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_fd = os.open(DIRECTORY / '.lock', os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            chain_file = DIRECTORY / 'chain.json'
            legacy = DIRECTORY / 'events.jsonl'
            if not chain_file.exists() and legacy.exists() and legacy.stat().st_size:
                # Preserve pre-chain records under a separate name so the chain
                # verifies from genesis without discarding historical events.
                os.replace(legacy, DIRECTORY / 'events.legacy.jsonl')
            previous = _last_hash()
            body = {**event, 'prev_hash': previous}
            digest = hashlib.sha256(previous.encode() + _canonical(body)).hexdigest()
            record = {**body, 'hash': digest}
            payload = (json.dumps(record, separators=(',', ':'), ensure_ascii=True) + '\n').encode()
            path = DIRECTORY / 'events.jsonl'
            if path.exists() and path.stat().st_size + len(payload) > MAX_BYTES:
                for index in (2, 1):
                    source = DIRECTORY / ('events.jsonl' if index == 1 else 'events.jsonl.1')
                    if source.exists():
                        os.replace(source, DIRECTORY / f'events.jsonl.{index}')
            fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            chain = DIRECTORY / 'chain.json'
            fd = os.open(chain, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
            try:
                os.write(fd, json.dumps({'last_hash': digest, 'records': _record_count()}).encode())
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.close(lock_fd)


def _record_count():
    path = DIRECTORY / 'events.jsonl'
    try:
        with path.open('rb') as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


def verify_chain():
    """Recompute the chain and report the first broken index, if any."""
    path = DIRECTORY / 'events.jsonl'
    try:
        lines = [line for line in path.read_bytes().splitlines() if line.strip()]
    except OSError:
        return {'valid': True, 'records': 0, 'first_broken_index': None,
                'message': 'No audit records yet.'}
    previous = GENESIS
    for index, line in enumerate(lines):
        try:
            record = json.loads(line)
        except ValueError:
            return {'valid': False, 'records': len(lines), 'first_broken_index': index,
                    'message': 'Record is not valid JSON.'}
        claimed = record.pop('hash', None)
        if record.get('prev_hash') != previous:
            return {'valid': False, 'records': len(lines), 'first_broken_index': index,
                    'message': 'prev_hash does not match the previous record.'}
        expected = hashlib.sha256(previous.encode() + _canonical(record)).hexdigest()
        if claimed != expected:
            return {'valid': False, 'records': len(lines), 'first_broken_index': index,
                    'message': 'Record hash does not match its contents.'}
        previous = claimed
    return {'valid': True, 'records': len(lines), 'first_broken_index': None,
            'last_hash': previous, 'message': 'Hash chain verified.'}

