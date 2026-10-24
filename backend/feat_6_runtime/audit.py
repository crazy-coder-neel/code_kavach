"""Local durable JSONL audit. Single-host file locking; no submitted source."""
import fcntl
import json
import os
from pathlib import Path
from threading import Lock
from threading import Condition, Thread
from collections import deque

DIRECTORY = Path(os.environ.get('CODEGUARD_AUDIT_DIR', Path(__file__).resolve().parents[1] / '.local' / 'audit'))
MAX_BYTES = 5 * 1024 * 1024
LOCK = Lock()


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


def append_event(event):
    payload = (json.dumps(event, separators=(',', ':'), ensure_ascii=True) + '\n').encode()
    with LOCK:
        DIRECTORY.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_fd = os.open(DIRECTORY / '.lock', os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
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
        finally:
            os.close(lock_fd)
