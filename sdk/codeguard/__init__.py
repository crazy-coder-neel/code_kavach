"""CodeGuard interception SDK.

The detector returns JSON; *this* layer enforces it. The wrapper scans the exact
bytes it will execute, refuses to run anything blocked, and fails closed on any
transport, timeout or schema error.

No submitted code is ever executed by this module except through
:class:`GuardedExecutor`, which the caller must explicitly invoke and which is
restricted (temp dir, rlimits, timeout, scrubbed environment).
"""
from __future__ import annotations

import hashlib
import json
import os
import resource
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from contextlib import nullcontext
from pathlib import Path

__all__ = [
    "BlockedByCodeGuard",
    "Guard",
    "GuardedExecutor",
    "guard",
    "guarded_execute",
]

VERSION = "0.1.0"
CATEGORIES = frozenset((
    "secret_access", "data_exfiltration", "destructive_command",
    "persistence_or_privesc", "obfuscated_execution", "dependency_risk",
    "resource_exhaustion", "ssrf_network_exfil", "ai_targeted_instructions",
))

_REPO_ROOT = Path(__file__).resolve().parents[2]
_BACKEND = _REPO_ROOT / "backend"


class BlockedByCodeGuard(Exception):
    """Raised when a verdict is block, or when no trustworthy verdict exists."""

    def __init__(self, reason, verdict=None):
        self.verdict = verdict or {}
        self.reason = reason
        super().__init__(reason)


def _valid(payload):
    """Schema validation; anything unexpected is treated as untrusted."""
    if not isinstance(payload, dict):
        return False
    if payload.get("verdict") not in ("allow", "block"):
        return False
    score = payload.get("risk_score")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 1:
        return False
    categories = payload.get("categories")
    if not isinstance(categories, list) or not all(c in CATEGORIES for c in categories):
        return False
    return isinstance(payload.get("code_language"), str) and bool(payload.get("code_language"))


class Guard:
    """Client for the CodeGuard detector.

    If ``base_url`` (or ``CODEGUARD_BASE_URL``) is set, the guard calls the HTTP
    service; otherwise it calls the identical engine in-process. Both paths fail
    closed: an invalid response is raised, never downgraded to ``allow``.
    """

    def __init__(self, base_url=None, timeout=2.0):
        self.base_url = (base_url or os.environ.get("CODEGUARD_BASE_URL") or "").rstrip("/")
        self.timeout = timeout

    def scan(self, code):
        if not isinstance(code, str):
            raise BlockedByCodeGuard("Non-string input; no execution is authorized.")
        payload = self._scan_http(code) if self.base_url else self._scan_local(code)
        if not _valid(payload):
            raise BlockedByCodeGuard("Invalid or unverifiable detector response; no execution is authorized.")
        if payload.get("verdict") == "block":
            raise BlockedByCodeGuard("CodeGuard blocked this snippet.", payload)
        return payload

    def _scan_http(self, code):
        url = f"{self.base_url}/v1/guard?detail=full"
        request = urllib.request.Request(
            url, data=json.dumps({"code": code}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if response.status != 200:
                    raise BlockedByCodeGuard("Detector returned a non-200 status; no execution is authorized.")
                return json.loads(response.read().decode("utf-8"))
        except BlockedByCodeGuard:
            raise
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as error:
            raise BlockedByCodeGuard(
                "Detector unavailable or unparsable; failing closed, no execution is authorized."
            ) from error

    def _scan_local(self, code):
        if str(_BACKEND) not in sys.path:
            sys.path.insert(0, str(_BACKEND))
        from feat_6_runtime.runtime import scan  # imported lazily, same engine as the API
        result = scan(code)
        if result.get("analysis_complete") is not True or result.get("degraded"):
            # Fail closed: an incomplete scan is a block, never permission.
            return {**result, "verdict": "block"}
        return result


class GuardedExecutor:
    """Restricted executor: temp cwd, rlimits, timeout, scrubbed environment."""

    def __init__(self, timeout=5.0, memory_bytes=256 * 1024 * 1024, allowed=None,
                 workdir=None, argv=()):
        self.timeout = timeout
        self.memory_bytes = memory_bytes
        self.allowed = allowed
        self.workdir = workdir
        self.argv = list(argv)
        self.calls = 0

    def __call__(self, code):
        """Run a Python snippet in a restricted subprocess. Explicit opt-in only."""
        if self.allowed is not None and code not in self.allowed:
            raise BlockedByCodeGuard("Snippet is not in the controlled execution allow-list.")
        self.calls += 1
        context = tempfile.TemporaryDirectory(prefix="codeguard-exec-") if self.workdir is None else nullcontext(self.workdir)
        with context as work:
            script = Path(work) / "snippet.py"
            script.write_text(code, encoding="utf-8")

            def limits():
                resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
                resource.setrlimit(resource.RLIMIT_AS, (self.memory_bytes, self.memory_bytes))
                resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
                resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
                os.setsid()

            try:
                completed = subprocess.run(
                    [sys.executable, "-I", "-S", str(script), *self.argv],
                    cwd=work, env={"PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1"},
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=self.timeout, preexec_fn=limits, check=False,
                )
            except subprocess.TimeoutExpired as error:
                raise BlockedByCodeGuard("Execution exceeded the time limit.") from error
        return {"executed": True, "returncode": completed.returncode,
                "stdout": completed.stdout.decode("utf-8", "replace")}


_default_guard = Guard()
_default_executor = GuardedExecutor()


def guarded_execute(code, executor=None, guard_client=None, on_error="block"):
    """Scan *code*, then run the exact scanned bytes only if allowed.

    ``on_error='allow'`` is a deliberate, discouraged opt-in; the default fails
    closed so a detector outage can never authorize execution.
    """
    guard_client = guard_client or _default_guard
    executor = executor or _default_executor
    digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
    try:
        verdict = guard_client.scan(code)
    except BlockedByCodeGuard:
        raise
    except Exception as error:  # unexpected error -> never permission
        if on_error == "allow":
            return executor(code)
        raise BlockedByCodeGuard(f"Guard error ({type(error).__name__}); no execution is authorized.") from error
    if verdict.get("code_hash") and verdict["code_hash"] != digest:
        raise BlockedByCodeGuard("Verdict does not match the scanned bytes; no execution is authorized.")
    return executor(code)


def guard(func):
    """Decorator: gate a function that takes code as its first argument."""
    def wrapper(code, *args, **kwargs):
        return guarded_execute(code, executor=lambda snippet: func(snippet, *args, **kwargs))
    wrapper.__name__ = getattr(func, "__name__", "wrapper")
    wrapper.__doc__ = func.__doc__
    return wrapper
