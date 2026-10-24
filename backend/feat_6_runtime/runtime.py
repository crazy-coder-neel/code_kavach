"""Bounded local cache of semantic results, without per-request metadata."""
from collections import OrderedDict
from copy import deepcopy
from hashlib import sha256
import json
from threading import Lock
from time import perf_counter
from uuid import uuid4
from feat_1_scan.analyzer import analyze

from feat_6_runtime.versions import ENGINE_VERSION, RULES_VERSION, POLICY_VERSION, MODEL_VERSION
_cache = OrderedDict()
_lock = Lock()
_cache_bytes = 0
MAX_CACHE_BYTES = 8 * 1024 * 1024

_sessions = OrderedDict()
_session_lock = Lock()
MAX_SESSIONS = 500


def record_session_event(session_id: str, event_type: str):
    if not session_id or not isinstance(session_id, str):
        return
    with _session_lock:
        events = _sessions.setdefault(session_id, set())
        events.add(event_type)
        _sessions.move_to_end(session_id)
        while len(_sessions) > MAX_SESSIONS:
            _sessions.popitem(last=False)


def get_session_events(session_id: str) -> set:
    if not session_id or not isinstance(session_id, str):
        return set()
    with _session_lock:
        return set(_sessions.get(session_id, set()))


def clear_sessions():
    with _session_lock:
        _sessions.clear()


def scan(code, session_id=None):
    global _cache_bytes
    start = perf_counter()
    key = (ENGINE_VERSION, RULES_VERSION, MODEL_VERSION, POLICY_VERSION,
           sha256(code.encode('utf-8')).hexdigest())
    with _lock:
        cached = _cache.get(key)
        if cached is not None:
            _cache.move_to_end(key)
    result = deepcopy(cached[0]) if cached is not None else analyze(code)
    if cached is None and result['analysis_complete']:
        with _lock:
            size = len(json.dumps(result).encode('utf-8'))
            if size <= MAX_CACHE_BYTES:
                old = _cache.pop(key, None)
                if old is not None:
                    _cache_bytes -= old[1]
                _cache[key] = (deepcopy(result), size)
                _cache_bytes += size
                while len(_cache) > 128 or _cache_bytes > MAX_CACHE_BYTES:
                    _, (_, evicted_size) = _cache.popitem(last=False)
                    _cache_bytes -= evicted_size

    if session_id and isinstance(session_id, str):
        categories = set(result.get('categories', []))
        if 'secret_access' in categories:
            record_session_event(session_id, 'sensitive_read')
        elif 'sensitive_read' in get_session_events(session_id):
            import re
            has_network = bool(re.search(r'\b(?:requests|httpx|urllib|aiohttp|socket)\b|https?://', code))
            if has_network and 'data_exfiltration' not in categories:
                from feat_2_results.scoring import aggregate
                cascade_finding = {
                    'category': 'data_exfiltration',
                    'severity': 'critical',
                    'lines': [1],
                    'title': 'Session Cascade: Cross-Step Exfiltration',
                    'why': f'A preceding step in session {session_id[:16]} accessed sensitive credentials; current step initiates outbound network transmission.',
                    'remediation': 'Isolate credential access steps from external network transmission sinks.',
                    'evidence': 'Multi-step session correlation detected',
                    'rule_id': 'CG-EXF-CASCADE',
                    'decision': 'risk_finding',
                    'confidence': 0.95,
                    'references': ['CWE-200', 'AEGIS Cross-Agent Cascade']
                }
                findings = list(result.get('findings', [])) + [cascade_finding]
                verdict, score, trace = aggregate(findings, complete=True)
                result = {
                    **result,
                    'verdict': verdict,
                    'risk_score': score,
                    'categories': sorted(set(result.get('categories', []) + ['data_exfiltration'])),
                    'reason': cascade_finding['why'],
                    'vulnerable_lines': sorted(set(result.get('vulnerable_lines', []) + [1])),
                    'findings': findings,
                    'score_trace': trace
                }

    return {**result, 'request_id': str(uuid4()), 'engine_version': ENGINE_VERSION,
            'cache_status': 'hit' if cached is not None else 'miss',
            'session_id': session_id,
            'latency_ms': round((perf_counter() - start) * 1000, 3)}
