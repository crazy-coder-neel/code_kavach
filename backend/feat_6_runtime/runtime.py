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


def scan(code):
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
    return {**result, 'request_id': str(uuid4()), 'engine_version': ENGINE_VERSION,
            'cache_status': 'hit' if cached is not None else 'miss',
            'latency_ms': round((perf_counter() - start) * 1000, 3)}
