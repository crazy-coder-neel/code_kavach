"""Reproducible local evaluation. Fixture source is parsed, never executed."""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import platform
import sys
from threading import Lock
from time import perf_counter
from uuid import uuid4

# Support both direct CLI execution and import from main.py.
if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from feat_1_scan.analyzer import analyze
from feat_2_results.results import MESSAGES
from feat_6_runtime.runtime import ENGINE_VERSION

DATASET = Path(__file__).resolve().parents[2] / 'codeguard_dev.jsonl'
RUN_LOCK = Lock()


def ratio(numerator, denominator):
    return round(numerator / denominator, 6) if denominator else None


def metrics(tp, fp, tn, fn):
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'precision': ratio(tp, tp + fp), 'recall': ratio(tp, tp + fn),
            'f1': ratio(2 * tp, 2 * tp + fp + fn), 'fpr': ratio(fp, fp + tn)}


def summarize(rows):
    counts = {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0}
    by_category = {}
    for row in rows:
        counts[('t' if row['expected'] == row['predicted'] else 'f') +
               ('p' if row['predicted'] == 'block' else 'n')] += 1
    for category in MESSAGES:
        tp = fp = tn = fn = 0
        for row in rows:
            expected = category in row['expected_categories']
            predicted = category in row['predicted_categories']
            tp += expected and predicted
            fp += not expected and predicted
            tn += not expected and not predicted
            fn += expected and not predicted
        by_category[category] = {**metrics(tp, fp, tn, fn), 'support': tp + fn}
    return metrics(**counts), by_category


def run_evaluation():
    raw = DATASET.read_bytes()
    fixtures = [json.loads(line) for line in raw.splitlines() if line.strip()]
    if not fixtures or len(fixtures) > 500 or len(raw) > 4 * 1024 * 1024:
        raise ValueError('Invalid bundled evaluation dataset size.')
    # Warm interpreter paths, but never use the verdict cache during measurement.
    analyze('value = 1')
    rows = []
    for fixture in fixtures:
        started = perf_counter()
        error = False
        try:
            result = analyze(fixture['code'])
        except Exception:
            error = True
            result = {'verdict': 'block', 'categories': [], 'analysis_complete': False,
                      'reason': 'Analysis failed; operational fail-closed decision.'}
        elapsed = (perf_counter() - started) * 1000
        expected_categories = sorted(c.strip() for c in fixture['category'].split(',') if c.strip() != 'benign')
        rows.append({'id': fixture['id'], 'language': fixture['language'],
                     'expected': 'block' if fixture['label'] == 1 else 'allow',
                     'predicted': result['verdict'], 'expected_categories': expected_categories,
                     'predicted_categories': result['categories'], 'latency_ms': round(elapsed, 4),
                     'analysis_complete': result['analysis_complete'], 'error': error,
                     'reason': result['reason'], 'score_trace': result.get('score_trace')})
    binary, per_category = summarize(rows)
    timings = sorted(row['latency_ms'] for row in rows)
    percentile = lambda q: timings[max(0, math.ceil(len(timings) * q) - 1)]
    return {'run_id': str(uuid4()), 'created_at': datetime.now(timezone.utc).isoformat(),
            'engine_version': ENGINE_VERSION, 'dataset': 'Public development set',
            'dataset_sha256': sha256(raw).hexdigest(), 'sample_count': len(rows),
            'malicious_count': sum(f['label'] == 1 for f in fixtures),
            'benign_count': sum(f['label'] == 0 for f in fixtures),
            'cache': 'bypassed', 'latency_scope': 'Warm direct analyzer; excludes HTTP, rendering and queue wait. Nearest-rank percentiles.',
            'machine': {'architecture': platform.machine(), 'logical_cpus': os.cpu_count(), 'python': platform.python_version()},
            'binary': binary, 'per_category': per_category,
            'latency_ms': {'p50': percentile(.5), 'p95': percentile(.95), 'p99': percentile(.99)},
            'incomplete_count': sum(not r['analysis_complete'] for r in rows),
            'error_count': sum(r['error'] for r in rows), 'results': rows,
            'notes': 'Development baseline, not a held-out or official score. Operational blocks count in binary metrics; category metrics measure actual findings. No sample code is executed.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Optional JSON report destination')
    args = parser.parse_args()
    report = json.dumps(run_evaluation(), indent=2)
    if args.output:
        args.output.write_text(report + '\n')
    else:
        print(report)
