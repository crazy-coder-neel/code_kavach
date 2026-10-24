"""Sequential warm benchmarks; source is scanned, never executed."""
import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import platform
import sys
from time import perf_counter_ns
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
from feat_1_scan.analyzer import analyze
from feat_6_runtime.runtime import ENGINE_VERSION, scan


def percentiles(values):
    ordered = sorted(values)
    return {name: ordered[max(0, math.ceil(len(ordered) * q) - 1)]
            for name, q in [('p50', .5), ('p95', .95), ('p99', .99)]}


def run(iterations, url=None):
    report = {'created_at': datetime.now(timezone.utc).isoformat(), 'engine_version': ENGINE_VERSION,
              'python': platform.python_version(), 'machine': platform.machine(),
              'iterations': iterations, 'method': 'nearest-rank; sequential; 10 warmups per bucket',
              'buckets': {}, 'http_url': url}
    for name, target in [('small', 256), ('medium', 2048), ('large', 4096)]:
        code = 'value = 1\n' + '# harmless padding\n' * ((target - 10) // 19)
        def http_scan(source):
            request = urllib.request.Request(url + '/v1/guard',
                data=json.dumps({'code': source}).encode(), headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(request, timeout=10) as response:
                result = json.load(response)
                if result.get('verdict') != 'allow':
                    raise RuntimeError('Benchmark scan degraded or blocked; inspect the service.')
                return float(response.headers['X-CodeGuard-Server-Ms'])
        modes = [('analyzer_uncached', analyze), ('runtime_cached', scan)]
        if url:
            modes.append(('http_cached_end_to_end', http_scan))
        data = {'bytes': len(code.encode()), 'timings_ms': {}}
        for mode, call in modes:
            for _ in range(10):
                call(code)
            times, server_times = [], []
            for _ in range(iterations):
                started = perf_counter_ns()
                result = call(code)
                times.append((perf_counter_ns() - started) / 1e6)
                if mode.startswith('http'):
                    server_times.append(result)
            data['timings_ms'][mode] = percentiles(times)
            if server_times:
                data['timings_ms']['http_cached_server'] = percentiles(server_times)
        report['buckets'][name] = data
    report['limitations'] = ('Harmless padding size baseline, not representative detection/load testing. '
        'Cached paths reuse identical input. Uncached analyzer excludes HTTP. Deadline only checked after scan in Phase 1.')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iterations', type=int, default=300)
    parser.add_argument('--url')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error('iterations must be positive')
    args.output.write_text(json.dumps(run(args.iterations, args.url), indent=2) + '\n')
