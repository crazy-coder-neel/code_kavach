"""Bounded, process-local metrics; no source text or unbounded labels."""
from threading import Lock


class Metrics:
    bounds = (1, 3, 5, 15, 25, 100, 1000)

    def __init__(self):
        self.lock = Lock()
        self.count = self.degraded = self.hits = 0
        self.total_ms = 0.0
        self.buckets = [0] * len(self.bounds)

    def observe(self, duration_ms, degraded, cache_hit):
        with self.lock:
            self.count += 1
            self.total_ms += duration_ms
            self.degraded += int(degraded)
            self.hits += int(cache_hit)
            for i, bound in enumerate(self.bounds):
                self.buckets[i] += int(duration_ms <= bound)

    def render(self):
        with self.lock:
            lines = ['# TYPE codeguard_http_duration_ms histogram']
            lines += [f'codeguard_http_duration_ms_bucket{{le="{bound}"}} {count}'
                      for bound, count in zip(self.bounds, self.buckets)]
            lines += [f'codeguard_http_duration_ms_bucket{{le="+Inf"}} {self.count}',
                      f'codeguard_http_duration_ms_count {self.count}',
                      f'codeguard_http_duration_ms_sum {self.total_ms}',
                      f'codeguard_http_degraded_total {self.degraded}',
                      f'codeguard_http_cache_hits_total {self.hits}']
            return '\n'.join(lines) + '\n'
