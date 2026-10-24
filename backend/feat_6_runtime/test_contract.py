import json
import threading
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
import main
from feat_6_runtime.audit import AuditQueue
from feat_6_runtime.contract import FIELDS, valid


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)

    def assert_contract(self, response, status=200):
        self.assertEqual(response.status_code, status)
        result = response.json()
        self.assertEqual(set(result), set(FIELDS))
        self.assertTrue(valid(result, 100000))
        for header in ('X-Request-Id', 'X-Engine-Version', 'X-Rules-Version', 'X-Policy-Version'):
            self.assertIn(header, response.headers)
        return result

    def test_intake_failures_have_fixed_schema(self):
        for body in (b'{', b'\xff', b'[]', b'{}', b'{"code":123}', b'{"code":""}',
                     b'{"code":" "}', b'{"code":"\\ud800"}', b'[' * 2000):
            with self.subTest(body=body[:30]):
                response = self.client.post('/v1/guard', content=body)
                self.assertEqual(self.assert_contract(response, 400)['verdict'], 'block')
        for code in ('x' * 65537, 'é' * 40000):
            self.assert_contract(self.client.post('/v1/guard', json={'code': code}), 413)
        self.assert_contract(self.client.post('/v1/guard', content=b'x' * (main.MAX_BODY_BYTES + 1)), 413)

    def test_failures_and_invalid_engine_results(self):
        for error in (ValueError, RuntimeError, TimeoutError, RecursionError):
            with self.subTest(error=error), patch('main.scan', side_effect=error):
                response = self.client.post('/v1/guard', json={'code': 'value=1'})
                self.assertEqual(self.assert_contract(response)['verdict'], 'block')
                self.assertEqual(response.headers['X-CodeGuard-Degraded'], '1')
        for result in ({}, {'verdict': 'allow'}, {'verdict': 'allow', 'risk_score': float('nan')}):
            with patch('main.scan', return_value=result):
                self.assertEqual(self.assert_contract(self.client.post('/v1/guard', json={'code': 'x=1'}))['verdict'], 'block')

    def test_incomplete_and_deadline_are_degraded(self):
        response = self.client.post('/v1/guard?detail=full', json={'code': 'def broken('})
        self.assertTrue(response.json()['degraded'])
        self.assertEqual(response.json()['verdict'], 'block')
        with patch('main.SCAN_DEADLINE_MS', -1):
            response = self.client.post('/v1/guard', json={'code': 'value=1'})
            self.assertEqual(self.assert_contract(response)['verdict'], 'block')
            self.assertIn('deadline', response.json()['reason'])

    def test_detail_is_opt_in_even_for_errors(self):
        for code in ('value=1', 'exec(payload)', 'def broken('):
            strict = self.client.post('/v1/guard', json={'code': code})
            self.assert_contract(strict)
            detail = self.client.post('/v1/guard?detail=full', json={'code': code}).json()
            self.assertIn('engine_version', detail)
            self.assertIn('degraded', detail)
        self.assertIn('degraded', self.client.post('/v1/guard?detail=full', content='{').json())

    def test_mixed_batch_is_isolated(self):
        response = self.client.post('/v1/guard/batch', json={'items': [
            {'id': 'safe', 'code': 'value=1'}, {'id': 'invalid', 'code': 3},
            {'id': 'blocked', 'code': 'exec(payload)'}, None]})
        results = response.json()['results']
        self.assertEqual([r['verdict'] for r in results], ['allow', 'block', 'block', 'block'])
        for result in results:
            self.assertEqual(set(result), set(FIELDS) | {'id'})
        self.assertEqual(response.headers['X-CodeGuard-Degraded'], '1')

    def test_audit_never_changes_verdict_or_retains_code(self):
        with patch.object(main.app.state.audit, 'enqueue', side_effect=OSError):
            response = self.client.post('/v1/guard', json={'code': 'value=1'})
            self.assertEqual(self.assert_contract(response)['verdict'], 'allow')
            self.assertEqual(response.headers['X-CodeGuard-Audit'], 'dropped')
        with patch.object(main.app.state.audit, 'enqueue', return_value=True) as enqueue:
            self.client.post('/v1/guard?detail=full', json={'code': 'unique_marker_abcdefgh=1'})
            event = enqueue.call_args.args[0]
            self.assertNotIn('unique_marker_abcdefgh', json.dumps(event))
            self.assertEqual(len(event['decision']['code_sha256']), 64)

    def test_warmup_controls_readiness(self):
        with TestClient(main.app) as client:
            self.assertEqual(client.get('/readyz').status_code, 200)
        self.assertFalse(main.app.state.ready)
        with patch('main.scan', side_effect=RuntimeError), TestClient(main.app) as client:
            self.assertEqual(client.get('/healthz').status_code, 200)
            self.assertEqual(client.get('/readyz').status_code, 503)

    def test_scan_has_no_network(self):
        with patch('socket.socket', side_effect=AssertionError('network prohibited')):
            result = main.analyze_request('import os\nos.system(command) # no-network regression')
        self.assertEqual(result['verdict'], 'block')
        self.assertTrue(result['analysis_complete'])

    def test_session_cascade_correlation(self):
        from feat_6_runtime.runtime import clear_sessions
        clear_sessions()
        s_id = 'test-session-cascade-1'
        r1 = self.client.post('/v1/guard', json={'code': 'open("~/.kube/config").read()', 'session_id': s_id})
        self.assertEqual(r1.json()['verdict'], 'block')
        self.assertIn('secret_access', r1.json()['categories'])

        r2 = self.client.post('/v1/guard', json={
            'code': 'import requests\nrequests.post("https://example.com/api", json={"status": "ok"})',
            'session_id': s_id
        })
        self.assertEqual(r2.json()['verdict'], 'block')
        self.assertIn('data_exfiltration', r2.json()['categories'])

        r3 = self.client.post('/v1/guard', json={
            'code': 'import requests\nrequests.post("https://example.com/api", json={"status": "ok"})',
            'session_id': 'different-session'
        })
        self.assertEqual(r3.json()['verdict'], 'allow')


class AuditQueueTests(unittest.TestCase):
    def test_overflow_drops_oldest_and_counts(self):
        queue = AuditQueue(capacity=2)
        for i in range(3):
            queue.enqueue({'index': i})
        self.assertEqual(list(queue.pending), [{'index': 1}, {'index': 2}])
        self.assertEqual(queue.stats()['dropped'], 1)

    def test_slow_and_failed_writer_do_not_block_enqueue(self):
        entered, release = threading.Event(), threading.Event()
        def writer(event):
            entered.set()
            release.wait(2)
            raise OSError('disk unavailable')
        queue = AuditQueue(writer=writer)
        queue.start()
        try:
            queue.enqueue({'index': 1})
            self.assertTrue(entered.wait(1))
            queue.enqueue({'index': 2})
            self.assertEqual(queue.stats()['queued'], 1)
        finally:
            release.set()
            queue.close()
        self.assertEqual(queue.stats()['errors'], 2)


class MetricsAndVersionTests(unittest.TestCase):
    def test_histogram_is_cumulative(self):
        from feat_6_runtime.metrics import Metrics
        metrics = Metrics()
        metrics.observe(2, False, True)
        metrics.observe(30, True, False)
        rendered = metrics.render()
        self.assertIn('bucket{le="1"} 0', rendered)
        self.assertIn('bucket{le="3"} 1', rendered)
        self.assertIn('bucket{le="100"} 2', rendered)
        self.assertIn('codeguard_http_degraded_total 1', rendered)
        self.assertIn('codeguard_http_cache_hits_total 1', rendered)

    def test_policy_change_invalidates_cache(self):
        from feat_6_runtime.runtime import scan
        code = 'cache_version_test = 123'
        scan(code)
        self.assertEqual(scan(code)['cache_status'], 'hit')
        for version in ('POLICY_VERSION', 'MODEL_VERSION', 'RULES_VERSION'):
            with patch('feat_6_runtime.runtime.' + version, 'test-next'):
                self.assertEqual(scan(code)['cache_status'], 'miss')

    def test_http_metrics_and_detail_header(self):
        client = TestClient(main.app)
        response = client.post('/v1/guard', json={'code': 'value=1'},
                               headers={'X-CodeGuard-Detail': 'full'})
        self.assertIn('rules_version', response.json())
        self.assertIn('codeguard_http_duration_ms_count', client.get('/metrics').text)
