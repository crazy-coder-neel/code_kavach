"""Enforcement tests use a spy executor; submitted source is never executed."""
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'sdk'))
from codeguard import BlockedByCodeGuard, Guard, guarded_execute


ALLOW = dict(verdict='allow', risk_score=0.0, categories=[], code_language='python')


class SDKTests(unittest.TestCase):
    def test_invalid_and_incomplete_verdicts_never_enter_executor(self):
        for verdict in (None, [], {}, {**ALLOW, 'verdict': 'block'},
                        {**ALLOW, 'risk_score': float('nan')},
                        {**ALLOW, 'categories': [{}]},
                        {**ALLOW, 'analysis_complete': False},
                        {**ALLOW, 'degraded': True},
                        {**ALLOW, 'code_hash': 'wrong'}):
            with self.subTest(verdict=verdict):
                executor = Mock()
                client = Mock(scan=Mock(return_value=verdict))
                with self.assertRaises(BlockedByCodeGuard):
                    guarded_execute('pass', executor=executor, guard_client=client)
                executor.assert_not_called()

    def test_errors_and_fail_open_setting_never_enter_executor(self):
        for mode in ('block', 'allow'):
            executor = Mock()
            client = Mock(scan=Mock(side_effect=TimeoutError))
            with self.assertRaises(BlockedByCodeGuard):
                guarded_execute('pass', executor=executor, guard_client=client, on_error=mode)
            executor.assert_not_called()

    def test_exact_source_reaches_scanner_and_executor(self):
        code = '# Unicode: café\r\nprint(1)\r\n'
        verdict = {**ALLOW, 'code_hash': hashlib.sha256(code.encode()).hexdigest()}
        client = Mock(scan=Mock(return_value=verdict))
        executor = Mock(return_value='done')
        self.assertEqual(guarded_execute(code, executor=executor, guard_client=client), 'done')
        client.scan.assert_called_once_with(code)
        executor.assert_called_once_with(code)

    def test_http_client_rejects_degraded_allow(self):
        client = Guard(base_url='http://unused.invalid')
        client._scan_http = Mock(return_value={**ALLOW, 'degraded': True})
        with self.assertRaises(BlockedByCodeGuard):
            client.scan('pass')
